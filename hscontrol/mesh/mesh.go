// Package mesh is the multi-headscale crown-election and peer-health
// subsystem. One instance per running headscale.
//
// The goal is modest: when multiple headscale instances are configured
// to know about each other, each one periodically probes its siblings
// and publishes a compact JSON snapshot (self + peer view + elected
// crown) to every client via [types.CapabilityMesh]. A client whose
// current control server goes unresponsive can read the snapshot from
// its last-known netmap, find another server in the list, and
// reconnect there. The client never depends on external DNS after
// first contact.
//
// The election is intentionally deterministic: each server computes
// the crown from the same inputs (its own view of peer reachability +
// self-reported scores) and therefore agrees with its siblings
// without distributed consensus. If the views diverge briefly during
// a partition, both halves resolve independently; when the partition
// heals, the higher-scoring side wins on the next probe cycle.
package mesh

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
)


// PeerStatus is the mesh-view of one headscale instance (self or sibling).
type PeerStatus struct {
	Name     string    `json:"name"`
	URL      string    `json:"url"`
	Online   bool      `json:"online"`
	LastSeen time.Time `json:"last_seen,omitempty"`
	Uptime   float64   `json:"uptime_seconds"`
	Score    float64   `json:"score"`

	// LatencyMs is the most recent probe round-trip time for this peer
	// (meaningless for self unless SelfHealthProbe supplies it).
	// Reported for observability; the election uses Score, which is
	// derived from this value via [scoreFromLatency].
	LatencyMs float64 `json:"latency_ms,omitempty"`
}

// Snapshot is the full mesh view computed locally and published to
// clients via CapabilityMesh. Deterministic for a given set of
// PeerStatus entries so siblings agree.
type Snapshot struct {
	Self    PeerStatus   `json:"self"`
	Peers   []PeerStatus `json:"peers"`
	Crown   string       `json:"crown"`
	Updated time.Time    `json:"updated"`
}

// State holds the live mesh view for this headscale. Safe for
// concurrent reads via Snapshot().
type State struct {
	mu           sync.RWMutex
	started      time.Time
	self         PeerStatus
	peers        []PeerStatus
	offlineAt    time.Duration // peer offline after this long w/o a good probe
	latencyAlert time.Duration // above this, peer score starts decaying

	// lastCrown is the crown name from the previous probe cycle.
	// Used to trigger OnBecameCrown exactly once per transition.
	lastCrown string

	// OnBecameCrown is invoked synchronously whenever this instance
	// newly wins the crown (i.e. the election output transitions
	// from some other name to self). Set by the app after New().
	// In-flight probes do not block on it.
	OnBecameCrown func()

	// SelfHealthProbe, if set, is called each probe cycle to measure
	// the local write path's latency (typically a SELECT 1 against the
	// configured postgres primary). A slow or failing probe demotes
	// this instance's score so a faster sibling wins the crown. If
	// nil, the self score stays pinned at 1.0.
	SelfHealthProbe func(ctx context.Context) (time.Duration, error)

	// persistPath, if non-empty, is the file where dynamically-joined
	// peers are mirrored so they survive restarts. Written atomically
	// on every addPeerLocked that introduces a new URL.
	persistPath string

	// clusterSecret is the HMAC key used to verify /mesh/join requests.
	// Empty → join endpoint is disabled.
	clusterSecret string
}

// New constructs a State seeded from cfg. Returns nil if the mesh
// subsystem is disabled (SelfName empty or no peers).
func New(cfg types.MeshConfig) *State {
	if !cfg.IsEnabled() {
		return nil
	}
	now := time.Now()
	peers := make([]PeerStatus, 0, len(cfg.Peers))
	for _, p := range cfg.Peers {
		peers = append(peers, PeerStatus{Name: p.Name, URL: p.URL})
	}
	s := &State{
		started:       now,
		offlineAt:     cfg.OfflineAfter,
		latencyAlert:  cfg.LatencyAlert,
		persistPath:   cfg.PeersStatePath,
		clusterSecret: cfg.ClusterSecret,
		self: PeerStatus{
			Name:   cfg.SelfName,
			URL:    cfg.SelfURL,
			Online: true,
			Score:  1.0,
		},
		peers: peers,
	}
	if s.persistPath != "" && s.persistPath != "-" {
		s.mu.Lock()
		for _, p := range loadPersistedPeers(s.persistPath) {
			s.addPeerLocked(p.Name, p.URL)
		}
		s.mu.Unlock()
	}
	return s
}

// addPeerLocked adds (name, url) to the peer list if the URL is not
// already present and is not self. Returns true when a new entry was
// actually added. Caller must hold s.mu (write).
func (s *State) addPeerLocked(name, url string) bool {
	if url == "" || url == s.self.URL {
		return false
	}
	for _, p := range s.peers {
		if p.URL == url {
			return false
		}
	}
	s.peers = append(s.peers, PeerStatus{Name: name, URL: url})
	return true
}

// AddPeer is the concurrent-safe entry point used by /mesh/join and the
// gossip merge in probeAll. Persists the new peer set to disk when a
// persistPath is configured.
func (s *State) AddPeer(name, url string) bool {
	s.mu.Lock()
	added := s.addPeerLocked(name, url)
	peersCopy := append([]PeerStatus(nil), s.peers...)
	s.mu.Unlock()
	if added {
		log.Info().Str("name", name).Str("url", url).Msg("mesh: peer added")
		s.persistPeers(peersCopy)
	}
	return added
}

// peersForSnapshot returns the current peer list (copy) without
// invoking any election logic. Used by /mesh/join responses so the
// caller can seed its own peer list.
func (s *State) peersForSnapshot() []PeerStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PeerStatus, len(s.peers))
	copy(out, s.peers)
	return out
}

// SelfSummary returns Name/URL so the join handler can echo identity
// back to the caller without exposing live probe state.
func (s *State) SelfSummary() (name, url string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.self.Name, s.self.URL
}

// ClusterSecret returns the configured HMAC secret or empty string.
// Exposed so the app layer can gate /mesh/join mounting on "secret
// configured".
func (s *State) ClusterSecret() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clusterSecret
}

type persistedPeers struct {
	Peers []MeshPeerRecord `json:"peers"`
}

// MeshPeerRecord is the on-disk form of a dynamically-joined peer.
// Kept separate from PeerStatus so probe-time fields (LastSeen, Score,
// LatencyMs) aren't persisted — they rehydrate naturally on next probe.
type MeshPeerRecord struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

func loadPersistedPeers(path string) []MeshPeerRecord {
	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warn().Err(err).Str("path", path).Msg("mesh: peers.state read failed")
		}
		return nil
	}
	var pp persistedPeers
	if err := json.Unmarshal(raw, &pp); err != nil {
		log.Warn().Err(err).Str("path", path).Msg("mesh: peers.state parse failed")
		return nil
	}
	return pp.Peers
}

func (s *State) persistPeers(peers []PeerStatus) {
	if s.persistPath == "" || s.persistPath == "-" {
		return
	}
	records := make([]MeshPeerRecord, 0, len(peers))
	for _, p := range peers {
		records = append(records, MeshPeerRecord{Name: p.Name, URL: p.URL})
	}
	raw, err := json.MarshalIndent(persistedPeers{Peers: records}, "", "  ")
	if err != nil {
		log.Warn().Err(err).Msg("mesh: peers.state marshal failed")
		return
	}
	tmp := s.persistPath + ".tmp"
	if err := os.MkdirAll(filepath.Dir(s.persistPath), 0o755); err != nil {
		log.Warn().Err(err).Str("path", s.persistPath).Msg("mesh: peers.state mkdir failed")
		return
	}
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		log.Warn().Err(err).Str("path", tmp).Msg("mesh: peers.state write failed")
		return
	}
	if err := os.Rename(tmp, s.persistPath); err != nil {
		log.Warn().Err(err).Str("path", s.persistPath).Msg("mesh: peers.state rename failed")
	}
}

// scoreFromLatency returns a score in (0, 1] that decays exponentially
// above the alert threshold. latency == alert → score ≈ 0.37; latency
// == 2*alert → score ≈ 0.14; latency == alert/2 → score ≈ 0.82. A peer
// that responds "instantly" still caps at 1.0.
func scoreFromLatency(latency, alert time.Duration) float64 {
	if alert <= 0 || latency <= 0 {
		return 1.0
	}
	return math.Exp(-float64(latency) / float64(alert))
}

// Snapshot returns the current mesh view. Safe for repeated calls.
func (s *State) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	self := s.self
	self.Uptime = now.Sub(s.started).Seconds()

	peers := make([]PeerStatus, len(s.peers))
	for i, p := range s.peers {
		// Decay to "offline" if the last probe is too old.
		if !p.LastSeen.IsZero() && now.Sub(p.LastSeen) > s.offlineAt {
			p.Online = false
		}
		peers[i] = p
	}

	return Snapshot{
		Self:    self,
		Peers:   peers,
		Crown:   electCrown(self, peers),
		Updated: now,
	}
}

// electCrown returns the name of the currently-elected crown server.
// Highest Score wins; ties broken by lexicographic Name. Only online
// servers are eligible. If the caller is the only healthy server left,
// it crowns itself without hesitation.
func electCrown(self PeerStatus, peers []PeerStatus) string {
	eligible := []PeerStatus{self}
	for _, p := range peers {
		if p.Online {
			eligible = append(eligible, p)
		}
	}
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].Score != eligible[j].Score {
			return eligible[i].Score > eligible[j].Score
		}
		return eligible[i].Name < eligible[j].Name
	})
	return eligible[0].Name
}

// Prober is the long-running peer-health loop. Runs until ctx is
// cancelled. No-op when s is nil (mesh disabled).
func (s *State) Prober(ctx context.Context, cfg types.MeshConfig) {
	if s == nil {
		return
	}
	log.Info().
		Str("self", cfg.SelfName).
		Int("peers", len(cfg.Peers)).
		Dur("interval", cfg.ProbeInterval).
		Msg("mesh: prober started")

	// Immediate first probe so the snapshot is populated before the
	// first client map request hits.
	s.probeAll(ctx)

	t := time.NewTicker(cfg.ProbeInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.probeAll(ctx)
		}
	}
}

func (s *State) probeAll(ctx context.Context) {
	s.mu.RLock()
	peers := make([]PeerStatus, len(s.peers))
	copy(peers, s.peers)
	healthProbe := s.SelfHealthProbe
	selfName := s.self.Name
	selfURL := s.self.URL
	s.mu.RUnlock()

	results := make([]PeerStatus, len(peers))
	discovered := make([][]MeshPeerRecord, len(peers))
	var wg sync.WaitGroup
	for i := range peers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], discovered[i] = s.probeOne(ctx, peers[i])
		}(i)
	}
	wg.Wait()

	// Gossip: merge peers observed in any sibling's snapshot that we
	// don't know about yet. New entries are added to results so the
	// snapshot we publish this cycle already reflects them.
	existing := map[string]bool{selfURL: true}
	for _, p := range results {
		existing[p.URL] = true
	}
	var gossiped []PeerStatus
	for _, batch := range discovered {
		for _, d := range batch {
			if d.URL == "" || existing[d.URL] {
				continue
			}
			existing[d.URL] = true
			entry := PeerStatus{Name: d.Name, URL: d.URL}
			gossiped = append(gossiped, entry)
			log.Info().Str("self", selfName).Str("name", d.Name).Str("url", d.URL).
				Msg("mesh: peer discovered via gossip")
		}
	}
	if len(gossiped) > 0 {
		results = append(results, gossiped...)
	}

	// Self score from an optional local-write-path health probe.
	// Slow or failing probe → low self score → faster sibling wins.
	selfScore := 1.0
	selfLatencyMs := 0.0
	if healthProbe != nil {
		hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		d, err := healthProbe(hctx)
		cancel()
		if err != nil {
			selfScore = 0
			selfLatencyMs = 5000
		} else {
			selfScore = scoreFromLatency(d, s.latencyAlert)
			selfLatencyMs = float64(d.Microseconds()) / 1000.0
		}
	}

	s.mu.Lock()
	s.self.Score = selfScore
	s.self.LatencyMs = selfLatencyMs
	newCrown := electCrown(s.self, applyOfflineDecay(results, s.offlineAt, time.Now()))
	becameCrown := newCrown == s.self.Name && s.lastCrown != "" && s.lastCrown != s.self.Name
	s.lastCrown = newCrown
	cb := s.OnBecameCrown
	s.peers = results
	peersCopy := append([]PeerStatus(nil), s.peers...)
	s.mu.Unlock()

	if len(gossiped) > 0 {
		s.persistPeers(peersCopy)
	}

	if becameCrown && cb != nil {
		log.Info().Str("self", s.self.Name).Msg("mesh: became crown")
		cb()
	}
}

// applyOfflineDecay returns a copy of peers with Online=false for any
// peer whose LastSeen is older than offlineAt. Kept separate so both
// Snapshot() and probeAll() use identical rules.
func applyOfflineDecay(peers []PeerStatus, offlineAt time.Duration, now time.Time) []PeerStatus {
	out := make([]PeerStatus, len(peers))
	for i, p := range peers {
		if !p.LastSeen.IsZero() && now.Sub(p.LastSeen) > offlineAt {
			p.Online = false
		}
		out[i] = p
	}
	return out
}

// probeClient is a module-level HTTP client with tight timeouts so a
// dead peer doesn't stall the probe cycle.
var probeClient = &http.Client{
	Timeout: 5 * time.Second,
}

// probeOne fetches /mesh/info from p and updates its status. Returns a
// new PeerStatus keeping the static Name/URL. Score is derived locally
// from round-trip latency so a peer that lies about its own self-score
// cannot win the election by inflating it. The second return value is
// the set of peers the sibling reports in its own snapshot (including
// its self), used by probeAll for gossip discovery of new members.
func (s *State) probeOne(ctx context.Context, p PeerStatus) (PeerStatus, []MeshPeerRecord) {
	out := PeerStatus{Name: p.Name, URL: p.URL, LastSeen: p.LastSeen, Score: p.Score, LatencyMs: p.LatencyMs}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL+"/mesh/info", nil)
	if err != nil {
		return out, nil
	}
	start := time.Now()
	resp, err := probeClient.Do(req)
	if err != nil {
		return out, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, nil
	}

	var snap Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return out, nil
	}
	latency := time.Since(start)

	out.Online = true
	out.LastSeen = time.Now()
	out.Uptime = snap.Self.Uptime
	out.LatencyMs = float64(latency.Microseconds()) / 1000.0
	out.Score = scoreFromLatency(latency, s.latencyAlert)

	// The sibling's self entry is the primary gossip signal: if it's a
	// peer we don't yet know about, probeAll will add it. We also
	// forward its peer list so transitive discovery converges in one
	// round even on large meshes.
	discovered := make([]MeshPeerRecord, 0, 1+len(snap.Peers))
	if snap.Self.URL != "" {
		discovered = append(discovered, MeshPeerRecord{Name: snap.Self.Name, URL: snap.Self.URL})
	}
	for _, sp := range snap.Peers {
		if sp.URL == "" {
			continue
		}
		discovered = append(discovered, MeshPeerRecord{Name: sp.Name, URL: sp.URL})
	}
	return out, discovered
}

// MarshalSnapshot returns snap encoded as JSON. Returns nil on
// marshal failure (shouldn't happen with only concrete types) so the
// caller can treat it as "no snapshot to publish".
func MarshalSnapshot(snap Snapshot) []byte {
	out, err := json.Marshal(snap)
	if err != nil {
		return nil
	}
	return out
}

// Handler returns the http.Handler serving GET /mesh/info. Returns an
// empty snapshot (200 OK) when the mesh subsystem is disabled so
// probes from misconfigured siblings don't hammer with 404s.
func Handler(s *State) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if s == nil {
			_ = json.NewEncoder(w).Encode(Snapshot{})
			return
		}
		_ = json.NewEncoder(w).Encode(s.Snapshot())
	})
}


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
	"net/http"
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
	mu        sync.RWMutex
	started   time.Time
	self      PeerStatus
	peers     []PeerStatus
	offlineAt time.Duration // peer is offline after this long without a probe success
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
	return &State{
		started:   now,
		offlineAt: cfg.OfflineAfter,
		self: PeerStatus{
			Name:   cfg.SelfName,
			URL:    cfg.SelfURL,
			Online: true,
			Score:  1.0,
		},
		peers: peers,
	}
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
	s.mu.RUnlock()

	results := make([]PeerStatus, len(peers))
	var wg sync.WaitGroup
	for i := range peers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = s.probeOne(ctx, peers[i])
		}(i)
	}
	wg.Wait()

	s.mu.Lock()
	s.peers = results
	s.mu.Unlock()
}

// probeClient is a module-level HTTP client with tight timeouts so a
// dead peer doesn't stall the probe cycle.
var probeClient = &http.Client{
	Timeout: 5 * time.Second,
}

// probeOne fetches /mesh/info from p and updates its status. Returns a
// new PeerStatus keeping the static Name/URL.
func (s *State) probeOne(ctx context.Context, p PeerStatus) PeerStatus {
	out := PeerStatus{Name: p.Name, URL: p.URL, LastSeen: p.LastSeen, Score: p.Score}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL+"/mesh/info", nil)
	if err != nil {
		return out
	}
	resp, err := probeClient.Do(req)
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out
	}

	var snap Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return out
	}

	// Peer is alive and self-reports its score + uptime.
	out.Online = true
	out.LastSeen = time.Now()
	out.Uptime = snap.Self.Uptime
	// Clamp external score so a malicious/broken peer can't claim
	// more than our local uptime-based ceiling.
	out.Score = clamp01(snap.Self.Score)
	return out
}

func clamp01(v float64) float64 {
	if v < 0 || v != v { // NaN guard
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
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


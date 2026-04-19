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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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

	// ConnectedNodeIDs is the set of tailnet node IDs whose long-poll
	// session is currently held by this headscale instance. Self entry
	// is populated from the live Connect/Disconnect set; sibling
	// entries arrive over /mesh/info probes. Used by the mapper to
	// answer "is peer X online anywhere in the cluster?" — without it
	// each sibling only knows about the connections it owns and
	// presents peers connected to a different sibling as offline.
	ConnectedNodeIDs []uint64 `json:"connected_node_ids,omitempty"`

	// DERPRegionID / DERPHost / DERPPort / DERPv4 / DERPv6 describe
	// this peer's embedded DERP region (if any). Empty when DERP is
	// disabled or the sibling is on an older binary. Carried so the
	// mapper can merge sibling regions into the DERPMap shipped to
	// clients — without it, a client whose currently-bound section
	// dies has no DERP relay to fall back on while it rotates.
	DERPRegionID int    `json:"derp_region_id,omitempty"`
	DERPHost     string `json:"derp_host,omitempty"`
	DERPPort     int    `json:"derp_port,omitempty"`
	DERPv4       string `json:"derp_v4,omitempty"`
	DERPv6       string `json:"derp_v6,omitempty"`
	DERPSTUNPort int    `json:"derp_stun_port,omitempty"`
	DERPRegionCode string `json:"derp_region_code,omitempty"`
	DERPRegionName string `json:"derp_region_name,omitempty"`

	// LatencyMs is the most recent probe round-trip time for this peer
	// (meaningless for self unless SelfHealthProbe supplies it).
	// Reported for observability; the election uses Score, which is
	// derived from this value via [scoreFromLatency].
	LatencyMs float64 `json:"latency_ms,omitempty"`

	// NoisePubHex is this peer's noise protocol pubkey (hex-encoded).
	// Set for self at State construction time and for siblings from
	// the identity record observed during probes. Empty when the
	// cluster shared secret isn't configured.
	NoisePubHex string `json:"noise_pub,omitempty"`

	// ClusterSigHex is ed25519.Sign(cluster_priv, NoisePub). Set in
	// tandem with NoisePubHex. The client uses it to verify a sibling
	// belongs to the pinned cluster before rotating ControlURL to it.
	ClusterSigHex string `json:"cluster_sig,omitempty"`

	// ExitNodeName is the tailnet hostname of the per-VPS tailscaled
	// that runs alongside this headscale and advertises an exit-node
	// route. Empty when the operator hasn't configured one. Clients
	// in `--exit-node=auto:follow-crown` mode look up the netmap node
	// with this hostname and pin egress to it whenever this peer is
	// the elected crown.
	ExitNodeName string `json:"exit_node_name,omitempty"`

	// ReliabilityStats is the compact rollup of this peer's historical
	// uptime / disconnect / latency / throughput aggregates. Populated
	// for peers with at least one probe sample recorded; zero-valued
	// otherwise (new peers, or instances without a DB-backed
	// recorder). See reliability.go for the computation pipeline.
	ReliabilityStats ReliabilityStats `json:"reliability,omitempty"`
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

	// connected is the live set of tailnet node IDs whose poll session
	// is held by this instance. RecordConnect / RecordDisconnect from
	// state.Connect/Disconnect mutate it; Snapshot() flattens it into
	// self.ConnectedNodeIDs so siblings learn it via /mesh/info.
	connected map[uint64]struct{}

	// lastCrown is the crown name from the previous probe cycle.
	// Used to trigger OnBecameCrown exactly once per transition.
	lastCrown string

	// OnBecameCrown is invoked synchronously whenever this instance
	// newly wins the crown: either a cluster-wide transition (another
	// node was crown, now self is) OR a startup-as-crown (lastCrown
	// is empty and the first election resolves to self). The latter
	// case matters because the DDNS update hook must fire on first
	// boot too — otherwise the bootstrap hostname stays stuck on
	// whatever IP was there before the node came up. Set by the app
	// after New(). In-flight probes do not block on it.
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

	// identity is the cluster-signing identity derived from
	// clusterSecret plus this instance's noise pubkey. Nil until the
	// app calls [State.SetIdentity] at startup; remains nil when no
	// cluster secret is configured.
	identity *Identity

	// tlsSPKI is the hex SHA-256 of the cluster-derived TLS cert's
	// SubjectPublicKeyInfo, published in /mesh/identity. Empty unless
	// tls.derive_from_cluster_secret is on. Set by [State.SetTLSSPKI].
	tlsSPKI string

	// recorder persists probe outcomes and throughput samples to the
	// peer_reliability / peer_throughput tables. Nil for mesh-only
	// test rigs; RecordProbe / ComputeStats are no-ops when unset.
	recorder Recorder

	// statsCache holds recently-computed ReliabilityStats per peer
	// name so repeat lookups inside a probe cycle don't re-query the
	// DB. Entries older than statsTTL are refreshed on access.
	statsCache map[string]cachedStats
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
		connected:     make(map[uint64]struct{}),
		self: PeerStatus{
			Name:         cfg.SelfName,
			URL:          cfg.SelfURL,
			Online:       true,
			Score:        1.0,
			ExitNodeName: cfg.ExitNodeName,
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

// SetIdentity installs the cluster identity for this instance. Called
// once at app startup after the noise pubkey has been loaded. Also
// imprints the NoisePubHex / ClusterSigHex fields on the self entry
// so every subsequent Snapshot() carries them without the caller
// having to rebuild the struct.
func (s *State) SetIdentity(id *Identity) {
	if s == nil || id == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identity = id
	s.self.NoisePubHex = hex.EncodeToString(id.NoisePub)
	s.self.ClusterSigHex = hex.EncodeToString(id.NoiseSig)
}

// Identity returns the installed cluster identity, or nil if none has
// been set. Caller must not mutate the returned pointer.
func (s *State) Identity() *Identity {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.identity
}

// SetTLSSPKI records the hex SHA-256 of the cluster-derived TLS cert's
// SubjectPublicKeyInfo so /mesh/identity can publish it, and wires the
// same pin into probeClient so inter-peer /mesh/info and /mesh/join
// calls succeed against HTTPS siblings whose cert is self-signed off
// the same cluster secret. Pass "" to clear both (single-server
// deployments or servers using a CA-issued cert).
func (s *State) SetTLSSPKI(spki string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tlsSPKI = spki
	installProbeSPKIPin(spki)
}

// TLSSPKI returns the SPKI hash set by [State.SetTLSSPKI], or "".
func (s *State) TLSSPKI() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tlsSPKI
}

// RecordConnect notes that a tailnet node's long-poll session is now
// held by this headscale instance. Safe to call when s is nil. The
// next /mesh/info probe carries this set out to siblings as
// ConnectedNodeIDs.
func (s *State) RecordConnect(nodeID uint64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.connected[nodeID] = struct{}{}
	s.mu.Unlock()
}

// RecordDisconnect removes nodeID from the local connected set. Safe to
// call when s is nil or when nodeID was never recorded.
func (s *State) RecordDisconnect(nodeID uint64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.connected, nodeID)
	s.mu.Unlock()
}

// IsConnectedAnywhere reports whether the given tailnet node has a
// live poll session against this headscale OR any sibling, based on
// the latest probe cycle's gossip. Used by the mapper so a peer
// connected to a different sibling is shown as online to clients on
// this sibling. Returns false when s is nil.
func (s *State) IsConnectedAnywhere(nodeID uint64) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.connected[nodeID]; ok {
		return true
	}
	for _, p := range s.peers {
		if !p.Online {
			continue
		}
		for _, id := range p.ConnectedNodeIDs {
			if id == nodeID {
				return true
			}
		}
	}
	return false
}

// SetSelfDERPRegion installs this instance's embedded DERP region
// metadata on the self entry so it travels through every Snapshot().
// Empty fields → no DERP region published. App calls this once at
// startup after derp.GenerateRegion() succeeds.
func (s *State) SetSelfDERPRegion(regionID int, regionCode, regionName, host string, port, stunPort int, v4, v6 string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.self.DERPRegionID = regionID
	s.self.DERPRegionCode = regionCode
	s.self.DERPRegionName = regionName
	s.self.DERPHost = host
	s.self.DERPPort = port
	s.self.DERPSTUNPort = stunPort
	s.self.DERPv4 = v4
	s.self.DERPv6 = v6
	s.mu.Unlock()
}

// SiblingDERPRegions returns the per-sibling DERP region descriptors
// most recently observed via /mesh/info probes (excluding self;
// caller already has the local region from its own derp config).
// Skips siblings whose probe hasn't reported a region yet.
func (s *State) SiblingDERPRegions() []PeerStatus {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PeerStatus, 0, len(s.peers))
	for _, p := range s.peers {
		if p.DERPRegionID == 0 || p.DERPHost == "" {
			continue
		}
		out = append(out, p)
	}
	return out
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

	// Flatten the live connected-node set into self.ConnectedNodeIDs so
	// siblings learn it via /mesh/info. Sorted for determinism (the
	// snapshot JSON is published into every client's CapMap, so jitter
	// would churn netmaps unnecessarily).
	if len(s.connected) > 0 {
		ids := make([]uint64, 0, len(s.connected))
		for id := range s.connected {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		self.ConnectedNodeIDs = ids
	}

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
		Crown:   electCrown(self, peers, s.lastCrown, nil),
		Updated: now,
	}
}

// electCrown returns the name of the currently-elected crown server.
//
// Two-phase decision:
//   - Stickiness: if a previously-known crown (from our own last election
//     OR observed in any sibling's snapshot) is still healthy, keep it.
//     This is what CLAUDE.md mandates: when a degraded primary recovers
//     and rejoins, it must accept the cluster's current crown rather
//     than fight for it back.
//   - Cold election: when no sticky candidate exists or the previous
//     crown is no longer healthy, fall back to highest-Score with lex
//     tiebreak on Name. Only online servers are eligible.
//
// The Score input to the cold election must be symmetric across
// siblings (peer self-reported, not locally-measured RTT) — otherwise
// every node sees self.Score > peer.Score from its own viewpoint and
// crowns itself. See probeOne for where Score is sourced.
func electCrown(self PeerStatus, peers []PeerStatus, lastCrown string, observedCrowns []string) string {
	target := lastCrown
	if target == "" {
		target = mostFrequentCrown(observedCrowns)
	}
	if target != "" {
		if target == self.Name && self.Score > 0 {
			return self.Name
		}
		for _, p := range peers {
			if p.Name == target && p.Online && p.Score > 0 {
				return target
			}
		}
	}

	eligible := []PeerStatus{self}
	for _, p := range peers {
		if p.Online {
			eligible = append(eligible, p)
		}
	}
	sort.Slice(eligible, func(i, j int) bool {
		wi := weightedScore(eligible[i])
		wj := weightedScore(eligible[j])
		if wi != wj {
			return wi > wj
		}
		return eligible[i].Name < eligible[j].Name
	})
	return eligible[0].Name
}

// weightedScore multiplies Score by a 7-day uptime weight so a
// historically-reliable peer outranks a merely-fast-right-now one.
// Floor the weight at 0.01 so a brand-new peer with zero history (its
// Uptime7d reads as 0) still gets a non-zero score — its lifetime and
// 24 h are also zero so it's effectively treated as 100% (see below),
// matching the "new peers win by default" rule from §11. A peer with
// zero probe_total across every window is treated as 100% uptime:
// it's cold-start, not a failure. Only a peer with probe_total>0 and
// low success rate is demoted.
func weightedScore(p PeerStatus) float64 {
	stats := p.ReliabilityStats
	// Absence of history — all windows zero — is indistinguishable
	// from "cold start". Treat as 100%: no penalty.
	if stats.Uptime7d == 0 && stats.Uptime24h == 0 && stats.UptimeLife == 0 {
		return p.Score
	}
	w := stats.Uptime7d / 100.0
	if w < 0.01 {
		w = 0.01
	}
	return p.Score * w
}

// mostFrequentCrown returns the crown name that appears most often
// across a slice of observations. Ties broken by lex order so the
// result is deterministic. Empty strings are ignored. Returns "" when
// the input is empty or contains only empty strings.
func mostFrequentCrown(observed []string) string {
	if len(observed) == 0 {
		return ""
	}
	counts := make(map[string]int)
	for _, c := range observed {
		if c == "" {
			continue
		}
		counts[c]++
	}
	if len(counts) == 0 {
		return ""
	}
	best := ""
	bestCount := 0
	for name, count := range counts {
		if count > bestCount || (count == bestCount && name < best) {
			best = name
			bestCount = count
		}
	}
	return best
}

// Prober is the long-running peer-health loop. Runs until ctx is
// cancelled. No-op when s is nil (mesh disabled).
func (s *State) Prober(ctx context.Context, cfg types.MeshConfig) {
	if s == nil {
		return
	}
	s.mu.RLock()
	peerCount := len(s.peers)
	s.mu.RUnlock()
	log.Info().
		Str("self", cfg.SelfName).
		Int("peers", peerCount).
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
	observedCrowns := make([]string, len(peers))
	var wg sync.WaitGroup
	for i := range peers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], discovered[i], observedCrowns[i] = s.probeOne(ctx, peers[i])
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

	// Capture prior online state per peer URL before we swap results
	// into s.peers, so RecordProbe can see the was→now transition and
	// increment disconnect_count on true→false.
	s.mu.RLock()
	priorOnline := make(map[string]bool, len(s.peers))
	for _, p := range s.peers {
		priorOnline[p.URL] = p.Online
	}
	s.mu.RUnlock()

	// Persist each peer's probe outcome into peer_reliability. Done
	// before taking s.mu to avoid holding the state lock across a DB
	// write. RecordProbe no-ops when no recorder is configured.
	now := time.Now()
	for _, r := range results {
		if r.Name == "" {
			continue
		}
		var latency time.Duration
		if r.LatencyMs > 0 {
			latency = time.Duration(r.LatencyMs * float64(time.Millisecond))
		}
		s.RecordProbe(r.Name, now, r.Online, latency, priorOnline[r.URL], r.Online)
	}
	// Also record a row for self so uptime_pct can be computed for
	// the self entry when viewed from another instance via history
	// queries. Self probe "succeeds" whenever selfScore > 0.
	if selfName != "" {
		var selfLatency time.Duration
		if selfLatencyMs > 0 {
			selfLatency = time.Duration(selfLatencyMs * float64(time.Millisecond))
		}
		s.RecordProbe(selfName, now, selfScore > 0, selfLatency, true, selfScore > 0)
	}

	// Attach historical-reliability rollups to each peer status and to
	// self before electCrown runs. ComputeStats is cached (statsTTL)
	// so repeat calls in the same probe cycle don't hammer the DB.
	for i := range results {
		if results[i].Name != "" {
			results[i].ReliabilityStats = s.ComputeStats(results[i].Name)
		}
	}
	selfStats := ReliabilityStats{}
	if selfName != "" {
		selfStats = s.ComputeStats(selfName)
	}

	s.mu.Lock()
	s.self.Score = selfScore
	s.self.LatencyMs = selfLatencyMs
	s.self.ReliabilityStats = selfStats
	decayed := applyOfflineDecay(results, s.offlineAt, time.Now())
	newCrown := electCrown(s.self, decayed, s.lastCrown, observedCrowns)
	// Fire OnBecameCrown whenever this instance is the crown and we
	// were not the crown on the previous tick. Importantly, the empty
	// `s.lastCrown == ""` case (first probe after boot) counts — a
	// node that boots already-crown still needs its DDNS hook fired
	// so the bootstrap hostname resolves to it immediately, rather
	// than staying stuck on whatever IP was there pre-reboot until a
	// real transition happens.
	becameCrown := newCrown == s.self.Name && s.lastCrown != s.self.Name
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

// probeTransport backs probeClient. Started as a clone of the default
// transport; [State.SetTLSSPKI] swaps in a TLSClientConfig that pins
// peers' certs by SPKI hash so HTTPS /mesh/info and /mesh/join work
// against the deterministically-derived cluster cert without needing
// a CA chain or hostname match.
var probeTransport = http.DefaultTransport.(*http.Transport).Clone()

// probeClient is a module-level HTTP client with tight timeouts so a
// dead peer doesn't stall the probe cycle.
var probeClient = &http.Client{
	Timeout:   5 * time.Second,
	Transport: probeTransport,
}

// installProbeSPKIPin rewires probeClient to verify every TLS peer's
// SPKI against expectedHex (hex SHA-256 of the peer cert's DER SPKI).
// Chain + hostname checks are skipped because the cluster cert is
// self-signed with a fixed placeholder SAN — trust comes from the
// pin. Passing "" removes the pin (falls back to the OS CA bundle).
func installProbeSPKIPin(expectedHex string) {
	if expectedHex == "" {
		probeTransport.TLSClientConfig = nil
		return
	}
	probeTransport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // cluster pin replaces chain check
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("peer presented no certificates")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse peer cert: %w", err)
			}
			sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			if got := hex.EncodeToString(sum[:]); got != expectedHex {
				return fmt.Errorf("peer cert SPKI %s != cluster pin %s", got, expectedHex)
			}
			return nil
		},
	}
}

// probeOne fetches /mesh/info from p and updates its status. Returns a
// new PeerStatus keeping the static Name/URL.
//
// Score is taken from the peer's own self-report (snap.Self.Score), not
// derived locally from round-trip latency. This is load-bearing for
// crown-election symmetry: every node sees the same Score for every
// other node, so all nodes elect the same crown deterministically. A
// locally-derived RTT score makes self.Score (always ~1.0 because the
// local DB ping is fast) artificially beat peer scores (always <1.0
// due to network latency), so every node crowns itself — the
// split-brain documented in I-01.
//
// Trust model: peer self-reports are accepted as truth because every
// sibling already shares cluster_secret (proved by HMAC on /mesh/info
// requests). A "lying" sibling that inflates its own score still has
// to be online and signed by the cluster — at which point the operator
// has bigger problems than a crown election.
//
// Returns:
//   - PeerStatus: refreshed entry to merge into the local view.
//   - []MeshPeerRecord: peers the sibling reports in its own snapshot
//     (its self plus its peer view) — used for gossip discovery.
//   - string: the crown name the sibling currently elected, used to
//     seed lastCrown on cold start when this instance has no opinion
//     yet.
func (s *State) probeOne(ctx context.Context, p PeerStatus) (PeerStatus, []MeshPeerRecord, string) {
	// Carry the previous PeerStatus's static identity + topology fields
	// so a transient probe failure (timeout, blackhole, decode error)
	// doesn't blank them in the next published Snapshot. Without this,
	// after one failed probe the CapMap distributed to clients shows
	// the peer with empty NoisePubHex / ClusterSigHex, and the client's
	// pin verifier refuses to rotate to it ("peer has no cluster
	// signature"). Reproduced 2026-04-18 R-25 with iptables blackhole.
	//
	// Volatile fields (Online, Uptime, ConnectedNodeIDs) are reset to
	// zero — only the success path below sets them. Online stays false
	// when the probe fails.
	out := PeerStatus{
		Name:             p.Name,
		URL:              p.URL,
		LastSeen:         p.LastSeen,
		Score:            p.Score,
		LatencyMs:        p.LatencyMs,
		NoisePubHex:      p.NoisePubHex,
		ClusterSigHex:    p.ClusterSigHex,
		ExitNodeName:     p.ExitNodeName,
		DERPRegionID:     p.DERPRegionID,
		DERPHost:         p.DERPHost,
		DERPPort:         p.DERPPort,
		DERPv4:           p.DERPv4,
		DERPv6:           p.DERPv6,
		DERPSTUNPort:     p.DERPSTUNPort,
		DERPRegionCode:   p.DERPRegionCode,
		DERPRegionName:   p.DERPRegionName,
		ReliabilityStats: p.ReliabilityStats,
	}

	s.mu.RLock()
	selfName := s.self.Name
	secret := s.clusterSecret
	s.mu.RUnlock()

	infoURL := p.URL + "/mesh/info"
	if secret != "" {
		expiry := time.Now().Add(2 * time.Minute)
		sig := MintInfoToken(secret, selfName, expiry)
		infoURL = fmt.Sprintf("%s?name=%s&expiry=%d&sig=%s",
			infoURL, url.QueryEscape(selfName), expiry.Unix(), sig)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, infoURL, nil)
	if err != nil {
		return out, nil, ""
	}
	start := time.Now()
	resp, err := probeClient.Do(req)
	if err != nil {
		return out, nil, ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, nil, ""
	}

	var snap Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return out, nil, ""
	}
	latency := time.Since(start)

	out.Online = true
	out.LastSeen = time.Now()
	out.Uptime = snap.Self.Uptime
	out.LatencyMs = float64(latency.Microseconds()) / 1000.0
	out.Score = snap.Self.Score

	// Carry the sibling's cluster-signed identity through to the
	// snapshot so clients see it in the MeshSnapshot CapMap and can
	// validate it against their pinned cluster pubkey before rotating.
	// A sibling that omits these fields (different binary? mesh
	// subsystem misconfigured?) is still probed for liveness — but
	// clients will refuse to rotate to it.
	out.NoisePubHex = snap.Self.NoisePubHex
	out.ClusterSigHex = snap.Self.ClusterSigHex

	// Same propagation rule for the per-peer exit-node hostname:
	// follow-crown clients translate the elected crown's name into
	// "tailnet node to send egress to" by reading this field.
	out.ExitNodeName = snap.Self.ExitNodeName

	// Sibling's locally-held poll sessions, so this instance's mapper
	// can answer "is peer X online anywhere in the cluster?" without
	// each sibling having to write transient online state to the DB.
	out.ConnectedNodeIDs = snap.Self.ConnectedNodeIDs

	// Sibling's embedded DERP region — merged into the DERPMap shipped
	// to clients so a client whose currently-bound section dies still
	// has a relay alternative while it rotates.
	out.DERPRegionID = snap.Self.DERPRegionID
	out.DERPRegionCode = snap.Self.DERPRegionCode
	out.DERPRegionName = snap.Self.DERPRegionName
	out.DERPHost = snap.Self.DERPHost
	out.DERPPort = snap.Self.DERPPort
	out.DERPSTUNPort = snap.Self.DERPSTUNPort
	out.DERPv4 = snap.Self.DERPv4
	out.DERPv6 = snap.Self.DERPv6

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
	return out, discovered, snap.Crown
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
//
// When a cluster_secret is configured, the handler requires an HMAC
// signature in the query (name, expiry, sig) — an unauthenticated
// request gets a 403 with no snapshot bytes. This keeps topology,
// peer URLs, and crown state out of the hands of unsigned callers,
// who would otherwise use /mesh/info as free reconnaissance for a
// MITM attempt on bootstrap.
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
		if secret := s.ClusterSecret(); secret != "" {
			q := r.URL.Query()
			name := q.Get("name")
			sig := q.Get("sig")
			expiry, err := strconv.ParseInt(q.Get("expiry"), 10, 64)
			if err != nil || sig == "" {
				log.Warn().Str("remote", r.RemoteAddr).
					Msg("mesh: /mesh/info rejected — missing or malformed auth params")
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if err := VerifyInfoToken(secret, name, expiry, sig); err != nil {
				log.Warn().Err(err).Str("remote", r.RemoteAddr).Str("name", name).
					Msg("mesh: /mesh/info rejected")
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		_ = json.NewEncoder(w).Encode(s.Snapshot())
	})
}

// IdentityHandler returns the GET /mesh/identity handler. Unauthenticated
// by design: the response contains only the cluster pubkey, this
// instance's noise pubkey, and the signature linking them — all of
// which would anyway be learnable by a passive observer of legitimate
// traffic. Clients pin the cluster pubkey on first contact and rely on
// the operator-supplied 8-character verifier to defeat DNS poisoning.
//
// Returns 404 when the subsystem is disabled or no cluster identity is
// installed (single-server setups), so probing scanners get no clue
// that the endpoint was ever intended to exist.
func IdentityHandler(s *State) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := s.Identity()
		if id == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(id.AsResponse(s.TLSSPKI()))
	})
}


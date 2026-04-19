// Copyright (c) benavex
// SPDX-License-Identifier: BSD-3-Clause

// Persistence + aggregation glue for the historical peer reliability
// subsystem (§11 of /opt/vpn/todo.md). Reliability rows are hour-
// bucketed and written by the probe loop; aggregate rollups feed into
// the per-peer PeerStatus.ReliabilityStats and into the crown
// election weight.
//
// The DB handle is injected via SetRecorder from the app; mesh.New()
// itself does not know about the database so mesh-only test rigs keep
// working with a nil recorder (methods no-op).

package mesh

import (
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
)

// ReliabilityStats is the compact, per-peer history rollup embedded in
// every PeerStatus published via the mesh snapshot (CapMap). Numbers
// are cheap to serialise and small enough to ship to every client in
// every MapResponse — this is the "always-visible" view (§10).
type ReliabilityStats struct {
	// Uptime percentages computed as probe_success / probe_total over
	// the respective window. 0–100.
	Uptime1h    float64 `json:"uptime_1h_pct,omitempty"`
	Uptime24h   float64 `json:"uptime_24h_pct,omitempty"`
	Uptime7d    float64 `json:"uptime_7d_pct,omitempty"`
	Uptime30d   float64 `json:"uptime_30d_pct,omitempty"`
	UptimeLife  float64 `json:"uptime_lifetime_pct,omitempty"`

	// Disconnect counts summed over the window.
	DisconnCount24h  int64 `json:"disconnect_count_24h,omitempty"`
	DisconnCountLife int64 `json:"disconnect_count_lifetime,omitempty"`

	// Latency min/max over the last 1 h (milliseconds). 0 if no
	// latency samples have been recorded yet.
	LatencyMinMs float64 `json:"latency_min_ms_1h,omitempty"`
	LatencyMaxMs float64 `json:"latency_max_ms_1h,omitempty"`

	// Throughput percentiles (Mbps). 0 when throughput_probe is
	// disabled or no samples exist.
	Throughput1hP50  float64 `json:"throughput_p50_1h_mbps,omitempty"`
	Throughput1hP1   float64 `json:"throughput_p01_1h_mbps,omitempty"`
	Throughput24hP50 float64 `json:"throughput_p50_24h_mbps,omitempty"`
}

// Recorder is the subset of *db.HSDatabase the reliability subsystem
// consumes. Kept as an interface so tests can fake it out without
// spinning up a real gorm instance.
type Recorder interface {
	RecordProbeSample(peerName string, ts time.Time, success bool, latencyUs int64, wasOnline, nowOnline bool) error
	RecordThroughputSample(peerName string, ts time.Time, mbps float64, bytes int64) error
	AggregateReliability(peerName string, since time.Time) (db.ReliabilityAggregate, error)
	ListReliabilityRows(peerName string, since time.Time) ([]db.PeerReliability, error)
	ListThroughputRows(peerName string, since time.Time) ([]db.PeerThroughput, error)
	ThroughputPercentile(peerName string, since time.Time, p float64) (float64, error)
}

// cachedStats holds a ComputeStats result with its generation time.
// Lookups newer than statsTTL reuse the cache; older ones re-query.
type cachedStats struct {
	at    time.Time
	stats ReliabilityStats
}

const statsTTL = 30 * time.Second

// SetRecorder installs a DB-backed recorder on the mesh State. Safe to
// call with rec == nil (stats subsystem becomes a no-op). Called from
// the app once the DB is open.
func (s *State) SetRecorder(rec Recorder) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recorder = rec
	if s.statsCache == nil {
		s.statsCache = make(map[string]cachedStats)
	}
}

// recorderLocked returns the current recorder (may be nil). Caller
// must hold s.mu read or write.
func (s *State) recorderLocked() Recorder {
	return s.recorder
}

// RecordProbe folds one probe cycle's outcome into peer_reliability.
// No-op when no recorder is configured or peerName is empty. Safe to
// call from probeAll concurrently for different peer names; the
// per-row atomic upsert in db.RecordProbeSample handles contention.
func (s *State) RecordProbe(
	peerName string,
	ts time.Time,
	success bool,
	latency time.Duration,
	wasOnline, nowOnline bool,
) {
	if s == nil {
		return
	}
	s.mu.RLock()
	rec := s.recorderLocked()
	s.mu.RUnlock()
	if rec == nil || peerName == "" {
		return
	}
	var latencyUs int64
	if latency > 0 {
		latencyUs = latency.Microseconds()
	}
	// Best-effort: a DB error here would just lose one sample. The
	// probe loop shouldn't block on persistence.
	_ = rec.RecordProbeSample(peerName, ts, success, latencyUs, wasOnline, nowOnline)
}

// ComputeStats returns the current ReliabilityStats for peerName,
// reading from peer_reliability and peer_throughput tables. Cached
// per-peer for statsTTL so repeated calls in the same probe cycle
// don't hammer the DB.
func (s *State) ComputeStats(peerName string) ReliabilityStats {
	if s == nil || peerName == "" {
		return ReliabilityStats{}
	}
	now := time.Now()

	s.mu.RLock()
	rec := s.recorderLocked()
	if entry, ok := s.statsCache[peerName]; ok && now.Sub(entry.at) < statsTTL {
		s.mu.RUnlock()
		return entry.stats
	}
	s.mu.RUnlock()

	if rec == nil {
		return ReliabilityStats{}
	}

	stats := computeStatsFromRecorder(rec, peerName, now)

	s.mu.Lock()
	if s.statsCache == nil {
		s.statsCache = make(map[string]cachedStats)
	}
	s.statsCache[peerName] = cachedStats{at: now, stats: stats}
	s.mu.Unlock()
	return stats
}

// computeStatsFromRecorder is ComputeStats without the cache — exposed
// for tests so they can assert against the deterministic function.
func computeStatsFromRecorder(rec Recorder, peerName string, now time.Time) ReliabilityStats {
	var stats ReliabilityStats

	windows := []struct {
		since time.Time
		apply func(db.ReliabilityAggregate)
	}{
		{now.Add(-1 * time.Hour), func(a db.ReliabilityAggregate) {
			stats.Uptime1h = a.UptimePct
			stats.LatencyMinMs = float64(a.MinLatencyUs) / 1000.0
			stats.LatencyMaxMs = float64(a.MaxLatencyUs) / 1000.0
		}},
		{now.Add(-24 * time.Hour), func(a db.ReliabilityAggregate) {
			stats.Uptime24h = a.UptimePct
			stats.DisconnCount24h = a.DisconnectCount
		}},
		{now.Add(-7 * 24 * time.Hour), func(a db.ReliabilityAggregate) {
			stats.Uptime7d = a.UptimePct
		}},
		{now.Add(-30 * 24 * time.Hour), func(a db.ReliabilityAggregate) {
			stats.Uptime30d = a.UptimePct
		}},
		{time.Time{}, func(a db.ReliabilityAggregate) {
			stats.UptimeLife = a.UptimePct
			stats.DisconnCountLife = a.DisconnectCount
		}},
	}
	for _, w := range windows {
		agg, err := rec.AggregateReliability(peerName, w.since)
		if err != nil {
			continue
		}
		w.apply(agg)
	}

	// Throughput percentiles — zero when no samples exist or probe
	// is disabled (same effect: empty table).
	if v, err := rec.ThroughputPercentile(peerName, now.Add(-1*time.Hour), 0.5); err == nil {
		stats.Throughput1hP50 = v
	}
	if v, err := rec.ThroughputPercentile(peerName, now.Add(-1*time.Hour), 0.01); err == nil {
		stats.Throughput1hP1 = v
	}
	if v, err := rec.ThroughputPercentile(peerName, now.Add(-24*time.Hour), 0.5); err == nil {
		stats.Throughput24hP50 = v
	}
	return stats
}


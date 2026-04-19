// Copyright (c) benavex
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
)

// fakeRecorder is an in-memory Recorder for mesh-level tests. It
// mirrors the semantics of the real DB-backed recorder without
// requiring a gorm harness: hour-bucketed upsert, min/max on positive
// latencies, disconnect-count transitions, and aggregate-over-window
// queries. Tests that need real SQL coverage live in hscontrol/db.
type fakeRecorder struct {
	mu           sync.Mutex
	reliability  map[string]map[time.Time]*db.PeerReliability // peer → bucket → row
	throughput   map[string][]db.PeerThroughput               // peer → samples in insert order
	autoIDRel    uint64
	autoIDThru   uint64
	probeErr     error
	throughErr   error
	aggErr       error
	percentileOv func(peer string, since time.Time, p float64) (float64, error)
}

func newFakeRecorder() *fakeRecorder {
	return &fakeRecorder{
		reliability: make(map[string]map[time.Time]*db.PeerReliability),
		throughput:  make(map[string][]db.PeerThroughput),
	}
}

func (f *fakeRecorder) RecordProbeSample(peer string, ts time.Time, success bool, latencyUs int64, wasOnline, nowOnline bool) error {
	if f.probeErr != nil {
		return f.probeErr
	}
	bucket := ts.UTC().Truncate(time.Hour)
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.reliability[peer]
	if !ok {
		m = make(map[time.Time]*db.PeerReliability)
		f.reliability[peer] = m
	}
	row, ok := m[bucket]
	if !ok {
		f.autoIDRel++
		row = &db.PeerReliability{
			ID:         f.autoIDRel,
			PeerName:   peer,
			HourBucket: bucket,
		}
		m[bucket] = row
	}
	row.ProbeTotal++
	if success {
		row.ProbeSuccess++
	}
	row.SumLatencyUs += latencyUs
	if latencyUs > 0 {
		if row.MinLatencyUs == 0 || latencyUs < row.MinLatencyUs {
			row.MinLatencyUs = latencyUs
		}
		if latencyUs > row.MaxLatencyUs {
			row.MaxLatencyUs = latencyUs
		}
	}
	if wasOnline && !nowOnline {
		row.DisconnectCount++
	}
	return nil
}

func (f *fakeRecorder) RecordThroughputSample(peer string, ts time.Time, mbps float64, bytes int64) error {
	if f.throughErr != nil {
		return f.throughErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.autoIDThru++
	f.throughput[peer] = append(f.throughput[peer], db.PeerThroughput{
		ID:            f.autoIDThru,
		PeerName:      peer,
		TS:            ts.UTC(),
		ObservedMbps:  mbps,
		BytesMeasured: bytes,
	})
	return nil
}

func (f *fakeRecorder) AggregateReliability(peer string, since time.Time) (db.ReliabilityAggregate, error) {
	if f.aggErr != nil {
		return db.ReliabilityAggregate{}, f.aggErr
	}
	var agg db.ReliabilityAggregate
	f.mu.Lock()
	defer f.mu.Unlock()
	lower := time.Time{}
	if !since.IsZero() {
		lower = since.UTC().Truncate(time.Hour)
	}
	for _, row := range f.reliability[peer] {
		if !lower.IsZero() && row.HourBucket.Before(lower) {
			continue
		}
		agg.ProbeSuccess += row.ProbeSuccess
		agg.ProbeTotal += row.ProbeTotal
		agg.SumLatencyUs += row.SumLatencyUs
		agg.DisconnectCount += row.DisconnectCount
		if row.MinLatencyUs > 0 && (agg.MinLatencyUs == 0 || row.MinLatencyUs < agg.MinLatencyUs) {
			agg.MinLatencyUs = row.MinLatencyUs
		}
		if row.MaxLatencyUs > agg.MaxLatencyUs {
			agg.MaxLatencyUs = row.MaxLatencyUs
		}
	}
	if agg.ProbeTotal > 0 {
		agg.UptimePct = 100.0 * float64(agg.ProbeSuccess) / float64(agg.ProbeTotal)
	}
	return agg, nil
}

func (f *fakeRecorder) ListReliabilityRows(peer string, since time.Time) ([]db.PeerReliability, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	lower := time.Time{}
	if !since.IsZero() {
		lower = since.UTC().Truncate(time.Hour)
	}
	var out []db.PeerReliability
	for _, row := range f.reliability[peer] {
		if !lower.IsZero() && row.HourBucket.Before(lower) {
			continue
		}
		out = append(out, *row)
	}
	// Order ASC by HourBucket.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].HourBucket.After(out[j].HourBucket); j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out, nil
}

func (f *fakeRecorder) ListThroughputRows(peer string, since time.Time) ([]db.PeerThroughput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []db.PeerThroughput
	for _, r := range f.throughput[peer] {
		if !since.IsZero() && r.TS.Before(since.UTC()) {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func (f *fakeRecorder) ThroughputPercentile(peer string, since time.Time, p float64) (float64, error) {
	if f.percentileOv != nil {
		return f.percentileOv(peer, since, p)
	}
	rows, _ := f.ListThroughputRows(peer, since)
	if len(rows) == 0 {
		return 0, nil
	}
	vals := make([]float64, 0, len(rows))
	for _, r := range rows {
		vals = append(vals, r.ObservedMbps)
	}
	for i := 1; i < len(vals); i++ {
		for j := i; j > 0 && vals[j-1] > vals[j]; j-- {
			vals[j-1], vals[j] = vals[j], vals[j-1]
		}
	}
	if p < 0 {
		p = 0
	}
	if p > 1 {
		p = 1
	}
	idx := int(float64(len(vals)-1) * p)
	return vals[idx], nil
}

// stateWithRecorder gives a tiny State hooked to a fake recorder, for
// probeAll-adjacent tests that don't need a real Prober.
func stateWithRecorder(rec Recorder) *State {
	s := newStateWithSecret("history-secret")
	s.SetRecorder(rec)
	return s
}

// TestRecordProbe_BucketsCorrectly — 3 probes within one hour share a
// single row; a 4th probe one hour later gets its own row.
func TestRecordProbe_BucketsCorrectly(t *testing.T) {
	rec := newFakeRecorder()
	s := stateWithRecorder(rec)

	base := time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	s.RecordProbe("peerA", base.Add(1*time.Minute), true, 20*time.Millisecond, true, true)
	s.RecordProbe("peerA", base.Add(10*time.Minute), true, 30*time.Millisecond, true, true)
	s.RecordProbe("peerA", base.Add(50*time.Minute), false, 0, true, false)
	s.RecordProbe("peerA", base.Add(90*time.Minute), true, 25*time.Millisecond, false, true)

	rows, err := rec.ListReliabilityRows("peerA", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2 hour-buckets, got %d", len(rows))
	}
	// Hour 12 bucket: 3 total (2 success, 1 fail).
	hour12 := rows[0]
	if hour12.ProbeTotal != 3 || hour12.ProbeSuccess != 2 {
		t.Errorf("hour 12: got total=%d success=%d, want 3/2",
			hour12.ProbeTotal, hour12.ProbeSuccess)
	}
	if hour12.DisconnectCount != 1 {
		t.Errorf("hour 12: disconnect_count=%d, want 1", hour12.DisconnectCount)
	}
	// Hour 13 bucket: 1 total, 1 success.
	hour13 := rows[1]
	if hour13.ProbeTotal != 1 || hour13.ProbeSuccess != 1 {
		t.Errorf("hour 13: got total=%d success=%d, want 1/1",
			hour13.ProbeTotal, hour13.ProbeSuccess)
	}
}

// TestRecordProbe_Disconnect — wasOnline true → nowOnline false
// increments disconnect_count; same-state or false→true do not.
func TestRecordProbe_Disconnect(t *testing.T) {
	rec := newFakeRecorder()
	s := stateWithRecorder(rec)

	base := time.Date(2026, 4, 19, 15, 0, 0, 0, time.UTC)
	s.RecordProbe("p", base, true, 10*time.Millisecond, true, true)       // no-op on disconnect
	s.RecordProbe("p", base.Add(1*time.Minute), false, 0, true, false)    // +1 disconnect
	s.RecordProbe("p", base.Add(2*time.Minute), true, 0, false, true)     // reconnect — no +
	s.RecordProbe("p", base.Add(3*time.Minute), false, 0, true, false)    // +1 disconnect
	s.RecordProbe("p", base.Add(4*time.Minute), false, 0, false, false)   // still offline

	agg, err := rec.AggregateReliability("p", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if agg.DisconnectCount != 2 {
		t.Fatalf("want disconnect_count=2, got %d", agg.DisconnectCount)
	}
	if agg.ProbeTotal != 5 || agg.ProbeSuccess != 2 {
		t.Fatalf("want total=5 success=2, got total=%d success=%d",
			agg.ProbeTotal, agg.ProbeSuccess)
	}
}

// TestComputeStats_UptimePercent — seed several hours with known
// success/total so the 7 d weighted uptime matches the expected
// aggregate.
func TestComputeStats_UptimePercent(t *testing.T) {
	rec := newFakeRecorder()

	// Seed 10 hours ending at now. 5 perfect hours (100% success), 5
	// degraded hours (50% success). Expected 7 d uptime =
	// (5*10 + 5*5) / (5*10 + 5*10) = 75/100 = 75%.
	now := time.Now()
	for i := 0; i < 5; i++ {
		bucket := now.Add(-time.Duration(i) * time.Hour)
		for j := 0; j < 10; j++ {
			_ = rec.RecordProbeSample("p", bucket, true, 15_000, true, true)
		}
	}
	for i := 5; i < 10; i++ {
		bucket := now.Add(-time.Duration(i) * time.Hour)
		for j := 0; j < 10; j++ {
			// 5 good, 5 bad per hour → 50% success.
			_ = rec.RecordProbeSample("p", bucket, j < 5, 0, j < 5, j < 5)
		}
	}

	stats := computeStatsFromRecorder(rec, "p", now.Add(1*time.Minute))
	if stats.Uptime7d < 74.5 || stats.Uptime7d > 75.5 {
		t.Errorf("uptime_7d = %.2f, want ~75.0", stats.Uptime7d)
	}
	if stats.Uptime1h < 99 {
		t.Errorf("uptime_1h = %.2f, want ~100 (newest hour is all-success)", stats.Uptime1h)
	}
	// Lifetime should match (no lower bound on hour_bucket).
	if stats.UptimeLife < 74.5 || stats.UptimeLife > 75.5 {
		t.Errorf("uptime_lifetime = %.2f, want ~75.0", stats.UptimeLife)
	}
}

// TestElectCrown_ReliabilityWeight — two peers with equal raw Score
// but divergent 7 d uptime. The higher-uptime peer must win the cold
// election.
func TestElectCrown_ReliabilityWeight(t *testing.T) {
	// Lex-greater name wins normally on a tie — pick names so the
	// reliability-weighted fast peer is also the lex-later one, and
	// see that weighting beats the tiebreak.
	self := PeerStatus{
		Name:             "alpha",
		Online:           true,
		Score:            1.0,
		ReliabilityStats: ReliabilityStats{Uptime7d: 50},
	}
	peers := []PeerStatus{
		{
			Name:             "zulu",
			Online:           true,
			Score:            1.0,
			ReliabilityStats: ReliabilityStats{Uptime7d: 99},
		},
	}
	got := electCrown(self, peers, "", nil)
	if got != "zulu" {
		t.Fatalf("reliability-weighted election must pick zulu (99%%) over alpha (50%%); got %q", got)
	}

	// Now reverse: alpha is the more reliable one — it must win even
	// when lex tiebreak would favour it anyway (sanity test).
	self.ReliabilityStats.Uptime7d = 99
	peers[0].ReliabilityStats.Uptime7d = 50
	got = electCrown(self, peers, "", nil)
	if got != "alpha" {
		t.Fatalf("reliability-weighted election must pick alpha; got %q", got)
	}
}

// TestElectCrown_ColdStartZeroHistory — a peer with no history (all
// uptime windows = 0) must not be penalised out of contention. With
// equal Score and no history for either side, lex tiebreak wins.
func TestElectCrown_ColdStartZeroHistory(t *testing.T) {
	self := PeerStatus{Name: "alpha", Online: true, Score: 1.0}
	peers := []PeerStatus{{Name: "zulu", Online: true, Score: 1.0}}
	got := electCrown(self, peers, "", nil)
	if got != "alpha" {
		t.Fatalf("zero-history peers: expected alpha by lex tiebreak, got %q", got)
	}
}

// TestHistoryHandler_HMAC — wrong / missing token is 401; valid token
// returns a JSON body with reliability rows.
func TestHistoryHandler_HMAC(t *testing.T) {
	rec := newFakeRecorder()
	// Seed one row so the response isn't trivially empty.
	_ = rec.RecordProbeSample("peerX", time.Now().Add(-30*time.Minute), true, 15_000, true, true)

	secret := "history-secret"
	s := newStateWithSecret(secret)
	s.SetRecorder(rec)
	srv := httptest.NewServer(HistoryHandler(s))
	defer srv.Close()

	// Unsigned → 401.
	resp, err := http.Get(srv.URL + "/mesh/history/peerX")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned: want 401, got %d", resp.StatusCode)
	}

	// Bad signature → 401.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/mesh/history/peerX", nil)
	req.Header.Set("X-Mesh-Token", fmt.Sprintf("%d|%s", time.Now().Add(time.Minute).Unix(), "deadbeef"))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad sig: want 401, got %d", resp.StatusCode)
	}

	// Good signature → 200 with body.
	expiry := time.Now().Add(time.Minute)
	sig := MintHistoryToken(secret, "peerX", expiry)
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/mesh/history/peerX", nil)
	req.Header.Set("X-Mesh-Token", fmt.Sprintf("%d|%s", expiry.Unix(), sig))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("good sig: want 200, got %d", resp.StatusCode)
	}
	buf := make([]byte, 2048)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if !strings.Contains(body, `"peer":"peerX"`) {
		t.Errorf("response body missing peer field: %q", body)
	}
	if !strings.Contains(body, `"reliability"`) {
		t.Errorf("response body missing reliability field: %q", body)
	}
}

// TestHistoryHandler_NoSecret — when no cluster secret is configured,
// /mesh/history returns 404 (subsystem-not-advertised) regardless of
// auth state, so probing scanners can't confirm the endpoint exists.
func TestHistoryHandler_NoSecret(t *testing.T) {
	s := newStateWithSecret("")
	srv := httptest.NewServer(HistoryHandler(s))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/mesh/history/peerX")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("no secret: want 404, got %d", resp.StatusCode)
	}
}

// TestComputeStats_Caching — ComputeStats must dedupe calls within
// statsTTL; beyond it, the recorder is called again.
func TestComputeStats_Caching(t *testing.T) {
	calls := 0
	bumper := &countingRecorder{
		inner: newFakeRecorder(),
		onAgg: func() { calls++ },
	}
	s := stateWithRecorder(bumper)

	_ = s.ComputeStats("p")
	_ = s.ComputeStats("p")
	// AggregateReliability is called 5× per ComputeStats (1 h, 24 h,
	// 7 d, 30 d, lifetime). Second call must hit cache → no further
	// AggregateReliability calls.
	if calls != 5 {
		t.Fatalf("ComputeStats called recorder.AggregateReliability %d times, want 5 (cache should dedupe)", calls)
	}
}

// countingRecorder wraps a fakeRecorder and tallies AggregateReliability
// calls for the caching test.
type countingRecorder struct {
	inner *fakeRecorder
	onAgg func()
}

func (c *countingRecorder) RecordProbeSample(peer string, ts time.Time, success bool, latencyUs int64, wasOnline, nowOnline bool) error {
	return c.inner.RecordProbeSample(peer, ts, success, latencyUs, wasOnline, nowOnline)
}

func (c *countingRecorder) RecordThroughputSample(peer string, ts time.Time, mbps float64, bytes int64) error {
	return c.inner.RecordThroughputSample(peer, ts, mbps, bytes)
}

func (c *countingRecorder) AggregateReliability(peer string, since time.Time) (db.ReliabilityAggregate, error) {
	if c.onAgg != nil {
		c.onAgg()
	}
	return c.inner.AggregateReliability(peer, since)
}

func (c *countingRecorder) ListReliabilityRows(peer string, since time.Time) ([]db.PeerReliability, error) {
	return c.inner.ListReliabilityRows(peer, since)
}

func (c *countingRecorder) ListThroughputRows(peer string, since time.Time) ([]db.PeerThroughput, error) {
	return c.inner.ListThroughputRows(peer, since)
}

func (c *countingRecorder) ThroughputPercentile(peer string, since time.Time, p float64) (float64, error) {
	return c.inner.ThroughputPercentile(peer, since, p)
}

// TestRecordProbe_NoRecorder — RecordProbe on a State with no recorder
// is a no-op (doesn't panic).
func TestRecordProbe_NoRecorder(t *testing.T) {
	s := newStateWithSecret("x")
	// No SetRecorder — recorder stays nil.
	s.RecordProbe("p", time.Now(), true, 10*time.Millisecond, true, true)
	// Nothing to assert; test passes if it doesn't panic.
}

// TestThroughputPercentile_EmptyWindow — no samples → zero.
func TestThroughputPercentile_EmptyWindow(t *testing.T) {
	rec := newFakeRecorder()
	v, err := rec.ThroughputPercentile("nobody", time.Now().Add(-1*time.Hour), 0.5)
	if err != nil {
		t.Fatal(err)
	}
	if v != 0 {
		t.Errorf("empty window percentile: want 0, got %v", v)
	}
}

// TestRecordProbe_RecorderError — a recorder returning an error must
// not propagate into mesh (RecordProbe swallows it).
func TestRecordProbe_RecorderError(t *testing.T) {
	rec := newFakeRecorder()
	rec.probeErr = errors.New("boom")
	s := stateWithRecorder(rec)
	// Should not panic or block.
	s.RecordProbe("p", time.Now(), true, 10*time.Millisecond, true, true)
}

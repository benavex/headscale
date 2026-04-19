// Copyright (c) benavex
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// peerstatsTestDB creates an in-memory SQLite DB with the two peer-
// stats tables created via the same SQL the migration runs, wrapped
// in an HSDatabase so the handle methods are exercised verbatim.
func peerstatsTestDB(t *testing.T) *HSDatabase {
	t.Helper()

	dbConn, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = createPeerStatsTables(dbConn)
	require.NoError(t, err)

	return &HSDatabase{DB: dbConn}
}

// TestPeerStats_RecordProbeSample_BucketsAndLatency — 3 probes in one
// hour roll into one row; a 4th in the next hour is separate. Min/max
// latency track correctly across samples.
func TestPeerStats_RecordProbeSample_BucketsAndLatency(t *testing.T) {
	hsdb := peerstatsTestDB(t)

	base := time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	require.NoError(t, hsdb.RecordProbeSample("peerA", base.Add(1*time.Minute), true, 20_000, true, true))
	require.NoError(t, hsdb.RecordProbeSample("peerA", base.Add(10*time.Minute), true, 5_000, true, true))
	require.NoError(t, hsdb.RecordProbeSample("peerA", base.Add(50*time.Minute), false, 0, true, false))
	require.NoError(t, hsdb.RecordProbeSample("peerA", base.Add(90*time.Minute), true, 100_000, false, true))

	rows, err := hsdb.ListReliabilityRows("peerA", time.Time{})
	require.NoError(t, err)
	require.Len(t, rows, 2)

	// First hour: 3 probes, 2 success, disconnect=1, min=5000, max=20000.
	assert.EqualValues(t, 3, rows[0].ProbeTotal)
	assert.EqualValues(t, 2, rows[0].ProbeSuccess)
	assert.EqualValues(t, 1, rows[0].DisconnectCount)
	assert.EqualValues(t, 5_000, rows[0].MinLatencyUs)
	assert.EqualValues(t, 20_000, rows[0].MaxLatencyUs)
	assert.EqualValues(t, 25_000, rows[0].SumLatencyUs) // 20_000 + 5_000 + 0

	// Second hour: 1 probe, 1 success, min=max=100_000.
	assert.EqualValues(t, 1, rows[1].ProbeTotal)
	assert.EqualValues(t, 1, rows[1].ProbeSuccess)
	assert.EqualValues(t, 100_000, rows[1].MinLatencyUs)
	assert.EqualValues(t, 100_000, rows[1].MaxLatencyUs)
}

// TestPeerStats_AggregateReliability — rolls up rows over a window,
// reports correct uptime % and min/max.
func TestPeerStats_AggregateReliability(t *testing.T) {
	hsdb := peerstatsTestDB(t)

	// Seed 4 hours of history. Window: last 2 hours only.
	now := time.Now().UTC().Truncate(time.Hour)
	// Hour 0 (oldest, outside window): 5 probes, all success.
	for i := 0; i < 5; i++ {
		require.NoError(t, hsdb.RecordProbeSample("p", now.Add(-3*time.Hour), true, 10_000, true, true))
	}
	// Hour 1 (inside window): 5 probes, 4 success.
	for i := 0; i < 4; i++ {
		require.NoError(t, hsdb.RecordProbeSample("p", now.Add(-1*time.Hour+time.Duration(i)*time.Minute), true, 20_000, true, true))
	}
	require.NoError(t, hsdb.RecordProbeSample("p", now.Add(-1*time.Hour), false, 0, true, false))
	// Hour 2 (current, inside window): 4 probes, 2 success, 1 disconnect.
	require.NoError(t, hsdb.RecordProbeSample("p", now, true, 40_000, true, true))
	require.NoError(t, hsdb.RecordProbeSample("p", now.Add(1*time.Minute), true, 50_000, true, true))
	require.NoError(t, hsdb.RecordProbeSample("p", now.Add(2*time.Minute), false, 0, true, false))
	require.NoError(t, hsdb.RecordProbeSample("p", now.Add(3*time.Minute), false, 0, false, false))

	// Aggregate over last 2 hours.
	agg, err := hsdb.AggregateReliability("p", now.Add(-90*time.Minute))
	require.NoError(t, err)

	// Expect: total = 5 + 4 = 9, success = 4 + 2 = 6.
	assert.EqualValues(t, 9, agg.ProbeTotal)
	assert.EqualValues(t, 6, agg.ProbeSuccess)
	// Uptime: 6/9 = ~66.67
	assert.InDelta(t, 66.67, agg.UptimePct, 0.1)
	// Min positive latency across window: 20_000 (from hour 1).
	assert.EqualValues(t, 20_000, agg.MinLatencyUs)
	// Max: 50_000.
	assert.EqualValues(t, 50_000, agg.MaxLatencyUs)
	// Disconnects: 1 (hour 1) + 1 (hour 2) = 2.
	assert.EqualValues(t, 2, agg.DisconnectCount)

	// Lifetime aggregate includes the oldest hour.
	life, err := hsdb.AggregateReliability("p", time.Time{})
	require.NoError(t, err)
	assert.EqualValues(t, 14, life.ProbeTotal) // +5
	assert.EqualValues(t, 11, life.ProbeSuccess) // +5
}

// TestPeerStats_Throughput_InsertAndPercentile — samples are recorded
// and percentile queries return sensible values.
func TestPeerStats_Throughput_InsertAndPercentile(t *testing.T) {
	hsdb := peerstatsTestDB(t)

	now := time.Now()
	// 10 samples: 1, 2, 3, ..., 10 mbps.
	for i := 1; i <= 10; i++ {
		require.NoError(t, hsdb.RecordThroughputSample("p", now.Add(-time.Duration(11-i)*time.Minute), float64(i), 1_000_000))
	}

	rows, err := hsdb.ListThroughputRows("p", time.Time{})
	require.NoError(t, err)
	require.Len(t, rows, 10)

	p50, err := hsdb.ThroughputPercentile("p", time.Time{}, 0.5)
	require.NoError(t, err)
	// Nearest-rank p50 of 10 sorted values (idx = 9*0.5 = 4) → 5.
	assert.InDelta(t, 5.0, p50, 0.01)

	p01, err := hsdb.ThroughputPercentile("p", time.Time{}, 0.0)
	require.NoError(t, err)
	assert.InDelta(t, 1.0, p01, 0.01)

	p99, err := hsdb.ThroughputPercentile("p", time.Time{}, 1.0)
	require.NoError(t, err)
	assert.InDelta(t, 10.0, p99, 0.01)
}

// TestPeerStats_NilHandle — methods are safe to call on a zero-valued
// HSDatabase (returns nil error, no-op).
func TestPeerStats_NilHandle(t *testing.T) {
	var hsdb *HSDatabase
	assert.NoError(t, hsdb.RecordProbeSample("p", time.Now(), true, 10, true, true))
	assert.NoError(t, hsdb.RecordThroughputSample("p", time.Now(), 1.0, 100))

	rows, err := hsdb.ListReliabilityRows("p", time.Time{})
	assert.NoError(t, err)
	assert.Nil(t, rows)
}

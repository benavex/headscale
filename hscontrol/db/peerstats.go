// Copyright (c) benavex
// SPDX-License-Identifier: BSD-3-Clause

// Persistence for the mesh peer-reliability subsystem (§11 of
// /opt/vpn/todo.md). Two append-only tables:
//
//   - peer_reliability: one row per (peer_name, hour_bucket) with
//     probe success / total / latency sums / disconnect counters.
//   - peer_throughput: one row per throughput probe sample (opt-in,
//     see mesh.throughput_probe config flag).
//
// Both tables are never pruned: storage cost for decade-plus history
// is negligible (see todo.md §11 "Storage cost" for the math).
package db

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// PeerReliability is one row per (peer_name, hour_bucket). The row is
// upserted every probe cycle — probe_total is incremented,
// probe_success is incremented on success, latency sums/min/max are
// updated, and disconnect_count is incremented on a true→false
// transition in the peer's online state.
type PeerReliability struct {
	ID           uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	PeerName     string    `gorm:"column:peer_name;index:idx_peer_reliability_peer_name_hour,priority:1;uniqueIndex:idx_peer_reliability_bucket,priority:1"`
	HourBucket   time.Time `gorm:"column:hour_bucket;index:idx_peer_reliability_peer_name_hour,priority:2,sort:desc;uniqueIndex:idx_peer_reliability_bucket,priority:2"`
	ProbeSuccess int64     `gorm:"column:probe_success"`
	ProbeTotal   int64     `gorm:"column:probe_total"`
	SumLatencyUs int64     `gorm:"column:sum_latency_us"`
	MinLatencyUs int64     `gorm:"column:min_latency_us"`
	MaxLatencyUs int64     `gorm:"column:max_latency_us"`
	// DisconnectCount counts wasOnline=true→nowOnline=false transitions
	// observed during this hour.
	DisconnectCount int64 `gorm:"column:disconnect_count"`
}

// TableName forces the gorm-generated table name to match schema.sql.
func (PeerReliability) TableName() string { return "peer_reliability" }

// PeerThroughput is one row per throughput probe sample. Only written
// when mesh.throughput_probe is true in config.
type PeerThroughput struct {
	ID            uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	PeerName      string    `gorm:"column:peer_name;index:idx_peer_throughput_peer_name_ts,priority:1"`
	TS            time.Time `gorm:"column:ts;index:idx_peer_throughput_peer_name_ts,priority:2,sort:desc"`
	ObservedMbps  float64   `gorm:"column:observed_mbps"`
	BytesMeasured int64     `gorm:"column:bytes_measured"`
}

// TableName forces the gorm-generated table name to match schema.sql.
func (PeerThroughput) TableName() string { return "peer_throughput" }

// createPeerStatsTables issues the DDL for both peer-stats tables plus
// their indexes. Called from the peer-stats migration; split out so the
// SQL is in one place and can be eyeballed against schema.sql. Branches
// on the database dialect — sqlite-flavored `datetime` vs postgres
// `timestamp` — so it works on both engines without AutoMigrate drift.
func createPeerStatsTables(tx *gorm.DB) error {
	dialect := tx.Dialector.Name()

	var reliabilityDDL, throughputDDL string
	switch dialect {
	case "sqlite":
		reliabilityDDL = `CREATE TABLE peer_reliability(
  id integer PRIMARY KEY AUTOINCREMENT,
  peer_name text NOT NULL,
  hour_bucket datetime NOT NULL,
  probe_success integer NOT NULL DEFAULT 0,
  probe_total integer NOT NULL DEFAULT 0,
  sum_latency_us integer NOT NULL DEFAULT 0,
  min_latency_us integer NOT NULL DEFAULT 0,
  max_latency_us integer NOT NULL DEFAULT 0,
  disconnect_count integer NOT NULL DEFAULT 0
)`
		throughputDDL = `CREATE TABLE peer_throughput(
  id integer PRIMARY KEY AUTOINCREMENT,
  peer_name text NOT NULL,
  ts datetime NOT NULL,
  observed_mbps real NOT NULL DEFAULT 0,
  bytes_measured integer NOT NULL DEFAULT 0
)`
	case "postgres":
		reliabilityDDL = `CREATE TABLE peer_reliability(
  id bigserial PRIMARY KEY,
  peer_name text NOT NULL,
  hour_bucket timestamp NOT NULL,
  probe_success bigint NOT NULL DEFAULT 0,
  probe_total bigint NOT NULL DEFAULT 0,
  sum_latency_us bigint NOT NULL DEFAULT 0,
  min_latency_us bigint NOT NULL DEFAULT 0,
  max_latency_us bigint NOT NULL DEFAULT 0,
  disconnect_count bigint NOT NULL DEFAULT 0
)`
		throughputDDL = `CREATE TABLE peer_throughput(
  id bigserial PRIMARY KEY,
  peer_name text NOT NULL,
  ts timestamp NOT NULL,
  observed_mbps double precision NOT NULL DEFAULT 0,
  bytes_measured bigint NOT NULL DEFAULT 0
)`
	default:
		return fmt.Errorf("peer-stats migration: unsupported dialect %q", dialect)
	}

	if err := tx.Exec(reliabilityDDL).Error; err != nil {
		return fmt.Errorf("creating peer_reliability: %w", err)
	}
	if err := tx.Exec(throughputDDL).Error; err != nil {
		return fmt.Errorf("creating peer_throughput: %w", err)
	}

	indexes := []string{
		`CREATE UNIQUE INDEX idx_peer_reliability_bucket ON peer_reliability(peer_name, hour_bucket)`,
		`CREATE INDEX idx_peer_reliability_peer_name_hour ON peer_reliability(peer_name, hour_bucket DESC)`,
		`CREATE INDEX idx_peer_throughput_peer_name_ts ON peer_throughput(peer_name, ts DESC)`,
	}
	for _, idx := range indexes {
		if err := tx.Exec(idx).Error; err != nil {
			return fmt.Errorf("creating peer-stats index: %w", err)
		}
	}
	return nil
}

// RecordProbeSample upserts the current-hour PeerReliability row for
// peerName. Increments probe_total unconditionally; increments
// probe_success iff success; updates latency aggregates iff
// latencyUs > 0; increments disconnect_count iff wasOnline && !nowOnline.
//
// Atomicity: uses ON CONFLICT (peer_name, hour_bucket) DO UPDATE so
// concurrent probers (shouldn't happen — Prober is single-goroutine
// per peer — but harmless if it does) can't lose rows.
func (hsdb *HSDatabase) RecordProbeSample(
	peerName string,
	ts time.Time,
	success bool,
	latencyUs int64,
	wasOnline, nowOnline bool,
) error {
	if hsdb == nil || hsdb.DB == nil {
		return nil
	}
	if peerName == "" {
		return nil
	}

	bucket := ts.UTC().Truncate(time.Hour)
	var successInc int64
	if success {
		successInc = 1
	}
	var disconnectInc int64
	if wasOnline && !nowOnline {
		disconnectInc = 1
	}

	// Atomic upsert pattern that works on both sqlite (ON CONFLICT DO
	// UPDATE, supported since 3.24) and postgres. Qualified
	// peer_reliability.* refers to the pre-existing row; EXCLUDED.*
	// would refer to the new row candidate (unused here).
	//
	// Min/max handling: the initial INSERT row sets min_latency_us
	// and max_latency_us to latencyUs (possibly 0 for a failed probe),
	// then subsequent UPSERTs use CASE to conditionally replace them:
	// - min: the smallest positive latency seen so far.
	// - max: the largest latency seen.
	//
	// "0 means unset" for min is handled by treating 0 and any value
	// strictly less than latencyUs as "replace".
	return hsdb.DB.Exec(`
INSERT INTO peer_reliability
  (peer_name, hour_bucket, probe_success, probe_total, sum_latency_us, min_latency_us, max_latency_us, disconnect_count)
VALUES
  (?, ?, ?, 1, ?, ?, ?, ?)
ON CONFLICT(peer_name, hour_bucket) DO UPDATE SET
  probe_success = peer_reliability.probe_success + ?,
  probe_total = peer_reliability.probe_total + 1,
  sum_latency_us = peer_reliability.sum_latency_us + ?,
  min_latency_us = CASE
    WHEN ? > 0 AND (peer_reliability.min_latency_us = 0 OR ? < peer_reliability.min_latency_us) THEN ?
    ELSE peer_reliability.min_latency_us
  END,
  max_latency_us = CASE
    WHEN ? > peer_reliability.max_latency_us THEN ?
    ELSE peer_reliability.max_latency_us
  END,
  disconnect_count = peer_reliability.disconnect_count + ?`,
		// VALUES (insert row)
		peerName, bucket, successInc, latencyUs, latencyUs, latencyUs, disconnectInc,
		// DO UPDATE params
		successInc,
		latencyUs,
		latencyUs, latencyUs, latencyUs,
		latencyUs, latencyUs,
		disconnectInc,
	).Error
}

// RecordThroughputSample appends one row to peer_throughput. Never
// fails the caller — returns error for the caller to log, but the
// throughput ticker treats it as best-effort.
func (hsdb *HSDatabase) RecordThroughputSample(
	peerName string,
	ts time.Time,
	mbps float64,
	bytes int64,
) error {
	if hsdb == nil || hsdb.DB == nil {
		return nil
	}
	if peerName == "" {
		return nil
	}
	row := PeerThroughput{
		PeerName:      peerName,
		TS:            ts.UTC(),
		ObservedMbps:  mbps,
		BytesMeasured: bytes,
	}
	if err := hsdb.DB.Create(&row).Error; err != nil {
		return fmt.Errorf("insert peer_throughput: %w", err)
	}
	return nil
}

// ReliabilityAggregate is a window-scoped rollup of peer_reliability
// rows. Uptime is probe_success/probe_total as a percentage (0–100).
// MinLatencyUs/MaxLatencyUs are set to 0 when no samples with
// latency>0 are in the window. DisconnectCount is the SUM over the
// window.
type ReliabilityAggregate struct {
	ProbeSuccess    int64
	ProbeTotal      int64
	UptimePct       float64
	SumLatencyUs    int64
	MinLatencyUs    int64
	MaxLatencyUs    int64
	DisconnectCount int64
}

// AggregateReliability returns rolled-up stats for peerName over the
// window [since, now]. since.IsZero() means "lifetime" (no WHERE on
// hour_bucket lower bound).
func (hsdb *HSDatabase) AggregateReliability(peerName string, since time.Time) (ReliabilityAggregate, error) {
	var agg ReliabilityAggregate
	if hsdb == nil || hsdb.DB == nil {
		return agg, nil
	}
	q := hsdb.DB.Model(&PeerReliability{}).
		Select(`
COALESCE(SUM(probe_success), 0) AS probe_success,
COALESCE(SUM(probe_total), 0) AS probe_total,
COALESCE(SUM(sum_latency_us), 0) AS sum_latency_us,
COALESCE(MIN(CASE WHEN min_latency_us > 0 THEN min_latency_us ELSE NULL END), 0) AS min_latency_us,
COALESCE(MAX(max_latency_us), 0) AS max_latency_us,
COALESCE(SUM(disconnect_count), 0) AS disconnect_count`).
		Where("peer_name = ?", peerName)
	if !since.IsZero() {
		q = q.Where("hour_bucket >= ?", since.UTC().Truncate(time.Hour))
	}
	row := struct {
		ProbeSuccess    int64
		ProbeTotal      int64
		SumLatencyUs    int64
		MinLatencyUs    int64
		MaxLatencyUs    int64
		DisconnectCount int64
	}{}
	if err := q.Scan(&row).Error; err != nil {
		return agg, fmt.Errorf("aggregate peer_reliability: %w", err)
	}
	agg.ProbeSuccess = row.ProbeSuccess
	agg.ProbeTotal = row.ProbeTotal
	agg.SumLatencyUs = row.SumLatencyUs
	agg.MinLatencyUs = row.MinLatencyUs
	agg.MaxLatencyUs = row.MaxLatencyUs
	agg.DisconnectCount = row.DisconnectCount
	if row.ProbeTotal > 0 {
		agg.UptimePct = 100.0 * float64(row.ProbeSuccess) / float64(row.ProbeTotal)
	}
	return agg, nil
}

// ListReliabilityRows returns raw per-hour rows for peerName since
// `since` (inclusive lower bound on hour_bucket). Ordered by
// hour_bucket ASC so the caller can iterate the timeline naturally.
func (hsdb *HSDatabase) ListReliabilityRows(peerName string, since time.Time) ([]PeerReliability, error) {
	if hsdb == nil || hsdb.DB == nil {
		return nil, nil
	}
	var out []PeerReliability
	q := hsdb.DB.Model(&PeerReliability{}).Where("peer_name = ?", peerName)
	if !since.IsZero() {
		q = q.Where("hour_bucket >= ?", since.UTC().Truncate(time.Hour))
	}
	if err := q.Order("hour_bucket ASC").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("list peer_reliability: %w", err)
	}
	return out, nil
}

// ListThroughputRows returns raw samples for peerName since `since`.
// Ordered by ts ASC.
func (hsdb *HSDatabase) ListThroughputRows(peerName string, since time.Time) ([]PeerThroughput, error) {
	if hsdb == nil || hsdb.DB == nil {
		return nil, nil
	}
	var out []PeerThroughput
	q := hsdb.DB.Model(&PeerThroughput{}).Where("peer_name = ?", peerName)
	if !since.IsZero() {
		q = q.Where("ts >= ?", since.UTC())
	}
	if err := q.Order("ts ASC").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("list peer_throughput: %w", err)
	}
	return out, nil
}

// ThroughputPercentile returns the observed_mbps percentile (0.0–1.0)
// for peerName over [since, now]. Pulls all rows and computes in Go
// rather than SQL because `percentile_cont` is not portable (postgres
// has it, sqlite doesn't). Sample counts here stay small
// (1 h = 12 rows at 5 min cadence, 30 d ≈ 8.6k rows) so the cost is
// negligible. Returns 0 when there are no samples in the window.
func (hsdb *HSDatabase) ThroughputPercentile(peerName string, since time.Time, p float64) (float64, error) {
	rows, err := hsdb.ListThroughputRows(peerName, since)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	vals := make([]float64, 0, len(rows))
	for _, r := range rows {
		vals = append(vals, r.ObservedMbps)
	}
	// Sort ascending.
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
	// Nearest-rank percentile: simple and matches what the UI wants
	// (p50/p1/p99). No interpolation.
	idx := int(float64(len(vals)-1) * p)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(vals) {
		idx = len(vals) - 1
	}
	return vals[idx], nil
}

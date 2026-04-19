// Copyright (c) benavex
// SPDX-License-Identifier: BSD-3-Clause

// Optional active-throughput probe. Off by default. When enabled,
// every ThroughputProbeInterval the instance GETs
// ThroughputProbeURL, measures the observed mbps, and appends one
// row to peer_throughput keyed to the instance's own SelfName.
//
// The "peer" recorded is always self — there's no useful "probe peer
// X's bandwidth through the internet" measurement without a
// cooperating iperf endpoint. What the UI wants is "what bandwidth
// does this headscale see from its upstream?", which this answers
// directly.

package mesh

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
)

// throughputClient keeps connections alive between probe ticks so
// measured bandwidth reflects the wire and not TLS handshake cost.
var throughputClient = &http.Client{
	Timeout: 30 * time.Second,
}

// RunThroughputProbe runs the periodic throughput probe until ctx is
// cancelled. No-op when s is nil, the probe is disabled in cfg, or
// no recorder is installed on s. Blocks until ctx.Done(), so callers
// typically start it in a goroutine.
func (s *State) RunThroughputProbe(ctx context.Context, cfg types.MeshConfig) {
	if s == nil || !cfg.ThroughputProbe {
		return
	}
	if cfg.ThroughputProbeURL == "" {
		log.Warn().Msg("mesh: throughput_probe enabled but throughput_probe_url empty; skipping")
		return
	}
	interval := cfg.ThroughputProbeInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}

	log.Info().
		Str("self", cfg.SelfName).
		Str("url", cfg.ThroughputProbeURL).
		Dur("interval", interval).
		Msg("mesh: throughput probe started")

	// One immediate tick so the first sample lands before the first
	// full interval elapses, matching the behaviour of the main
	// prober loop.
	s.doThroughputProbe(ctx, cfg.SelfName, cfg.ThroughputProbeURL)

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.doThroughputProbe(ctx, cfg.SelfName, cfg.ThroughputProbeURL)
		}
	}
}

// doThroughputProbe performs one sample and records it. Errors are
// logged but never propagated — the ticker should keep retrying on
// the next interval regardless of transient upstream hiccups.
func (s *State) doThroughputProbe(ctx context.Context, peerName, url string) {
	if peerName == "" {
		return
	}
	s.mu.RLock()
	rec := s.recorder
	s.mu.RUnlock()
	if rec == nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		log.Warn().Err(err).Str("url", url).Msg("mesh: throughput probe request build failed")
		return
	}
	start := time.Now()
	resp, err := throughputClient.Do(req)
	if err != nil {
		log.Warn().Err(err).Str("url", url).Msg("mesh: throughput probe request failed")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Warn().Int("status", resp.StatusCode).Str("url", url).
			Msg("mesh: throughput probe unexpected status")
		return
	}
	n, err := io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(start)
	if err != nil {
		log.Warn().Err(err).Str("url", url).Msg("mesh: throughput probe read failed")
		return
	}
	if elapsed <= 0 || n <= 0 {
		return
	}
	// Mbps = bytes*8 / seconds / 1_000_000
	mbps := (float64(n) * 8.0) / elapsed.Seconds() / 1_000_000.0

	if err := rec.RecordThroughputSample(peerName, time.Now(), mbps, n); err != nil {
		log.Warn().Err(err).Msg("mesh: throughput sample record failed")
		return
	}
	log.Debug().
		Str("self", peerName).
		Float64("mbps", mbps).
		Int64("bytes", n).
		Dur("elapsed", elapsed).
		Msg("mesh: throughput sample recorded")
}

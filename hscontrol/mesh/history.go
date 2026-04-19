// Copyright (c) benavex
// SPDX-License-Identifier: BSD-3-Clause

// GET /mesh/history/{peer} — HMAC-signed, returns raw per-hour
// reliability rows plus (optionally) raw throughput samples for the
// detail tap in §10 UI. Uses the same cluster secret as /mesh/info;
// the signature label is "history|" so a captured info token can't be
// replayed here and vice-versa.

package mesh

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// HistoryResponse is the JSON body of GET /mesh/history/{peer}.
type HistoryResponse struct {
	Peer        string           `json:"peer"`
	Since       int64            `json:"since_unix"`
	Reliability []HistoryRelRow  `json:"reliability"`
	Throughput  []HistoryThroRow `json:"throughput,omitempty"`
}

// HistoryRelRow is one hour-bucketed reliability sample.
type HistoryRelRow struct {
	Hour            time.Time `json:"hour"`
	ProbeSuccess    int64     `json:"probe_success"`
	ProbeTotal      int64     `json:"probe_total"`
	SumLatencyUs    int64     `json:"sum_latency_us"`
	MinLatencyUs    int64     `json:"min_latency_us"`
	MaxLatencyUs    int64     `json:"max_latency_us"`
	DisconnectCount int64     `json:"disconnect_count"`
}

// HistoryThroRow is one throughput probe sample.
type HistoryThroRow struct {
	TS            time.Time `json:"ts"`
	ObservedMbps  float64   `json:"observed_mbps"`
	BytesMeasured int64     `json:"bytes_measured"`
}

// historyPayloadForSig is the MAC input for /mesh/history requests.
// Prefix "history|" so a captured /mesh/info or /mesh/join token can't
// be replayed against the history endpoint.
func historyPayloadForSig(peer string, expiry int64) string {
	return "history|" + peer + "|" + strconv.FormatInt(expiry, 10)
}

// MintHistoryToken computes the HMAC a caller must include (via
// X-Mesh-Token header) on GET /mesh/history/{peer}.
func MintHistoryToken(secret, peer string, expiry time.Time) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(historyPayloadForSig(peer, expiry.Unix())))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyHistoryToken recomputes the MAC and constant-time-compares.
// Returns nil on success.
func VerifyHistoryToken(secret, peer string, expiry int64, sig string) error {
	if secret == "" {
		return errors.New("cluster secret not configured")
	}
	if time.Now().Unix() >= expiry {
		return errors.New("history token expired")
	}
	want, err := hex.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("bad signature encoding: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(historyPayloadForSig(peer, expiry)))
	if !hmac.Equal(mac.Sum(nil), want) {
		return errors.New("signature mismatch")
	}
	return nil
}

// HistoryHandler returns GET /mesh/history/{peer}. Auth: same HMAC
// scheme as /mesh/info, with the token in the X-Mesh-Token header and
// expiry/peer/sig encoded as "expiry|sig". Unsigned or disabled-
// cluster requests get 401. Missing peer path component returns 404.
func HistoryHandler(s *State) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s == nil {
			http.NotFound(w, r)
			return
		}
		secret := s.ClusterSecret()
		if secret == "" {
			// Subsystem disabled — don't even confirm endpoint exists.
			http.NotFound(w, r)
			return
		}

		// Path: /mesh/history/{peer}. Peer is everything after
		// /mesh/history/ — url-decoded. Empty → 404.
		path := strings.TrimPrefix(r.URL.Path, "/mesh/history/")
		path = strings.TrimSuffix(path, "/")
		if path == "" || path == r.URL.Path {
			http.NotFound(w, r)
			return
		}
		peer := path

		// X-Mesh-Token: "<expiry_unix>|<sig_hex>"
		tok := r.Header.Get("X-Mesh-Token")
		parts := strings.SplitN(tok, "|", 2)
		if len(parts) != 2 {
			log.Warn().Str("remote", r.RemoteAddr).Str("peer", peer).
				Msg("mesh: /mesh/history rejected — malformed X-Mesh-Token")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		expiry, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := VerifyHistoryToken(secret, peer, expiry, parts[1]); err != nil {
			log.Warn().Err(err).Str("remote", r.RemoteAddr).Str("peer", peer).
				Msg("mesh: /mesh/history rejected")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Query params.
		q := r.URL.Query()
		since := time.Now().Add(-24 * time.Hour)
		if v := q.Get("since"); v != "" {
			if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
				since = time.Unix(sec, 0)
			}
		}
		includeThroughput := q.Get("throughput") == "true"

		s.mu.RLock()
		rec := s.recorder
		s.mu.RUnlock()

		resp := HistoryResponse{
			Peer:        peer,
			Since:       since.Unix(),
			Reliability: []HistoryRelRow{},
		}

		if rec != nil {
			rows, err := rec.ListReliabilityRows(peer, since)
			if err != nil {
				log.Warn().Err(err).Str("peer", peer).Msg("mesh: /mesh/history reliability query failed")
			} else {
				for _, r := range rows {
					resp.Reliability = append(resp.Reliability, HistoryRelRow{
						Hour:            r.HourBucket,
						ProbeSuccess:    r.ProbeSuccess,
						ProbeTotal:      r.ProbeTotal,
						SumLatencyUs:    r.SumLatencyUs,
						MinLatencyUs:    r.MinLatencyUs,
						MaxLatencyUs:    r.MaxLatencyUs,
						DisconnectCount: r.DisconnectCount,
					})
				}
			}
			if includeThroughput {
				trows, err := rec.ListThroughputRows(peer, since)
				if err != nil {
					log.Warn().Err(err).Str("peer", peer).
						Msg("mesh: /mesh/history throughput query failed")
				} else {
					resp.Throughput = make([]HistoryThroRow, 0, len(trows))
					for _, r := range trows {
						resp.Throughput = append(resp.Throughput, HistoryThroRow{
							TS:            r.TS,
							ObservedMbps:  r.ObservedMbps,
							BytesMeasured: r.BytesMeasured,
						})
					}
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// Copyright (c) benavex
// SPDX-License-Identifier: BSD-3-Clause

// Seamless-join subsystem: a freshly-provisioned headscale can POST a
// signed payload to /mesh/join on any existing member to be added to
// the cluster without editing config files or restarting peers. The
// accepting member adds the joiner to its peer list (persisted if
// peers_state_path is set) and returns its current snapshot so the
// joiner can populate its own peer list. Gossip inside probeAll
// propagates the new member to everyone else on the next cycle.
//
// The signature is a fixed-format HMAC-SHA256 over "name|url|expiry"
// with the cluster secret as key. No replay protection beyond the
// expiry field — the accepting node just verifies "secret held within
// window". That matches Tailscale's own shared-secret join flow and is
// adequate for a small operator-run cluster.

package mesh

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// JoinRequest is the JSON body posted to /mesh/join.
type JoinRequest struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Expiry int64  `json:"expiry"` // unix seconds; reject if in the past
	Sig    string `json:"sig"`    // hex(hmac_sha256(secret, payloadForSig))
}

// JoinResponse echoes the accepting node's current peer view so the
// joiner can bootstrap its own peer list without a separate probe.
type JoinResponse struct {
	Accepted bool         `json:"accepted"`
	Peer     PeerStatus   `json:"peer"`  // the accepting node's identity
	Peers    []PeerStatus `json:"peers"` // accepting node's current peer list (excludes self and joiner)
	Crown    string       `json:"crown"`
	Error    string       `json:"error,omitempty"`
}

func payloadForSig(name, url string, expiry int64) string {
	return name + "|" + url + "|" + strconv.FormatInt(expiry, 10)
}

// MintJoinToken computes the signature a joiner must send for the
// given identity and expiry. Exported so operators can pre-mint tokens
// via a small helper binary; the normal path is for the joiner itself
// to compute it using the shared secret at startup.
func MintJoinToken(secret, name, url string, expiry time.Time) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payloadForSig(name, url, expiry.Unix())))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyJoinToken recomputes the MAC and constant-time-compares.
func VerifyJoinToken(secret, name, url string, expiry int64, sig string) error {
	if secret == "" {
		return errors.New("cluster secret not configured")
	}
	if time.Now().Unix() >= expiry {
		return errors.New("join token expired")
	}
	want, err := hex.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("bad signature encoding: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payloadForSig(name, url, expiry)))
	if !hmac.Equal(mac.Sum(nil), want) {
		return errors.New("signature mismatch")
	}
	return nil
}

// infoPayloadForSig is the MAC input for /mesh/info requests. Distinct
// from the join payload ("info|name|expiry") so a captured join token
// cannot be replayed as an info query and vice-versa.
func infoPayloadForSig(name string, expiry int64) string {
	return "info|" + name + "|" + strconv.FormatInt(expiry, 10)
}

// MintInfoToken computes the HMAC a sibling must include as the "sig"
// query param on GET /mesh/info. Name identifies the caller (its own
// cfg.SelfName) so the receiver can log who probed; it is not
// authoritative. Expiry is the unix second beyond which the receiver
// must reject.
func MintInfoToken(secret, name string, expiry time.Time) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(infoPayloadForSig(name, expiry.Unix())))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyInfoToken recomputes the MAC over (name, expiry) and compares
// in constant time. Returns nil on success.
func VerifyInfoToken(secret, name string, expiry int64, sig string) error {
	if secret == "" {
		return errors.New("cluster secret not configured")
	}
	if time.Now().Unix() >= expiry {
		return errors.New("info token expired")
	}
	want, err := hex.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("bad signature encoding: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(infoPayloadForSig(name, expiry)))
	if !hmac.Equal(mac.Sum(nil), want) {
		return errors.New("signature mismatch")
	}
	return nil
}

// JoinHandler returns the POST /mesh/join handler. Verifies the signed
// payload with s.ClusterSecret() and adds the caller to the peer list.
// Returns 404 when the subsystem is disabled (no secret configured) so
// probing scanners can't tell the endpoint even exists.
func JoinHandler(s *State) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		secret := s.ClusterSecret()
		if secret == "" {
			http.NotFound(w, r)
			return
		}
		// Rate-limit by source IP before any body read / HMAC check.
		// An attacker holding no secret can still spray signed-looking
		// bodies at us; the bucket bounds both the CPU cost of
		// verifying them and the log volume per source.
		if !defaultJoinLimiter.allow(clientIP(r)) {
			log.Warn().Str("remote", r.RemoteAddr).
				Msg("mesh: /mesh/join rate-limited")
			w.Header().Set("Retry-After", "10")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			writeJoinError(w, http.StatusBadRequest, "read body: "+err.Error())
			return
		}
		var req JoinRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeJoinError(w, http.StatusBadRequest, "bad json: "+err.Error())
			return
		}
		if req.Name == "" || req.URL == "" {
			writeJoinError(w, http.StatusBadRequest, "name and url required")
			return
		}
		if !strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://") {
			writeJoinError(w, http.StatusBadRequest, "url must be http(s)://")
			return
		}
		if err := VerifyJoinToken(secret, req.Name, req.URL, req.Expiry, req.Sig); err != nil {
			log.Warn().Err(err).Str("name", req.Name).Str("url", req.URL).
				Str("remote", r.RemoteAddr).Msg("mesh: /mesh/join rejected")
			writeJoinError(w, http.StatusForbidden, err.Error())
			return
		}

		added := s.AddPeer(req.Name, req.URL)
		selfName, selfURL := s.SelfSummary()
		peers := s.peersForSnapshot()
		// Strip the joiner from the response peer list so it doesn't
		// immediately probe itself.
		filtered := peers[:0]
		for _, p := range peers {
			if p.URL != req.URL {
				filtered = append(filtered, p)
			}
		}

		snap := s.Snapshot()
		resp := JoinResponse{
			Accepted: true,
			Peer:     PeerStatus{Name: selfName, URL: selfURL},
			Peers:    filtered,
			Crown:    snap.Crown,
		}
		log.Info().Str("self", selfName).Str("joiner", req.Name).Str("url", req.URL).
			Bool("new", added).Msg("mesh: /mesh/join accepted")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}

func writeJoinError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(JoinResponse{Accepted: false, Error: msg})
}

// SelfJoin is the startup-time self-registration used by a
// freshly-provisioned node. Posts a signed payload to bootstrapURL,
// merges the returned peer list into s, and logs the outcome. Safe to
// call when s is nil or the preconditions aren't met — it just returns
// nil without doing anything.
func SelfJoin(s *State, bootstrapURL, secret, selfName, selfURL string) error {
	if s == nil || bootstrapURL == "" || secret == "" {
		return nil
	}
	expiry := time.Now().Add(2 * time.Minute)
	req := JoinRequest{
		Name:   selfName,
		URL:    selfURL,
		Expiry: expiry.Unix(),
		Sig:    MintJoinToken(secret, selfName, selfURL, expiry),
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	url := strings.TrimRight(bootstrapURL, "/") + "/mesh/join"
	httpReq, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := probeClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("post join: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("join rejected: %s: %s", resp.Status, string(raw))
	}
	var jr JoinResponse
	if err := json.Unmarshal(raw, &jr); err != nil {
		return fmt.Errorf("decode join response: %w", err)
	}
	if !jr.Accepted {
		return fmt.Errorf("join not accepted: %s", jr.Error)
	}
	// Merge bootstrap node + its peers into our list.
	s.AddPeer(jr.Peer.Name, jr.Peer.URL)
	for _, p := range jr.Peers {
		s.AddPeer(p.Name, p.URL)
	}
	log.Info().Str("self", selfName).Str("bootstrap", jr.Peer.URL).
		Int("peers", 1+len(jr.Peers)).Str("crown", jr.Crown).
		Msg("mesh: self-joined cluster")
	return nil
}


// Copyright (c) benavex
// SPDX-License-Identifier: BSD-3-Clause

// FormatInvite packs the three first-run values an end user needs —
// bootstrap URL, 8-char cluster verifier, pre-auth key — into a single
// paste-safe vpn:// string. The matching parser lives on the client
// side (tailscale/ipn/mesh/invite on the CLI, MeshInvite.kt on
// Android) and strips arbitrary whitespace before decoding so the
// operator can copy the blob out of a terminal that word-wrapped it.
//
// Wire format:
//
//	vpn://<base64url-nopad-of-json>
//
// JSON fields are single-letter to keep the encoded string short:
//
//	z: int     format version, always 1 today
//	u: string  bootstrap URL (http:// or https://)
//	v: string  8-char cluster verifier
//	k: string  pre-auth key ("hskey-auth-…")
//	n: string  optional operator note (device label)

package mesh

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// InviteScheme is the vpn:// URL-style prefix.
const InviteScheme = "vpn://"

// InviteVersion is the current payload version Format emits.
const InviteVersion = 1

// InvitePayload is the JSON body Format serialises inside the invite.
type InvitePayload struct {
	Ver      int    `json:"z"`
	URL      string `json:"u"`
	Verifier string `json:"v"`
	AuthKey  string `json:"k"`
	Note     string `json:"n,omitempty"`
}

// FormatInvite returns the vpn:// invite string for the given values.
// Returns an error if any load-bearing field is empty or clearly wrong.
func FormatInvite(p InvitePayload) (string, error) {
	if p.Ver == 0 {
		p.Ver = InviteVersion
	}
	if p.URL == "" {
		return "", errors.New("invite: url is required")
	}
	if !strings.HasPrefix(p.URL, "http://") && !strings.HasPrefix(p.URL, "https://") {
		return "", fmt.Errorf("invite: url must start with http:// or https:// (got %q)", p.URL)
	}
	if len(p.Verifier) != 8 {
		return "", fmt.Errorf("invite: verifier must be 8 chars (got %d)", len(p.Verifier))
	}
	if p.AuthKey == "" {
		return "", errors.New("invite: auth key is required")
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("marshal invite: %w", err)
	}
	return InviteScheme + base64.RawURLEncoding.EncodeToString(raw), nil
}

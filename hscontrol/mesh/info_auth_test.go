// Copyright (c) benavex
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// newStateWithSecret builds a minimal State with a cluster secret set,
// bypassing New() (which requires a full MeshConfig). Sufficient for
// testing the Handler's auth gate.
func newStateWithSecret(secret string) *State {
	return &State{
		started:       time.Now(),
		offlineAt:     90 * time.Second,
		latencyAlert:  2 * time.Second,
		clusterSecret: secret,
		self: PeerStatus{
			Name:   "self",
			URL:    "http://self.example",
			Online: true,
			Score:  1.0,
		},
	}
}

// TestMeshInfoRejectsUnauthenticated: when a cluster secret is
// configured, /mesh/info must return 403 to an unsigned probe.
func TestMeshInfoRejectsUnauthenticated(t *testing.T) {
	s := newStateWithSecret("shh")
	srv := httptest.NewServer(Handler(s))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/mesh/info")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

// TestMeshInfoRejectsBadSignature: a signed request with a wrong MAC
// is refused.
func TestMeshInfoRejectsBadSignature(t *testing.T) {
	s := newStateWithSecret("shh")
	srv := httptest.NewServer(Handler(s))
	defer srv.Close()

	expiry := time.Now().Add(time.Minute).Unix()
	u := fmt.Sprintf("%s/mesh/info?name=%s&expiry=%d&sig=%s",
		srv.URL, url.QueryEscape("peer"), expiry, "deadbeef")
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

// TestMeshInfoAcceptsGoodSignature: a correctly signed request gets a
// 200 with a JSON snapshot.
func TestMeshInfoAcceptsGoodSignature(t *testing.T) {
	secret := "shh"
	s := newStateWithSecret(secret)
	srv := httptest.NewServer(Handler(s))
	defer srv.Close()

	expiry := time.Now().Add(time.Minute)
	sig := MintInfoToken(secret, "peer", expiry)
	u := fmt.Sprintf("%s/mesh/info?name=%s&expiry=%d&sig=%s",
		srv.URL, url.QueryEscape("peer"), expiry.Unix(), sig)
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
}

// TestMeshInfoNoSecretIsOpen: backward-compat — a state without a
// cluster secret configured still serves /mesh/info to anyone.
func TestMeshInfoNoSecretIsOpen(t *testing.T) {
	s := newStateWithSecret("")
	srv := httptest.NewServer(Handler(s))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/mesh/info")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200 (open), got %d", resp.StatusCode)
	}
}

// TestMeshIdentityHandler: /mesh/identity is 404 before SetIdentity
// and 200 with a full payload after.
func TestMeshIdentityHandler(t *testing.T) {
	s := newStateWithSecret("shh")
	srv := httptest.NewServer(IdentityHandler(s))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/mesh/identity")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404 before SetIdentity, got %d", resp.StatusCode)
	}

	id, err := DeriveIdentity("shh", []byte("noise-pub-32-bytes-long-for-test"))
	if err != nil {
		t.Fatal(err)
	}
	s.SetIdentity(id)

	resp, err = http.Get(srv.URL + "/mesh/identity")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200 after SetIdentity, got %d", resp.StatusCode)
	}
}

// Copyright (c) benavex
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

// TestDeriveIdentityDeterministic: the same secret + noise pub must
// produce byte-identical keypairs. This is load-bearing: every
// headscale in the cluster re-derives independently.
func TestDeriveIdentityDeterministic(t *testing.T) {
	secret := "example-cluster-secret"
	noisePub := bytes.Repeat([]byte{0x42}, 32)

	a, err := DeriveIdentity(secret, noisePub)
	if err != nil {
		t.Fatalf("first derive: %v", err)
	}
	b, err := DeriveIdentity(secret, noisePub)
	if err != nil {
		t.Fatalf("second derive: %v", err)
	}
	if !bytes.Equal(a.ClusterPub, b.ClusterPub) {
		t.Fatalf("cluster pub not deterministic: %x vs %x", a.ClusterPub, b.ClusterPub)
	}
	if !bytes.Equal(a.clusterPriv, b.clusterPriv) {
		t.Fatal("cluster priv not deterministic")
	}
	if len(a.ClusterPub) != ed25519.PublicKeySize {
		t.Fatalf("cluster pub wrong size: %d", len(a.ClusterPub))
	}
}

// TestDeriveIdentityDifferentSecret: different secrets must yield
// different identities even with the same noise pub.
func TestDeriveIdentityDifferentSecret(t *testing.T) {
	noisePub := bytes.Repeat([]byte{0x01}, 32)
	a, err := DeriveIdentity("alpha", noisePub)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveIdentity("beta", noisePub)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.ClusterPub, b.ClusterPub) {
		t.Fatal("different secrets produced same cluster pub")
	}
}

// TestVerifierLength: the operator-facing string is exactly 8 base32
// characters, no padding. Type-ability matters — anything longer and
// users fat-finger it.
func TestVerifierLength(t *testing.T) {
	id, err := DeriveIdentity("s", []byte("somenoisepub"))
	if err != nil {
		t.Fatal(err)
	}
	v := id.Verifier()
	if len(v) != 8 {
		t.Fatalf("verifier wrong length: %q (%d)", v, len(v))
	}
	// Standard base32 alphabet: A-Z and 2-7, all uppercase.
	for _, c := range v {
		if !((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')) {
			t.Fatalf("verifier has out-of-alphabet char %q in %q", c, v)
		}
	}
}

// TestVerifierStableAcrossNoiseKeys: two instances with the same
// cluster secret but different noise keys must produce the same
// verifier — that's the whole point of a cluster-scoped identity.
func TestVerifierStableAcrossNoiseKeys(t *testing.T) {
	secret := "shared"
	a, err := DeriveIdentity(secret, []byte("aaaaaaaaaa"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveIdentity(secret, []byte("bbbbbbbbbb"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Verifier() != b.Verifier() {
		t.Fatalf("verifiers diverge across noise keys: %q vs %q", a.Verifier(), b.Verifier())
	}
	// Sanity: but their NoiseSig must differ because they signed
	// different noise pubs.
	if bytes.Equal(a.NoiseSig, b.NoiseSig) {
		t.Fatal("different noise pubs signed to same output")
	}
}

// TestVerifyNoisePubRoundtrip: the signature over the instance's own
// noise pub must verify under the cluster pub.
func TestVerifyNoisePubRoundtrip(t *testing.T) {
	noisePub := []byte("this is the noise public key 123")
	id, err := DeriveIdentity("my-cluster", noisePub)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyNoisePub(id.ClusterPub, id.NoisePub, id.NoiseSig); err != nil {
		t.Fatalf("own signature failed verify: %v", err)
	}
	// Tampering must be detected.
	bad := append([]byte{}, id.NoisePub...)
	bad[0] ^= 0x01
	if err := VerifyNoisePub(id.ClusterPub, bad, id.NoiseSig); err == nil {
		t.Fatal("tampered noise pub verified")
	}
}

// TestVerifierFromClusterPubMatches: hex-encoded pub round-trips
// through VerifierFromClusterPub to the same value Identity.Verifier
// returns. Client and server must agree byte-for-byte.
func TestVerifierFromClusterPubMatches(t *testing.T) {
	id, err := DeriveIdentity("s", []byte("noise-pub"))
	if err != nil {
		t.Fatal(err)
	}
	want := id.Verifier()
	got := VerifierFromClusterPub(id.ClusterPub)
	if want != got {
		t.Fatalf("verifier round-trip: want %q got %q", want, got)
	}
}

// TestAsResponseFieldsNonEmpty: the on-wire response for
// /mesh/identity must always include hex-encoded fields of the
// expected sizes. A silent truncation would fail-open clients.
func TestAsResponseFieldsNonEmpty(t *testing.T) {
	id, err := DeriveIdentity("s", []byte("noise-pub-of-some-length"))
	if err != nil {
		t.Fatal(err)
	}
	r := id.AsResponse()
	if len(r.ClusterPub) != ed25519.PublicKeySize*2 { // hex of 32 bytes
		t.Errorf("cluster pub hex wrong len: %q", r.ClusterPub)
	}
	if r.NoisePub == "" {
		t.Error("noise pub empty")
	}
	if r.Signature == "" {
		t.Error("signature empty")
	}
	if len(r.Verifier) != 8 {
		t.Errorf("verifier wrong: %q", r.Verifier)
	}
	// Decodable as hex end-to-end.
	if _, err := hex.DecodeString(r.ClusterPub); err != nil {
		t.Errorf("cluster pub not hex: %v", err)
	}
	if _, err := hex.DecodeString(r.NoisePub); err != nil {
		t.Errorf("noise pub not hex: %v", err)
	}
	if _, err := hex.DecodeString(r.Signature); err != nil {
		t.Errorf("signature not hex: %v", err)
	}
}

// TestDeriveIdentityRejectsEmpty: empty secret or noise pub yields a
// clear error. Silent zero-value identity would bypass verification.
func TestDeriveIdentityRejectsEmpty(t *testing.T) {
	if _, err := DeriveIdentity("", []byte("noise")); err == nil {
		t.Fatal("empty secret accepted")
	}
	if _, err := DeriveIdentity("s", nil); err == nil {
		t.Fatal("nil noise accepted")
	}
	if _, err := DeriveIdentity("s", []byte{}); err == nil {
		t.Fatal("empty noise accepted")
	}
}

// TestVerifyInfoTokenReplayExpired: a token past its expiry must be
// rejected even with a valid signature. Replay resistance is load-bearing
// for the /mesh/info HMAC flow.
func TestVerifyInfoTokenReplayExpired(t *testing.T) {
	if err := VerifyInfoToken("s", "peer", 1, "00"); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiry rejection, got %v", err)
	}
}

// Copyright (c) benavex
// SPDX-License-Identifier: BSD-3-Clause

// Cluster identity pinning. Treats the cluster shared secret as the
// seed for an asymmetric (ed25519) keypair. Every headscale in the
// cluster holds the same secret, so every headscale derives the same
// cluster keypair; the public half is the cluster's identity. A short
// base32 hash of that public key is the verifier the operator hands to
// the user on first contact.
//
// Each instance signs its own noise pubkey with the cluster signing
// key. Clients fetch that signature + the noise pubkey from
// /mesh/identity once per device, check the verifier matches the hash
// of the returned cluster key, then pin the cluster pubkey locally.
// Thereafter the client trusts any noise pubkey that carries a valid
// signature from the pinned cluster key — including siblings
// discovered later via the mesh snapshot.
//
// Defeats: DNS poisoning on the bootstrap hostname, a compromised
// non-crown peer impersonating the crown, a forged headscale stood up
// by an attacker without the cluster secret. Does NOT defeat an
// attacker who has the cluster secret (that's a separate rotation
// step — same posture as today).

package mesh

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// clusterIdentityInfo label is mixed into HKDF so rotating the derivation
// procedure in a future release (different curve, different label)
// doesn't overlap with existing deployments' keys.
const clusterIdentityHKDFLabel = "headscale-cluster-identity-v1"

// Identity is the fully-materialised cluster identity for this instance:
// derived keypair, signature over the noise pubkey, and verifier.
type Identity struct {
	// ClusterPub is the cluster's ed25519 public key. Identical across
	// every instance that holds the same cluster secret.
	ClusterPub ed25519.PublicKey

	// clusterPriv is the derived signing key. Kept unexported so
	// handlers that only need to publish cannot accidentally leak it.
	clusterPriv ed25519.PrivateKey

	// NoisePub is this instance's noise protocol pubkey (the one
	// clients see at /key). Signed by clusterPriv so a client pinned
	// to ClusterPub can verify that this specific headscale instance
	// really is a legitimate member of the cluster.
	NoisePub []byte

	// NoiseSig is ed25519.Sign(clusterPriv, NoisePub). Hex-encoded on
	// the wire.
	NoiseSig []byte
}

// DeriveIdentity returns a fully-materialised Identity for the given
// cluster secret and noise pubkey. Safe to call at startup; the
// derivation is deterministic so every instance with the same secret
// produces the same ClusterPub.
//
// secret must be non-empty. noisePub must be the instance's noise
// protocol public key bytes (typically 32 bytes).
func DeriveIdentity(secret string, noisePub []byte) (*Identity, error) {
	if secret == "" {
		return nil, errors.New("cluster secret not configured")
	}
	if len(noisePub) == 0 {
		return nil, errors.New("noise pubkey is empty")
	}
	seed, err := deriveClusterSeed(secret)
	if err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, noisePub)
	npCopy := make([]byte, len(noisePub))
	copy(npCopy, noisePub)
	return &Identity{
		ClusterPub:  pub,
		clusterPriv: priv,
		NoisePub:    npCopy,
		NoiseSig:    sig,
	}, nil
}

// deriveClusterSeed mixes the cluster secret through HKDF-SHA256 with
// a fixed label to get a 32-byte ed25519 seed. HKDF (rather than a raw
// SHA-256) so future schemes can swap the label without colliding.
func deriveClusterSeed(secret string) ([]byte, error) {
	r := hkdf.New(sha256.New, []byte(secret), nil, []byte(clusterIdentityHKDFLabel))
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return seed, nil
}

// SignNoisePub produces an ed25519 signature over noisePub with the
// cluster signing key. Exposed so siblings' noise pubkeys picked up
// during gossip can be signed for inclusion in the mesh snapshot.
func (id *Identity) SignNoisePub(noisePub []byte) []byte {
	if id == nil {
		return nil
	}
	return ed25519.Sign(id.clusterPriv, noisePub)
}

// Verifier returns the 8-character base32 short-hash of the cluster
// pubkey that the operator gives to the user on first contact. Unpadded
// lowercase base32 so it's unambiguous to type (no 0/O collisions:
// base32 standard alphabet uses A-Z and 2-7).
func (id *Identity) Verifier() string {
	if id == nil {
		return ""
	}
	return VerifierFromClusterPub(id.ClusterPub)
}

// VerifierFromClusterPub computes the 8-character verifier from a raw
// cluster pubkey. Exposed so clients can compare the verifier the user
// typed against the hash of the pubkey they pinned.
func VerifierFromClusterPub(pub []byte) string {
	sum := sha256.Sum256(pub)
	// 5 bytes = 40 bits → 8 base32 chars, zero padding.
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:5])
}

// VerifyNoisePub returns nil iff sig is a valid ed25519 signature over
// noisePub under the cluster pubkey. Used on the client side to
// validate sibling control servers before rotating ControlURL to them.
func VerifyNoisePub(clusterPub, noisePub, sig []byte) error {
	if len(clusterPub) != ed25519.PublicKeySize {
		return fmt.Errorf("cluster pubkey wrong size: got %d want %d",
			len(clusterPub), ed25519.PublicKeySize)
	}
	if !ed25519.Verify(clusterPub, noisePub, sig) {
		return errors.New("cluster signature over noise pubkey invalid")
	}
	return nil
}

// IdentityResponse is the JSON body of GET /mesh/identity. Clients use
// it to pin the cluster identity on first contact.
type IdentityResponse struct {
	// ClusterPub is the cluster's ed25519 public key, hex-encoded.
	// The user-visible verifier is VerifierFromClusterPub(hex-decode).
	ClusterPub string `json:"cluster_pub"`

	// NoisePub is this instance's noise protocol pubkey, hex-encoded.
	NoisePub string `json:"noise_pub"`

	// Signature is hex(ed25519.Sign(cluster_priv, noise_pub)).
	Signature string `json:"signature"`

	// Verifier is the 8-character short hash of ClusterPub. Echoed so
	// an operator can eyeball that the returned values match what they
	// see in their server logs / CLI; never trust this field for
	// authorisation — always re-derive from ClusterPub client-side.
	Verifier string `json:"verifier"`
}

// AsResponse returns the wire form of this identity. Safe to call when
// id is nil: returns a zero-valued response the handler can translate
// into a 404.
func (id *Identity) AsResponse() IdentityResponse {
	if id == nil {
		return IdentityResponse{}
	}
	return IdentityResponse{
		ClusterPub: hex.EncodeToString(id.ClusterPub),
		NoisePub:   hex.EncodeToString(id.NoisePub),
		Signature:  hex.EncodeToString(id.NoiseSig),
		Verifier:   id.Verifier(),
	}
}

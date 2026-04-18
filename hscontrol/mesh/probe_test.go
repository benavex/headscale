// Copyright (c) benavex
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestProbeOne_PreservesIdentityOnFailure is the regression test for
// R-25: a transient probe failure must not blank the static identity
// fields (NoisePubHex, ClusterSigHex, ExitNodeName, DERP topology).
//
// Before the fix: probeOne started `out` with only Name/URL/LastSeen/
// Score/LatencyMs, so an HTTP timeout returned a PeerStatus with empty
// NoisePubHex / ClusterSigHex even when the previous probe had set
// them. The next CapMap distribution then carried an unverifiable peer
// to clients, and the pin verifier on the client refused to rotate to
// it ("peer has no cluster signature, server side identity not
// configured").
//
// After the fix: probeOne carries those fields through from the input
// `p`, so they survive any number of failed probes and only get
// updated by a successful one.
func TestProbeOne_PreservesIdentityOnFailure(t *testing.T) {
	// Bind a free port, then close the listener, so the URL is
	// guaranteed to refuse the connection synchronously.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := srv.URL
	srv.Close()

	s := newStateWithSecret("test-secret")

	prior := PeerStatus{
		Name:           "section2",
		URL:            deadURL,
		LastSeen:       s.started,
		Score:          0.95,
		LatencyMs:      12.5,
		NoisePubHex:    "deadbeef00112233445566778899aabbccddeeff00112233445566778899aabb",
		ClusterSigHex:  "feedface" + "00" + "11223344556677889900112233445566778899aabbccddeeff0011223344556677889900112233445566778899aabbccddeeff0011",
		ExitNodeName:   "exit-vps2",
		DERPRegionID:   902,
		DERPHost:       "194.87.49.70",
		DERPPort:       8090,
		DERPv4:         "194.87.49.70",
		DERPSTUNPort:   3478,
		DERPRegionCode: "section2",
		DERPRegionName: "section2",
	}

	out, _, _ := s.probeOne(context.Background(), prior)

	if out.Online {
		t.Fatalf("probe of dead URL should leave Online=false, got true")
	}
	if out.NoisePubHex != prior.NoisePubHex {
		t.Errorf("NoisePubHex blanked on probe failure: got %q want %q",
			out.NoisePubHex, prior.NoisePubHex)
	}
	if out.ClusterSigHex != prior.ClusterSigHex {
		t.Errorf("ClusterSigHex blanked on probe failure: got %q want %q",
			out.ClusterSigHex, prior.ClusterSigHex)
	}
	if out.ExitNodeName != prior.ExitNodeName {
		t.Errorf("ExitNodeName blanked on probe failure: got %q want %q",
			out.ExitNodeName, prior.ExitNodeName)
	}
	if out.DERPRegionID != prior.DERPRegionID {
		t.Errorf("DERPRegionID blanked on probe failure: got %d want %d",
			out.DERPRegionID, prior.DERPRegionID)
	}
	if out.DERPHost != prior.DERPHost {
		t.Errorf("DERPHost blanked on probe failure: got %q want %q",
			out.DERPHost, prior.DERPHost)
	}
	if out.Score != prior.Score {
		t.Errorf("Score blanked on probe failure: got %v want %v",
			out.Score, prior.Score)
	}
}

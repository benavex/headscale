// Copyright (c) Headscale authors
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import "testing"

// TestElectCrown_SymmetricInputs is the regression test for I-01:
// when both siblings see identical scores for everyone (the property
// we get from peer-self-reported scoring), they must elect the same
// crown. Before the fix, each instance saw self.Score=1.0 (local DB
// probe) vs peer.Score<1.0 (remote RTT probe) and crowned itself.
func TestElectCrown_SymmetricInputs(t *testing.T) {
	// section1's local view.
	view1Self := PeerStatus{Name: "section1", Online: true, Score: 1.0}
	view1Peers := []PeerStatus{{Name: "section2", Online: true, Score: 1.0}}

	// section2's local view (mirror).
	view2Self := PeerStatus{Name: "section2", Online: true, Score: 1.0}
	view2Peers := []PeerStatus{{Name: "section1", Online: true, Score: 1.0}}

	c1 := electCrown(view1Self, view1Peers, "", nil)
	c2 := electCrown(view2Self, view2Peers, "", nil)

	if c1 != c2 {
		t.Fatalf("split-brain: section1 elected %q, section2 elected %q (must be identical)", c1, c2)
	}
	if c1 != "section1" {
		t.Fatalf("with equal scores and lex tiebreak, expected section1, got %q", c1)
	}
}

// TestElectCrown_StickyOnRecovery is the regression test for the
// CLAUDE.md mandate: "A comes back, sees B is main, accepts it (does
// NOT fight for crown back)". section1 is the recovering instance
// (lex-smaller name); section2 is the current crown the cluster
// agreed on while section1 was down. After section1 recovers and sees
// section2 as crown, both must keep section2.
func TestElectCrown_StickyOnRecovery(t *testing.T) {
	// section1 has just rejoined. Its previous lastCrown is "" (cold
	// start) but it observes section2 reporting crown=section2.
	view1Self := PeerStatus{Name: "section1", Online: true, Score: 1.0}
	view1Peers := []PeerStatus{{Name: "section2", Online: true, Score: 1.0}}
	got := electCrown(view1Self, view1Peers, "", []string{"section2"})
	if got != "section2" {
		t.Fatalf("recovering section1 must accept section2 as crown, got %q", got)
	}

	// section2 has lastCrown=section2, sees section1 back and healthy.
	// Must keep itself.
	view2Self := PeerStatus{Name: "section2", Online: true, Score: 1.0}
	view2Peers := []PeerStatus{{Name: "section1", Online: true, Score: 1.0}}
	got = electCrown(view2Self, view2Peers, "section2", []string{"section2"})
	if got != "section2" {
		t.Fatalf("current crown section2 must keep crown when healthy, got %q", got)
	}
}

// TestElectCrown_FallsOverWhenCrownDies verifies stickiness yields
// when the previous crown is offline.
func TestElectCrown_FallsOverWhenCrownDies(t *testing.T) {
	// section2 was crown but is now offline. section1 must take over.
	self := PeerStatus{Name: "section1", Online: true, Score: 1.0}
	peers := []PeerStatus{{Name: "section2", Online: false, Score: 1.0}}
	got := electCrown(self, peers, "section2", nil)
	if got != "section1" {
		t.Fatalf("with section2 offline, section1 must crown itself, got %q", got)
	}
}

// TestElectCrown_HighScoreWinsColdStart with no prior crown and no
// observations, the highest-Score instance wins; ties broken by lex.
func TestElectCrown_HighScoreWinsColdStart(t *testing.T) {
	self := PeerStatus{Name: "zulu", Online: true, Score: 0.5}
	peers := []PeerStatus{{Name: "alpha", Online: true, Score: 0.9}}
	got := electCrown(self, peers, "", nil)
	if got != "alpha" {
		t.Fatalf("higher-score peer must win, got %q", got)
	}
}

// TestElectCrown_LonelySelf when self is the only entry and no prior
// crown, self wins regardless.
func TestElectCrown_LonelySelf(t *testing.T) {
	self := PeerStatus{Name: "section1", Online: true, Score: 1.0}
	got := electCrown(self, nil, "", nil)
	if got != "section1" {
		t.Fatalf("lonely self must crown itself, got %q", got)
	}
}

// TestMostFrequentCrown verifies the helper used by cold-start
// stickiness when multiple peers report different crowns.
func TestMostFrequentCrown(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{}, ""},
		{[]string{""}, ""},
		{[]string{"a"}, "a"},
		{[]string{"a", "a", "b"}, "a"},
		{[]string{"b", "a"}, "a"}, // tie broken by lex order
		{[]string{"section2", "section2", "section1"}, "section2"},
	}
	for _, tc := range cases {
		got := mostFrequentCrown(tc.in)
		if got != tc.want {
			t.Errorf("mostFrequentCrown(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

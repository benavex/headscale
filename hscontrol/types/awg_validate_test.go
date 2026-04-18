// Copyright (c) benavex
// SPDX-License-Identifier: BSD-3-Clause

package types

import (
	"strings"
	"testing"
)

// TestAWGValidateEmptyIsZero: an unset block validates — single-server
// deploys that don't use obfuscation must still boot.
func TestAWGValidateEmptyIsZero(t *testing.T) {
	if err := (AWGConfig{}).Validate(); err != nil {
		t.Fatalf("empty AWG should validate; got %v", err)
	}
}

// TestAWGValidateFullGoodConfig: a fully-populated, in-range config
// passes.
func TestAWGValidateFullGoodConfig(t *testing.T) {
	good := AWGConfig{
		Jc:   3,
		Jmin: 10,
		Jmax: 30,
		S1:   15,
		S2:   18,
		S3:   20,
		S4:   23,
		H1:   "1020325451",
		H2:   "3288052141",
		H3:   "1766607858",
		H4:   "2528465083",
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("good config rejected: %v", err)
	}
}

// TestAWGValidatePartialRejected: the existing "all-or-nothing" rule
// must still fire.
func TestAWGValidatePartialRejected(t *testing.T) {
	partial := AWGConfig{Jc: 3, Jmin: 10}
	err := partial.Validate()
	if err == nil || !strings.Contains(err.Error(), "partial") {
		t.Fatalf("partial config should fail as partial; got %v", err)
	}
}

// TestAWGValidateOutOfRange: numeric fields outside their bounds are
// refused with a descriptive error.
func TestAWGValidateOutOfRange(t *testing.T) {
	base := AWGConfig{
		Jc:   3,
		Jmin: 10,
		Jmax: 30,
		S1:   15,
		S2:   18,
		S3:   20,
		S4:   23,
		H1:   "1",
		H2:   "2",
		H3:   "3",
		H4:   "4",
	}
	cases := []struct {
		name  string
		mod   func(*AWGConfig)
		match string
	}{
		{"jc too high", func(c *AWGConfig) { c.Jc = 100000 }, "jc"},
		{"jmin too high", func(c *AWGConfig) { c.Jmin = 999999 }, "jmin"},
		{"jmax below jmin", func(c *AWGConfig) { c.Jmin = 100; c.Jmax = 50 }, "jmax"},
		{"s1 negative", func(c *AWGConfig) { c.S1 = -1 }, "s1"},
		{"h1 bad format", func(c *AWGConfig) { c.H1 = "not-a-number" }, "h1"},
		{"h2 reversed range", func(c *AWGConfig) { c.H2 = "200-100" }, "h2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mod(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.match) {
				t.Fatalf("want error mentioning %q, got %v", tc.match, err)
			}
		})
	}
}

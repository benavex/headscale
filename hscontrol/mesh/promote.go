// Copyright (c) benavex
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx" driver
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

// PromotePlan captures everything needed to take over as the primary
// postgres writer when the configured remote primary stops responding.
// Assembled by the app from [types.MeshConfig] + [types.DatabaseConfig]
// and passed into [RunPromote] from inside a crown-self-transition
// handler.
type PromotePlan struct {
	// RemoteHost is the current (dying) primary's address. RunPromote
	// first verifies it really is unreachable before promoting, so
	// healthy crown-self-transitions (e.g. operator-initiated restart
	// of the prior crown) don't trigger a split-brain promotion.
	RemoteHost string
	RemotePort int

	// LocalHost / LocalPort is the standby on this VPS. We connect
	// here as LocalUser / LocalPassword / LocalDB and issue
	// pg_promote().
	LocalHost     string
	LocalPort     int
	LocalUser     string
	LocalPassword string
	LocalDB       string

	// ConfigPath is the on-disk YAML config; RunPromote rewrites
	// database.postgres.host to LocalHost so the next restart points
	// at the freshly-promoted local DB.
	ConfigPath string
}

// RunPromote is invoked from the OnBecameCrown callback. It:
//
//  1. Confirms RemoteHost:RemotePort is genuinely unreachable (2 s
//     dial timeout). If it answers, we back off — the old crown
//     probably just restarted briefly and we don't want two primaries.
//  2. Opens a DB connection to the local standby.
//  3. Runs `SELECT pg_promote(wait => true, wait_seconds => 30)`.
//  4. Polls `pg_is_in_recovery()` until it returns false.
//  5. Rewrites ConfigPath in place so the restart picks up LocalHost.
//
// Returns nil on success; on failure returns a wrapped error and leaves
// the on-disk config untouched.
func RunPromote(ctx context.Context, p PromotePlan) error {
	if p.LocalHost == "" {
		return errors.New("promote: LocalHost empty; auto-promotion disabled")
	}

	if p.RemoteHost != "" && remoteAlive(p.RemoteHost, p.RemotePort) {
		log.Info().
			Str("remote", fmt.Sprintf("%s:%d", p.RemoteHost, p.RemotePort)).
			Msg("mesh: remote primary still answering; skipping promotion")
		return nil
	}

	log.Warn().
		Str("remote", fmt.Sprintf("%s:%d", p.RemoteHost, p.RemotePort)).
		Str("local", fmt.Sprintf("%s:%d", p.LocalHost, p.LocalPort)).
		Msg("mesh: remote primary unreachable; promoting local standby")

	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable connect_timeout=5",
		p.LocalHost, p.LocalPort, p.LocalUser, p.LocalPassword, p.LocalDB,
	)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("promote: open local db: %w", err)
	}
	defer db.Close()

	pctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()

	if _, err := db.ExecContext(pctx, "SELECT pg_promote(wait => true, wait_seconds => 30)"); err != nil {
		return fmt.Errorf("promote: pg_promote: %w", err)
	}

	// pg_promote(wait=>true) already blocks until promotion completes,
	// but double-check with pg_is_in_recovery() for belt-and-braces.
	var inRecovery bool
	if err := db.QueryRowContext(pctx, "SELECT pg_is_in_recovery()").Scan(&inRecovery); err != nil {
		return fmt.Errorf("promote: pg_is_in_recovery: %w", err)
	}
	if inRecovery {
		return errors.New("promote: pg_promote returned but still in recovery")
	}

	if err := rewriteConfigDBHost(p.ConfigPath, p.LocalHost); err != nil {
		return fmt.Errorf("promote: rewrite config %q: %w", p.ConfigPath, err)
	}

	log.Warn().Str("config", p.ConfigPath).Str("new_host", p.LocalHost).
		Msg("mesh: promotion complete; config rewritten for restart")
	return nil
}

// remoteAlive returns true iff we can open a TCP connection to host:port
// within 2 s. Any failure (refused, timeout, DNS) counts as dead.
func remoteAlive(host string, port int) bool {
	conn, err := net.DialTimeout("tcp",
		net.JoinHostPort(host, fmt.Sprintf("%d", port)),
		2*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// rewriteConfigDBHost updates database.postgres.host in the YAML file
// at path, preserving surrounding keys. We use a full parse-and-reemit
// (yaml.v3 Node tree) rather than a regex so comments and ordering
// survive cleanly.
func rewriteConfigDBHost(path, newHost string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return err
	}
	// yaml.v3 wraps the top-level document in a DocumentNode -> MappingNode.
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return errors.New("config: unexpected YAML root")
	}
	mapping := root.Content[0]
	if mapping.Kind != yaml.MappingNode {
		return errors.New("config: top-level is not a mapping")
	}
	// Locate database.postgres.host.
	postgres := findSubMap(mapping, "database", "postgres")
	if postgres == nil {
		return errors.New("config: database.postgres block not found")
	}
	if err := setMapValue(postgres, "host", newHost); err != nil {
		return err
	}
	out, err := yaml.Marshal(&root)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

// findSubMap walks a chain of keys starting from root, returning the
// final mapping node or nil if any step is missing.
func findSubMap(root *yaml.Node, keys ...string) *yaml.Node {
	cur := root
	for _, k := range keys {
		if cur == nil || cur.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for i := 0; i < len(cur.Content); i += 2 {
			if cur.Content[i].Value == k {
				next = cur.Content[i+1]
				break
			}
		}
		if next == nil {
			return nil
		}
		cur = next
	}
	return cur
}

// setMapValue writes key=value into mapping (a yaml MappingNode),
// updating an existing entry in place or appending one.
func setMapValue(mapping *yaml.Node, key, value string) error {
	if mapping.Kind != yaml.MappingNode {
		return errors.New("not a mapping")
	}
	for i := 0; i < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			mapping.Content[i+1].Value = value
			mapping.Content[i+1].Tag = "!!str"
			mapping.Content[i+1].Style = 0
			return nil
		}
	}
	mapping.Content = append(mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: key, Tag: "!!str"},
		&yaml.Node{Kind: yaml.ScalarNode, Value: value, Tag: "!!str"},
	)
	return nil
}

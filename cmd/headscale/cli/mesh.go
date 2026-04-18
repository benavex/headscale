// Copyright (c) benavex
// SPDX-License-Identifier: BSD-3-Clause

// Mesh subcommand group. For now, the only subcommand is `verifier`,
// which prints the 8-character cluster-identity verifier derived from
// cluster_secret + this instance's noise pubkey. Operators hand that
// string to end users on first contact.

package cli

import (
	"errors"
	"fmt"

	"github.com/juanfont/headscale/hscontrol"
	"github.com/juanfont/headscale/hscontrol/mesh"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(meshCmd)
	meshCmd.AddCommand(meshVerifierCmd)
}

var meshCmd = &cobra.Command{
	Use:   "mesh",
	Short: "Mesh-specific commands (crown, cluster identity)",
}

var meshVerifierCmd = &cobra.Command{
	Use:   "verifier",
	Short: "Print this instance's 8-character cluster identity verifier",
	Long: `Print the 8-character verifier derived from cluster_secret + noise pubkey.

Hand this string to an end user before they run "tailscale mesh pin". The
client refuses to pin if the server's returned cluster pubkey does not
hash to this string, defeating DNS poisoning of the bootstrap hostname.

Verifier is stable across every headscale instance in the same cluster
(derived from the same shared secret) and across restarts. It changes
only when cluster_secret is rotated.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := types.LoadServerConfig()
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		if cfg.Mesh.ClusterSecret == "" {
			return errors.New("mesh.cluster_secret not configured — cluster identity pinning is disabled")
		}
		privKey, err := hscontrol.ReadOrCreatePrivateKey(cfg.NoisePrivateKeyPath)
		if err != nil {
			return fmt.Errorf("load noise key: %w", err)
		}
		noisePub := privKey.Public().UntypedBytes()
		id, err := mesh.DeriveIdentity(cfg.Mesh.ClusterSecret, noisePub)
		if err != nil {
			return fmt.Errorf("derive identity: %w", err)
		}
		return printOutput(cmd, map[string]string{
			"verifier":    id.Verifier(),
			"cluster_pub": fmt.Sprintf("%x", id.ClusterPub),
		}, id.Verifier())
	},
}

// Copyright (c) benavex
// SPDX-License-Identifier: BSD-3-Clause

// Mesh subcommand group: cluster-identity verifier + single-string
// user invites for the benavex fork's paste-one-blob onboarding flow.

package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/juanfont/headscale/hscontrol"
	"github.com/juanfont/headscale/hscontrol/mesh"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/prometheus/common/model"
	"github.com/spf13/cobra"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func init() {
	rootCmd.AddCommand(meshCmd)
	meshCmd.AddCommand(meshVerifierCmd)
	meshCmd.AddCommand(meshUserInviteCmd)

	meshUserInviteCmd.Flags().Uint64P("user", "u", 0, "User ID to mint the pre-auth key under")
	_ = meshUserInviteCmd.MarkFlagRequired("user")
	meshUserInviteCmd.Flags().Bool("reusable", false, "Mint a reusable key (capped at 30d expiry)")
	meshUserInviteCmd.Flags().String("expiration", "", "Key expiry (non-reusable default 87600h=10y, reusable default 30d)")
	meshUserInviteCmd.Flags().String("url", "", "Bootstrap URL baked into the invite (defaults to mesh.bootstrap_url)")
	meshUserInviteCmd.Flags().String("note", "", "Optional human label carried in the invite (e.g. device name)")
	meshUserInviteCmd.Flags().StringSlice("tags", []string{}, "ACL tags to apply to nodes registered with this key")
}

var meshCmd = &cobra.Command{
	Use:   "mesh",
	Short: "Mesh-specific commands (crown, cluster identity)",
}

// reusableInviteExpiryCap caps the expiry on reusable invite keys.
// Reusability + a long life is a revocation-footgun: one lost phone
// means every reuse has to be invalidated. 30 days is long enough for
// onboarding a batch of devices but short enough that stale keys
// rotate out on their own.
const reusableInviteExpiryCap = 30 * 24 * time.Hour

// nonReusableInviteDefault is the default expiry for single-use invite
// keys. Long because non-reusable keys are used exactly once, at which
// point the key is consumed; a 10-year expiry just means the operator
// can mint one now and hand it to the user whenever.
const nonReusableInviteDefault = 87600 * time.Hour // 10 years

var meshUserInviteCmd = &cobra.Command{
	Use:   "user-invite",
	Short: "Mint a single-string vpn:// invite for a user device",
	Long: `Mint a pre-auth key and bundle it with this cluster's bootstrap URL and
verifier into one paste-safe string the end user drops into their app.

The recommended default is non-reusable + long expiry: single-use means
revoking a lost device is cheap (just delete or expire that one key),
long expiry means the operator can hand the invite out whenever. For
onboarding a batch of devices at once, pass --reusable (capped at 30d).

Output is printed on its own line, no prefix, so it can be piped into a
QR-code renderer or copy-buffer tool.`,
	RunE: grpcRunE(func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error {
		user, _ := cmd.Flags().GetUint64("user")
		reusable, _ := cmd.Flags().GetBool("reusable")
		tags, _ := cmd.Flags().GetStringSlice("tags")
		url, _ := cmd.Flags().GetString("url")
		note, _ := cmd.Flags().GetString("note")
		expiryStr, _ := cmd.Flags().GetString("expiration")

		cfg, err := types.LoadServerConfig()
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		if cfg.Mesh.ClusterSecret == "" {
			return errors.New("mesh.cluster_secret not configured — cluster identity pinning is disabled, cannot mint invite")
		}
		if url == "" {
			url = cfg.Mesh.BootstrapURL
		}
		if url == "" {
			return errors.New("bootstrap URL: pass --url or set mesh.bootstrap_url in config.yaml")
		}

		// Work out expiry: explicit flag wins; otherwise default based
		// on reusability. For reusable keys, clamp to the 30-day cap.
		var expiry time.Duration
		if expiryStr != "" {
			d, err := model.ParseDuration(expiryStr)
			if err != nil {
				return fmt.Errorf("parse --expiration: %w", err)
			}
			expiry = time.Duration(d)
		} else if reusable {
			expiry = reusableInviteExpiryCap
		} else {
			expiry = nonReusableInviteDefault
		}
		if reusable && expiry > reusableInviteExpiryCap {
			return fmt.Errorf("reusable invites are capped at %s; got %s. Drop --reusable for long-lived single-use keys.",
				reusableInviteExpiryCap, expiry)
		}

		privKey, err := hscontrol.ReadOrCreatePrivateKey(cfg.NoisePrivateKeyPath)
		if err != nil {
			return fmt.Errorf("load noise key: %w", err)
		}
		id, err := mesh.DeriveIdentity(cfg.Mesh.ClusterSecret, privKey.Public().UntypedBytes())
		if err != nil {
			return fmt.Errorf("derive identity: %w", err)
		}
		verifier := id.Verifier()

		resp, err := client.CreatePreAuthKey(ctx, &v1.CreatePreAuthKeyRequest{
			User:       user,
			Reusable:   reusable,
			AclTags:    tags,
			Expiration: timestamppb.New(time.Now().UTC().Add(expiry)),
		})
		if err != nil {
			return fmt.Errorf("create pre-auth key: %w", err)
		}
		authKey := resp.GetPreAuthKey().GetKey()

		inviteStr, err := mesh.FormatInvite(mesh.InvitePayload{
			URL:      url,
			Verifier: verifier,
			AuthKey:  authKey,
			Note:     note,
		})
		if err != nil {
			return fmt.Errorf("format invite: %w", err)
		}

		return printOutput(cmd, map[string]string{
			"invite":   inviteStr,
			"url":      url,
			"verifier": verifier,
			"auth_key": authKey,
			"reusable": fmt.Sprintf("%t", reusable),
			"expires":  resp.GetPreAuthKey().GetExpiration().AsTime().Format(time.RFC3339),
		}, inviteStr)
	}),
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

package types

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/prometheus/common/model"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/set"
)

const (
	PKCEMethodPlain string = "plain"
	PKCEMethodS256  string = "S256"

	defaultNodeStoreBatchSize = 100
)

var (
	errOidcMutuallyExclusive     = errors.New("oidc_client_secret and oidc_client_secret_path are mutually exclusive")
	errServerURLSuffix           = errors.New("server_url cannot be part of base_domain in a way that could make the DERP and headscale server unreachable")
	errServerURLSame             = errors.New("server_url cannot use the same domain as base_domain in a way that could make the DERP and headscale server unreachable")
	errInvalidPKCEMethod         = errors.New("pkce.method must be either 'plain' or 'S256'")
	ErrNoPrefixConfigured        = errors.New("no IPv4 or IPv6 prefix configured, minimum one prefix is required")
	ErrInvalidAllocationStrategy = errors.New("invalid prefix allocation strategy")
)

type IPAllocationStrategy string

const (
	IPAllocationStrategySequential IPAllocationStrategy = "sequential"
	IPAllocationStrategyRandom     IPAllocationStrategy = "random"
)

type PolicyMode string

const (
	PolicyModeDB   = "database"
	PolicyModeFile = "file"
)

// EphemeralConfig contains configuration for ephemeral node lifecycle.
type EphemeralConfig struct {
	// InactivityTimeout is how long an ephemeral node can be offline
	// before it is automatically deleted.
	InactivityTimeout time.Duration
}

// NodeConfig contains configuration for node lifecycle and expiry.
type NodeConfig struct {
	// Expiry is the default key expiry duration for non-tagged nodes.
	// Applies to all registration methods (auth key, CLI, web, OIDC).
	// Tagged nodes are exempt and never expire.
	// A zero/negative duration means no default expiry (nodes never expire).
	Expiry time.Duration

	// Ephemeral contains configuration for ephemeral node lifecycle.
	Ephemeral EphemeralConfig
}

// Config contains the initial Headscale configuration.
type Config struct {
	ServerURL           string
	Addr                string
	MetricsAddr         string
	GRPCAddr            string
	GRPCAllowInsecure   bool
	Node                NodeConfig
	PrefixV4            *netip.Prefix
	PrefixV6            *netip.Prefix
	IPAllocation        IPAllocationStrategy
	NoisePrivateKeyPath string
	BaseDomain          string
	Log                 LogConfig
	DisableUpdateCheck  bool

	Database DatabaseConfig

	DERP DERPConfig

	TLS TLSConfig

	ACMEURL   string
	ACMEEmail string

	// DNSConfig is the headscale representation of the DNS configuration.
	// It is kept in the config update for some settings that are
	// not directly converted into a tailcfg.DNSConfig.
	DNSConfig DNSConfig

	// TailcfgDNSConfig is the tailcfg representation of the DNS configuration,
	// it can be used directly when sending Netmaps to clients.
	TailcfgDNSConfig *tailcfg.DNSConfig

	UnixSocket           string
	UnixSocketPermission fs.FileMode

	OIDC OIDCConfig

	LogTail             LogTailConfig
	RandomizeClientPort bool
	Taildrop            TaildropConfig
	AWG                 AWGConfig
	Mesh                MeshConfig

	// MeshSnapshotJSON returns the current mesh view serialised as
	// JSON (the value of CapabilityMesh in each node's CapMap) or
	// nil when the mesh subsystem is disabled. Injected at runtime
	// by app startup so the mapper can read a fresh snapshot on
	// every map request without import cycles.
	MeshSnapshotJSON func() []byte `json:"-"`

	// MeshIsConnectedAnywhere, when set, returns true if the given
	// tailnet node ID has a live poll session against any sibling in
	// the cluster (not just this instance). The mapper OR-s this
	// with the node's local IsOnline so peers connected to a
	// different sibling are presented as online to clients here.
	// Nil when the mesh subsystem is disabled.
	MeshIsConnectedAnywhere func(uint64) bool `json:"-"`

	CLI CLIConfig

	Policy PolicyConfig

	Tuning Tuning
}

type DNSConfig struct {
	MagicDNS         bool   `mapstructure:"magic_dns"`
	BaseDomain       string `mapstructure:"base_domain"`
	OverrideLocalDNS bool   `mapstructure:"override_local_dns"`
	Nameservers      Nameservers
	SearchDomains    []string            `mapstructure:"search_domains"`
	ExtraRecords     []tailcfg.DNSRecord `mapstructure:"extra_records"`
	ExtraRecordsPath string              `mapstructure:"extra_records_path"`
}

type Nameservers struct {
	Global []string
	Split  map[string][]string
}

type SqliteConfig struct {
	Path              string
	WriteAheadLog     bool
	WALAutoCheckPoint int
}

type PostgresConfig struct {
	Host                string
	Port                int
	Name                string
	User                string
	Pass                string `json:"-"` // never serialise the database password
	Ssl                 string
	MaxOpenConnections  int
	MaxIdleConnections  int
	ConnMaxIdleTimeSecs int
}

type GormConfig struct {
	Debug                 bool
	SlowThreshold         time.Duration
	SkipErrRecordNotFound bool
	ParameterizedQueries  bool
	PrepareStmt           bool
}

type DatabaseConfig struct {
	// Type sets the database type, either "sqlite3" or "postgres"
	Type  string
	Debug bool

	// Type sets the gorm configuration
	Gorm GormConfig

	Sqlite   SqliteConfig
	Postgres PostgresConfig
}

type TLSConfig struct {
	CertPath string
	KeyPath  string

	LetsEncrypt LetsEncryptConfig
}

type LetsEncryptConfig struct {
	Listen        string
	Hostname      string
	CacheDir      string
	ChallengeType string
}

type PKCEConfig struct {
	Enabled bool
	Method  string
}

type OIDCConfig struct {
	OnlyStartIfOIDCIsAvailable bool
	Issuer                     string
	ClientID                   string
	ClientSecret               string `json:"-"` // never serialise the OIDC client secret
	Scope                      []string
	ExtraParams                map[string]string
	AllowedDomains             []string
	AllowedUsers               []string
	AllowedGroups              []string
	EmailVerifiedRequired      bool
	UseExpiryFromToken         bool
	PKCE                       PKCEConfig
}

type DERPConfig struct {
	ServerEnabled                      bool
	AutomaticallyAddEmbeddedDerpRegion bool
	ServerRegionID                     int
	ServerRegionCode                   string
	ServerRegionName                   string
	ServerPrivateKeyPath               string
	ServerVerifyClients                bool
	STUNAddr                           string
	URLs                               []url.URL
	Paths                              []string
	DERPMap                            *tailcfg.DERPMap
	AutoUpdate                         bool
	UpdateFrequency                    time.Duration
	IPv4                               string
	IPv6                               string
}

type LogTailConfig struct {
	Enabled bool
}

type TaildropConfig struct {
	Enabled bool
}

// AWGConfig holds AmneziaWG obfuscation parameters that headscale
// distributes to every node via MapResponse.SelfNode.CapMap under the
// key [CapabilityAmneziaWG]. Clients apply them to the underlying
// amneziawg-go device so all peers in the tailnet share wire-format
// settings. Zero values are omitted from the UAPI write on the client.
type AWGConfig struct {
	Jc, Jmin, Jmax int
	S1, S2, S3, S4 int
	H1, H2, H3, H4 string
}

// IsZero reports whether the obfuscation config is empty, i.e. whether
// headscale should suppress the capability key entirely.
func (c AWGConfig) IsZero() bool { return c == AWGConfig{} }

// AWG parameter bounds. Enforced at config-load so an operator
// typo can't push wire-format-breaking values, and mirrored on the
// client (wgcfg.ValidateAWGParams) so a compromised headscale can't
// do the same via MapResponse.
//
// Upper bounds are chosen generously above real-world defaults
// (AmneziaVPN's reference Jc=3, S1..S4 in 15-23) but well below
// values that would make the engine behave pathologically: Jmax=1280
// at Jc=128 would still emit <200KB of junk per handshake which is
// tolerable; anything higher wastes client CPU without adding
// unobservability.
const (
	awgMaxJc      = 128  // junk packet count per handshake
	awgMaxJSize   = 1280 // jmin/jmax, upper bound on each junk packet
	awgMaxPadding = 1280 // s1..s4, padding added to each handshake/transport variant
)

// Validate enforces "all-or-nothing" (either every field is set
// or none are — mixed configs would break wire-format compatibility
// with peers using the rest of the profile) AND that every numeric
// field is inside a sane range. Partial configs and out-of-range
// values crash at startup rather than silently producing a
// misbehaving tunnel.
func (c AWGConfig) Validate() error {
	if c.IsZero() {
		return nil
	}
	var missing []string
	check := func(name string, set bool) {
		if !set {
			missing = append(missing, name)
		}
	}
	check("jc", c.Jc != 0)
	check("jmin", c.Jmin != 0)
	check("jmax", c.Jmax != 0)
	check("s1", c.S1 != 0)
	check("s2", c.S2 != 0)
	check("s3", c.S3 != 0)
	check("s4", c.S4 != 0)
	check("h1", c.H1 != "")
	check("h2", c.H2 != "")
	check("h3", c.H3 != "")
	check("h4", c.H4 != "")
	if len(missing) != 0 {
		return fmt.Errorf("awg config is partial; missing %v — set every field or omit the awg block entirely", missing)
	}

	// Range checks. amneziawg-go UAPI already rejects <=0 for Jc/Jmin/Jmax
	// and <0 for S1-S4, but accepts unbounded large values; we clamp here.
	if c.Jc < 1 || c.Jc > awgMaxJc {
		return fmt.Errorf("awg.jc must be in [1, %d], got %d", awgMaxJc, c.Jc)
	}
	if c.Jmin < 1 || c.Jmin > awgMaxJSize {
		return fmt.Errorf("awg.jmin must be in [1, %d], got %d", awgMaxJSize, c.Jmin)
	}
	if c.Jmax < c.Jmin || c.Jmax > awgMaxJSize {
		return fmt.Errorf("awg.jmax must be in [jmin=%d, %d], got %d", c.Jmin, awgMaxJSize, c.Jmax)
	}
	for _, p := range [...]struct {
		name string
		val  int
	}{{"s1", c.S1}, {"s2", c.S2}, {"s3", c.S3}, {"s4", c.S4}} {
		if p.val < 0 || p.val > awgMaxPadding {
			return fmt.Errorf("awg.%s must be in [0, %d], got %d", p.name, awgMaxPadding, p.val)
		}
	}
	for _, p := range [...]struct {
		name, val string
	}{{"h1", c.H1}, {"h2", c.H2}, {"h3", c.H3}, {"h4", c.H4}} {
		if err := validateAWGMagicHeader(p.val); err != nil {
			return fmt.Errorf("awg.%s: %w", p.name, err)
		}
	}
	return nil
}

// validateAWGMagicHeader parses a magic-header spec as amneziawg-go
// does ("N" or "N-M" where both are uint32 and M >= N) and returns an
// error for any malformed input. Kept alongside AWGConfig so the
// headscale-side validation matches wire semantics exactly.
func validateAWGMagicHeader(spec string) error {
	if spec == "" {
		return fmt.Errorf("empty")
	}
	parts := strings.Split(spec, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return fmt.Errorf("bad format %q (want N or N-M)", spec)
	}
	start, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return fmt.Errorf("start not uint32: %w", err)
	}
	if len(parts) == 1 {
		return nil
	}
	end, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return fmt.Errorf("end not uint32: %w", err)
	}
	if end < start {
		return fmt.Errorf("end %d < start %d", end, start)
	}
	return nil
}

// CapabilityAmneziaWG is the tailcfg.NodeCapability under which
// headscale publishes AmneziaWG params in each client's SelfNode.CapMap.
const CapabilityAmneziaWG tailcfg.NodeCapability = "benavex.com/cap/amneziawg"

// CapabilityMesh is the tailcfg.NodeCapability under which headscale
// publishes the current mesh view (peer list + current crown) so that
// clients can fail over to another control server without depending on
// DNS after first contact.
const CapabilityMesh tailcfg.NodeCapability = "benavex.com/cap/mesh"

// MeshConfig declares this headscale's identity in a multi-server mesh
// and the static peer list it should probe. Leave SelfName empty to
// disable the crown-election subsystem entirely.
type MeshConfig struct {
	// SelfName is a stable short label (e.g. "de1", "nl1") used in
	// crown tiebreaks and MapResponse mesh info. Required when Peers
	// is non-empty.
	SelfName string `mapstructure:"self_name"`

	// SelfURL is the URL other headscale instances reach this one at.
	// Typically the same as server_url but may differ behind a proxy.
	// If empty, falls back to Config.ServerURL.
	SelfURL string `mapstructure:"self_url"`

	// ProbeInterval is how often each peer is probed. Defaults to 30s.
	ProbeInterval time.Duration `mapstructure:"probe_interval"`

	// OfflineAfter is how long a peer must stay unreachable before it
	// is considered offline for crown calculation. Defaults to 90s.
	OfflineAfter time.Duration `mapstructure:"offline_after"`

	// LatencyAlert is the probe-latency threshold above which a
	// peer's score starts to decay; defaults to 2s. Used by the
	// crown-election subsystem so a slow-but-alive peer can lose the
	// crown to a faster sibling.
	LatencyAlert time.Duration `mapstructure:"latency_alert"`

	// LocalDBHost is the hostname (or unix socket path) to reach a
	// local postgres standby on this VPS. When the configured primary
	// becomes unreachable and this instance wins the crown, the
	// app-level handler connects here, runs pg_promote() to turn the
	// standby into a primary, rewrites the on-disk config's
	// database.postgres.host to this value, and exits so the next
	// restart runs against a writable DB.
	//
	// Leave empty to disable automatic promotion — the process will
	// just crash-loop until the remote primary recovers.
	LocalDBHost string `mapstructure:"local_db_host"`

	// Peers is the static list of sibling headscale instances. It
	// may be empty; dynamically-joined peers are merged at runtime.
	Peers []MeshPeerConfig `mapstructure:"peers"`

	// ClusterSecret is the shared HMAC secret used to sign join
	// requests. Any node holding this secret may join the mesh by
	// POSTing a signed payload to /mesh/join on any existing member.
	// Empty disables dynamic join (only statically-configured peers
	// participate).
	ClusterSecret string `mapstructure:"cluster_secret"`

	// BootstrapURL, on a freshly-provisioned node, is the URL of any
	// existing mesh member. When set AND Peers is empty AND
	// ClusterSecret is set, this instance self-joins at startup by
	// POSTing its name+url signed with ClusterSecret. After that the
	// peer list is driven by the join response + gossip.
	BootstrapURL string `mapstructure:"bootstrap_url"`

	// PeersStatePath is where runtime-discovered peers are persisted
	// across restarts. Defaults to peers.state.json beside the config
	// file. Set to "-" to disable persistence entirely.
	PeersStatePath string `mapstructure:"peers_state_path"`

	// DDNSUpdateURL, if set, is GETed once this instance newly wins
	// the crown. The URL must already include credentials; headscale
	// appends nothing. Omit &ip= and the provider (e.g. DuckDNS) will
	// use the source IP of the request — which is this VPS's public
	// IP, i.e. the new crown. Used so tailscale clients and freshly
	// provisioned mesh members can always reach the current crown via
	// a single stable hostname after first contact.
	DDNSUpdateURL string `mapstructure:"ddns_update_url"`

	// ExitNodeName is the tailnet hostname of the per-VPS tailscaled
	// that runs alongside this headscale and advertises an exit-node
	// route (--advertise-exit-node). Published in the per-PeerStatus
	// snapshot so clients in `--exit-node=auto:follow-crown` mode can
	// translate "current crown" into "tailnet node to send egress to".
	// Empty disables follow-crown for this peer (clients keep their
	// previously-pinned exit). Each headscale sets its own value;
	// siblings learn it through probes.
	ExitNodeName string `mapstructure:"exit_node_name"`

	// SkipCrownExit, when true, suppresses the os.Exit(0) at the end
	// of the crown-self-transition handler. The exit was originally
	// there to force a NodeStore rehydrate from the shared DB —
	// obsolete now that state.runNodeStoreDBSync re-reads on a 5s
	// tick — and is only useful when running under docker (which
	// restarts on exit). Bare deployments (test rigs, systemd-without-
	// Restart=always) crash-loop without this. Default false preserves
	// the docker-friendly historical behaviour. The DDNS update and
	// RunPromote logic still runs; only the os.Exit is skipped.
	SkipCrownExit bool `mapstructure:"skip_crown_exit"`

	// ThroughputProbe, when true, starts a background ticker that
	// periodically GETs ThroughputProbeURL, times the download, and
	// writes one row per sample to the peer_throughput table. Off by
	// default: this is active bandwidth use against an external server
	// and operators of metered links won't want it. See §11 for the
	// full design.
	ThroughputProbe bool `mapstructure:"throughput_probe"`

	// ThroughputProbeURL is the URL fetched by the throughput probe.
	// Must serve a fixed-size payload over HTTPS. Defaults to
	// https://cachefly.cachefly.net/1mb.test — a 1 MiB file on
	// Cachefly's free anycast CDN, usually the nearest PoP wins so the
	// measurement reflects the instance's upstream bandwidth rather
	// than any specific long-haul route.
	ThroughputProbeURL string `mapstructure:"throughput_probe_url"`

	// ThroughputProbeInterval is how often the throughput ticker
	// runs. Defaults to 5 min.
	ThroughputProbeInterval time.Duration `mapstructure:"throughput_probe_interval"`
}

// MeshPeerConfig identifies a sibling headscale instance.
type MeshPeerConfig struct {
	Name string `mapstructure:"name"`
	URL  string `mapstructure:"url"`
}

// IsEnabled reports whether the mesh subsystem should start. Disabled
// when no SelfName is set so single-server installations pay nothing.
// Having either static peers or a dynamic-join path (bootstrap + cluster
// secret) is enough to enable — empty peers + no bootstrap just means
// "wait for someone to join me".
func (m MeshConfig) IsEnabled() bool {
	if m.SelfName == "" {
		return false
	}
	return len(m.Peers) > 0 || m.ClusterSecret != ""
}

type CLIConfig struct {
	Address  string
	APIKey   string `json:"-"` // never serialise the headscale admin API key
	Timeout  time.Duration
	Insecure bool
}

type PolicyConfig struct {
	Path string
	Mode PolicyMode
}

func (p *PolicyConfig) IsEmpty() bool {
	return p.Mode == PolicyModeFile && p.Path == ""
}

type LogConfig struct {
	Format string
	Level  zerolog.Level
}

// Tuning contains advanced performance tuning parameters for Headscale.
// These settings control internal batching, timeouts, and resource allocation.
// The defaults are carefully chosen for typical deployments and should rarely
// need adjustment. Changes to these values can significantly impact performance
// and resource usage.
type Tuning struct {
	// NotifierSendTimeout is the maximum time to wait when sending notifications
	// to connected clients about network changes.
	NotifierSendTimeout time.Duration

	// BatchChangeDelay controls how long to wait before sending batched updates
	// to clients when multiple changes occur in rapid succession.
	BatchChangeDelay time.Duration

	// NodeMapSessionBufferedChanSize sets the buffer size for the channel that
	// queues map updates to be sent to connected clients.
	NodeMapSessionBufferedChanSize int

	// BatcherWorkers controls the number of parallel workers processing map
	// updates for connected clients.
	BatcherWorkers int

	// RegisterCacheExpiration is how long registration cache entries remain
	// valid before being eligible for eviction.
	RegisterCacheExpiration time.Duration

	// RegisterCacheMaxEntries bounds the number of pending registration
	// entries the auth cache will hold. Older entries are evicted (LRU)
	// when the cap is reached, preventing unauthenticated cache-fill DoS.
	// A value of 0 falls back to defaultRegisterCacheMaxEntries (1024).
	RegisterCacheMaxEntries int

	// NodeStoreBatchSize controls how many write operations are accumulated
	// before rebuilding the in-memory node snapshot.
	//
	// The NodeStore batches write operations (add/update/delete nodes) before
	// rebuilding its in-memory data structures. Rebuilding involves recalculating
	// peer relationships between all nodes based on the current ACL policy, which
	// is computationally expensive and scales with the square of the number of nodes.
	//
	// By batching writes, Headscale can process N operations but only rebuild once,
	// rather than rebuilding N times. This significantly reduces CPU usage during
	// bulk operations like initial sync or policy updates.
	//
	// Trade-off: Higher values reduce CPU usage from rebuilds but increase latency
	// for individual operations waiting for their batch to complete.
	NodeStoreBatchSize int

	// NodeStoreBatchTimeout is the maximum time to wait before processing a
	// partial batch of node operations.
	//
	// When NodeStoreBatchSize operations haven't accumulated, this timeout ensures
	// writes don't wait indefinitely. The batch processes when either the size
	// threshold is reached OR this timeout expires, whichever comes first.
	//
	// Trade-off: Lower values provide faster response for individual operations
	// but trigger more frequent (expensive) peer map rebuilds. Higher values
	// optimize for bulk throughput at the cost of individual operation latency.
	NodeStoreBatchTimeout time.Duration
}

func validatePKCEMethod(method string) error {
	if method != PKCEMethodPlain && method != PKCEMethodS256 {
		return errInvalidPKCEMethod
	}

	return nil
}

// Domain returns the hostname/domain part of the ServerURL.
// If the ServerURL is not a valid URL, it returns the BaseDomain.
func (c *Config) Domain() string {
	u, err := url.Parse(c.ServerURL)
	if err != nil {
		return c.BaseDomain
	}

	return u.Hostname()
}

// LoadConfig prepares and loads the Headscale configuration into Viper.
// This means it sets the default values, reads the configuration file and
// environment variables, and handles deprecated configuration options.
// It has to be called before LoadServerConfig and LoadCLIConfig.
// The configuration is not validated and the caller should check for errors
// using a validation function.
func LoadConfig(path string, isFile bool) error {
	if isFile {
		viper.SetConfigFile(path)
	} else {
		viper.SetConfigName("config")

		if path == "" {
			viper.AddConfigPath("/etc/headscale/")
			viper.AddConfigPath("$HOME/.headscale")
			viper.AddConfigPath(".")
		} else {
			// For testing
			viper.AddConfigPath(path)
		}
	}

	envPrefix := "headscale"
	viper.SetEnvPrefix(envPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	viper.SetDefault("policy.mode", "file")

	viper.SetDefault("tls_letsencrypt_cache_dir", "/var/www/.cache")
	viper.SetDefault("tls_letsencrypt_challenge_type", HTTP01ChallengeType)

	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.format", TextLogFormat)

	viper.SetDefault("dns.magic_dns", true)
	viper.SetDefault("dns.base_domain", "")
	viper.SetDefault("dns.override_local_dns", true)
	viper.SetDefault("dns.nameservers.global", []string{})
	viper.SetDefault("dns.nameservers.split", map[string]string{})
	viper.SetDefault("dns.search_domains", []string{})

	viper.SetDefault("derp.server.enabled", false)
	viper.SetDefault("derp.server.verify_clients", true)
	viper.SetDefault("derp.server.stun.enabled", true)
	viper.SetDefault("derp.server.automatically_add_embedded_derp_region", true)
	viper.SetDefault("derp.update_frequency", "3h")

	viper.SetDefault("unix_socket", "/var/run/headscale/headscale.sock")
	viper.SetDefault("unix_socket_permission", "0o770")

	viper.SetDefault("grpc_listen_addr", ":50443")
	viper.SetDefault("grpc_allow_insecure", false)

	viper.SetDefault("cli.timeout", "5s")
	viper.SetDefault("cli.insecure", false)

	viper.SetDefault("database.postgres.ssl", false)
	viper.SetDefault("database.postgres.max_open_conns", 10)
	viper.SetDefault("database.postgres.max_idle_conns", 10)
	viper.SetDefault("database.postgres.conn_max_idle_time_secs", 3600)

	viper.SetDefault("database.sqlite.write_ahead_log", true)
	viper.SetDefault("database.sqlite.wal_autocheckpoint", 1000) // SQLite default

	viper.SetDefault("oidc.scope", []string{oidc.ScopeOpenID, "profile", "email"})
	viper.SetDefault("oidc.only_start_if_oidc_is_available", true)
	viper.SetDefault("oidc.use_expiry_from_token", false)
	viper.SetDefault("oidc.pkce.enabled", false)
	viper.SetDefault("oidc.pkce.method", "S256")
	viper.SetDefault("oidc.email_verified_required", true)

	viper.SetDefault("logtail.enabled", false)
	viper.SetDefault("randomize_client_port", false)
	viper.SetDefault("taildrop.enabled", true)

	viper.SetDefault("awg.jc", 0)
	viper.SetDefault("awg.jmin", 0)
	viper.SetDefault("awg.jmax", 0)
	viper.SetDefault("awg.s1", 0)
	viper.SetDefault("awg.s2", 0)
	viper.SetDefault("awg.s3", 0)
	viper.SetDefault("awg.s4", 0)
	viper.SetDefault("awg.h1", "")
	viper.SetDefault("awg.h2", "")
	viper.SetDefault("awg.h3", "")
	viper.SetDefault("awg.h4", "")

	viper.SetDefault("mesh.self_name", "")
	viper.SetDefault("mesh.self_url", "")
	viper.SetDefault("mesh.probe_interval", "30s")
	viper.SetDefault("mesh.offline_after", "90s")
	viper.SetDefault("mesh.latency_alert", "2s")
	viper.SetDefault("mesh.local_db_host", "")
	viper.SetDefault("mesh.cluster_secret", "")
	viper.SetDefault("mesh.bootstrap_url", "")
	viper.SetDefault("mesh.peers_state_path", "")
	viper.SetDefault("mesh.ddns_update_url", "")
	viper.SetDefault("mesh.exit_node_name", "")
	viper.SetDefault("mesh.peers", []map[string]string{})

	viper.SetDefault("node.expiry", "0")
	viper.SetDefault("node.ephemeral.inactivity_timeout", "120s")

	viper.SetDefault("tuning.notifier_send_timeout", "800ms")
	viper.SetDefault("tuning.batch_change_delay", "800ms")
	viper.SetDefault("tuning.node_mapsession_buffered_chan_size", 30)
	viper.SetDefault("tuning.node_store_batch_size", defaultNodeStoreBatchSize)
	viper.SetDefault("tuning.node_store_batch_timeout", "500ms")

	viper.SetDefault("prefixes.allocation", string(IPAllocationStrategySequential))

	err := viper.ReadInConfig()
	if err != nil {
		if _, ok := errors.AsType[viper.ConfigFileNotFoundError](err); ok {
			log.Warn().Msg("no config file found, using defaults")
			return nil
		}

		return fmt.Errorf("fatal error reading config file: %w", err)
	}

	return nil
}

// resolveEphemeralInactivityTimeout resolves the ephemeral inactivity timeout
// from config, supporting both the new key (node.ephemeral.inactivity_timeout)
// and the old key (ephemeral_node_inactivity_timeout) for backwards compatibility.
//
// We cannot use viper.RegisterAlias here because aliases silently ignore
// config values set under the alias name. If a user writes the new key in
// their config file, RegisterAlias redirects reads to the old key (which
// has no config value), returning only the default and discarding the
// user's setting.
func resolveEphemeralInactivityTimeout() time.Duration {
	// New key takes precedence if explicitly set in config.
	if viper.IsSet("node.ephemeral.inactivity_timeout") &&
		viper.GetString("node.ephemeral.inactivity_timeout") != "" {
		return viper.GetDuration("node.ephemeral.inactivity_timeout")
	}

	// Fall back to old key for backwards compatibility.
	if viper.IsSet("ephemeral_node_inactivity_timeout") {
		return viper.GetDuration("ephemeral_node_inactivity_timeout")
	}

	// Default
	return viper.GetDuration("node.ephemeral.inactivity_timeout")
}

// resolveNodeExpiry parses the node.expiry config value.
// Returns 0 if set to "0" (no default expiry) or on parse failure.
func resolveNodeExpiry() time.Duration {
	value := viper.GetString("node.expiry")
	if value == "" || value == "0" {
		return 0
	}

	expiry, err := model.ParseDuration(value)
	if err != nil {
		log.Warn().
			Str("value", value).
			Msg("failed to parse node.expiry, defaulting to no expiry")

		return 0
	}

	return time.Duration(expiry)
}

func validateServerConfig() error {
	depr := deprecator{
		warns:  make(set.Set[string]),
		fatals: make(set.Set[string]),
	}

	// Register aliases for backward compatibility
	// Has to be called _after_ viper.ReadInConfig()
	// https://github.com/spf13/viper/issues/560

	// Alias the old ACL Policy path with the new configuration option.
	depr.fatalIfNewKeyIsNotUsed("policy.path", "acl_policy_path")

	// Move dns_config -> dns
	depr.fatalIfNewKeyIsNotUsed("dns.magic_dns", "dns_config.magic_dns")
	depr.fatalIfNewKeyIsNotUsed("dns.base_domain", "dns_config.base_domain")
	depr.fatalIfNewKeyIsNotUsed("dns.override_local_dns", "dns_config.override_local_dns")
	depr.fatalIfNewKeyIsNotUsed("dns.nameservers.global", "dns_config.nameservers")
	depr.fatalIfNewKeyIsNotUsed("dns.nameservers.split", "dns_config.restricted_nameservers")
	depr.fatalIfNewKeyIsNotUsed("dns.search_domains", "dns_config.domains")
	depr.fatalIfNewKeyIsNotUsed("dns.extra_records", "dns_config.extra_records")
	depr.fatal("dns.use_username_in_magic_dns")
	depr.fatal("dns_config.use_username_in_magic_dns")

	// Removed since version v0.26.0
	depr.fatal("oidc.strip_email_domain")
	depr.fatal("oidc.map_legacy_users")

	// Deprecated: ephemeral_node_inactivity_timeout -> node.ephemeral.inactivity_timeout
	depr.warnNoAlias("node.ephemeral.inactivity_timeout", "ephemeral_node_inactivity_timeout")

	// Removed: oidc.expiry -> node.expiry
	depr.fatalIfSet("oidc.expiry", "node.expiry")

	if viper.GetBool("oidc.enabled") {
		err := validatePKCEMethod(viper.GetString("oidc.pkce.method"))
		if err != nil {
			return err
		}
	}

	depr.Log()

	if viper.IsSet("dns.extra_records") && viper.IsSet("dns.extra_records_path") {
		log.Fatal().Msg("fatal config error: dns.extra_records and dns.extra_records_path are mutually exclusive. Please remove one of them from your config file")
	}

	// Collect any validation errors and return them all at once
	var errorText string
	if (viper.GetString("tls_letsencrypt_hostname") != "") &&
		((viper.GetString("tls_cert_path") != "") || (viper.GetString("tls_key_path") != "")) {
		errorText += "Fatal config error: set either tls_letsencrypt_hostname or tls_cert_path/tls_key_path, not both\n"
	}

	if viper.GetString("noise.private_key_path") == "" {
		errorText += "Fatal config error: headscale now requires a new `noise.private_key_path` field in the config file for the Tailscale v2 protocol\n"
	}

	if (viper.GetString("tls_letsencrypt_hostname") != "") &&
		(viper.GetString("tls_letsencrypt_challenge_type") == TLSALPN01ChallengeType) &&
		(!strings.HasSuffix(viper.GetString("listen_addr"), ":443")) {
		// this is only a warning because there could be something sitting in front of headscale that redirects the traffic (e.g. an iptables rule)
		log.Warn().
			Msg("Warning: when using tls_letsencrypt_hostname with TLS-ALPN-01 as challenge type, headscale must be reachable on port 443, i.e. listen_addr should probably end in :443")
	}

	if (viper.GetString("tls_letsencrypt_challenge_type") != HTTP01ChallengeType) &&
		(viper.GetString("tls_letsencrypt_challenge_type") != TLSALPN01ChallengeType) {
		errorText += "Fatal config error: the only supported values for tls_letsencrypt_challenge_type are HTTP-01 and TLS-ALPN-01\n"
	}

	if !strings.HasPrefix(viper.GetString("server_url"), "http://") &&
		!strings.HasPrefix(viper.GetString("server_url"), "https://") {
		errorText += "Fatal config error: server_url must start with https:// or http://\n"
	}

	// Minimum inactivity time out is keepalive timeout (60s) plus a few seconds
	// to avoid races
	minInactivityTimeout, _ := time.ParseDuration("65s")

	ephemeralTimeout := resolveEphemeralInactivityTimeout()
	if ephemeralTimeout <= minInactivityTimeout {
		errorText += fmt.Sprintf(
			"Fatal config error: node.ephemeral.inactivity_timeout (%s) is set too low, must be more than %s",
			ephemeralTimeout,
			minInactivityTimeout,
		)
	}

	if viper.GetBool("dns.override_local_dns") {
		if global := viper.GetStringSlice("dns.nameservers.global"); len(global) == 0 {
			errorText += "Fatal config error: dns.nameservers.global must be set when dns.override_local_dns is true\n"
		}
	}

	// Validate tuning parameters
	if size := viper.GetInt("tuning.node_store_batch_size"); size <= 0 {
		errorText += fmt.Sprintf(
			"Fatal config error: tuning.node_store_batch_size must be positive, got %d\n",
			size,
		)
	}

	if timeout := viper.GetDuration("tuning.node_store_batch_timeout"); timeout <= 0 {
		errorText += fmt.Sprintf(
			"Fatal config error: tuning.node_store_batch_timeout must be positive, got %s\n",
			timeout,
		)
	}

	awg := AWGConfig{
		Jc:   viper.GetInt("awg.jc"),
		Jmin: viper.GetInt("awg.jmin"),
		Jmax: viper.GetInt("awg.jmax"),
		S1:   viper.GetInt("awg.s1"),
		S2:   viper.GetInt("awg.s2"),
		S3:   viper.GetInt("awg.s3"),
		S4:   viper.GetInt("awg.s4"),
		H1:   viper.GetString("awg.h1"),
		H2:   viper.GetString("awg.h2"),
		H3:   viper.GetString("awg.h3"),
		H4:   viper.GetString("awg.h4"),
	}
	if err := awg.Validate(); err != nil {
		errorText += "Fatal config error: " + err.Error() + "\n"
	}

	if errorText != "" {
		// nolint
		return errors.New(strings.TrimSuffix(errorText, "\n"))
	}

	return nil
}

func tlsConfig() TLSConfig {
	return TLSConfig{
		LetsEncrypt: LetsEncryptConfig{
			Hostname: viper.GetString("tls_letsencrypt_hostname"),
			Listen:   viper.GetString("tls_letsencrypt_listen"),
			CacheDir: util.AbsolutePathFromConfigPath(
				viper.GetString("tls_letsencrypt_cache_dir"),
			),
			ChallengeType: viper.GetString("tls_letsencrypt_challenge_type"),
		},
		CertPath: util.AbsolutePathFromConfigPath(
			viper.GetString("tls_cert_path"),
		),
		KeyPath: util.AbsolutePathFromConfigPath(
			viper.GetString("tls_key_path"),
		),
	}
}

func derpConfig() DERPConfig {
	serverEnabled := viper.GetBool("derp.server.enabled")
	serverRegionID := viper.GetInt("derp.server.region_id")
	serverRegionCode := viper.GetString("derp.server.region_code")
	serverRegionName := viper.GetString("derp.server.region_name")
	serverVerifyClients := viper.GetBool("derp.server.verify_clients")
	stunAddr := viper.GetString("derp.server.stun_listen_addr")
	privateKeyPath := util.AbsolutePathFromConfigPath(
		viper.GetString("derp.server.private_key_path"),
	)
	ipv4 := viper.GetString("derp.server.ipv4")
	ipv6 := viper.GetString("derp.server.ipv6")
	automaticallyAddEmbeddedDerpRegion := viper.GetBool(
		"derp.server.automatically_add_embedded_derp_region",
	)

	if serverEnabled && stunAddr == "" {
		log.Fatal().
			Msg("derp.server.stun_listen_addr must be set if derp.server.enabled is true")
	}

	urlStrs := viper.GetStringSlice("derp.urls")

	urls := make([]url.URL, len(urlStrs))
	for index, urlStr := range urlStrs {
		urlAddr, err := url.Parse(urlStr)
		if err != nil {
			log.Error().
				Caller().
				Str("url", urlStr).
				Err(err).
				Msg("Failed to parse url, ignoring...")
		}

		urls[index] = *urlAddr
	}

	paths := viper.GetStringSlice("derp.paths")

	if serverEnabled && !automaticallyAddEmbeddedDerpRegion && len(paths) == 0 {
		log.Fatal().
			Msg("Disabling derp.server.automatically_add_embedded_derp_region requires to configure the derp server in derp.paths")
	}

	autoUpdate := viper.GetBool("derp.auto_update_enabled")
	updateFrequency := viper.GetDuration("derp.update_frequency")

	return DERPConfig{
		ServerEnabled:                      serverEnabled,
		ServerRegionID:                     serverRegionID,
		ServerRegionCode:                   serverRegionCode,
		ServerRegionName:                   serverRegionName,
		ServerVerifyClients:                serverVerifyClients,
		ServerPrivateKeyPath:               privateKeyPath,
		STUNAddr:                           stunAddr,
		URLs:                               urls,
		Paths:                              paths,
		AutoUpdate:                         autoUpdate,
		UpdateFrequency:                    updateFrequency,
		IPv4:                               ipv4,
		IPv6:                               ipv6,
		AutomaticallyAddEmbeddedDerpRegion: automaticallyAddEmbeddedDerpRegion,
	}
}

func logtailConfig() LogTailConfig {
	enabled := viper.GetBool("logtail.enabled")

	return LogTailConfig{
		Enabled: enabled,
	}
}

// meshConfigFromViper reads the `mesh:` section from viper. serverURL is
// the already-resolved top-level server_url; used as the default for
// SelfURL so operators don't have to repeat themselves.
func meshConfigFromViper(serverURL string) MeshConfig {
	mc := MeshConfig{
		SelfName:                viper.GetString("mesh.self_name"),
		SelfURL:                 viper.GetString("mesh.self_url"),
		ProbeInterval:           viper.GetDuration("mesh.probe_interval"),
		OfflineAfter:            viper.GetDuration("mesh.offline_after"),
		LatencyAlert:            viper.GetDuration("mesh.latency_alert"),
		LocalDBHost:             viper.GetString("mesh.local_db_host"),
		ClusterSecret:           viper.GetString("mesh.cluster_secret"),
		BootstrapURL:            viper.GetString("mesh.bootstrap_url"),
		PeersStatePath:          viper.GetString("mesh.peers_state_path"),
		DDNSUpdateURL:           viper.GetString("mesh.ddns_update_url"),
		ExitNodeName:            viper.GetString("mesh.exit_node_name"),
		SkipCrownExit:           viper.GetBool("mesh.skip_crown_exit"),
		ThroughputProbe:         viper.GetBool("mesh.throughput_probe"),
		ThroughputProbeURL:      viper.GetString("mesh.throughput_probe_url"),
		ThroughputProbeInterval: viper.GetDuration("mesh.throughput_probe_interval"),
	}
	if mc.ThroughputProbeURL == "" {
		mc.ThroughputProbeURL = "https://cachefly.cachefly.net/1mb.test"
	}
	if mc.ThroughputProbeInterval <= 0 {
		mc.ThroughputProbeInterval = 5 * time.Minute
	}
	if mc.SelfURL == "" {
		mc.SelfURL = serverURL
	}
	if mc.ProbeInterval <= 0 {
		mc.ProbeInterval = 30 * time.Second
	}
	if mc.OfflineAfter <= 0 {
		mc.OfflineAfter = 90 * time.Second
	}
	if mc.LatencyAlert <= 0 {
		mc.LatencyAlert = 2 * time.Second
	}
	// Default peers_state_path to peers.state.json beside the config
	// file so operators get durable dynamic-peer state for free.
	if mc.PeersStatePath == "" {
		if cfg := viper.ConfigFileUsed(); cfg != "" {
			mc.PeersStatePath = filepath.Join(filepath.Dir(cfg), "peers.state.json")
		}
	}

	// Unmarshal peers into a structured slice; viper returns
	// []map[string]any when the YAML has inline mappings.
	raw := viper.Get("mesh.peers")
	entries, _ := raw.([]any)
	for _, e := range entries {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		url, _ := m["url"].(string)
		if name == "" || url == "" {
			continue
		}
		mc.Peers = append(mc.Peers, MeshPeerConfig{Name: name, URL: url})
	}
	return mc
}

func policyConfig() PolicyConfig {
	policyPath := viper.GetString("policy.path")
	policyMode := viper.GetString("policy.mode")

	return PolicyConfig{
		Path: policyPath,
		Mode: PolicyMode(policyMode),
	}
}

func logConfig() LogConfig {
	logLevelStr := viper.GetString("log.level")

	logLevel, err := zerolog.ParseLevel(logLevelStr)
	if err != nil {
		logLevel = zerolog.DebugLevel
	}

	logFormatOpt := viper.GetString("log.format")

	var logFormat string

	switch logFormatOpt {
	case JSONLogFormat:
		logFormat = JSONLogFormat
	case TextLogFormat:
		logFormat = TextLogFormat
	case "":
		logFormat = TextLogFormat
	default:
		log.Error().
			Caller().
			Str("func", "GetLogConfig").
			Msgf("Could not parse log format: %s. Valid choices are 'json' or 'text'", logFormatOpt)
	}

	return LogConfig{
		Format: logFormat,
		Level:  logLevel,
	}
}

func databaseConfig() DatabaseConfig {
	debug := viper.GetBool("database.debug")

	type_ := viper.GetString("database.type")

	skipErrRecordNotFound := viper.GetBool("database.gorm.skip_err_record_not_found")
	slowThreshold := time.Duration(viper.GetInt64("database.gorm.slow_threshold")) * time.Millisecond
	parameterizedQueries := viper.GetBool("database.gorm.parameterized_queries")
	prepareStmt := viper.GetBool("database.gorm.prepare_stmt")

	switch type_ {
	case DatabaseSqlite, DatabasePostgres:
		break
	case "sqlite":
		type_ = "sqlite3"
	default:
		log.Fatal().
			Msgf("invalid database type %q, must be sqlite, sqlite3 or postgres", type_)
	}

	return DatabaseConfig{
		Type:  type_,
		Debug: debug,
		Gorm: GormConfig{
			Debug:                 debug,
			SkipErrRecordNotFound: skipErrRecordNotFound,
			SlowThreshold:         slowThreshold,
			ParameterizedQueries:  parameterizedQueries,
			PrepareStmt:           prepareStmt,
		},
		Sqlite: SqliteConfig{
			Path: util.AbsolutePathFromConfigPath(
				viper.GetString("database.sqlite.path"),
			),
			WriteAheadLog:     viper.GetBool("database.sqlite.write_ahead_log"),
			WALAutoCheckPoint: viper.GetInt("database.sqlite.wal_autocheckpoint"),
		},
		Postgres: PostgresConfig{
			Host:               viper.GetString("database.postgres.host"),
			Port:               viper.GetInt("database.postgres.port"),
			Name:               viper.GetString("database.postgres.name"),
			User:               viper.GetString("database.postgres.user"),
			Pass:               viper.GetString("database.postgres.pass"),
			Ssl:                viper.GetString("database.postgres.ssl"),
			MaxOpenConnections: viper.GetInt("database.postgres.max_open_conns"),
			MaxIdleConnections: viper.GetInt("database.postgres.max_idle_conns"),
			ConnMaxIdleTimeSecs: viper.GetInt(
				"database.postgres.conn_max_idle_time_secs",
			),
		},
	}
}

func dns() (DNSConfig, error) {
	var dns DNSConfig

	// TODO: Use this instead of manually getting settings when
	// UnmarshalKey is compatible with Environment Variables.
	// err := viper.UnmarshalKey("dns", &dns)
	// if err != nil {
	// 	return DNSConfig{}, fmt.Errorf("unmarshalling dns config: %w", err)
	// }

	dns.MagicDNS = viper.GetBool("dns.magic_dns")
	dns.BaseDomain = viper.GetString("dns.base_domain")
	dns.OverrideLocalDNS = viper.GetBool("dns.override_local_dns")
	dns.Nameservers.Global = viper.GetStringSlice("dns.nameservers.global")
	dns.Nameservers.Split = viper.GetStringMapStringSlice("dns.nameservers.split")
	dns.SearchDomains = viper.GetStringSlice("dns.search_domains")
	dns.ExtraRecordsPath = viper.GetString("dns.extra_records_path")

	if viper.IsSet("dns.extra_records") {
		var extraRecords []tailcfg.DNSRecord

		err := viper.UnmarshalKey("dns.extra_records", &extraRecords)
		if err != nil {
			return DNSConfig{}, fmt.Errorf("unmarshalling dns extra records: %w", err)
		}

		dns.ExtraRecords = extraRecords
	}

	return dns, nil
}

// globalResolvers returns the global DNS resolvers
// defined in the config file.
// If a nameserver is a valid IP, it will be used as a regular resolver.
// If a nameserver is a valid URL, it will be used as a DoH resolver.
// If a nameserver is neither a valid URL nor a valid IP, it will be ignored.
func (d *DNSConfig) globalResolvers() []*dnstype.Resolver {
	var resolvers []*dnstype.Resolver

	for _, nsStr := range d.Nameservers.Global {
		if _, err := netip.ParseAddr(nsStr); err == nil { //nolint:noinlineerr
			resolvers = append(resolvers, &dnstype.Resolver{
				Addr: nsStr,
			})

			continue
		}

		if _, err := url.Parse(nsStr); err == nil { //nolint:noinlineerr
			resolvers = append(resolvers, &dnstype.Resolver{
				Addr: nsStr,
			})

			continue
		}

		log.Warn().Str("nameserver", nsStr).Msg("invalid global nameserver, ignoring")
	}

	return resolvers
}

// splitResolvers returns a map of domain to DNS resolvers.
// If a nameserver is a valid IP, it will be used as a regular resolver.
// If a nameserver is a valid URL, it will be used as a DoH resolver.
// If a nameserver is neither a valid URL nor a valid IP, it will be ignored.
func (d *DNSConfig) splitResolvers() map[string][]*dnstype.Resolver {
	routes := make(map[string][]*dnstype.Resolver)

	for domain, nameservers := range d.Nameservers.Split {
		var resolvers []*dnstype.Resolver

		for _, nsStr := range nameservers {
			if _, err := netip.ParseAddr(nsStr); err == nil { //nolint:noinlineerr
				resolvers = append(resolvers, &dnstype.Resolver{
					Addr: nsStr,
				})

				continue
			}

			if _, err := url.Parse(nsStr); err == nil { //nolint:noinlineerr
				resolvers = append(resolvers, &dnstype.Resolver{
					Addr: nsStr,
				})

				continue
			}

			log.Warn().Str("nameserver", nsStr).Str("domain", domain).Msg("invalid split dns nameserver, ignoring")
		}

		routes[domain] = resolvers
	}

	return routes
}

func dnsToTailcfgDNS(dns DNSConfig) *tailcfg.DNSConfig {
	cfg := tailcfg.DNSConfig{}

	if dns.BaseDomain == "" && dns.MagicDNS {
		log.Fatal().Msg("dns.base_domain must be set when using MagicDNS (dns.magic_dns)")
	}

	cfg.Proxied = dns.MagicDNS

	cfg.ExtraRecords = dns.ExtraRecords
	if dns.OverrideLocalDNS {
		cfg.Resolvers = dns.globalResolvers()
	} else {
		cfg.FallbackResolvers = dns.globalResolvers()
	}

	routes := dns.splitResolvers()

	cfg.Routes = routes
	if dns.BaseDomain != "" {
		cfg.Domains = []string{dns.BaseDomain}
	}

	cfg.Domains = append(cfg.Domains, dns.SearchDomains...)

	return &cfg
}

// warnBanner prints a highly visible warning banner to the log output.
// It wraps the provided lines in an ASCII-art box with a "Warning!" header.
// This is intended for critical configuration issues that users must not ignore.
func warnBanner(lines []string) {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString("################################################################\n")
	b.WriteString("###      __          __              _             _         ###\n")
	b.WriteString("###      \\ \\        / /             (_)           | |        ###\n")
	b.WriteString("###       \\ \\  /\\  / /_ _ _ __ _ __  _ _ __   __ _| |        ###\n")
	b.WriteString("###        \\ \\/  \\/ / _` | '__| '_ \\| | '_ \\ / _` | |        ###\n")
	b.WriteString("###         \\  /\\  / (_| | |  | | | | | | | | (_| |_|        ###\n")
	b.WriteString("###          \\/  \\/ \\__,_|_|  |_| |_|_|_| |_|\\__, (_)        ###\n")
	b.WriteString("###                                           __/ |          ###\n")
	b.WriteString("###                                          |___/           ###\n")
	b.WriteString("################################################################\n")
	b.WriteString("###                                                          ###\n")

	for _, line := range lines {
		fmt.Fprintf(&b, "###  %-54s  ###\n", line)
	}

	b.WriteString("###                                                          ###\n")
	b.WriteString("################################################################")

	log.Warn().Msg(b.String())
}

func prefixV4() (*netip.Prefix, bool, error) {
	prefixV4Str := viper.GetString("prefixes.v4")

	if prefixV4Str == "" {
		return nil, false, nil
	}

	prefixV4, err := netip.ParsePrefix(prefixV4Str)
	if err != nil {
		return nil, false, fmt.Errorf("parsing IPv4 prefix from config: %w", err)
	}

	builder := netipx.IPSetBuilder{}
	builder.AddPrefix(tsaddr.CGNATRange())

	ipSet, _ := builder.IPSet()

	return &prefixV4, !ipSet.ContainsPrefix(prefixV4), nil
}

func prefixV6() (*netip.Prefix, bool, error) {
	prefixV6Str := viper.GetString("prefixes.v6")

	if prefixV6Str == "" {
		return nil, false, nil
	}

	prefixV6, err := netip.ParsePrefix(prefixV6Str)
	if err != nil {
		return nil, false, fmt.Errorf("parsing IPv6 prefix from config: %w", err)
	}

	builder := netipx.IPSetBuilder{}
	builder.AddPrefix(tsaddr.TailscaleULARange())
	ipSet, _ := builder.IPSet()

	return &prefixV6, !ipSet.ContainsPrefix(prefixV6), nil
}

// LoadCLIConfig returns the needed configuration for the CLI client
// of Headscale to connect to a Headscale server.
func LoadCLIConfig() (*Config, error) {
	logConfig := logConfig()
	zerolog.SetGlobalLevel(logConfig.Level)

	return &Config{
		DisableUpdateCheck: viper.GetBool("disable_check_updates"),
		UnixSocket:         viper.GetString("unix_socket"),
		CLI: CLIConfig{
			Address:  viper.GetString("cli.address"),
			APIKey:   viper.GetString("cli.api_key"),
			Timeout:  viper.GetDuration("cli.timeout"),
			Insecure: viper.GetBool("cli.insecure"),
		},
		Log: logConfig,
	}, nil
}

// LoadServerConfig returns the full Headscale configuration to
// host a Headscale server. This is called as part of `headscale serve`.
func LoadServerConfig() (*Config, error) {
	if err := validateServerConfig(); err != nil { //nolint:noinlineerr
		return nil, err
	}

	logConfig := logConfig()
	zerolog.SetGlobalLevel(logConfig.Level)

	prefix4, v4NonStandard, err := prefixV4()
	if err != nil {
		return nil, err
	}

	prefix6, v6NonStandard, err := prefixV6()
	if err != nil {
		return nil, err
	}

	if prefix4 == nil && prefix6 == nil {
		return nil, ErrNoPrefixConfigured
	}

	if v4NonStandard || v6NonStandard {
		warnBanner([]string{
			"You have overridden the default Headscale IP prefixes",
			"with a range outside of the standard CGNAT and/or ULA",
			"ranges. This is NOT a supported configuration.",
			"",
			"Using subsets of the default ranges (100.64.0.0/10 for",
			"IPv4, fd7a:115c:a1e0::/48 for IPv6) is fine. Using",
			"ranges outside of these will cause undefined behaviour",
			"as the Tailscale client is NOT designed to operate on",
			"any other ranges.",
			"",
			"Please revert your prefixes to subsets of the standard",
			"ranges as described in the example configuration.",
			"",
			"Any issue raised using a range outside of the",
			"supported range will be labelled as wontfix",
			"and closed.",
		})
	}

	allocStr := viper.GetString("prefixes.allocation")

	var alloc IPAllocationStrategy

	switch allocStr {
	case string(IPAllocationStrategySequential):
		alloc = IPAllocationStrategySequential
	case string(IPAllocationStrategyRandom):
		alloc = IPAllocationStrategyRandom
	default:
		return nil, fmt.Errorf(
			"%w: %q, allowed options: %s, %s",
			ErrInvalidAllocationStrategy,
			allocStr,
			IPAllocationStrategySequential,
			IPAllocationStrategyRandom,
		)
	}

	dnsConfig, err := dns()
	if err != nil {
		return nil, err
	}

	derpConfig := derpConfig()
	logTailConfig := logtailConfig()
	randomizeClientPort := viper.GetBool("randomize_client_port")

	oidcClientSecret := viper.GetString("oidc.client_secret")

	oidcClientSecretPath := viper.GetString("oidc.client_secret_path")
	if oidcClientSecretPath != "" && oidcClientSecret != "" {
		return nil, errOidcMutuallyExclusive
	}

	if oidcClientSecretPath != "" {
		secretBytes, err := os.ReadFile(os.ExpandEnv(oidcClientSecretPath))
		if err != nil {
			return nil, err
		}

		oidcClientSecret = strings.TrimSpace(string(secretBytes))
	}

	serverURL := viper.GetString("server_url")

	// BaseDomain cannot be the same as the server URL.
	// This is because Tailscale takes over the domain in BaseDomain,
	// causing the headscale server and DERP to be unreachable.
	// For Tailscale upstream, the following is true:
	// - DERP run on their own domains
	// - Control plane runs on login.tailscale.com/controlplane.tailscale.com
	// - MagicDNS (BaseDomain) for users is on a *.ts.net domain per tailnet (e.g. tail-scale.ts.net)
	if dnsConfig.BaseDomain != "" {
		err := isSafeServerURL(serverURL, dnsConfig.BaseDomain)
		if err != nil {
			return nil, err
		}
	}

	return &Config{
		ServerURL:          serverURL,
		Addr:               viper.GetString("listen_addr"),
		MetricsAddr:        viper.GetString("metrics_listen_addr"),
		GRPCAddr:           viper.GetString("grpc_listen_addr"),
		GRPCAllowInsecure:  viper.GetBool("grpc_allow_insecure"),
		DisableUpdateCheck: false,

		PrefixV4:     prefix4,
		PrefixV6:     prefix6,
		IPAllocation: alloc,

		NoisePrivateKeyPath: util.AbsolutePathFromConfigPath(
			viper.GetString("noise.private_key_path"),
		),
		BaseDomain: dnsConfig.BaseDomain,

		DERP: derpConfig,

		Node: NodeConfig{
			Expiry: resolveNodeExpiry(),
			Ephemeral: EphemeralConfig{
				InactivityTimeout: resolveEphemeralInactivityTimeout(),
			},
		},

		Database: databaseConfig(),

		TLS: tlsConfig(),

		DNSConfig:        dnsConfig,
		TailcfgDNSConfig: dnsToTailcfgDNS(dnsConfig),

		ACMEEmail: viper.GetString("acme_email"),
		ACMEURL:   viper.GetString("acme_url"),

		UnixSocket:           viper.GetString("unix_socket"),
		UnixSocketPermission: util.GetFileMode("unix_socket_permission"),

		OIDC: OIDCConfig{
			OnlyStartIfOIDCIsAvailable: viper.GetBool(
				"oidc.only_start_if_oidc_is_available",
			),
			Issuer:                viper.GetString("oidc.issuer"),
			ClientID:              viper.GetString("oidc.client_id"),
			ClientSecret:          oidcClientSecret,
			Scope:                 viper.GetStringSlice("oidc.scope"),
			ExtraParams:           viper.GetStringMapString("oidc.extra_params"),
			AllowedDomains:        viper.GetStringSlice("oidc.allowed_domains"),
			AllowedUsers:          viper.GetStringSlice("oidc.allowed_users"),
			AllowedGroups:         viper.GetStringSlice("oidc.allowed_groups"),
			EmailVerifiedRequired: viper.GetBool("oidc.email_verified_required"),
			UseExpiryFromToken:    viper.GetBool("oidc.use_expiry_from_token"),
			PKCE: PKCEConfig{
				Enabled: viper.GetBool("oidc.pkce.enabled"),
				Method:  viper.GetString("oidc.pkce.method"),
			},
		},

		LogTail:             logTailConfig,
		RandomizeClientPort: randomizeClientPort,
		Taildrop: TaildropConfig{
			Enabled: viper.GetBool("taildrop.enabled"),
		},
		AWG: AWGConfig{
			Jc:   viper.GetInt("awg.jc"),
			Jmin: viper.GetInt("awg.jmin"),
			Jmax: viper.GetInt("awg.jmax"),
			S1:   viper.GetInt("awg.s1"),
			S2:   viper.GetInt("awg.s2"),
			S3:   viper.GetInt("awg.s3"),
			S4:   viper.GetInt("awg.s4"),
			H1:   viper.GetString("awg.h1"),
			H2:   viper.GetString("awg.h2"),
			H3:   viper.GetString("awg.h3"),
			H4:   viper.GetString("awg.h4"),
		},
		Mesh: meshConfigFromViper(serverURL),

		Policy: policyConfig(),

		CLI: CLIConfig{
			Address:  viper.GetString("cli.address"),
			APIKey:   viper.GetString("cli.api_key"),
			Timeout:  viper.GetDuration("cli.timeout"),
			Insecure: viper.GetBool("cli.insecure"),
		},

		Log: logConfig,

		Tuning: Tuning{
			NotifierSendTimeout: viper.GetDuration("tuning.notifier_send_timeout"),
			BatchChangeDelay:    viper.GetDuration("tuning.batch_change_delay"),
			NodeMapSessionBufferedChanSize: viper.GetInt(
				"tuning.node_mapsession_buffered_chan_size",
			),
			BatcherWorkers: func() int {
				if workers := viper.GetInt("tuning.batcher_workers"); workers > 0 {
					return workers
				}

				return DefaultBatcherWorkers()
			}(),
			RegisterCacheExpiration: viper.GetDuration("tuning.register_cache_expiration"),
			RegisterCacheMaxEntries: viper.GetInt("tuning.register_cache_max_entries"),
			NodeStoreBatchSize:      viper.GetInt("tuning.node_store_batch_size"),
			NodeStoreBatchTimeout:   viper.GetDuration("tuning.node_store_batch_timeout"),
		},
	}, nil
}

// BaseDomain cannot be a suffix of the server URL.
// This is because Tailscale takes over the domain in BaseDomain,
// causing the headscale server and DERP to be unreachable.
// For Tailscale upstream, the following is true:
// - DERP run on their own domains.
// - Control plane runs on login.tailscale.com/controlplane.tailscale.com.
// - MagicDNS (BaseDomain) for users is on a *.ts.net domain per tailnet (e.g. tail-scale.ts.net).
func isSafeServerURL(serverURL, baseDomain string) error {
	server, err := url.Parse(serverURL)
	if err != nil {
		return err
	}

	if server.Hostname() == baseDomain {
		return errServerURLSame
	}

	serverDomainParts := strings.Split(server.Host, ".")
	baseDomainParts := strings.Split(baseDomain, ".")

	if len(serverDomainParts) <= len(baseDomainParts) {
		return nil
	}

	s := len(serverDomainParts)

	b := len(baseDomainParts)
	for i := range baseDomainParts {
		if serverDomainParts[s-i-1] != baseDomainParts[b-i-1] {
			return nil
		}
	}

	return errServerURLSuffix
}

type deprecator struct {
	warns  set.Set[string]
	fatals set.Set[string]
}

// warnWithAlias will register an alias between the newKey and the oldKey,
// and log a deprecation warning if the oldKey is set.
//
//nolint:unused
func (d *deprecator) warnWithAlias(newKey, oldKey string) {
	// NOTE: RegisterAlias is called with NEW KEY -> OLD KEY
	viper.RegisterAlias(newKey, oldKey)

	if viper.IsSet(oldKey) {
		d.warns.Add(
			fmt.Sprintf(
				"The %q configuration key is deprecated. Please use %q instead. %q will be removed in the future.",
				oldKey,
				newKey,
				oldKey,
			),
		)
	}
}

// fatal deprecates and adds an entry to the fatal list of options if the oldKey is set.
func (d *deprecator) fatal(oldKey string) {
	if viper.IsSet(oldKey) {
		d.fatals.Add(
			fmt.Sprintf(
				"The %q configuration key has been removed. Please see the changelog for more details.",
				oldKey,
			),
		)
	}
}

// fatalIfNewKeyIsNotUsed deprecates and adds an entry to the fatal list of options if the oldKey is set and the new key is _not_ set.
// If the new key is set, a warning is emitted instead.
func (d *deprecator) fatalIfNewKeyIsNotUsed(newKey, oldKey string) {
	if viper.IsSet(oldKey) && !viper.IsSet(newKey) {
		d.fatals.Add(
			fmt.Sprintf(
				"The %q configuration key is deprecated. Please use %q instead. %q has been removed.",
				oldKey,
				newKey,
				oldKey,
			),
		)
	} else if viper.IsSet(oldKey) {
		d.warns.Add(fmt.Sprintf("The %q configuration key is deprecated. Please use %q instead. %q has been removed.", oldKey, newKey, oldKey))
	}
}

// fatalIfSet fatals if the oldKey is set at all, regardless of whether
// the newKey is set. Use this when the old key has been fully removed
// and any use of it should be a hard error.
func (d *deprecator) fatalIfSet(oldKey, newKey string) {
	if viper.IsSet(oldKey) {
		d.fatals.Add(
			fmt.Sprintf(
				"The %q configuration key has been removed. Please use %q instead.",
				oldKey,
				newKey,
			),
		)
	}
}

// warn deprecates and adds an option to log a warning if the oldKey is set.
//
//nolint:unused
func (d *deprecator) warnNoAlias(newKey, oldKey string) {
	if viper.IsSet(oldKey) {
		d.warns.Add(
			fmt.Sprintf(
				"The %q configuration key is deprecated. Please use %q instead. %q has been removed.",
				oldKey,
				newKey,
				oldKey,
			),
		)
	}
}

// warn deprecates and adds an entry to the warn list of options if the oldKey is set.
//
//nolint:unused
func (d *deprecator) warn(oldKey string) {
	if viper.IsSet(oldKey) {
		d.warns.Add(
			fmt.Sprintf(
				"The %q configuration key is deprecated and has been removed. Please see the changelog for more details.",
				oldKey,
			),
		)
	}
}

func (d *deprecator) String() string {
	var b strings.Builder

	for _, w := range d.warns.Slice() {
		fmt.Fprintf(&b, "WARN: %s\n", w)
	}

	for _, f := range d.fatals.Slice() {
		fmt.Fprintf(&b, "FATAL: %s\n", f)
	}

	return b.String()
}

func (d *deprecator) Log() {
	if len(d.fatals) > 0 {
		log.Fatal().Msg("\n" + d.String())
	} else if len(d.warns) > 0 {
		log.Warn().Msg("\n" + d.String())
	}
}

package db

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"sync"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"go4.org/netipx"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
)

var (
	errGeneratedIPBytesInvalid = errors.New("generated ip bytes are invalid ip")
	errGeneratedIPNotInPrefix  = errors.New("generated ip not in prefix")
	errIPAllocatorNil          = errors.New("ip allocator was nil")
)

// ipAllocAdvisoryLockKey is the postgres pg_advisory_xact_lock key used
// to serialize IP claims across sibling headscale instances sharing one
// postgres. Arbitrary 64-bit constant; only the value's uniqueness within
// the cluster's advisory-lock namespace matters. Held inside the same
// tx as the node-row insert, so it auto-releases on commit/rollback.
const ipAllocAdvisoryLockKey int64 = 0x495341_4C4C4F43 // "ISALLOC"

// IPAllocator is a singleton responsible for allocating
// IP addresses for nodes and making sure the same
// address is not handed out twice. There can only be one
// and it needs to be created before any other database
// writes occur.
//
// In a multi-headscale deployment sharing one postgres, the in-memory
// usedIPs cache is intentionally bypassed by [IPAllocator.NextInTx]:
// each allocation reads live IPs from the DB inside a tx that holds
// pg_advisory_xact_lock, so two siblings can never hand out the same
// IP. The cache is kept only for the nil-DB test path and the legacy
// single-process [IPAllocator.Next] entry point.
type IPAllocator struct {
	mu sync.Mutex

	// db is retained so [IPAllocator.NextInTx] can detect the database
	// driver (postgres uses an advisory lock; sqlite is single-process
	// and skips it). May be nil in tests.
	db *HSDatabase

	prefix4 *netip.Prefix
	prefix6 *netip.Prefix

	// Previous IPs handed out (hint for sequential search; not load-bearing
	// for correctness — re-derived from DB on every NextInTx).
	prev4 netip.Addr
	prev6 netip.Addr

	// strategy used for handing out IP addresses.
	strategy types.IPAllocationStrategy

	// Set of all IPs handed out (legacy in-memory cache used by the
	// nil-DB test path and the single-process [IPAllocator.Next] entry
	// point). Authoritative across siblings is the live DB query inside
	// [IPAllocator.NextInTx].
	usedIPs netipx.IPSetBuilder
}

// NewIPAllocator returns a new IPAllocator singleton which
// can be used to hand out unique IP addresses within the
// provided IPv4 and IPv6 prefix. It needs to be created
// when headscale starts and needs to finish its read
// transaction before any writes to the database occur.
func NewIPAllocator(
	db *HSDatabase,
	prefix4, prefix6 *netip.Prefix,
	strategy types.IPAllocationStrategy,
) (*IPAllocator, error) {
	ret := IPAllocator{
		db:      db,
		prefix4: prefix4,
		prefix6: prefix6,

		strategy: strategy,
	}

	var (
		v4s []sql.NullString
		v6s []sql.NullString
	)

	if db != nil {
		err := db.Read(func(rx *gorm.DB) error {
			return rx.Model(&types.Node{}).Pluck("ipv4", &v4s).Error
		})
		if err != nil {
			return nil, fmt.Errorf("reading IPv4 addresses from database: %w", err)
		}

		err = db.Read(func(rx *gorm.DB) error {
			return rx.Model(&types.Node{}).Pluck("ipv6", &v6s).Error
		})
		if err != nil {
			return nil, fmt.Errorf("reading IPv6 addresses from database: %w", err)
		}
	}

	var ips netipx.IPSetBuilder

	// Add network and broadcast addrs to used pool so they
	// are not handed out to nodes.
	if prefix4 != nil {
		network4, broadcast4 := util.GetIPPrefixEndpoints(*prefix4)
		ips.Add(network4)
		ips.Add(broadcast4)

		// Use network as starting point, it will be used to call .Next()
		// TODO(kradalby): Could potentially take all the IPs loaded from
		// the database into account to start at a more "educated" location.
		ret.prev4 = network4
	}

	if prefix6 != nil {
		network6, broadcast6 := util.GetIPPrefixEndpoints(*prefix6)
		ips.Add(network6)
		ips.Add(broadcast6)

		ret.prev6 = network6
	}

	// Fetch all the IP Addresses currently handed out from the Database
	// and add them to the used IP set.
	for _, addrStr := range append(v4s, v6s...) {
		if addrStr.Valid {
			addr, err := netip.ParseAddr(addrStr.String)
			if err != nil {
				return nil, fmt.Errorf("parsing IP address from database: %w", err)
			}

			ips.Add(addr)
		}
	}

	// Build the initial IPSet to validate that we can use it.
	_, err := ips.IPSet()
	if err != nil {
		return nil, fmt.Errorf(
			"building initial IP Set: %w",
			err,
		)
	}

	ret.usedIPs = ips

	return &ret, nil
}

// Next allocates the next pair of IPs (IPv4, IPv6 — either may be nil
// when its prefix is unset) using the in-memory cache only. Safe to use
// in single-process contexts (sqlite, tests, BackfillNodeIPs at startup
// before the prober loop ever races); for multi-instance postgres
// deployments, callers must use [IPAllocator.NextInTx] inside the same
// tx as the node-row insert so the advisory lock prevents siblings from
// duplicate-allocating between read and save.
func (i *IPAllocator) Next() (*netip.Addr, *netip.Addr, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	var (
		err  error
		ret4 *netip.Addr
		ret6 *netip.Addr
	)

	if i.prefix4 != nil {
		ret4, err = i.next(i.prev4, i.prefix4)
		if err != nil {
			return nil, nil, fmt.Errorf("allocating IPv4 address: %w", err)
		}

		i.prev4 = *ret4
	}

	if i.prefix6 != nil {
		ret6, err = i.next(i.prev6, i.prefix6)
		if err != nil {
			return nil, nil, fmt.Errorf("allocating IPv6 address: %w", err)
		}

		i.prev6 = *ret6
	}

	return ret4, ret6, nil
}

// NextInTx is the cluster-safe IP allocator. The caller must pass an
// open transaction — typically the same tx the new node row will be
// INSERTed into — so the advisory lock taken here covers both the read
// of existing IPs and the eventual commit of the new IP. Postgres only:
// for sqlite (single-process) it falls through to the in-memory path.
//
// Without this, two sibling headscales sharing one postgres can read
// the same "next free" IP and assign it to two nodes (race window:
// from the read to the commit). Hit on the test rig in 2026-04 — both
// section1 and section2 handed out 100.65.0.1.
func (i *IPAllocator) NextInTx(tx *gorm.DB) (*netip.Addr, *netip.Addr, error) {
	// nil-DB or sqlite path: no cross-process race possible, in-memory
	// mutex is sufficient. Tests and BackfillNodeIPs go this way.
	if i.db == nil || i.db.cfg == nil || i.db.cfg.Database.Type != types.DatabasePostgres {
		return i.Next()
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	// Hold the cluster-wide advisory lock for the rest of the tx. Auto-
	// released on commit or rollback, so we never have to remember to
	// unlock — even on panic or early return.
	if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", ipAllocAdvisoryLockKey).Error; err != nil {
		return nil, nil, fmt.Errorf("acquiring ip-allocator advisory lock: %w", err)
	}

	// Re-read live IPs from the DB now that we hold the lock. Any
	// in-flight sibling allocation either already committed (and is in
	// this query) or is still waiting on the same lock (so it'll see
	// our row when we commit). Either way, no double-claim is possible.
	live, err := i.liveIPSet(tx)
	if err != nil {
		return nil, nil, fmt.Errorf("reading live IPs under lock: %w", err)
	}

	var (
		ret4 *netip.Addr
		ret6 *netip.Addr
	)
	if i.prefix4 != nil {
		ip, err := i.nextFromSet(i.prev4, i.prefix4, live)
		if err != nil {
			return nil, nil, fmt.Errorf("allocating IPv4 address: %w", err)
		}
		ret4 = ip
		i.prev4 = *ip
	}
	if i.prefix6 != nil {
		ip, err := i.nextFromSet(i.prev6, i.prefix6, live)
		if err != nil {
			return nil, nil, fmt.Errorf("allocating IPv6 address: %w", err)
		}
		ret6 = ip
		i.prev6 = *ip
	}
	return ret4, ret6, nil
}

// liveIPSet returns the set of IPs currently committed to the nodes
// table plus the prefix's network/broadcast addresses (so we never
// hand them out). Only used under advisory-lock inside NextInTx.
func (i *IPAllocator) liveIPSet(tx *gorm.DB) (*netipx.IPSet, error) {
	var (
		v4s []sql.NullString
		v6s []sql.NullString
	)
	if err := tx.Model(&types.Node{}).Pluck("ipv4", &v4s).Error; err != nil {
		return nil, fmt.Errorf("pluck ipv4: %w", err)
	}
	if err := tx.Model(&types.Node{}).Pluck("ipv6", &v6s).Error; err != nil {
		return nil, fmt.Errorf("pluck ipv6: %w", err)
	}
	var b netipx.IPSetBuilder
	if i.prefix4 != nil {
		network4, broadcast4 := util.GetIPPrefixEndpoints(*i.prefix4)
		b.Add(network4)
		b.Add(broadcast4)
	}
	if i.prefix6 != nil {
		network6, broadcast6 := util.GetIPPrefixEndpoints(*i.prefix6)
		b.Add(network6)
		b.Add(broadcast6)
	}
	for _, addrStr := range append(v4s, v6s...) {
		if !addrStr.Valid {
			continue
		}
		addr, err := netip.ParseAddr(addrStr.String)
		if err != nil {
			return nil, fmt.Errorf("parsing IP %q: %w", addrStr.String, err)
		}
		b.Add(addr)
	}
	return b.IPSet()
}

// nextFromSet is the strategy-aware "find the next free IP" loop, but
// against the live DB-backed set rather than the in-memory cache. Pulled
// out of [IPAllocator.next] so NextInTx doesn't depend on i.usedIPs at
// all — that cache can be arbitrarily stale across siblings.
func (i *IPAllocator) nextFromSet(prev netip.Addr, prefix *netip.Prefix, set *netipx.IPSet) (*netip.Addr, error) {
	var (
		ip  netip.Addr
		err error
	)
	switch i.strategy {
	case types.IPAllocationStrategySequential:
		ip = prev.Next()
	case types.IPAllocationStrategyRandom:
		ip, err = randomNext(*prefix)
		if err != nil {
			return nil, fmt.Errorf("getting random IP: %w", err)
		}
	}
	for {
		if !prefix.Contains(ip) {
			return nil, ErrCouldNotAllocateIP
		}
		if set.Contains(ip) || isTailscaleReservedIP(ip) {
			switch i.strategy {
			case types.IPAllocationStrategySequential:
				ip = ip.Next()
			case types.IPAllocationStrategyRandom:
				ip, err = randomNext(*prefix)
				if err != nil {
					return nil, fmt.Errorf("getting random IP: %w", err)
				}
			}
			continue
		}
		return &ip, nil
	}
}

var ErrCouldNotAllocateIP = errors.New("failed to allocate IP")

func (i *IPAllocator) nextLocked(prev netip.Addr, prefix *netip.Prefix) (*netip.Addr, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	return i.next(prev, prefix)
}

func (i *IPAllocator) next(prev netip.Addr, prefix *netip.Prefix) (*netip.Addr, error) {
	var (
		err error
		ip  netip.Addr
	)

	switch i.strategy {
	case types.IPAllocationStrategySequential:
		// Get the first IP in our prefix
		ip = prev.Next()
	case types.IPAllocationStrategyRandom:
		ip, err = randomNext(*prefix)
		if err != nil {
			return nil, fmt.Errorf("getting random IP: %w", err)
		}
	}

	// TODO(kradalby): maybe this can be done less often.
	set, err := i.usedIPs.IPSet()
	if err != nil {
		return nil, err
	}

	for {
		if !prefix.Contains(ip) {
			return nil, ErrCouldNotAllocateIP
		}

		// Check if the IP has already been allocated
		// or if it is a IP reserved by Tailscale.
		if set.Contains(ip) || isTailscaleReservedIP(ip) {
			switch i.strategy {
			case types.IPAllocationStrategySequential:
				ip = ip.Next()
			case types.IPAllocationStrategyRandom:
				ip, err = randomNext(*prefix)
				if err != nil {
					return nil, fmt.Errorf("getting random IP: %w", err)
				}
			}

			continue
		}

		i.usedIPs.Add(ip)

		return &ip, nil
	}
}

func randomNext(pfx netip.Prefix) (netip.Addr, error) {
	rang := netipx.RangeOfPrefix(pfx)
	fromIP, toIP := rang.From(), rang.To()

	var from, to big.Int

	from.SetBytes(fromIP.AsSlice())
	to.SetBytes(toIP.AsSlice())

	// Find the max, this is how we can do "random range",
	// get the "max" as 0 -> to - from and then add back from
	// after.
	tempMax := big.NewInt(0).Sub(&to, &from)

	out, err := rand.Int(rand.Reader, tempMax)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("generating random IP: %w", err)
	}

	valInRange := big.NewInt(0).Add(&from, out)

	ip, ok := netip.AddrFromSlice(valInRange.Bytes())
	if !ok {
		return netip.Addr{}, errGeneratedIPBytesInvalid
	}

	if !pfx.Contains(ip) {
		return netip.Addr{}, fmt.Errorf(
			"%w: ip(%s) not in prefix(%s)",
			errGeneratedIPNotInPrefix,
			ip.String(),
			pfx.String(),
		)
	}

	return ip, nil
}

func isTailscaleReservedIP(ip netip.Addr) bool {
	return tsaddr.ChromeOSVMRange().Contains(ip) ||
		tsaddr.TailscaleServiceIP() == ip ||
		tsaddr.TailscaleServiceIPv6() == ip
}

// BackfillNodeIPs will take a database transaction, and
// iterate through all of the current nodes in headscale
// and ensure it has IP addresses according to the current
// configuration.
// This means that if both IPv4 and IPv6 is set in the
// config, and some nodes are missing that type of IP,
// it will be added.
// If a prefix type has been removed (IPv4 or IPv6), it
// will remove the IPs in that family from the node.
func (db *HSDatabase) BackfillNodeIPs(i *IPAllocator) ([]string, error) {
	var (
		err error
		ret []string
	)

	err = db.Write(func(tx *gorm.DB) error {
		if i == nil {
			return fmt.Errorf("backfilling IPs: %w", errIPAllocatorNil)
		}

		log.Trace().Caller().Msgf("starting to backfill IPs")

		nodes, err := ListNodes(tx)
		if err != nil {
			return fmt.Errorf("listing nodes to backfill IPs: %w", err)
		}

		for _, node := range nodes {
			log.Trace().Caller().EmbedObject(node).Msg("ip backfill check started because node found in database")

			changed := false
			// IPv4 prefix is set, but node ip is missing, alloc
			if i.prefix4 != nil && node.IPv4 == nil {
				ret4, err := i.nextLocked(i.prev4, i.prefix4)
				if err != nil {
					return fmt.Errorf("allocating IPv4 for node(%d): %w", node.ID, err)
				}

				node.IPv4 = ret4
				changed = true

				ret = append(ret, fmt.Sprintf("assigned IPv4 %q to Node(%d) %q", ret4.String(), node.ID, node.Hostname))
			}

			// IPv6 prefix is set, but node ip is missing, alloc
			if i.prefix6 != nil && node.IPv6 == nil {
				ret6, err := i.nextLocked(i.prev6, i.prefix6)
				if err != nil {
					return fmt.Errorf("allocating IPv6 for node(%d): %w", node.ID, err)
				}

				node.IPv6 = ret6
				changed = true

				ret = append(ret, fmt.Sprintf("assigned IPv6 %q to Node(%d) %q", ret6.String(), node.ID, node.Hostname))
			}

			// IPv4 prefix is not set, but node has IP, remove
			if i.prefix4 == nil && node.IPv4 != nil {
				ret = append(ret, fmt.Sprintf("removing IPv4 %q from Node(%d) %q", node.IPv4.String(), node.ID, node.Hostname))
				node.IPv4 = nil
				changed = true
			}

			// IPv6 prefix is not set, but node has IP, remove
			if i.prefix6 == nil && node.IPv6 != nil {
				ret = append(ret, fmt.Sprintf("removing IPv6 %q from Node(%d) %q", node.IPv6.String(), node.ID, node.Hostname))
				node.IPv6 = nil
				changed = true
			}

			if changed {
				// Use Updates() with Select() to only update IP fields, avoiding overwriting
				// other fields like Expiry. We need Select() because Updates() alone skips
				// zero values, but we DO want to update IPv4/IPv6 to nil when removing them.
				// See issue #2862.
				err := tx.Model(node).Select("ipv4", "ipv6").Updates(node).Error
				if err != nil {
					return fmt.Errorf("saving node(%d) after adding IPs: %w", node.ID, err)
				}
			}
		}

		return nil
	})

	return ret, err
}

func (i *IPAllocator) FreeIPs(ips []netip.Addr) {
	i.mu.Lock()
	defer i.mu.Unlock()

	for _, ip := range ips {
		i.usedIPs.Remove(ip)
	}
}

// Copyright (c) 2015-2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	cfgldap "github.com/minio/minio/internal/config/identity/ldap"
	"github.com/minio/pkg/v3/env"
	xldap "github.com/minio/pkg/v3/ldap"
)

// Limits for LDAP logins (STS AssumeRoleWithLDAPIdentity, SFTP and FTP).
// All state is in-memory and per node.
//
//   - pair: failures of one username from one source. This is what slows
//     down a single client guessing one user's password, without affecting
//     the same user logging in from elsewhere.
//   - user: failures of one username across all sources within a fixed
//     window. A high ceiling that caps distributed guessing. It does not
//     apply to sources that recently logged in successfully as that user.
//   - source: distinct usernames failing from one source (password spraying).
//   - site: distinct usernames failing from one IPv6 /48, with a much higher
//     limit, so that rotating through /64s does not avoid the source limit
//     while one /64 cannot block its /48 neighbours.
var (
	ldapThrottlePairPolicy   = backoffPolicy{freeAttempts: 5, baseDelay: time.Second, maxDelay: 5 * time.Minute}
	ldapThrottleUserPolicy   = backoffPolicy{freeAttempts: 50, baseDelay: time.Second, maxDelay: 5 * time.Minute}
	ldapThrottleSourcePolicy = backoffPolicy{freeAttempts: 20, baseDelay: time.Second, maxDelay: 5 * time.Minute}
	ldapThrottleSitePolicy   = backoffPolicy{freeAttempts: 200, baseDelay: time.Second, maxDelay: 5 * time.Minute}
)

const (
	ldapThrottleEntryTTL       = time.Hour      // idle expiry, and the user ceiling window
	ldapThrottleKnownGoodTTL   = 24 * time.Hour // how long a successful (user, source) is remembered
	ldapThrottleOverflowShards = 64
	ldapThrottleMaxEntries     = 50000 // per table, plus overflow shards
	ldapThrottleSweepInterval  = time.Minute
	ldapThrottleEvictScan      = 64

	// ldapMaxUsernameLen bounds login usernames; longer ones are rejected
	// like invalid credentials.
	ldapMaxUsernameLen = 1024

	// EnvLDAPSTSTrustedProxies lists comma-separated CIDRs (or addresses) of
	// reverse proxies. Only for requests whose TCP peer is in this list, the
	// LDAP STS login throttle takes the client address from the right-most
	// X-Forwarded-For hop that is not itself a trusted proxy.
	EnvLDAPSTSTrustedProxies = "MINIO_IDENTITY_LDAP_STS_TRUSTED_PROXIES"
)

// globalLDAPLoginThrottle throttles LDAP logins.
var globalLDAPLoginThrottle = newLDAPLoginThrottle()

// backoffPolicy describes the exponential backoff applied to a key once it
// has used up its free attempts.
type backoffPolicy struct {
	freeAttempts int
	baseDelay    time.Duration
	maxDelay     time.Duration
}

// delay returns the time a key must wait after its n-th counted attempt.
func (p backoffPolicy) delay(attempts int) time.Duration {
	if attempts < p.freeAttempts {
		return 0
	}
	d := p.baseDelay
	for i := p.freeAttempts; i < attempts && d < p.maxDelay; i++ {
		d *= 2
	}
	return min(d, p.maxDelay)
}

// ldapThrottleKey is a fixed size key, so memory per entry does not depend
// on client supplied input.
type ldapThrottleKey [sha256.Size]byte

type throttleEntry struct {
	attempts     int
	blockedUntil time.Time
	firstSeen    time.Time
	lastSeen     time.Time
}

type throttleTable struct {
	policy backoffPolicy
	// fixedWindow expires entries ttl after their first attempt (a rate
	// ceiling); otherwise entries expire ttl after their last attempt.
	fixedWindow bool
	entries     map[ldapThrottleKey]*throttleEntry
}

func (tbl *throttleTable) expired(e *throttleEntry, now time.Time, ttl time.Duration) bool {
	if now.Before(e.blockedUntil) {
		return false
	}
	if tbl.fixedWindow {
		return now.Sub(e.firstSeen) > ttl
	}
	return now.Sub(e.lastSeen) > ttl
}

// ldapLoginThrottle keeps exponential-backoff counters of LDAP login
// attempts. An attempt is counted when it is admitted (so concurrent
// requests cannot exceed the limits) and is refunded when it turns out not
// to be a credential failure.
type ldapLoginThrottle struct {
	mu        sync.Mutex
	pairs     throttleTable
	users     throttleTable
	sources   throttleTable
	sites     throttleTable
	knownGood map[ldapThrottleKey]time.Time // (user, source) -> expiry

	ttl        time.Duration
	maxEntries int
	lastSweep  time.Time
	now        func() time.Time
	// salt keys all hashes, so that clients cannot predict which entry or
	// overflow shard a username or source maps to.
	salt [32]byte
}

func newLDAPLoginThrottle() *ldapLoginThrottle {
	t := &ldapLoginThrottle{
		pairs:      throttleTable{policy: ldapThrottlePairPolicy, entries: make(map[ldapThrottleKey]*throttleEntry)},
		users:      throttleTable{policy: ldapThrottleUserPolicy, fixedWindow: true, entries: make(map[ldapThrottleKey]*throttleEntry)},
		sources:    throttleTable{policy: ldapThrottleSourcePolicy, entries: make(map[ldapThrottleKey]*throttleEntry)},
		sites:      throttleTable{policy: ldapThrottleSitePolicy, entries: make(map[ldapThrottleKey]*throttleEntry)},
		knownGood:  make(map[ldapThrottleKey]time.Time),
		ttl:        ldapThrottleEntryTTL,
		maxEntries: ldapThrottleMaxEntries,
		now:        time.Now,
	}
	// crypto/rand.Read does not fail on supported platforms.
	_, _ = rand.Read(t.salt[:])
	return t
}

func (t *ldapLoginThrottle) tables() []*throttleTable {
	return []*throttleTable{&t.pairs, &t.users, &t.sources, &t.sites}
}

// ldapThrottleShard returns the overflow shard of a (salted) key.
func ldapThrottleShard(k ldapThrottleKey) int {
	return int(k[0]) % ldapThrottleOverflowShards
}

// key returns the salted, fixed size key of s.
func (t *ldapLoginThrottle) key(s string) (k ldapThrottleKey) {
	h := sha256.New()
	h.Write(t.salt[:])
	h.Write([]byte(s))
	h.Sum(k[:0])
	return k
}

// ldapThrottleSource identifies the source of a login for throttling.
type ldapThrottleSource struct {
	net  string // IPv4 address or IPv6 /64
	site string // IPv6 /48, empty for IPv4
}

// ldapThrottleSourceOfAddr returns the throttling source of a client
// address ("host:port" or "host"). IPv6 clients are grouped by /64, the
// usual size of a single subscriber network, and additionally by /48, the
// usual size of a site allocation.
func ldapThrottleSourceOfAddr(hostport string) ldapThrottleSource {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return ldapThrottleSource{net: "invalid"}
	}
	addr = addr.WithZone("").Unmap()
	if !addr.Is6() {
		return ldapThrottleSource{net: addr.String()}
	}
	p64, _ := addr.Prefix(64)
	p48, _ := addr.Prefix(48)
	return ldapThrottleSource{net: p64.String(), site: p48.String()}
}

// ldapThrottleSourceOf returns the throttling source of an HTTP request: the
// TCP peer address, or, when the peer is a configured trusted proxy, the
// client address it forwarded.
func ldapThrottleSourceOf(r *http.Request) ldapThrottleSource {
	return ldapThrottleSourceOfAddr(ldapClientAddr(r, ldapTrustedProxies()))
}

// ldapTrustedProxies returns the trusted proxies configured with
// EnvLDAPSTSTrustedProxies (none by default).
var ldapTrustedProxies = sync.OnceValue(func() []netip.Prefix {
	proxies, err := parseLDAPTrustedProxies(env.Get(EnvLDAPSTSTrustedProxies, ""))
	if err != nil {
		stsLogIf(GlobalContext, fmt.Errorf("invalid %s: %w", EnvLDAPSTSTrustedProxies, err))
	}
	return proxies
})

// parseLDAPTrustedProxies parses comma-separated CIDRs or addresses. Invalid
// entries are reported and skipped.
func parseLDAPTrustedProxies(s string) (proxies []netip.Prefix, err error) {
	var errs []error
	for v := range strings.SplitSeq(s, ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if p, perr := netip.ParsePrefix(v); perr == nil {
			proxies = append(proxies, p.Masked())
			continue
		}
		if a, perr := netip.ParseAddr(v); perr == nil {
			a = a.Unmap()
			proxies = append(proxies, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		errs = append(errs, fmt.Errorf("%q is not a CIDR or IP address", v))
	}
	return proxies, errors.Join(errs...)
}

func ldapIsTrustedProxy(addr netip.Addr, trusted []netip.Prefix) bool {
	addr = addr.WithZone("").Unmap()
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ldapClientAddr returns the client address of r for throttling. Forwarding
// headers are only honoured when the TCP peer is a trusted proxy; then the
// right-most X-Forwarded-For hop that is not itself a trusted proxy is used.
// If no such hop exists or a hop cannot be parsed, the peer address is used.
func ldapClientAddr(r *http.Request, trusted []netip.Prefix) string {
	if len(trusted) == 0 {
		return r.RemoteAddr
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !ldapIsTrustedProxy(peer, trusted) {
		return r.RemoteAddr
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		addr, err := netip.ParseAddr(hop)
		if err != nil {
			ap, perr := netip.ParseAddrPort(hop)
			if perr != nil {
				return r.RemoteAddr
			}
			addr = ap.Addr()
		}
		if !ldapIsTrustedProxy(addr, trusted) {
			return addr.WithZone("").Unmap().String()
		}
	}
	return r.RemoteAddr
}

// ldapThrottleOverflowKeys are the shared counters of a table used for new
// keys while the table is full and no entry may be evicted. Keys are spread
// over the shards by their salted hash, so a flood cannot funnel every
// untracked key into a single counter.
var ldapThrottleOverflowKeys = func() (keys [ldapThrottleOverflowShards]ldapThrottleKey) {
	for i := range keys {
		keys[i] = sha256.Sum256([]byte{'o', 'v', 'e', 'r', 'f', 'l', 'o', 'w', byte(i)})
	}
	return keys
}()

// ldapAttempt is an admitted login attempt.
type ldapAttempt struct {
	t            *ldapLoginThrottle
	pair         ldapThrottleKey
	user         ldapThrottleKey
	source       ldapThrottleKey
	site         ldapThrottleKey
	good         ldapThrottleKey
	hasUser      bool
	hasSite      bool
	newPair      bool
	pairOverflow bool
}

// acquire admits a login attempt for username from source, or returns nil if
// the attempt is throttled (or the username is too long). The attempt is
// counted as a failure until succeeded or notCredentialFailure is called.
func (t *ldapLoginThrottle) acquire(username string, source ldapThrottleSource) *ldapAttempt {
	if len(username) > ldapMaxUsernameLen {
		return nil
	}
	username = strings.ToLower(strings.TrimSpace(username))

	// Hash outside the lock.
	pairK := t.key("pair\x00" + username + "\x00" + source.net)
	userK := t.key("user\x00" + username)
	sourceK := t.key("source\x00" + source.net)
	var siteK ldapThrottleKey
	if source.site != "" {
		siteK = t.key("site\x00" + source.site)
	}
	a := &ldapAttempt{t: t, good: t.key("good\x00" + username + "\x00" + source.net), hasSite: source.site != ""}

	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	if now.Sub(t.lastSweep) > ldapThrottleSweepInterval {
		for _, tbl := range t.tables() {
			for k, e := range tbl.entries {
				if tbl.expired(e, now, t.ttl) {
					delete(tbl.entries, k)
				}
			}
		}
		for k, exp := range t.knownGood {
			if !now.Before(exp) {
				delete(t.knownGood, k)
			}
		}
		t.lastSweep = now
	}

	// A source that recently logged in as this user is not subject to the
	// per-user ceiling or the spraying limits for this user, so that
	// attacks from elsewhere cannot lock it out.
	exp, known := t.knownGood[a.good]
	known = known && now.Before(exp)

	a.pair, a.pairOverflow = t.slot(&t.pairs, pairK, now)
	// When the users table is full, untracked users are not subject to the
	// per-user ceiling (pair and source limits still apply), so that a
	// flood of usernames cannot block legitimate users.
	var userOverflow bool
	a.user, userOverflow = t.slot(&t.users, userK, now)
	a.hasUser = !userOverflow
	a.source, _ = t.slot(&t.sources, sourceK, now)
	if a.hasSite {
		a.site, _ = t.slot(&t.sites, siteK, now)
	}

	if t.blocked(&t.pairs, a.pair, now) {
		return nil
	}
	if !known && ((a.hasUser && t.blocked(&t.users, a.user, now)) ||
		t.blocked(&t.sources, a.source, now) || (a.hasSite && t.blocked(&t.sites, a.site, now))) {
		return nil
	}
	// Sources count distinct usernames, not repeated attempts. Pairs that
	// could not be tracked count every attempt.
	a.newPair = t.count(&t.pairs, a.pair, now) || a.pairOverflow
	if a.hasUser {
		t.count(&t.users, a.user, now)
	}
	if a.newPair {
		t.count(&t.sources, a.source, now)
		if a.hasSite {
			t.count(&t.sites, a.site, now)
		}
	}
	return a
}

// succeeded clears the backoff of the (username, source) pair, refunds the
// attempt to the per-user and per-source counters and remembers the pair as
// known good. It does not reset the per-user ceiling.
func (a *ldapAttempt) succeeded() {
	a.t.mu.Lock()
	defer a.t.mu.Unlock()
	if a.pairOverflow {
		// Never clear a shared overflow counter.
		a.t.refund(&a.t.pairs, a.pair)
	} else {
		delete(a.t.pairs.entries, a.pair)
	}
	a.refundUserAndSources()

	now := a.t.now()
	if _, ok := a.t.knownGood[a.good]; !ok && len(a.t.knownGood) >= a.t.maxEntries {
		a.t.evictKnownGood(now)
	}
	a.t.knownGood[a.good] = now.Add(ldapThrottleKnownGoodTTL)
}

// notCredentialFailure refunds the attempt, e.g. when the LDAP server could
// not be reached.
func (a *ldapAttempt) notCredentialFailure() {
	a.t.mu.Lock()
	defer a.t.mu.Unlock()
	a.t.refund(&a.t.pairs, a.pair)
	a.refundUserAndSources()
}

func (a *ldapAttempt) refundUserAndSources() {
	if a.hasUser {
		a.t.refund(&a.t.users, a.user)
	}
	if !a.newPair {
		return
	}
	a.t.refund(&a.t.sources, a.source)
	if a.hasSite {
		a.t.refund(&a.t.sites, a.site)
	}
}

// evictKnownGood removes the entry expiring first among a bounded sample.
func (t *ldapLoginThrottle) evictKnownGood(now time.Time) {
	var victim ldapThrottleKey
	var victimExp time.Time
	n := 0
	for k, exp := range t.knownGood {
		if !now.Before(exp) {
			delete(t.knownGood, k)
			return
		}
		if n == 0 || exp.Before(victimExp) {
			victim, victimExp = k, exp
		}
		n++
		if n >= ldapThrottleEvictScan {
			break
		}
	}
	if n > 0 {
		delete(t.knownGood, victim)
	}
}

func (t *ldapLoginThrottle) refund(tbl *throttleTable, key ldapThrottleKey) {
	e, ok := tbl.entries[key]
	if !ok || e.attempts == 0 {
		return
	}
	e.attempts--
	if e.attempts == 0 {
		delete(tbl.entries, key)
		return
	}
	if tbl.policy.delay(e.attempts) == 0 {
		e.blockedUntil = time.Time{}
	}
}

func (t *ldapLoginThrottle) blocked(tbl *throttleTable, key ldapThrottleKey, now time.Time) bool {
	e, ok := tbl.entries[key]
	if !ok {
		return false
	}
	if tbl.expired(e, now, t.ttl) {
		delete(tbl.entries, key)
		return false
	}
	return now.Before(e.blockedUntil)
}

// count records an attempt for key and reports whether a new entry was
// created.
func (t *ldapLoginThrottle) count(tbl *throttleTable, key ldapThrottleKey, now time.Time) bool {
	e, ok := tbl.entries[key]
	if !ok {
		e = &throttleEntry{firstSeen: now}
		tbl.entries[key] = e
	}
	e.attempts++
	e.lastSeen = now
	if d := tbl.policy.delay(e.attempts); d > 0 {
		e.blockedUntil = now.Add(d)
	}
	return !ok
}

// slot returns the key under which an attempt for key is tracked. When the
// table is full it frees room by evicting an expired or failure-free entry
// from a bounded sample. Entries holding failures are never evicted, since
// that would let a flood of new keys reset them; if none can be evicted the
// attempt is tracked under one of the table's shared overflow counters
// (chosen by the key's hash), which limit untracked keys together until
// room frees up. It reports whether an overflow counter was chosen.
func (t *ldapLoginThrottle) slot(tbl *throttleTable, key ldapThrottleKey, now time.Time) (ldapThrottleKey, bool) {
	if _, ok := tbl.entries[key]; ok || len(tbl.entries) < t.maxEntries {
		return key, false
	}
	n := 0
	for k, e := range tbl.entries {
		if tbl.expired(e, now, t.ttl) || e.attempts == 0 {
			delete(tbl.entries, k)
			return key, false
		}
		n++
		if n >= ldapThrottleEvictScan {
			break
		}
	}
	return ldapThrottleOverflowKeys[ldapThrottleShard(key)], true
}

// errLDAPLoginThrottled is returned for throttled LDAP logins. It wraps
// cfgldap.ErrInvalidCredentials so that callers respond exactly as for
// invalid credentials.
var errLDAPLoginThrottled = fmt.Errorf("%w: LDAP login attempt throttled", cfgldap.ErrInvalidCredentials)

// ldapBindFn authenticates LDAP users; it is a variable so that tests can
// run without an LDAP server.
var ldapBindFn = func(username, password string) (*xldap.DNSearchResult, []string, error) {
	return globalIAMSys.LDAPConfig.Bind(username, password)
}

// ldapThrottledBind authenticates an LDAP login subject to
// globalLDAPLoginThrottle. Throttled attempts and invalid credentials
// return errors wrapping cfgldap.ErrInvalidCredentials; other errors are
// LDAP server problems and are not counted against the client. On success
// the caller must call succeeded on the returned attempt once the login is
// accepted.
func ldapThrottledBind(username, password string, source ldapThrottleSource) (*xldap.DNSearchResult, []string, *ldapAttempt, error) {
	if len(username) > ldapMaxUsernameLen {
		return nil, nil, nil, fmt.Errorf("%w (username longer than %d bytes)", errLDAPLoginThrottled, ldapMaxUsernameLen)
	}
	attempt := globalLDAPLoginThrottle.acquire(username, source)
	if attempt == nil {
		return nil, nil, nil, fmt.Errorf("%w for %q from %s", errLDAPLoginThrottled, username, source.net)
	}
	lookupResult, groups, err := ldapBindFn(username, password)
	if err != nil {
		if !errors.Is(err, cfgldap.ErrInvalidCredentials) {
			attempt.notCredentialFailure()
		}
		return nil, nil, nil, err
	}
	return lookupResult, groups, attempt, nil
}

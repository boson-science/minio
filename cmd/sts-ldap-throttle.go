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
	"crypto/sha256"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Limits for AssumeRoleWithLDAPIdentity attempts. All state is in-memory and
// per node.
//
//   - pair: failures of one username from one source. This is what slows
//     down a single client guessing one user's password, without affecting
//     the same user logging in from elsewhere.
//   - user: failures of one username across all sources within a fixed
//     window. A high ceiling that caps distributed guessing.
//   - source: distinct usernames failing from one source (password spraying).
var (
	ldapThrottlePairPolicy   = backoffPolicy{freeAttempts: 5, baseDelay: time.Second, maxDelay: 5 * time.Minute}
	ldapThrottleUserPolicy   = backoffPolicy{freeAttempts: 50, baseDelay: time.Second, maxDelay: 5 * time.Minute}
	ldapThrottleSourcePolicy = backoffPolicy{freeAttempts: 20, baseDelay: time.Second, maxDelay: 5 * time.Minute}
)

const (
	ldapThrottleEntryTTL      = time.Hour // idle expiry, and the user ceiling window
	ldapThrottleMaxEntries    = 50000     // per table
	ldapThrottleSweepInterval = time.Minute
	ldapThrottleEvictScan     = 64
)

// globalLDAPLoginThrottle throttles LDAP STS logins.
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
	mu         sync.Mutex
	pairs      throttleTable
	users      throttleTable
	sources    throttleTable
	ttl        time.Duration
	maxEntries int
	lastSweep  time.Time
	now        func() time.Time
}

func newLDAPLoginThrottle() *ldapLoginThrottle {
	return &ldapLoginThrottle{
		pairs:      throttleTable{policy: ldapThrottlePairPolicy, entries: make(map[ldapThrottleKey]*throttleEntry)},
		users:      throttleTable{policy: ldapThrottleUserPolicy, fixedWindow: true, entries: make(map[ldapThrottleKey]*throttleEntry)},
		sources:    throttleTable{policy: ldapThrottleSourcePolicy, entries: make(map[ldapThrottleKey]*throttleEntry)},
		ttl:        ldapThrottleEntryTTL,
		maxEntries: ldapThrottleMaxEntries,
		now:        time.Now,
	}
}

// ldapThrottleSource identifies the source of a request for throttling. It
// uses the TCP peer address, which unlike forwarding headers cannot be
// chosen by the client.
type ldapThrottleSource struct {
	pair  string // source for the (username, source) backoff
	spray string // source for the distinct-username (spraying) limit
}

// ldapThrottleSourceOf returns the throttling sources of a request. IPv6
// peers are grouped by /64 for the (username, source) backoff, the usual
// size of a single subscriber network, so that neighbours are not blocked
// for someone else's guesses, and by /48, the usual size of a site
// allocation, for the spraying limit, so that rotating through /64s of one
// allocation does not avoid it.
func ldapThrottleSourceOf(r *http.Request) ldapThrottleSource {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return ldapThrottleSource{pair: "invalid", spray: "invalid"}
	}
	addr = addr.WithZone("").Unmap()
	if !addr.Is6() {
		return ldapThrottleSource{pair: addr.String(), spray: addr.String()}
	}
	p64, _ := addr.Prefix(64)
	p48, _ := addr.Prefix(48)
	return ldapThrottleSource{pair: p64.String(), spray: p48.String()}
}

// ldapThrottleOverflowKey is the shared counter of a table used for new keys
// while the table is full and no entry may be evicted.
var ldapThrottleOverflowKey = ldapThrottleKey(sha256.Sum256([]byte("overflow")))

// ldapAttempt is an admitted login attempt.
type ldapAttempt struct {
	t            *ldapLoginThrottle
	pair         ldapThrottleKey
	user         ldapThrottleKey
	source       ldapThrottleKey
	newPair      bool
	pairOverflow bool
}

// acquire admits a login attempt for username from source, or returns nil if
// the attempt is throttled. The attempt is counted as a failure until
// succeeded or notCredentialFailure is called.
func (t *ldapLoginThrottle) acquire(username string, source ldapThrottleSource) *ldapAttempt {
	username = strings.ToLower(strings.TrimSpace(username))

	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	if now.Sub(t.lastSweep) > ldapThrottleSweepInterval {
		for _, tbl := range []*throttleTable{&t.pairs, &t.users, &t.sources} {
			for k, e := range tbl.entries {
				if tbl.expired(e, now, t.ttl) {
					delete(tbl.entries, k)
				}
			}
		}
		t.lastSweep = now
	}

	a := &ldapAttempt{
		t:      t,
		pair:   t.slot(&t.pairs, sha256.Sum256([]byte("pair\x00"+username+"\x00"+source.pair)), now),
		user:   t.slot(&t.users, sha256.Sum256([]byte("user\x00"+username)), now),
		source: t.slot(&t.sources, sha256.Sum256([]byte("source\x00"+source.spray)), now),
	}
	a.pairOverflow = a.pair == ldapThrottleOverflowKey

	if t.blocked(&t.pairs, a.pair, now) || t.blocked(&t.users, a.user, now) || t.blocked(&t.sources, a.source, now) {
		return nil
	}
	// The source counts distinct usernames, not repeated attempts. Pairs
	// that could not be tracked count every attempt.
	a.newPair = t.count(&t.pairs, a.pair, now) || a.pairOverflow
	t.count(&t.users, a.user, now)
	if a.newPair {
		t.count(&t.sources, a.source, now)
	}
	return a
}

// succeeded clears the backoff of the (username, source) pair and refunds
// the attempt to the per-user and per-source counters. It does not reset
// the per-user ceiling.
func (a *ldapAttempt) succeeded() {
	a.t.mu.Lock()
	defer a.t.mu.Unlock()
	if a.pairOverflow {
		// Never clear the shared overflow counter.
		a.t.refund(&a.t.pairs, a.pair)
	} else {
		delete(a.t.pairs.entries, a.pair)
	}
	a.t.refund(&a.t.users, a.user)
	if a.newPair {
		a.t.refund(&a.t.sources, a.source)
	}
}

// notCredentialFailure refunds the attempt, e.g. when the LDAP server could
// not be reached.
func (a *ldapAttempt) notCredentialFailure() {
	a.t.mu.Lock()
	defer a.t.mu.Unlock()
	a.t.refund(&a.t.pairs, a.pair)
	a.t.refund(&a.t.users, a.user)
	if a.newPair {
		a.t.refund(&a.t.sources, a.source)
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
// attempt is tracked under the table's shared overflow counter, which
// limits all such untracked keys together until room frees up.
func (t *ldapLoginThrottle) slot(tbl *throttleTable, key ldapThrottleKey, now time.Time) ldapThrottleKey {
	if _, ok := tbl.entries[key]; ok || len(tbl.entries) < t.maxEntries {
		return key
	}
	n := 0
	for k, e := range tbl.entries {
		if k != ldapThrottleOverflowKey && (tbl.expired(e, now, t.ttl) || e.attempts == 0) {
			delete(tbl.entries, k)
			return key
		}
		n++
		if n >= ldapThrottleEvictScan {
			break
		}
	}
	return ldapThrottleOverflowKey
}

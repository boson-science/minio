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
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Defaults for throttling AssumeRoleWithLDAPIdentity attempts. Limits are
// in-memory and per node.
const (
	ldapThrottleUserFreeAttempts = 5
	ldapThrottleIPFreeAttempts   = 20
	ldapThrottleBaseDelay        = time.Second
	ldapThrottleMaxDelay         = 5 * time.Minute
	ldapThrottleEntryTTL         = time.Hour
	ldapThrottleMaxEntries       = 50000 // per table
	ldapThrottleSweepInterval    = time.Minute
	ldapThrottleEvictScan        = 64
)

// globalLDAPLoginThrottle throttles LDAP STS logins per username and per
// source IP.
var globalLDAPLoginThrottle = newLDAPLoginThrottle()

// backoffPolicy describes the exponential backoff applied to a key once it
// has used up its free attempts.
type backoffPolicy struct {
	freeAttempts int
	baseDelay    time.Duration
	maxDelay     time.Duration
}

// delay returns the time a key must wait after its n-th unsuccessful attempt.
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

type throttleEntry struct {
	attempts     int
	blockedUntil time.Time
	lastSeen     time.Time
}

func (e *throttleEntry) expired(now time.Time, ttl time.Duration) bool {
	return !now.Before(e.blockedUntil) && now.Sub(e.lastSeen) > ttl
}

type throttleTable struct {
	policy  backoffPolicy
	entries map[string]*throttleEntry
}

// ldapLoginThrottle keeps exponential-backoff counters of unsuccessful LDAP
// login attempts per normalized username and per source IP. An attempt is
// counted when it is admitted and is forgiven only on a successful login, so
// concurrent requests cannot exceed the free attempts. Memory is bounded by
// expiring idle entries and capping the number of entries per table.
type ldapLoginThrottle struct {
	mu         sync.Mutex
	users      throttleTable
	ips        throttleTable
	ttl        time.Duration
	maxEntries int
	lastSweep  time.Time
	now        func() time.Time
}

func newLDAPLoginThrottle() *ldapLoginThrottle {
	return &ldapLoginThrottle{
		users: throttleTable{
			policy:  backoffPolicy{ldapThrottleUserFreeAttempts, ldapThrottleBaseDelay, ldapThrottleMaxDelay},
			entries: make(map[string]*throttleEntry),
		},
		ips: throttleTable{
			policy:  backoffPolicy{ldapThrottleIPFreeAttempts, ldapThrottleBaseDelay, ldapThrottleMaxDelay},
			entries: make(map[string]*throttleEntry),
		},
		ttl:        ldapThrottleEntryTTL,
		maxEntries: ldapThrottleMaxEntries,
		now:        time.Now,
	}
}

// ldapThrottleUserKey normalizes a login username into a fixed size key.
func ldapThrottleUserKey(username string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(username))))
	return string(sum[:])
}

// ldapThrottleIPKey normalizes a source IP. IPv6 addresses are grouped by
// their /64 prefix, which is what a single client usually controls.
func ldapThrottleIPKey(ip string) string {
	addr, err := netip.ParseAddr(strings.Trim(ip, "[]"))
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is6() {
		if p, err := addr.WithZone("").Prefix(64); err == nil {
			return p.String()
		}
	}
	return addr.String()
}

// acquire reports whether a login attempt for the given keys may proceed. An
// admitted attempt is counted against both keys until release is called.
func (t *ldapLoginThrottle) acquire(userKey, ipKey string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	if now.Sub(t.lastSweep) > ldapThrottleSweepInterval {
		t.sweep(&t.users, now)
		t.sweep(&t.ips, now)
		t.lastSweep = now
	}

	if t.blocked(&t.users, userKey, now) || t.blocked(&t.ips, ipKey, now) {
		return false
	}
	t.count(&t.users, userKey, now)
	t.count(&t.ips, ipKey, now)
	return true
}

// release forgives the attempt admitted by acquire after a successful
// login: the user's counter is reset and the attempt is refunded to the IP.
func (t *ldapLoginThrottle) release(userKey, ipKey string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.users.entries, userKey)
	if e, ok := t.ips.entries[ipKey]; ok && e.attempts > 0 {
		e.attempts--
	}
}

func (t *ldapLoginThrottle) blocked(tbl *throttleTable, key string, now time.Time) bool {
	e, ok := tbl.entries[key]
	if !ok {
		return false
	}
	if e.expired(now, t.ttl) {
		delete(tbl.entries, key)
		return false
	}
	return now.Before(e.blockedUntil)
}

func (t *ldapLoginThrottle) count(tbl *throttleTable, key string, now time.Time) {
	e, ok := tbl.entries[key]
	if !ok {
		if len(tbl.entries) >= t.maxEntries {
			t.sweep(tbl, now)
			if len(tbl.entries) >= t.maxEntries {
				t.evictOne(tbl)
			}
		}
		e = &throttleEntry{}
		tbl.entries[key] = e
	}
	e.attempts++
	e.lastSeen = now
	if d := tbl.policy.delay(e.attempts); d > 0 {
		e.blockedUntil = now.Add(d)
	}
}

func (t *ldapLoginThrottle) sweep(tbl *throttleTable, now time.Time) {
	for k, e := range tbl.entries {
		if e.expired(now, t.ttl) {
			delete(tbl.entries, k)
		}
	}
}

// evictOne removes the entry whose block ends first among a bounded random
// sample of entries, preferring entries that are not currently blocked.
func (t *ldapLoginThrottle) evictOne(tbl *throttleTable) {
	var victim string
	var victimUntil time.Time
	n := 0
	for k, e := range tbl.entries {
		if n == 0 || e.blockedUntil.Before(victimUntil) {
			victim, victimUntil = k, e.blockedUntil
		}
		n++
		if n >= ldapThrottleEvictScan {
			break
		}
	}
	if n > 0 {
		delete(tbl.entries, victim)
	}
}

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
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cfgldap "github.com/minio/minio/internal/config/identity/ldap"
	xldap "github.com/minio/pkg/v3/ldap"
)

// resetForTest clears all counters and installs the given clock.
func (t *ldapLoginThrottle) resetForTest(now func() time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.users.entries = make(map[string]*throttleEntry)
	t.ips.entries = make(map[string]*throttleEntry)
	t.lastSweep = time.Time{}
	t.now = now
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeClock) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

func TestLDAPThrottleBackoffGrowth(t *testing.T) {
	p := backoffPolicy{freeAttempts: 3, baseDelay: time.Second, maxDelay: 10 * time.Second}
	want := []time.Duration{0, 0, 0, 1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second, 10 * time.Second}
	for i, w := range want {
		if got := p.delay(i); got != w {
			t.Errorf("delay(%d) = %v, want %v", i, got, w)
		}
	}
	if got := p.delay(1000); got != p.maxDelay {
		t.Errorf("delay(1000) = %v, want cap %v", got, p.maxDelay)
	}
}

func TestLDAPThrottleAcquire(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	th := newLDAPLoginThrottle()
	th.resetForTest(clk.now)
	u, ip := ldapThrottleUserKey("alice"), ldapThrottleIPKey("10.0.0.1")

	for i := range ldapThrottleUserFreeAttempts {
		if !th.acquire(u, ip) {
			t.Fatalf("attempt %d should be admitted", i+1)
		}
	}
	if th.acquire(u, ip) {
		t.Fatal("attempt after free attempts should be throttled")
	}
	// Username normalization: case and surrounding space do not matter.
	if th.acquire(ldapThrottleUserKey("  ALICE "), ldapThrottleIPKey("10.0.0.2")) {
		t.Fatal("normalized username should share the counter")
	}

	// Backoff grows: after the first window one more attempt is admitted,
	// then the next window is twice as long.
	clk.advance(ldapThrottleBaseDelay)
	if !th.acquire(u, ip) {
		t.Fatal("attempt after first backoff window should be admitted")
	}
	clk.advance(ldapThrottleBaseDelay)
	if th.acquire(u, ip) {
		t.Fatal("second backoff window should be longer than the first")
	}
	clk.advance(ldapThrottleBaseDelay)
	if !th.acquire(u, ip) {
		t.Fatal("attempt after second backoff window should be admitted")
	}

	// Success resets the user counter.
	th.release(u, ip)
	for i := range ldapThrottleUserFreeAttempts - 1 {
		if !th.acquire(u, ldapThrottleIPKey("10.0.0.3")) {
			t.Fatalf("attempt %d after reset should be admitted", i+1)
		}
	}
}

func TestLDAPThrottleIPKey(t *testing.T) {
	testCases := map[string]string{
		"10.1.2.3":                "10.1.2.3",
		"[2001:db8:1:2:3:4:5:6]":  "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1":    "2001:db8:1:2::/64",
		"::ffff:192.0.2.1":        "192.0.2.1",
		"not-an-ip":               "not-an-ip",
		"fe80::1%eth0":            "fe80::/64",
		"2001:db8:1:3:3:4:5:6":    "2001:db8:1:3::/64",
		"[::ffff:198.51.100.200]": "198.51.100.200",
	}
	for in, want := range testCases {
		if got := ldapThrottleIPKey(in); got != want {
			t.Errorf("ldapThrottleIPKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLDAPThrottleExpiryAndMemoryBound(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	th := newLDAPLoginThrottle()
	th.resetForTest(clk.now)
	th.maxEntries = 10

	// Expiry: idle entries are dropped once their block is over and the
	// TTL has passed.
	for i := range 5 {
		th.acquire(ldapThrottleUserKey(fmt.Sprint("u", i)), "ip-a")
	}
	clk.advance(ldapThrottleEntryTTL + time.Second)
	th.acquire(ldapThrottleUserKey("fresh"), "ip-b")
	if n := len(th.users.entries); n != 1 {
		t.Fatalf("expected expired user entries to be swept, have %d", n)
	}
	if _, ok := th.ips.entries["ip-a"]; ok {
		t.Fatal("expected expired IP entry to be swept")
	}

	// Memory bound: the number of entries never exceeds maxEntries.
	for i := range 1000 {
		th.acquire(ldapThrottleUserKey(fmt.Sprint("spray", i)), fmt.Sprint("ip-", i))
		if len(th.users.entries) > th.maxEntries || len(th.ips.entries) > th.maxEntries {
			t.Fatalf("throttle exceeded its bound: users=%d ips=%d", len(th.users.entries), len(th.ips.entries))
		}
	}

	// Eviction prefers entries that are not blocked: a blocked user survives
	// a flood of single attempts from other usernames.
	th.resetForTest(clk.now)
	th.maxEntries = 10
	victim := ldapThrottleUserKey("victim")
	for range ldapThrottleUserFreeAttempts {
		th.acquire(victim, "ip-v")
	}
	for i := range 100 {
		th.acquire(ldapThrottleUserKey(fmt.Sprint("flood", i)), fmt.Sprint("ip-f", i))
	}
	if th.acquire(victim, "ip-other") {
		t.Fatal("blocked user must not be evicted in favour of unblocked entries")
	}
}

// ldapSTSResult is the observable outcome of an LDAP STS request.
type ldapSTSResult struct {
	status int
	code   string
	msg    string
	body   string
}

func (s *TestSuiteIAM) ldapSTSRequest(c *check, user, pass, ip string, formBody bool) ldapSTSResult {
	v := url.Values{}
	v.Set("Action", ldapIdentity)
	v.Set("Version", stsAPIVersion)
	v.Set("LDAPUsername", user)
	v.Set("LDAPPassword", pass)
	v.Set("DurationSeconds", "3600")

	var req *http.Request
	var err error
	if formBody {
		req, err = http.NewRequest(http.MethodPost, s.endPoint+"/", strings.NewReader(v.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		req, err = http.NewRequest(http.MethodPost, s.endPoint+"/?"+v.Encode(), nil)
	}
	if err != nil {
		c.Fatalf("request error: %v", err)
	}
	req.Header.Set("X-Real-IP", ip)
	resp, err := s.TestSuiteCommon.client.Do(req)
	if err != nil {
		c.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	res := ldapSTSResult{status: resp.StatusCode, body: string(b)}
	if resp.StatusCode != http.StatusOK {
		var e STSErrorResponse
		if err := xml.Unmarshal(b, &e); err != nil {
			c.Fatalf("unable to parse STS error %q: %v", b, err)
		}
		res.code, res.msg = e.Error.Code, e.Error.Message
	}
	return res
}

func TestLDAPSTSUniformErrorsAndThrottle(t *testing.T) {
	suite := newTestSuiteIAM(TestSuiteCommon{serverType: "ErasureSD", signer: signerV4}, false)
	c := &check{t, suite.serverType}
	suite.SetUpSuite(c)
	defer suite.TearDownSuite(c)

	const (
		aliceDN = "uid=alice,ou=people,dc=min,dc=io"
		bobDN   = "uid=bob,ou=people,dc=min,dc=io"
		goodPW  = "correct-horse"
	)
	var bindCalls atomic.Int64
	oldBind := ldapBindFn
	defer func() { ldapBindFn = oldBind }()
	// Fake directory that fails the way cfgldap.Config.Bind does.
	ldapBindFn = func(username, password string) (*xldap.DNSearchResult, []string, error) {
		bindCalls.Add(1)
		var dn string
		switch username {
		case "alice":
			dn = aliceDN
		case "bob":
			dn = bobDN
		default:
			return nil, nil, fmt.Errorf("%w: unable to find user DN: User DN not found for: %s", cfgldap.ErrInvalidCredentials, username)
		}
		if password != goodPW {
			return nil, nil, fmt.Errorf("%w: LDAP auth failed for DN %s: LDAP Result Code 49 \"Invalid Credentials\": 80090308: LdapErr: DSID-0C09044E, data 52e", cfgldap.ErrInvalidCredentials, dn)
		}
		return &xldap.DNSearchResult{NormDN: dn, ActualDN: dn}, []string{"cn=projecta,ou=groups,dc=min,dc=io"}, nil
	}

	ctx := context.Background()
	if _, err := globalIAMSys.PolicyDBSet(ctx, aliceDN, "readwrite", stsUser, false); err != nil {
		c.Fatalf("unable to map policy: %v", err)
	}

	clk := &fakeClock{t: time.Now()}
	defer globalLDAPLoginThrottle.resetForTest(time.Now)
	reset := func() { globalLDAPLoginThrottle.resetForTest(clk.now) }

	assertDenied := func(name string, got, want ldapSTSResult) {
		c.Helper()
		if got.status != want.status || got.code != want.code || got.msg != want.msg {
			c.Fatalf("%s: response differs: got %d/%s/%q, want %d/%s/%q", name, got.status, got.code, got.msg, want.status, want.code, want.msg)
		}
		for _, leak := range []string{"uid=", "dc=min", "alice", "bob", "nobody", "DN", "LDAP", "52e", "projecta"} {
			if strings.Contains(got.body, leak) {
				c.Fatalf("%s: response leaks %q: %s", name, leak, got.body)
			}
		}
	}
	generic := ldapSTSResult{
		status: http.StatusForbidden,
		code:   stsErrCodes[ErrSTSAccessDenied].Code,
		msg:    stsErrCodes[ErrSTSAccessDenied].Description,
	}

	// 1. Unknown user, wrong password and missing policy are indistinguishable.
	reset()
	for _, formBody := range []bool{false, true} {
		assertDenied("unknown user", suite.ldapSTSRequest(c, "nobody", "x", "192.0.2.1", formBody), generic)
		assertDenied("wrong password", suite.ldapSTSRequest(c, "alice", "x", "192.0.2.2", formBody), generic)
		assertDenied("no policy", suite.ldapSTSRequest(c, "bob", goodPW, "192.0.2.3", formBody), generic)
	}

	// 2. After the free failures the user is throttled even with the correct
	// password and from another IP, without contacting LDAP.
	reset()
	for range ldapThrottleUserFreeAttempts {
		assertDenied("failure", suite.ldapSTSRequest(c, "alice", "x", "198.51.100.1", false), generic)
	}
	calls := bindCalls.Load()
	assertDenied("throttled user", suite.ldapSTSRequest(c, "alice", goodPW, "198.51.100.2", false), generic)
	assertDenied("throttled unknown user", suite.ldapSTSRequest(c, "ALICE ", goodPW, "198.51.100.3", true), generic)
	if bindCalls.Load() != calls {
		c.Fatal("throttled requests must not reach LDAP")
	}

	// 3. After the backoff window the correct password succeeds and resets
	// the user's counter.
	clk.advance(ldapThrottleBaseDelay)
	if res := suite.ldapSTSRequest(c, "alice", goodPW, "198.51.100.2", false); res.status != http.StatusOK || !strings.Contains(res.body, "<AccessKeyId>") {
		c.Fatalf("expected credentials after backoff, got %d %s", res.status, res.body)
	}
	for range ldapThrottleUserFreeAttempts - 1 {
		assertDenied("failure after reset", suite.ldapSTSRequest(c, "alice", "x", "198.51.100.4", false), generic)
	}
	if res := suite.ldapSTSRequest(c, "alice", goodPW, "198.51.100.4", false); res.status != http.StatusOK {
		c.Fatalf("success must reset the user counter, got %d %s", res.status, res.body)
	}

	// 4. One IP spraying many usernames is throttled; other IPs are not.
	reset()
	for i := range ldapThrottleIPFreeAttempts {
		assertDenied("spray", suite.ldapSTSRequest(c, fmt.Sprint("spray", i), "x", "203.0.113.9", i%2 == 0), generic)
	}
	calls = bindCalls.Load()
	assertDenied("throttled IP", suite.ldapSTSRequest(c, "alice", goodPW, "203.0.113.9", false), generic)
	if bindCalls.Load() != calls {
		c.Fatal("throttled IP must not reach LDAP")
	}
	if res := suite.ldapSTSRequest(c, "alice", goodPW, "203.0.113.10", false); res.status != http.StatusOK {
		c.Fatalf("other IPs must not be throttled, got %d %s", res.status, res.body)
	}

	// 5. The POST body route (AssumeRoleWithSSO) is throttled too and shares
	// counters with the query route.
	reset()
	for range ldapThrottleUserFreeAttempts {
		assertDenied("body failure", suite.ldapSTSRequest(c, "alice", "x", "198.51.100.20", true), generic)
	}
	calls = bindCalls.Load()
	assertDenied("body throttled", suite.ldapSTSRequest(c, "alice", goodPW, "198.51.100.21", true), generic)
	assertDenied("query throttled", suite.ldapSTSRequest(c, "alice", goodPW, "198.51.100.22", false), generic)
	if bindCalls.Load() != calls {
		c.Fatal("throttled body requests must not reach LDAP")
	}
}

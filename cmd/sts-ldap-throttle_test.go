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
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cfgldap "github.com/minio/minio/internal/config/identity/ldap"
	"github.com/minio/mux"
	xldap "github.com/minio/pkg/v3/ldap"
)

// resetForTest clears all counters and installs the given clock.
func (t *ldapLoginThrottle) resetForTest(now func() time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pairs.entries = make(map[ldapThrottleKey]*throttleEntry)
	t.users.entries = make(map[ldapThrottleKey]*throttleEntry)
	t.sources.entries = make(map[ldapThrottleKey]*throttleEntry)
	t.maxEntries = ldapThrottleMaxEntries
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

func newTestLDAPThrottle() (*ldapLoginThrottle, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	th := newLDAPLoginThrottle()
	th.resetForTest(clk.now)
	return th, clk
}

// failN makes n failed attempts and reports how many were admitted.
func failN(th *ldapLoginThrottle, user, source string, n int) (admitted int) {
	for range n {
		if th.acquire(user, source) != nil {
			admitted++
		}
	}
	return admitted
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

func TestLDAPThrottlePairBackoff(t *testing.T) {
	th, clk := newTestLDAPThrottle()
	free := ldapThrottlePairPolicy.freeAttempts

	if n := failN(th, "alice", "10.0.0.1", free+3); n != free {
		t.Fatalf("expected %d admitted attempts, got %d", free, n)
	}
	// Username normalization: case and surrounding space do not matter.
	if th.acquire("  ALICE ", "10.0.0.1") != nil {
		t.Fatal("normalized username must share the pair counter")
	}
	// The same user from another source is not affected.
	if a := th.acquire("alice", "10.0.0.2"); a == nil {
		t.Fatal("victim from another source must not be blocked")
	} else {
		a.succeeded()
	}

	// Backoff grows: one attempt after the first window, then a window
	// twice as long.
	clk.advance(ldapThrottlePairPolicy.baseDelay)
	if th.acquire("alice", "10.0.0.1") == nil {
		t.Fatal("attempt after first backoff window should be admitted")
	}
	clk.advance(ldapThrottlePairPolicy.baseDelay)
	if th.acquire("alice", "10.0.0.1") != nil {
		t.Fatal("second backoff window should be longer than the first")
	}
	clk.advance(ldapThrottlePairPolicy.baseDelay)
	a := th.acquire("alice", "10.0.0.1")
	if a == nil {
		t.Fatal("attempt after second backoff window should be admitted")
	}

	// Success clears the pair.
	a.succeeded()
	if n := failN(th, "alice", "10.0.0.1", free); n != free {
		t.Fatalf("success must clear the pair backoff, admitted %d", n)
	}
}

func TestLDAPThrottleUserCeiling(t *testing.T) {
	th, clk := newTestLDAPThrottle()
	ceiling := ldapThrottleUserPolicy.freeAttempts

	// Distributed guessing: one failure per source.
	for i := range ceiling {
		if th.acquire("alice", fmt.Sprint("10.1.", i/250, ".", i%250)) == nil {
			t.Fatalf("attempt %d below the ceiling should be admitted", i+1)
		}
	}
	if th.acquire("alice", "10.9.9.9") != nil {
		t.Fatal("user ceiling must apply across sources")
	}

	// A success does not reset the ceiling (only the pair).
	clk.advance(ldapThrottleUserPolicy.baseDelay)
	a := th.acquire("alice", "10.9.9.9")
	if a == nil {
		t.Fatal("attempt after ceiling backoff should be admitted")
	}
	a.succeeded()
	if th.acquire("alice", "10.9.9.8") != nil {
		t.Fatal("success must not reset the per-user ceiling")
	}

	// The ceiling is a fixed window: it resets after the window passes.
	clk.advance(ldapThrottleEntryTTL + ldapThrottleUserPolicy.maxDelay + time.Second)
	if th.acquire("alice", "10.9.9.7") == nil {
		t.Fatal("ceiling should reset after its window")
	}
}

func TestLDAPThrottleSourceSpray(t *testing.T) {
	th, _ := newTestLDAPThrottle()
	limit := ldapThrottleSourcePolicy.freeAttempts

	for i := range limit {
		if th.acquire(fmt.Sprint("user", i), "10.0.0.1") == nil {
			t.Fatalf("distinct user %d below the spray limit should be admitted", i)
		}
	}
	if th.acquire("another", "10.0.0.1") != nil {
		t.Fatal("source spraying usernames must be throttled")
	}
	if th.acquire("another", "10.0.0.2") == nil {
		t.Fatal("other sources must not be throttled")
	}

	// Repeated attempts for one user count against the pair only.
	th2, _ := newTestLDAPThrottle()
	failN(th2, "alice", "10.0.0.1", 50)
	if th2.acquire("bob", "10.0.0.1") == nil {
		t.Fatal("repeated failures for one user must not count as spraying")
	}
}

func TestLDAPThrottleRefund(t *testing.T) {
	th, _ := newTestLDAPThrottle()
	// LDAP outages do not count as failed attempts.
	for range 3 * ldapThrottleUserPolicy.freeAttempts {
		a := th.acquire("alice", "10.0.0.1")
		if a == nil {
			t.Fatal("refunded attempts must not cause throttling")
		}
		a.notCredentialFailure()
	}
	if n := len(th.pairs.entries) + len(th.users.entries) + len(th.sources.entries); n != 0 {
		t.Fatalf("refunded attempts must not leave entries, have %d", n)
	}
}

func TestLDAPThrottleSourceIgnoresHeaders(t *testing.T) {
	testCases := map[string]string{
		"10.1.2.3:4567":                 "10.1.2.3",
		"[2001:db8:1:2:3:4:5:6]:9000":   "2001:db8:1:2::/64",
		"[2001:db8:1:2:ffff::1]:9000":   "2001:db8:1:2::/64",
		"[::ffff:192.0.2.1]:80":         "192.0.2.1",
		"[fe80::1%eth0]:80":             "fe80::/64",
		"10.1.2.3":                      "10.1.2.3",
		"not-an-ip:80":                  "invalid",
		strings.Repeat("x", 8000) + ":": "invalid",
	}
	for remote, want := range testCases {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.RemoteAddr = remote
		// Spoofed forwarding headers must not change the source.
		r.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
		r.Header.Set("X-Real-IP", "203.0.113.8")
		r.Header.Set("Forwarded", "for=203.0.113.9")
		if got := ldapThrottleSource(r); got != want {
			t.Errorf("ldapThrottleSource(%q) = %q, want %q", remote, got, want)
		}
	}
}

func TestLDAPThrottleMemoryBound(t *testing.T) {
	th, clk := newTestLDAPThrottle()
	th.maxEntries = 10

	// Expiry: idle entries are swept.
	failN(th, "u", "10.0.0.1", 1)
	clk.advance(ldapThrottleEntryTTL + ldapThrottleSweepInterval + time.Second)
	th.acquire("fresh", "10.0.0.2")
	if n := len(th.pairs.entries); n != 1 {
		t.Fatalf("expected expired entries to be swept, have %d pairs", n)
	}

	// A blocked attacker pair, then a flood of huge junk usernames: tables
	// stay bounded, keys are fixed size and blocked entries are not evicted
	// in favour of unblocked ones.
	free := ldapThrottlePairPolicy.freeAttempts
	failN(th, "victim", "10.0.0.66", free)
	junk := strings.Repeat("j", 8<<10)
	for i := range 1000 {
		th.acquire(fmt.Sprint(junk, i), fmt.Sprint("10.2.", i/250, ".", i%250))
		for _, tbl := range []*throttleTable{&th.pairs, &th.users, &th.sources} {
			if len(tbl.entries) > th.maxEntries {
				t.Fatalf("throttle table exceeded its bound: %d", len(tbl.entries))
			}
		}
	}
	if th.acquire("victim", "10.0.0.66") != nil {
		t.Fatal("blocked pair must not be evicted in favour of unblocked entries")
	}
}

// ldapSTSResult is the observable outcome of an LDAP STS request.
type ldapSTSResult struct {
	status int
	code   string
	msg    string
	body   string
}

func ldapSTSValues(user, pass string) url.Values {
	v := url.Values{}
	v.Set("Action", ldapIdentity)
	v.Set("Version", stsAPIVersion)
	v.Set("LDAPUsername", user)
	v.Set("LDAPPassword", pass)
	v.Set("DurationSeconds", "3600")
	return v
}

func newLDAPSTSRequest(c *check, endpoint string, v url.Values, formBody bool) *http.Request {
	var req *http.Request
	var err error
	if formBody {
		req, err = http.NewRequest(http.MethodPost, endpoint+"/", strings.NewReader(v.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		req, err = http.NewRequest(http.MethodPost, endpoint+"/?"+v.Encode(), strings.NewReader(""))
	}
	if err != nil {
		c.Fatalf("request error: %v", err)
	}
	return req
}

func parseLDAPSTSResult(c *check, status int, b []byte) ldapSTSResult {
	res := ldapSTSResult{status: status, body: string(b)}
	if status != http.StatusOK {
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
	ldapDown := atomic.Bool{}
	oldBind := ldapBindFn
	defer func() { ldapBindFn = oldBind }()
	// Fake directory that fails the way cfgldap.Config.Bind does.
	ldapBindFn = func(username, password string) (*xldap.DNSearchResult, []string, error) {
		bindCalls.Add(1)
		if ldapDown.Load() {
			return nil, nil, fmt.Errorf("Could not connect to any LDAP server: dial tcp: connection refused")
		}
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

	if _, err := globalIAMSys.PolicyDBSet(context.Background(), aliceDN, "readwrite", stsUser, false); err != nil {
		c.Fatalf("unable to map policy: %v", err)
	}

	clk := &fakeClock{t: time.Now()}
	defer globalLDAPLoginThrottle.resetForTest(time.Now)
	reset := func() { globalLDAPLoginThrottle.resetForTest(clk.now) }

	// Requests through the STS router with a chosen TCP peer address.
	router := mux.NewRouter()
	registerSTSRouter(router)
	call := func(user, pass, remote string, formBody bool) ldapSTSResult {
		req := newLDAPSTSRequest(c, "http://localhost", ldapSTSValues(user, pass), formBody)
		req.RemoteAddr = remote
		// Forwarding headers are attacker controlled and must be ignored.
		req.Header.Set("X-Real-IP", fmt.Sprint("203.0.113.", bindCalls.Load()%250))
		req.Header.Set("X-Forwarded-For", fmt.Sprint("198.18.0.", bindCalls.Load()%250))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return parseLDAPSTSResult(c, rec.Code, rec.Body.Bytes())
	}

	generic := ldapSTSResult{
		status: http.StatusForbidden,
		code:   stsErrCodes[ErrSTSAccessDenied].Code,
		msg:    stsErrCodes[ErrSTSAccessDenied].Description,
	}
	assertDenied := func(name string, got ldapSTSResult) {
		c.Helper()
		if got.status != generic.status || got.code != generic.code || got.msg != generic.msg {
			c.Fatalf("%s: response differs: got %d/%s/%q, want %d/%s/%q", name, got.status, got.code, got.msg, generic.status, generic.code, generic.msg)
		}
		for _, leak := range []string{"uid=", "dc=min", "alice", "bob", "nobody", "DN", "LDAP", "52e", "projecta"} {
			if strings.Contains(got.body, leak) {
				c.Fatalf("%s: response leaks %q: %s", name, leak, got.body)
			}
		}
	}
	assertOK := func(name string, got ldapSTSResult) {
		c.Helper()
		if got.status != http.StatusOK || !strings.Contains(got.body, "<AccessKeyId>") {
			c.Fatalf("%s: expected credentials, got %d %s", name, got.status, got.body)
		}
	}
	const attacker, victim = "192.0.2.66:40000", "198.51.100.7:50000"
	free := ldapThrottlePairPolicy.freeAttempts

	// 1. Unknown user, wrong password and missing policy are
	// indistinguishable, on both routes and over the real listener.
	reset()
	for _, formBody := range []bool{false, true} {
		assertDenied("unknown user", call("nobody", "x", "192.0.2.1:1", formBody))
		assertDenied("wrong password", call("alice", "x", "192.0.2.2:1", formBody))
		assertDenied("no policy", call("bob", goodPW, "192.0.2.3:1", formBody))

		for _, user := range []string{"nobody", "alice"} {
			req := newLDAPSTSRequest(c, suite.endPoint, ldapSTSValues(user, "x"), formBody)
			resp, err := suite.TestSuiteCommon.client.Do(req)
			if err != nil {
				c.Fatalf("request failed: %v", err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			assertDenied("network "+user, parseLDAPSTSResult(c, resp.StatusCode, b))
		}
	}

	// 2. The attacker's source is blocked for the user, even with the correct
	// password and rotating forwarding headers, without contacting LDAP;
	// the victim from another source still logs in.
	reset()
	for range free {
		assertDenied("failure", call("alice", "x", attacker, false))
	}
	calls := bindCalls.Load()
	assertDenied("throttled pair", call("alice", goodPW, attacker, false))
	assertDenied("throttled pair (variant, body route)", call("ALICE ", goodPW, attacker, true))
	if bindCalls.Load() != calls {
		c.Fatal("throttled requests must not reach LDAP")
	}
	assertOK("victim from another source", call("alice", goodPW, victim, false))
	assertDenied("attacker still throttled after victim success", call("alice", goodPW, attacker, false))

	// 3. After the backoff window the correct password succeeds from the
	// attacker's source too, and the success clears that pair.
	clk.advance(ldapThrottlePairPolicy.baseDelay)
	assertOK("after backoff", call("alice", goodPW, attacker, false))
	for range free - 1 {
		assertDenied("failure after success", call("alice", "x", attacker, false))
	}
	assertOK("pair cleared by success", call("alice", goodPW, attacker, false))

	// 4. One source spraying usernames is throttled; other sources are not.
	reset()
	for i := range ldapThrottleSourcePolicy.freeAttempts {
		assertDenied("spray", call(fmt.Sprint("spray", i), "x", attacker, i%2 == 0))
	}
	calls = bindCalls.Load()
	assertDenied("throttled source", call("alice", goodPW, attacker, false))
	if bindCalls.Load() != calls {
		c.Fatal("throttled source must not reach LDAP")
	}
	assertOK("other source", call("alice", goodPW, victim, false))

	// 5. The POST body route (AssumeRoleWithSSO) is throttled and shares
	// counters with the query route.
	reset()
	for range free {
		assertDenied("body failure", call("alice", "x", attacker, true))
	}
	calls = bindCalls.Load()
	assertDenied("body throttled", call("alice", goodPW, attacker, true))
	assertDenied("query throttled", call("alice", goodPW, attacker, false))
	if bindCalls.Load() != calls {
		c.Fatal("throttled body requests must not reach LDAP")
	}

	// 6. LDAP outages are not counted as failed attempts.
	reset()
	ldapDown.Store(true)
	for range 3 * free {
		if res := call("alice", goodPW, attacker, false); res.status != http.StatusInternalServerError || strings.Contains(res.body, "connect") {
			c.Fatalf("expected generic upstream error, got %d %s", res.status, res.body)
		}
	}
	ldapDown.Store(false)
	assertOK("after outage", call("alice", goodPW, attacker, false))
}

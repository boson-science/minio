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

package ldap

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	xldap "github.com/minio/pkg/v3/ldap"
)

func TestIsUserLookupMiss(t *testing.T) {
	// Obtain the real "not found" error from minio/pkg: with no user search
	// bases configured LookupUsername finds nothing without touching the
	// connection. A wording change in minio/pkg makes this test fail.
	var cfg xldap.Config
	_, notFound := cfg.LookupUsername(nil, "alice")
	if notFound == nil {
		t.Fatal("expected LookupUsername to report a missing user")
	}

	testCases := []struct {
		err  error
		miss bool
	}{
		{notFound, true},
		// minio/pkg does not expose a way to produce this error without an
		// LDAP server returning two entries; message copied from
		// xldap.Config.LookupUsername (minio/pkg v3.1.3).
		{fmt.Errorf("Multiple DNs for %s found - please fix the search filter", "alice"), true},
		// Infrastructure failures must not be reported as credential errors.
		{errors.New("LDAP client: connection reset"), false},
		{fmt.Errorf("Base DN (%s) for user DN search does not exist: %w", "ou=x", errors.New("no such object")), false},
	}
	for i, tc := range testCases {
		if got := isUserLookupMiss(tc.err); got != tc.miss {
			t.Errorf("case %d: isUserLookupMiss(%q) = %v, want %v", i, tc.err, got, tc.miss)
		}
	}
}

func TestIsNetworkError(t *testing.T) {
	if !isNetworkError(ldap.NewError(ldap.ErrorNetwork, errors.New("connection reset"))) {
		t.Fatal("go-ldap network errors must be classified as network errors")
	}
	if !isNetworkError(fmt.Errorf("wrapped: %w", ldap.NewError(ldap.ErrorNetwork, errors.New("timeout")))) {
		t.Fatal("wrapped network errors must be classified as network errors")
	}
	if isNetworkError(ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))) {
		t.Fatal("invalid credentials must not be classified as a network error")
	}
	if isNetworkError(ldap.NewError(ldap.LDAPResultUnwillingToPerform, errors.New("account locked"))) {
		t.Fatal("server responses must not be classified as network errors")
	}
}

func TestDummyBindDN(t *testing.T) {
	l := Config{LDAP: xldap.Config{UserDNSearchBaseDistName: " ou=people,dc=min,dc=io ;ou=other,dc=min,dc=io"}}
	dn1, dn2 := l.dummyBindDN(), l.dummyBindDN()
	if dn1 == dn2 {
		t.Fatalf("expected random dummy DNs, got %q twice", dn1)
	}
	if !strings.HasSuffix(dn1, ",ou=people,dc=min,dc=io") {
		t.Fatalf("expected dummy DN under the first user search base, got %q", dn1)
	}
	if _, err := ldap.ParseDN(dn1); err != nil {
		t.Fatalf("dummy DN %q must be a valid DN: %v", dn1, err)
	}

	l = Config{}
	if dn := l.dummyBindDN(); strings.Contains(dn, ",") {
		t.Fatalf("expected a single RDN without search base, got %q", dn)
	}
}

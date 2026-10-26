// Copyright (c) 2015-2022 MinIO, Inc.
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

package openid

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v4"
	"github.com/minio/minio/internal/arn"
	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/config"
	jwtm "github.com/minio/minio/internal/jwt"
	xnet "github.com/minio/pkg/v3/net"
)

func TestUpdateClaimsExpiry(t *testing.T) {
	testCases := []struct {
		exp             any
		dsecs           string
		expectedFailure bool
	}{
		{"", "", true},
		{"-1", "0", true},
		{"-1", "900", true},
		{"1574812326", "900", false},
		{1574812326, "900", false},
		{int64(1574812326), "900", false},
		{int(1574812326), "900", false},
		{uint(1574812326), "900", false},
		{uint64(1574812326), "900", false},
		{json.Number("1574812326"), "900", false},
		{1574812326.000, "900", false},
		{time.Duration(3) * time.Minute, "900", false},
	}

	for _, testCase := range testCases {
		t.Run("", func(t *testing.T) {
			claims := map[string]any{}
			claims["exp"] = testCase.exp
			err := updateClaimsExpiry(testCase.dsecs, claims)
			if err != nil && !testCase.expectedFailure {
				t.Errorf("Expected success, got failure %s", err)
			}
			if err == nil && testCase.expectedFailure {
				t.Error("Expected failure, got success")
			}
		})
	}
}

// testIDP - minimal OpenID provider serving a JWKS document of RSA keys.
type testIDP struct {
	server *httptest.Server
	issuer string

	mu      sync.Mutex
	keys    map[string]*rsa.PrivateKey
	fetches int
}

func newTestIDP(t *testing.T, kids ...string) *testIDP {
	t.Helper()
	idp := &testIDP{keys: map[string]*rsa.PrivateKey{}}
	for _, kid := range kids {
		idp.addKey(t, kid)
	}
	idp.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idp.mu.Lock()
		defer idp.mu.Unlock()
		idp.fetches++
		var jwks JWKS
		for kid, k := range idp.keys {
			jwks.Keys = append(jwks.Keys, &JWKS{
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				Kid: kid,
				N:   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
			})
		}
		json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(idp.server.Close)
	idp.issuer = idp.server.URL
	return idp
}

func (idp *testIDP) addKey(t *testing.T, kid string) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.keys[kid] = k
	return k
}

func (idp *testIDP) key(kid string) *rsa.PrivateKey {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.keys[kid]
}

func (idp *testIDP) fetchCount() int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.fetches
}

func newTestProviderCfg(t *testing.T, idp *testIDP, clientID, clientSecret string) *providerCfg {
	t.Helper()
	u, err := xnet.ParseHTTPURL(idp.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := &providerCfg{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		DiscoveryDoc: DiscoveryDoc{Issuer: idp.issuer},
		pubKeys:      newPublicKeys(),
	}
	p.JWKS.URL = u
	return p
}

func newTestOpenIDConfig(t *testing.T, providers map[arn.ARN]*providerCfg) Config {
	t.Helper()
	cfg := Config{
		Enabled:            true,
		arnProviderCfgsMap: providers,
		ProviderCfgs:       map[string]*providerCfg{},
		closeRespFn: func(rc io.ReadCloser) {
			rc.Close()
		},
	}
	for roleArn, p := range providers {
		cfg.ProviderCfgs[roleArn.String()] = p
		if err := cfg.PopulatePublicKey(roleArn); err != nil {
			t.Fatal(err)
		}
	}
	return cfg
}

func newTestRoleARN(t *testing.T, resourceID string) arn.ARN {
	t.Helper()
	a, err := arn.NewIAMRoleARN(resourceID, "")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func signTestToken(t *testing.T, method jwtgo.SigningMethod, kid string, claims jwtgo.MapClaims, key any) string {
	t.Helper()
	tok := jwtgo.NewWithClaims(method, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validTestClaims(issuer, clientID string) jwtgo.MapClaims {
	return jwtgo.MapClaims{
		"iss":    issuer,
		"aud":    clientID,
		"sub":    "test-user",
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
		"policy": "consoleAdmin",
	}
}

// expectRejected - fails unless err is non-nil and mentions want, so that a
// token is shown to be rejected for the intended reason.
func expectRejected(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected token to be rejected with %q, got success", want)
	}
	if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(want)) {
		t.Fatalf("expected rejection with %q, got: %v", want, err)
	}
}

const (
	errMethodInvalid = "is invalid"
	errKeyMismatch   = "is not valid for the key"
	errBadSignature  = "verification error"
	errNoKey         = "no public key found for kid"
	errIssuer        = "`iss` claim invalid"
	errExpired       = "expired"
)

func TestJWTRejectsAlgorithmConfusion(t *testing.T) {
	const (
		clientID     = "76b95ae5-33ef-4283-97b7-d2a85dc2d8f4"
		clientSecret = "WNGvKVyyNmXq0TraSvjaDN9CtpFgx35IXtGEffMCPR0"
		rsaKid       = "rsa-kid"
	)

	idp := newTestIDP(t, rsaKid)
	p := newTestProviderCfg(t, idp, clientID, clientSecret)
	cfg := newTestOpenIDConfig(t, map[arn.ARN]*providerCfg{DummyRoleARN: p})

	if k := p.pubKeys.get(clientID); k != nil {
		t.Fatalf("client secret must not be registered as a verification key, got %T", k)
	}

	// Positive control: a correctly signed RS256 token is accepted.
	claims := validTestClaims(idp.issuer, clientID)
	good := signTestToken(t, jwtgo.SigningMethodRS256, rsaKid, claims, idp.key(rsaKid))
	if err := cfg.Validate(t.Context(), DummyRoleARN, good, "", "", map[string]any{}); err != nil {
		t.Fatalf("expected valid RS256 token to be accepted: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&idp.key(rsaKid).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attackerRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name    string
		token   string
		wantErr string
	}{
		{"HS256 signed with client secret", signTestToken(t, jwtgo.SigningMethodHS256, clientID, claims, []byte(clientSecret)), errMethodInvalid},
		{"HS384 signed with client secret", signTestToken(t, jwtgo.SigningMethodHS384, clientID, claims, []byte(clientSecret)), errMethodInvalid},
		{"HS512 signed with client secret", signTestToken(t, jwtgo.SigningMethodHS512, clientID, claims, []byte(clientSecret)), errMethodInvalid},
		{"HS256 signed with RSA public key PEM", signTestToken(t, jwtgo.SigningMethodHS256, rsaKid, claims, pubPEM), errMethodInvalid},
		{"HS256 signed with RSA public key DER", signTestToken(t, jwtgo.SigningMethodHS256, rsaKid, claims, pubDER), errMethodInvalid},
		{"HS256 with unknown kid", signTestToken(t, jwtgo.SigningMethodHS256, "unknown-kid", claims, []byte(clientSecret)), errMethodInvalid},
		{"alg none", signTestToken(t, jwtgo.SigningMethodNone, rsaKid, claims, jwtgo.UnsafeAllowNoneSignatureType), errMethodInvalid},
		{"alg none without kid", signTestToken(t, jwtgo.SigningMethodNone, "", claims, jwtgo.UnsafeAllowNoneSignatureType), errMethodInvalid},
		{"EdDSA presented with RSA kid", signTestToken(t, jwtgo.SigningMethodEdDSA, rsaKid, claims, edKey), errMethodInvalid},
		{"ES256 presented with RSA kid", signTestToken(t, jwtgo.SigningMethodES256, rsaKid, claims, ecKey), errKeyMismatch},
		{"RS256 signed with a foreign RSA key", signTestToken(t, jwtgo.SigningMethodRS256, rsaKid, claims, attackerRSA), errBadSignature},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := cfg.Validate(t.Context(), DummyRoleARN, tc.token, "", "", map[string]any{})
			expectRejected(t, err, tc.wantErr)
		})
	}
}

func TestSigningMethodMatchesKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]any{
		"rsa":     &rsaKey.PublicKey,
		"ecdsa":   &ecKey.PublicKey,
		"ed25519": edPub,
		"hmac":    []byte("secret"),
		"empty":   []byte{},
	}
	methods := map[jwtgo.SigningMethod]string{
		jwtgo.SigningMethodRS256: "rsa",
		jwtgo.SigningMethodRS512: "rsa",
		jwtgo.SigningMethodPS256: "rsa",
		SigningMethodRS3256:      "rsa",
		jwtgo.SigningMethodES256: "ecdsa",
		jwtgo.SigningMethodES512: "ecdsa",
		SigningMethodES3256:      "ecdsa",
		jwtgo.SigningMethodEdDSA: "ed25519",
		jwtgo.SigningMethodHS256: "",
		jwtgo.SigningMethodNone:  "",
	}
	for method, wantKey := range methods {
		for keyType, key := range keys {
			if got := signingMethodMatchesKey(method, key); got != (keyType == wantKey) {
				t.Errorf("signingMethodMatchesKey(%s, %s) = %v", method.Alg(), keyType, got)
			}
		}
	}
}

func TestJWTRejectsHMACWithEmptyClientSecret(t *testing.T) {
	const clientID = "empty-secret-client"

	idp := newTestIDP(t, "rsa-kid")
	p := newTestProviderCfg(t, idp, clientID, "")
	cfg := newTestOpenIDConfig(t, map[arn.ARN]*providerCfg{DummyRoleARN: p})

	if k := p.pubKeys.get(clientID); k != nil {
		t.Fatalf("empty client secret must not be registered as a verification key, got %T", k)
	}

	// golang-jwt refuses to sign with an empty HMAC key, so build the
	// token by hand: HMAC-SHA256 over the signing input with an empty key.
	tok := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, validTestClaims(idp.issuer, clientID))
	tok.Header["kid"] = clientID
	signingString, err := tok.SigningString()
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte{})
	mac.Write([]byte(signingString))
	token := signingString + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	err = cfg.Validate(t.Context(), DummyRoleARN, token, "", "", map[string]any{})
	expectRejected(t, err, errMethodInvalid)
}

func TestJWTUnknownKidRefresh(t *testing.T) {
	const clientID = "refresh-client"

	idp := newTestIDP(t, "kid-1")
	p := newTestProviderCfg(t, idp, clientID, "secret")
	cfg := newTestOpenIDConfig(t, map[arn.ARN]*providerCfg{DummyRoleARN: p})
	claims := validTestClaims(idp.issuer, clientID)

	// HS* is rejected by the method allow-list before any key lookup, so it
	// never triggers a JWKS refresh even if the kid is unknown.
	before := idp.fetchCount()
	hs := signTestToken(t, jwtgo.SigningMethodHS256, "unknown-kid", claims, []byte("secret"))
	expectRejected(t, cfg.Validate(t.Context(), DummyRoleARN, hs, "", "", map[string]any{}), errMethodInvalid)
	if got := idp.fetchCount(); got != before {
		t.Fatalf("HS256 token must not trigger a JWKS refresh, fetches %d -> %d", before, got)
	}

	// A known kid with a bad signature must not trigger a refresh either.
	foreignKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	forged := signTestToken(t, jwtgo.SigningMethodRS256, "kid-1", claims, foreignKey)
	expectRejected(t, cfg.Validate(t.Context(), DummyRoleARN, forged, "", "", map[string]any{}), errBadSignature)
	if got := idp.fetchCount(); got != before {
		t.Fatalf("known kid must not trigger a JWKS refresh, fetches %d -> %d", before, got)
	}

	// Unknown kid triggers exactly one refresh and is still rejected.
	unknown := signTestToken(t, jwtgo.SigningMethodRS256, "kid-unknown", claims, idp.key("kid-1"))
	expectRejected(t, cfg.Validate(t.Context(), DummyRoleARN, unknown, "", "", map[string]any{}), errNoKey)
	if got := idp.fetchCount(); got != before+1 {
		t.Fatalf("unknown kid must trigger exactly one JWKS refresh, fetches %d -> %d", before, got)
	}

	// After a key rotation on the IdP, the refresh picks up the new key.
	rotated := idp.addKey(t, "kid-2")
	token := signTestToken(t, jwtgo.SigningMethodRS256, "kid-2", claims, rotated)
	if err := cfg.Validate(t.Context(), DummyRoleARN, token, "", "", map[string]any{}); err != nil {
		t.Fatalf("expected token signed with rotated key to be accepted: %v", err)
	}
}

func TestJWTProviderBinding(t *testing.T) {
	// Both IdPs publish a key under the same kid, with different key material.
	idpA := newTestIDP(t, "kid-1", "kid-a")
	idpB := newTestIDP(t, "kid-1")

	arnA := newTestRoleARN(t, "provider-a")
	arnB := newTestRoleARN(t, "provider-b")
	arnC := newTestRoleARN(t, "provider-c")
	pA := newTestProviderCfg(t, idpA, "client-a", "secret-a")
	pB := newTestProviderCfg(t, idpB, "client-b", "secret-b")
	// Provider C uses the same IdP as A, with a different client ID.
	pC := newTestProviderCfg(t, idpA, "client-c", "secret-c")
	cfg := newTestOpenIDConfig(t, map[arn.ARN]*providerCfg{arnA: pA, arnB: pB, arnC: pC})

	if pB.pubKeys.get("kid-a") != nil {
		t.Fatal("provider B must not hold keys published by provider A")
	}

	validForA := signTestToken(t, jwtgo.SigningMethodRS256, "kid-a", validTestClaims(idpA.issuer, "client-a"), idpA.key("kid-a"))
	if err := cfg.Validate(t.Context(), arnA, validForA, "", "", map[string]any{}); err != nil {
		t.Fatalf("expected provider A token to be accepted for provider A: %v", err)
	}

	noIss := validTestClaims(idpA.issuer, "client-a")
	delete(noIss, "iss")

	testCases := []struct {
		name    string
		roleArn arn.ARN
		token   string
		wantErr string
	}{
		{"provider A token presented for provider B", arnB, validForA, errNoKey},
		{
			"provider A key with provider B claims, unknown kid at B", arnB,
			signTestToken(t, jwtgo.SigningMethodRS256, "kid-a", validTestClaims(idpB.issuer, "client-b"), idpA.key("kid-a")),
			errNoKey,
		},
		{
			"provider A key with provider B claims, colliding kid", arnB,
			signTestToken(t, jwtgo.SigningMethodRS256, "kid-1", validTestClaims(idpB.issuer, "client-b"), idpA.key("kid-1")),
			errBadSignature,
		},
		{
			"same IdP, token for client A presented for client C", arnC,
			signTestToken(t, jwtgo.SigningMethodRS256, "kid-a", validTestClaims(idpA.issuer, "client-a"), idpA.key("kid-a")),
			"must match configured OpenID Client ID",
		},
		{
			"issuer mismatch", arnA,
			signTestToken(t, jwtgo.SigningMethodRS256, "kid-a", validTestClaims("https://attacker.example", "client-a"), idpA.key("kid-a")),
			errIssuer,
		},
		{
			"issuer missing", arnA,
			signTestToken(t, jwtgo.SigningMethodRS256, "kid-a", noIss, idpA.key("kid-a")),
			errIssuer,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := cfg.Validate(t.Context(), tc.roleArn, tc.token, "", "", map[string]any{})
			expectRejected(t, err, tc.wantErr)
		})
	}

	t.Run("provider without issuer in discovery doc", func(t *testing.T) {
		pNoIss := newTestProviderCfg(t, idpA, "client-d", "secret-d")
		pNoIss.DiscoveryDoc.Issuer = ""
		arnD := newTestRoleARN(t, "provider-d")
		cfgD := newTestOpenIDConfig(t, map[arn.ARN]*providerCfg{arnD: pNoIss})
		token := signTestToken(t, jwtgo.SigningMethodRS256, "kid-a", validTestClaims("", "client-d"), idpA.key("kid-a"))
		err := cfgD.Validate(t.Context(), arnD, token, "", "", map[string]any{})
		expectRejected(t, err, "discovery document has no issuer")
	})
}

func TestJWTExpiry(t *testing.T) {
	const clientID = "expiry-client"

	idp := newTestIDP(t, "kid-1")
	p := newTestProviderCfg(t, idp, clientID, "secret")
	cfg := newTestOpenIDConfig(t, map[arn.ARN]*providerCfg{DummyRoleARN: p})

	withExp := func(exp any) string {
		c := validTestClaims(idp.issuer, clientID)
		if exp == nil {
			delete(c, "exp")
		} else {
			c["exp"] = exp
		}
		return signTestToken(t, jwtgo.SigningMethodRS256, "kid-1", c, idp.key("kid-1"))
	}

	for _, tc := range []struct {
		name  string
		token string
		dsecs string
	}{
		{"missing exp", withExp(nil), ""},
		{"missing exp with DurationSeconds", withExp(nil), "900"},
		{"zero exp", withExp(0), ""},
		{"zero exp with DurationSeconds", withExp(0), "900"},
		{"negative exp", withExp(-1), ""},
		{"string exp", withExp(strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := cfg.Validate(t.Context(), DummyRoleARN, tc.token, "", tc.dsecs, map[string]any{})
			expectRejected(t, err, errExpired)
		})
	}

	t.Run("expired", func(t *testing.T) {
		err := cfg.Validate(t.Context(), DummyRoleARN, withExp(time.Now().Add(-time.Minute).Unix()), "", "", map[string]any{})
		var ve *jwtgo.ValidationError
		if !errors.As(err, &ve) || ve.Errors&jwtgo.ValidationErrorExpired == 0 {
			t.Fatalf("expected token expired error, got %v", err)
		}
	})

	t.Run("valid with DurationSeconds", func(t *testing.T) {
		claims := map[string]any{}
		exp := time.Now().Add(10 * time.Hour).Unix()
		if err := cfg.Validate(t.Context(), DummyRoleARN, withExp(exp), "", "900", claims); err != nil {
			t.Fatalf("expected valid token to be accepted: %v", err)
		}
		got, err := auth.ExpToInt64(claims["exp"])
		if err != nil {
			t.Fatal(err)
		}
		if limit := time.Now().Add(900*time.Second + time.Minute).Unix(); got > limit {
			t.Fatalf("expected exp to be capped by DurationSeconds, got %d (limit %d)", got, limit)
		}
	})
}

func TestJWT(t *testing.T) {
	const jsonkey = `{"keys":
       [
         {"kty":"RSA",
          "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          "e":"AQAB",
          "alg":"RS256",
          "kid":"2011-04-29"}
       ]
     }`

	pubKeys := newPublicKeys()
	err := pubKeys.parseAndAdd(bytes.NewBuffer([]byte(jsonkey)))
	if err != nil {
		t.Fatal("Error loading pubkeys:", err)
	}
	if len(pubKeys.pkMap) != 1 {
		t.Fatalf("Expected 1 keys, got %d", len(pubKeys.pkMap))
	}

	u1, err := xnet.ParseHTTPURL("http://127.0.0.1:8443")
	if err != nil {
		t.Fatal(err)
	}

	provider := providerCfg{pubKeys: pubKeys}
	provider.JWKS.URL = u1
	cfg := Config{
		Enabled: true,
		arnProviderCfgsMap: map[arn.ARN]*providerCfg{
			DummyRoleARN: &provider,
		},
		ProviderCfgs: map[string]*providerCfg{
			"1": &provider,
		},
	}

	u, err := url.Parse("http://127.0.0.1:8443/?Token=invalid")
	if err != nil {
		t.Fatal(err)
	}

	var claims jwtgo.MapClaims
	if err = cfg.Validate(t.Context(), DummyRoleARN, u.Query().Get("Token"), "", "", claims); err == nil {
		t.Fatal(err)
	}
}

func TestDefaultExpiryDuration(t *testing.T) {
	testCases := []struct {
		reqURL    string
		duration  time.Duration
		expectErr bool
	}{
		{
			reqURL:   "http://127.0.0.1:8443/?Token=xxxxx",
			duration: time.Duration(60) * time.Minute,
		},
		{
			reqURL:    "http://127.0.0.1:8443/?DurationSeconds=9s",
			expectErr: true,
		},
		{
			reqURL:    "http://127.0.0.1:8443/?DurationSeconds=31536001",
			expectErr: true,
		},
		{
			reqURL:    "http://127.0.0.1:8443/?DurationSeconds=800",
			expectErr: true,
		},
		{
			reqURL:   "http://127.0.0.1:8443/?DurationSeconds=901",
			duration: time.Duration(901) * time.Second,
		},
	}

	for i, testCase := range testCases {
		u, err := url.Parse(testCase.reqURL)
		if err != nil {
			t.Fatal(err)
		}
		d, err := GetDefaultExpiration(u.Query().Get("DurationSeconds"))
		gotErr := (err != nil)
		if testCase.expectErr != gotErr {
			t.Errorf("Test %d: Expected %v, got %v with error %s", i+1, testCase.expectErr, gotErr, err)
		}
		if d != testCase.duration {
			t.Errorf("Test %d: Expected duration %d, got %d", i+1, testCase.duration, d)
		}
	}
}

func TestExpCorrect(t *testing.T) {
	signKey, _ := base64.StdEncoding.DecodeString("NTNv7j0TuYARvmNMmWXo6fKvM4o6nv/aUi9ryX38ZH+L1bkrnD1ObOQ8JAUmHCBq7Iy7otZcyAagBLHVKvvYaIpmMuxmARQ97jUVG16Jkpkp1wXOPsrF9zwew6TpczyHkHgX5EuLg2MeBuiT/qJACs1J0apruOOJCg/gOtkjB4c=")

	claimsMap := jwtm.NewMapClaims()
	claimsMap.SetExpiry(time.Now().Add(time.Minute))
	claimsMap.SetAccessKey("test-access")
	if err := updateClaimsExpiry("3600", claimsMap.MapClaims); err != nil {
		t.Error(err)
	}
	// Build simple token with updated expiration claim
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, claimsMap)
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		t.Error(err)
	}

	// Parse token to be sure it is valid
	err = jwtm.ParseWithClaims(tokenString, claimsMap, func(*jwtm.MapClaims) ([]byte, error) {
		return signKey, nil
	})
	if err != nil {
		t.Error(err)
	}
}

func TestKeycloakProviderInitialization(t *testing.T) {
	testConfig := providerCfg{
		DiscoveryDoc: DiscoveryDoc{
			TokenEndpoint: "http://keycloak.test/token/endpoint",
		},
	}
	testKvs := config.KVS{}
	testKvs.Set(Vendor, "keycloak")
	testKvs.Set(KeyCloakRealm, "TestRealm")
	testKvs.Set(KeyCloakAdminURL, "http://keycloak.test/auth/admin")
	cfgGet := func(param string) string {
		return testKvs.Get(param)
	}

	if testConfig.provider != nil {
		t.Errorf("Empty config cannot have any provider!")
	}

	if err := testConfig.initializeProvider(cfgGet, http.DefaultTransport); err != nil {
		t.Error(err)
	}

	if testConfig.provider == nil {
		t.Errorf("keycloak provider must be initialized!")
	}
}

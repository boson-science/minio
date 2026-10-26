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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/auth"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/pkg/v3/policy"
)

const (
	unsignedTrailerTestURL = "http://127.0.0.1:9000/bucket/object"
	readOnlyTestAccessKey  = "readonlyuser"
	readOnlyTestSecretKey  = "readonlysecret"
)

// setupUnsignedTrailerAuthTest starts an in-process object layer with the
// root credential and a read-only IAM user.
func setupUnsignedTrailerAuthTest(t *testing.T) (context.Context, auth.Credentials) {
	t.Helper()
	ctx, cancel := context.WithCancel(GlobalContext)
	t.Cleanup(cancel)

	objLayer, fsDir, err := prepareFS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(fsDir) })
	if err = newTestConfig(globalMinioDefaultRegion, objLayer); err != nil {
		t.Fatalf("unable initialize config file, %s", err)
	}
	initAllSubsystems(ctx)
	initConfigSubsystem(ctx, objLayer)

	root, err := auth.CreateCredentials("myuser", "mypassword")
	if err != nil {
		t.Fatalf("unable create credential, %s", err)
	}
	globalActiveCred = root
	globalIAMSys.Init(ctx, objLayer, globalEtcdClient, 2*time.Second)

	if _, err = globalIAMSys.CreateUser(ctx, readOnlyTestAccessKey, madmin.AddOrUpdateUserReq{
		SecretKey: readOnlyTestSecretKey,
		Status:    madmin.AccountEnabled,
	}); err != nil {
		t.Fatalf("unable to create user, %s", err)
	}
	if _, err = globalIAMSys.PolicyDBSet(ctx, readOnlyTestAccessKey, "readonly", regUser, false); err != nil {
		t.Fatalf("unable to attach policy, %s", err)
	}
	return ctx, root
}

// errCodeName names an APIErrorCode for test failure messages.
func errCodeName(code APIErrorCode) string {
	if code == ErrNone {
		return "no error (allowed)"
	}
	return errorCodes.ToAPIErr(code).Code
}

// queryCredential returns a SigV4 credential scope for accessKey.
func queryCredential(accessKey string) string {
	return fmt.Sprintf("%s/%s/%s/s3/aws4_request", accessKey, UTCNow().Format(yyyymmdd), globalMinioDefaultRegion)
}

// newUnsignedTrailerRequest returns an unsigned-trailer PUT. When accessKey is
// set the request is signed with SigV4 in the Authorization header.
func newUnsignedTrailerRequest(t *testing.T, rawQuery, accessKey, secretKey string) *http.Request {
	t.Helper()
	req := mustNewRequest(http.MethodPut, unsignedTrailerTestURL, 0, nil, t)
	req.URL.RawQuery = rawQuery
	req.Header.Set(xhttp.AmzContentSha256, unsignedPayloadTrailer)
	if accessKey != "" {
		if err := signRequestV4(req, accessKey, secretKey); err != nil {
			t.Fatal(err)
		}
	}
	if aType := getRequestAuthType(req); aType != authTypeStreamingUnsignedTrailer {
		t.Fatalf("expected unsigned-trailer request, got %v", aType)
	}
	return req
}

// Unsigned-trailer uploads must be authorized as the identity proven by the
// header signature, never as an access key named elsewhere in the request
// (GHSA-hv4r-mvr4-25vw, GHSA-9c4q-hq6p-c237).
func TestUnsignedTrailerPutAuthorization(t *testing.T) {
	ctx, root := setupUnsignedTrailerAuthTest(t)

	rootInQuery := url.Values{xhttp.AmzCredential: {queryCredential(root.AccessKey)}}.Encode()
	rootInQueryWithSig := url.Values{
		xhttp.AmzCredential: {queryCredential(root.AccessKey)},
		xhttp.AmzAlgorithm:  {signV4Algorithm},
		xhttp.AmzSignature:  {"0000000000000000000000000000000000000000000000000000000000000000"},
	}.Encode()

	badHeaderSignature := newUnsignedTrailerRequest(t, "", root.AccessKey, root.SecretKey)
	badHeaderSignature.Header.Set(xhttp.Authorization, fmt.Sprintf(
		"%s Credential=%s, SignedHeaders=host, Signature=%s",
		signV4Algorithm, queryCredential(root.AccessKey),
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))

	testCases := []struct {
		name string
		req  *http.Request
		want APIErrorCode
	}{
		{
			name: "root access key in query string without a signature",
			req:  newUnsignedTrailerRequest(t, rootInQuery, "", ""),
			want: ErrSignatureVersionNotSupported,
		},
		{
			name: "root access key in query string with a made-up signature",
			req:  newUnsignedTrailerRequest(t, rootInQueryWithSig, "", ""),
			want: ErrSignatureVersionNotSupported,
		},
		{
			name: "root access key in header with an invalid signature",
			req:  badHeaderSignature,
			want: ErrSignatureDoesNotMatch,
		},
		{
			name: "read-only user signs, root access key added to the query string",
			req:  newUnsignedTrailerRequest(t, rootInQuery, readOnlyTestAccessKey, readOnlyTestSecretKey),
			want: ErrSignatureVersionNotSupported,
		},
		{
			name: "no credentials and no bucket policy",
			req:  newUnsignedTrailerRequest(t, "", "", ""),
			want: ErrAccessDenied,
		},
		{
			name: "read-only user with a valid signature is denied by policy",
			req:  newUnsignedTrailerRequest(t, "", readOnlyTestAccessKey, readOnlyTestSecretKey),
			want: ErrAccessDenied,
		},
		{
			name: "root with a valid signature",
			req:  newUnsignedTrailerRequest(t, "", root.AccessKey, root.SecretKey),
			want: ErrNone,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := isPutActionAllowed(ctx, authTypeStreamingUnsignedTrailer, "bucket", "object", tc.req, policy.PutObjectAction)
			if got != tc.want {
				t.Fatalf("got %v, want %v", errCodeName(got), errCodeName(tc.want))
			}
		})
	}
}

// A request signed by one user must not be authorized as an access key named
// in the query string, for any signed request type.
func TestGetReqAccessKeyV4UsesVerifiedCredential(t *testing.T) {
	_, root := setupUnsignedTrailerAuthTest(t)

	req := mustNewRequest(http.MethodGet, unsignedTrailerTestURL, 0, nil, t)
	req.URL.RawQuery = url.Values{xhttp.AmzCredential: {queryCredential(root.AccessKey)}}.Encode()
	req.Header.Set(xhttp.AmzContentSha256, unsignedPayload)
	if err := signRequestV4(req, readOnlyTestAccessKey, readOnlyTestSecretKey); err != nil {
		t.Fatal(err)
	}
	if aType := getRequestAuthType(req); aType != authTypeSigned {
		t.Fatalf("expected signed request, got %v", aType)
	}
	if s3Err := doesSignatureMatch(unsignedPayload, req, globalSite.Region(), serviceS3); s3Err != ErrNone {
		t.Fatalf("expected the read-only user's signature to verify, got %v", errCodeName(s3Err))
	}
	cred, owner, s3Err := getReqAccessKeyV4(req, globalSite.Region(), serviceS3)
	if s3Err != ErrInvalidRequest || owner || cred.AccessKey != "" {
		t.Fatalf("got access key %q owner=%t err=%v, want rejection", cred.AccessKey, owner, errCodeName(s3Err))
	}

	signed := mustNewRequest(http.MethodGet, unsignedTrailerTestURL, 0, nil, t)
	signed.Header.Set(xhttp.AmzContentSha256, unsignedPayload)
	if err := signRequestV4(signed, readOnlyTestAccessKey, readOnlyTestSecretKey); err != nil {
		t.Fatal(err)
	}
	getRequestAuthType(signed)
	if cred, _, s3Err = getReqAccessKeyV4(signed, globalSite.Region(), serviceS3); s3Err != ErrNone || cred.AccessKey != readOnlyTestAccessKey {
		t.Fatalf("got access key %q err=%v, want %q", cred.AccessKey, errCodeName(s3Err), readOnlyTestAccessKey)
	}

	presigned := mustNewPresignedRequest(http.MethodGet, unsignedTrailerTestURL, 0, nil, t)
	getRequestAuthType(presigned)
	if cred, _, s3Err = getReqAccessKeyV4(presigned, globalSite.Region(), serviceS3); s3Err != ErrNone || cred.AccessKey == "" {
		t.Fatalf("presigned request: got access key %q err=%v", cred.AccessKey, errCodeName(s3Err))
	}
}

// Signed unsigned-trailer uploads get the same date checks as other signed
// requests; anonymous ones are passed on for bucket policy to decide.
func TestUnsignedTrailerRequestTimeSkew(t *testing.T) {
	_, root := setupUnsignedTrailerAuthTest(t)

	handler := setAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	stale := newUnsignedTrailerRequest(t, "", root.AccessKey, root.SecretKey)
	stale.Header.Set(xhttp.AmzDate, UTCNow().Add(-2*globalMaxSkewTime).Format(iso8601Format))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, stale)
	if want := errorCodes.ToAPIErr(ErrRequestTimeTooSkewed).HTTPStatusCode; rec.Code != want {
		t.Fatalf("stale signed request: got status %d, want %d", rec.Code, want)
	}

	fresh := newUnsignedTrailerRequest(t, "", root.AccessKey, root.SecretKey)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, fresh)
	if rec.Code != http.StatusOK {
		t.Fatalf("fresh signed request: got status %d, want %d", rec.Code, http.StatusOK)
	}

	anonymous := newUnsignedTrailerRequest(t, "", "", "")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, anonymous)
	if rec.Code != http.StatusOK {
		t.Fatalf("anonymous request: got status %d, want %d", rec.Code, http.StatusOK)
	}
}

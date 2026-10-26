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
	"archive/tar"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio-go/v7"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/mux"
)

// replicationMetadataTestHeaders returns the replication-only metadata
// headers with plausible SSE-C replication values.
func replicationMetadataTestHeaders(t testing.TB) map[string]string {
	t.Helper()
	sealedKey := make([]byte, 64)
	iv := make([]byte, 32)
	crc := make([]byte, 8)
	for _, b := range [][]byte{sealedKey, iv, crc} {
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
	}
	return map[string]string{
		"X-Minio-Replication-Server-Side-Encryption-Sealed-Key":     base64.StdEncoding.EncodeToString(sealedKey),
		"X-Minio-Replication-Server-Side-Encryption-Seal-Algorithm": "DARE-SHA256",
		"X-Minio-Replication-Server-Side-Encryption-Iv":             base64.StdEncoding.EncodeToString(iv),
		"X-Minio-Replication-Encrypted-Multipart":                   "true",
		"X-Minio-Replication-Actual-Object-Size":                    "999999",
		ReplicationSsecChecksumHeader:                               base64.StdEncoding.EncodeToString(crc),
	}
}

func TestExtractMetadataIgnoresReplicationHeaders(t *testing.T) {
	hdrs := replicationMetadataTestHeaders(t)
	if len(hdrs) != len(replicationToInternalHeaders) {
		t.Fatalf("test headers do not cover all replication headers")
	}
	h := make(textproto.MIMEHeader)
	q := make(textproto.MIMEHeader)
	for k, v := range hdrs {
		h.Set(k, v)
		// query string / form values are not canonicalized
		q[k] = []string{v}
	}
	h.Set("X-Amz-Meta-Foo", "bar")

	for name, input := range map[string][]textproto.MIMEHeader{
		"header": {h},
		"query":  {q},
		"both":   {q, h},
	} {
		t.Run(name, func(t *testing.T) {
			m, err := extractMetadata(t.Context(), input...)
			if err != nil {
				t.Fatal(err)
			}
			for k := range m {
				if stringsHasPrefixFold(k, ReservedMetadataPrefix) {
					t.Errorf("internal metadata key %q extracted from user input", k)
				}
				if _, ok := replicationToInternalHeaders[http.CanonicalHeaderKey(k)]; ok {
					t.Errorf("replication metadata key %q extracted from user input", k)
				}
			}
		})
	}
}

func TestExtractReplicationMetadata(t *testing.T) {
	hdrs := replicationMetadataTestHeaders(t)
	h := make(http.Header)
	for k, v := range hdrs {
		h.Set(k, v)
	}
	if !hasReplicationMetadata(h) {
		t.Fatal("expected replication metadata to be detected")
	}
	if hasReplicationMetadata(http.Header{"X-Amz-Meta-Foo": []string{"bar"}}) {
		t.Fatal("unexpected replication metadata detected")
	}
	m := make(map[string]string)
	extractReplicationMetadata(h, m)
	for k, internal := range replicationToInternalHeaders {
		if m[internal] != hdrs[k] {
			t.Errorf("%s: want %q, got %q", internal, hdrs[k], m[internal])
		}
	}
}

func TestReplicationMetadataNotAllowedWithoutSourceHeader(t *testing.T) {
	r := httptestNewRequest(t)
	for k, v := range replicationMetadataTestHeaders(t) {
		r.Header.Set(k, v)
	}
	allowed, s3Err := replicationMetadataAllowed(t.Context(), r, "bucket", "object")
	if allowed || s3Err != ErrNone {
		t.Fatalf("want (false, ErrNone), got (%v, %v)", allowed, s3Err)
	}
}

func httptestNewRequest(t *testing.T) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPut, "http://localhost/bucket/object", nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestContainsReservedMetadataInternalSSEKeys(t *testing.T) {
	// Map iteration order is random, repeat to cover all orders.
	for range 100 {
		h := http.Header{
			"X-Minio-Internal-Server-Side-Encryption-Iv": []string{"iv"},
			"X-Minio-Internal-Foo":                       []string{"bar"},
		}
		if !containsReservedMetadata(h) {
			t.Fatal("internal metadata keys must always be reserved")
		}
	}
	for k := range validSSEReplicationHeaders {
		if !containsReservedMetadata(http.Header{k: []string{"v"}}) {
			t.Fatalf("%s must be reserved", k)
		}
	}
}

// replTestUser creates an IAM user with a policy allowing actions on the
// objects of the given buckets.
func replTestUser(ctx context.Context, c *check, s *TestSuiteIAM, name string, buckets []string, actions ...string) madmin.Credentials {
	c.Helper()
	resources := make([]string, 0, len(buckets))
	for _, b := range buckets {
		resources = append(resources, "arn:aws:s3:::"+b+"/*")
	}
	pol := map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{{
			"Effect":   "Allow",
			"Action":   actions,
			"Resource": resources,
		}},
	}
	polBytes, err := json.Marshal(pol)
	if err != nil {
		c.Fatal(err)
	}
	if err = s.adm.AddCannedPolicy(ctx, name, polBytes); err != nil {
		c.Fatalf("policy add error: %v", err)
	}
	cred := c.mustCreateIAMUser(ctx, s.adm)
	if _, err = s.adm.AttachPolicy(ctx, madmin.PolicyAssociationReq{Policies: []string{name}, User: cred.AccessKey}); err != nil {
		c.Fatalf("unable to attach policy: %v", err)
	}
	return cred
}

// replTestDo sends a V4 signed request and returns the response and its body.
func replTestDo(c *check, s *TestSuiteIAM, cred madmin.Credentials, method, urlStr string, body []byte, hdrs map[string]string) (*http.Response, []byte) {
	c.Helper()
	req, err := newTestSignedRequestV4(method, urlStr, int64(len(body)), bytes.NewReader(body), cred.AccessKey, cred.SecretKey, hdrs)
	if err != nil {
		c.Fatal(err)
	}
	resp, err := s.TestSuiteCommon.client.Do(req)
	if err != nil {
		c.Fatal(err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.Fatal(err)
	}
	return resp, respBody
}

// TestReplicationMetadataInjection verifies that replication-only SSE, size
// and checksum metadata cannot be injected by principals that are not
// allowed to replicate objects (GHSA-3rh2-v3gr-35p9).
func TestReplicationMetadataInjection(t *testing.T) {
	s := newTestSuiteIAM(TestSuiteCommon{serverType: "ErasureSD", signer: signerV4}, false)
	c := &check{t, s.serverType}
	s.SetUpSuite(c)
	defer s.TearDownSuite(c)

	ctx, cancel := context.WithTimeout(context.Background(), 2*testDefaultTimeout)
	defer cancel()

	bucket := getRandomBucketName()
	if err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
		c.Fatalf("bucket create error: %v", err)
	}

	user := replTestUser(ctx, c, s, "replmeta-putget", []string{bucket}, "s3:PutObject", "s3:GetObject")
	replicator := replTestUser(ctx, c, s, "replmeta-replicator", []string{bucket}, "s3:PutObject", "s3:GetObject", "s3:ReplicateObject")

	do := func(cred madmin.Credentials, method, urlStr string, body []byte, hdrs map[string]string) (*http.Response, []byte) {
		c.Helper()
		return replTestDo(c, s, cred, method, urlStr, body, hdrs)
	}
	objURL := func(object string, q url.Values) string {
		return makeTestTargetURL(s.endPoint, bucket, object, q)
	}
	expectStatus := func(what string, resp *http.Response, body []byte, want int) {
		c.Helper()
		if resp.StatusCode != want {
			c.Fatalf("%s: want status %d, got %d: %s", what, want, resp.StatusCode, body)
		}
	}
	withHeaders := func(extra map[string]string, base map[string]string) map[string]string {
		m := make(map[string]string, len(extra)+len(base))
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	injected := replicationMetadataTestHeaders(t)
	sourceRepl := map[string]string{xhttp.MinIOSourceReplicationRequest: "true"}

	assertNoReplicationMetadata := func(object string) ObjectInfo {
		c.Helper()
		oi, err := s.testServer.Obj.GetObjectInfo(ctx, bucket, object, ObjectOptions{})
		if err != nil {
			c.Fatalf("%s: %v", object, err)
		}
		for _, internal := range replicationToInternalHeaders {
			if _, ok := oi.UserDefined[internal]; ok {
				c.Fatalf("%s: injected metadata %q stored", object, internal)
			}
		}
		return oi
	}
	// assertIntact verifies the object is readable via plain GET/HEAD
	// with identical bytes and carries no injected metadata.
	assertIntact := func(object string, data []byte) {
		c.Helper()
		resp, body := do(user, http.MethodGet, objURL(object, nil), nil, nil)
		expectStatus("GET "+object, resp, body, http.StatusOK)
		if !bytes.Equal(body, data) {
			c.Fatalf("GET %s: content mismatch", object)
		}
		resp, body = do(user, http.MethodHead, objURL(object, nil), nil, nil)
		expectStatus("HEAD "+object, resp, body, http.StatusOK)
		if resp.ContentLength != int64(len(data)) {
			c.Fatalf("HEAD %s: want size %d, got %d", object, len(data), resp.ContentLength)
		}
		assertNoReplicationMetadata(object)
	}
	newData := func() []byte {
		b := make([]byte, 1024)
		rand.Read(b)
		return b
	}

	type initResp struct {
		UploadID string `xml:"UploadId"`
	}
	multipartUpload := func(cred madmin.Credentials, object string, data []byte, initHdrs, completeHdrs map[string]string) (*http.Response, []byte) {
		c.Helper()
		resp, body := do(cred, http.MethodPost, objURL(object, url.Values{"uploads": {""}}), nil, initHdrs)
		if resp.StatusCode != http.StatusOK {
			return resp, body
		}
		var ir initResp
		if err := xml.Unmarshal(body, &ir); err != nil {
			c.Fatal(err)
		}
		resp, body = do(cred, http.MethodPut, objURL(object, url.Values{"uploadId": {ir.UploadID}, "partNumber": {"1"}}), data, nil)
		expectStatus("PutObjectPart", resp, body, http.StatusOK)
		cmu := CompleteMultipartUpload{Parts: []CompletePart{{PartNumber: 1, ETag: resp.Header.Get(xhttp.ETag)}}}
		cbody, err := xml.Marshal(cmu)
		if err != nil {
			c.Fatal(err)
		}
		return do(cred, http.MethodPost, objURL(object, url.Values{"uploadId": {ir.UploadID}}), cbody, completeHdrs)
	}

	// 1. PutObject with replication headers, without replication request header.
	data := newData()
	resp, body := do(user, http.MethodPut, objURL("put-headers", nil), data, injected)
	expectStatus("PutObject headers", resp, body, http.StatusOK)
	assertIntact("put-headers", data)

	// 2. PutObject with replication metadata in the query string.
	q := url.Values{}
	for k, v := range injected {
		q.Set(k, v)
	}
	q.Set(xhttp.MinIOSourceReplicationRequest, "true")
	resp, body = do(user, http.MethodPut, objURL("put-query", q), data, nil)
	expectStatus("PutObject query", resp, body, http.StatusOK)
	assertIntact("put-query", data)

	// 3. PutObject claiming replication without s3:ReplicateObject.
	resp, body = do(user, http.MethodPut, objURL("put-repl", nil), data, withHeaders(sourceRepl, injected))
	expectStatus("PutObject replication claim", resp, body, http.StatusForbidden)

	// 4. NewMultipartUpload + Complete with replication headers.
	resp, body = multipartUpload(user, "mp-headers", data, injected, nil)
	expectStatus("multipart headers", resp, body, http.StatusOK)
	assertIntact("mp-headers", data)

	// 5. NewMultipartUpload claiming replication without s3:ReplicateObject.
	resp, body = multipartUpload(user, "mp-repl", data, withHeaders(sourceRepl, injected), nil)
	expectStatus("NewMultipartUpload replication claim", resp, body, http.StatusForbidden)

	// 6. NewMultipartUpload marked as replica without s3:ReplicateObject.
	resp, body = multipartUpload(user, "mp-replica", data, map[string]string{xhttp.AmzBucketReplicationStatus: "REPLICA"}, nil)
	expectStatus("NewMultipartUpload replica", resp, body, http.StatusForbidden)

	// 7. CompleteMultipartUpload claiming replication with an actual size.
	resp, body = multipartUpload(user, "mp-size", data, nil, withHeaders(sourceRepl, map[string]string{
		xhttp.MinIOReplicationActualObjectSize: "999999",
		ReplicationSsecChecksumHeader:          injected[ReplicationSsecChecksumHeader],
	}))
	expectStatus("CompleteMultipartUpload replication claim", resp, body, http.StatusOK)
	assertIntact("mp-size", data)
	oi := assertNoReplicationMetadata("mp-size")
	if got := oi.UserDefined[ReservedMetadataPrefix+"actual-size"]; got != strconv.Itoa(len(data)) {
		c.Fatalf("CompleteMultipartUpload: want actual size %d, got %q", len(data), got)
	}

	// 8. CopyObject with REPLACE directive.
	resp, body = do(user, http.MethodPut, objURL("copy-src", nil), data, nil)
	expectStatus("PutObject copy source", resp, body, http.StatusOK)
	resp, body = do(user, http.MethodPut, objURL("copy-dst", nil), nil, withHeaders(map[string]string{
		xhttp.AmzCopySource:        "/" + bucket + "/copy-src",
		xhttp.AmzMetadataDirective: replaceDirective,
	}, injected))
	expectStatus("CopyObject REPLACE", resp, body, http.StatusOK)
	assertIntact("copy-dst", data)

	// 9. PostPolicy with replication metadata form fields.
	{
		now := UTCNow()
		region := "us-east-1"
		credStr := getCredentialString(user.AccessKey, region, now)
		fields := map[string]string{
			"bucket":           bucket,
			"key":              "post-policy",
			"x-amz-credential": credStr,
			"x-amz-date":       now.Format(iso8601DateFormat),
			"x-amz-algorithm":  "AWS4-HMAC-SHA256",
		}
		for k, v := range injected {
			fields[k] = v
		}
		conds := []any{}
		for k, v := range fields {
			conds = append(conds, []string{"eq", "$" + k, v})
		}
		policyBytes, err := json.Marshal(map[string]any{
			"expiration": now.Add(5 * time.Minute).Format(iso8601TimeFormat),
			"conditions": conds,
		})
		if err != nil {
			c.Fatal(err)
		}
		encodedPolicy := base64.StdEncoding.EncodeToString(policyBytes)
		fields["policy"] = encodedPolicy
		fields["x-amz-signature"] = postPresignSignatureV4(encodedPolicy, now, user.SecretKey, region)

		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		for k, v := range fields {
			w.WriteField(k, v)
		}
		fw, err := w.CreateFormFile("file", "upload.txt")
		if err != nil {
			c.Fatal(err)
		}
		fw.Write(data)
		w.Close()
		req, err := http.NewRequest(http.MethodPost, makeTestTargetURL(s.endPoint, bucket, "", nil), &buf)
		if err != nil {
			c.Fatal(err)
		}
		req.Header.Set("Content-Type", w.FormDataContentType())
		presp, err := s.TestSuiteCommon.client.Do(req)
		if err != nil {
			c.Fatal(err)
		}
		pbody, _ := io.ReadAll(presp.Body)
		presp.Body.Close()
		expectStatus("PostPolicy", presp, pbody, http.StatusNoContent)
		assertIntact("post-policy", data)
	}

	// 10. Snowball auto-extract with replication metadata PAX records.
	{
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		pax := map[string]string{}
		for k, v := range injected {
			pax["minio.metadata."+k] = v
		}
		hdr := &tar.Header{
			Name:       "snowball-obj",
			Mode:       0o600,
			Size:       int64(len(data)),
			ModTime:    time.Now(),
			Format:     tar.FormatPAX,
			PAXRecords: pax,
			Typeflag:   tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			c.Fatal(err)
		}
		tw.Write(data)
		tw.Close()
		resp, body = do(user, http.MethodPut, objURL("archive.tar", nil), buf.Bytes(), map[string]string{
			xhttp.AmzSnowballExtract: "true",
		})
		expectStatus("PutObjectExtract", resp, body, http.StatusOK)
		assertIntact("snowball-obj", data)
	}

	// 11. Positive control: an authorized replicator may set the metadata.
	resp, body = do(replicator, http.MethodPut, objURL("repl-ok", nil), data, withHeaders(sourceRepl, injected))
	expectStatus("replicator PutObject", resp, body, http.StatusOK)
	oi, err := s.testServer.Obj.GetObjectInfo(ctx, bucket, "repl-ok", ObjectOptions{})
	if err != nil {
		c.Fatal(err)
	}
	for k, internal := range replicationToInternalHeaders {
		if k == ReplicationSsecChecksumHeader {
			// consumed by the object layer into the object checksum
			continue
		}
		if got := oi.UserDefined[internal]; got != injected[k] {
			c.Fatalf("replicator PutObject: %s want %q, got %q", internal, injected[k], got)
		}
	}

	resp, body = multipartUpload(replicator, "repl-mp-size", data, nil, withHeaders(sourceRepl, map[string]string{
		xhttp.MinIOReplicationActualObjectSize: "12345",
	}))
	expectStatus("replicator CompleteMultipartUpload", resp, body, http.StatusOK)
	oi, err = s.testServer.Obj.GetObjectInfo(ctx, bucket, "repl-mp-size", ObjectOptions{})
	if err != nil {
		c.Fatal(err)
	}
	if got := oi.UserDefined[ReservedMetadataPrefix+"actual-size"]; got != "12345" {
		c.Fatal(fmt.Sprintf("replicator CompleteMultipartUpload: want actual size 12345, got %q", got))
	}
}

// TestReplicationHeadersRequirePermission verifies that replication-only
// request headers (X-Minio-Source-Replication-Request, replication status,
// source ETag/mtime and friends) are honoured only for principals allowed
// to replicate.
func TestReplicationHeadersRequirePermission(t *testing.T) {
	// SSE-C requires TLS.
	defer func(isTLS bool) { globalIsTLS = isTLS }(globalIsTLS)
	globalIsTLS = true
	s := newTestSuiteIAM(TestSuiteCommon{serverType: "ErasureSD", signer: signerV4}, false)
	c := &check{t, s.serverType}
	s.SetUpSuite(c)
	defer s.TearDownSuite(c)

	ctx, cancel := context.WithTimeout(context.Background(), 2*testDefaultTimeout)
	defer cancel()

	bucket := getRandomBucketName()
	if err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
		c.Fatalf("bucket create error: %v", err)
	}
	lockBucket := getRandomBucketName()
	if err := s.client.MakeBucket(ctx, lockBucket, minio.MakeBucketOptions{ObjectLocking: true}); err != nil {
		c.Fatalf("bucket create error: %v", err)
	}
	buckets := []string{bucket, lockBucket}
	user := replTestUser(ctx, c, s, "replhdr-user", buckets,
		"s3:PutObject", "s3:GetObject", "s3:PutObjectRetention")
	replicator := replTestUser(ctx, c, s, "replhdr-replicator", buckets,
		"s3:PutObject", "s3:GetObject", "s3:PutObjectRetention", "s3:ReplicateObject", "s3:ReplicateDelete")

	do := func(cred madmin.Credentials, method, urlStr string, body []byte, hdrs map[string]string) (*http.Response, []byte) {
		c.Helper()
		return replTestDo(c, s, cred, method, urlStr, body, hdrs)
	}
	objURL := func(b, object string, q url.Values) string {
		return makeTestTargetURL(s.endPoint, b, object, q)
	}
	expectStatus := func(what string, resp *http.Response, body []byte, want int) {
		c.Helper()
		if resp.StatusCode != want {
			c.Fatalf("%s: want status %d, got %d: %s", what, want, resp.StatusCode, body)
		}
	}
	merge := func(ms ...map[string]string) map[string]string {
		out := map[string]string{}
		for _, m := range ms {
			for k, v := range m {
				out[k] = v
			}
		}
		return out
	}
	data := make([]byte, 1024)
	rand.Read(data)
	sourceRepl := map[string]string{xhttp.MinIOSourceReplicationRequest: "true"}

	// 1. Source ETag and mtime are preserved only for replicators.
	const srcETag = "0123456789abcdef0123456789abcdef"
	srcMTime := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	preserve := merge(sourceRepl, map[string]string{
		xhttp.MinIOSourceETag:  srcETag,
		xhttp.MinIOSourceMTime: srcMTime.Format(time.RFC3339Nano),
	})
	for _, tc := range []struct {
		cred     madmin.Credentials
		object   string
		preserve bool
	}{
		{user, "preserve-user", false},
		{replicator, "preserve-replicator", true},
	} {
		resp, body := do(tc.cred, http.MethodPut, objURL(bucket, tc.object, nil), data, preserve)
		expectStatus("PutObject "+tc.object, resp, body, http.StatusOK)
		oi, err := s.testServer.Obj.GetObjectInfo(ctx, bucket, tc.object, ObjectOptions{})
		if err != nil {
			c.Fatal(err)
		}
		if got := oi.ETag == srcETag; got != tc.preserve {
			c.Fatalf("%s: ETag %q, want preserved=%v", tc.object, oi.ETag, tc.preserve)
		}
		if got := oi.ModTime.Equal(srcMTime); got != tc.preserve {
			c.Fatalf("%s: mtime %v, want preserved=%v", tc.object, oi.ModTime, tc.preserve)
		}
	}

	// 2. Past retain-until dates are accepted only from replicators.
	pastRetention := merge(sourceRepl, map[string]string{
		xhttp.AmzObjectLockMode:            "GOVERNANCE",
		xhttp.AmzObjectLockRetainUntilDate: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	})
	resp, body := do(user, http.MethodPut, objURL(lockBucket, "retention", nil), data, pastRetention)
	expectStatus("PutObject past retention by user", resp, body, http.StatusBadRequest)
	resp, body = do(replicator, http.MethodPut, objURL(lockBucket, "retention", nil), data, pastRetention)
	expectStatus("PutObject past retention by replicator", resp, body, http.StatusOK)

	// 3. Requests are treated as replication requests (no re-replication,
	//    no event notification) only for replicators.
	for _, tc := range []struct {
		cred madmin.Credentials
		want bool
	}{{user, false}, {replicator, true}} {
		object := "opts"
		req, err := newTestSignedRequestV4(http.MethodPut, objURL(bucket, object, nil), 0, nil, tc.cred.AccessKey, tc.cred.SecretKey, sourceRepl)
		if err != nil {
			c.Fatal(err)
		}
		req = mux.SetURLVars(req, map[string]string{"bucket": bucket, "object": object})
		popts, err := putOptsFromReq(ctx, req, bucket, object, map[string]string{})
		if err != nil {
			c.Fatal(err)
		}
		gopts, err := getOpts(ctx, req, bucket, object)
		if err != nil {
			c.Fatal(err)
		}
		_, evtSuppressed := extractReqParams(req)[xhttp.MinIOSourceReplicationRequest]
		if popts.ReplicationRequest != tc.want || gopts.ReplicationRequest != tc.want || evtSuppressed != tc.want {
			c.Fatalf("%s: replication request put=%v get=%v event=%v, want %v", tc.cred.AccessKey,
				popts.ReplicationRequest, gopts.ReplicationRequest, evtSuppressed, tc.want)
		}

		dreq, err := newTestSignedRequestV4(http.MethodDelete, objURL(bucket, object, nil), 0, nil, tc.cred.AccessKey, tc.cred.SecretKey,
			merge(sourceRepl, map[string]string{xhttp.MinIOSourceDeleteMarker: "true"}))
		if err != nil {
			c.Fatal(err)
		}
		dopts, err := delOpts(ctx, dreq, bucket, object)
		if err != nil {
			c.Fatal(err)
		}
		if dopts.ReplicationRequest != tc.want || dopts.DeleteMarker != tc.want {
			c.Fatalf("%s: delete replication request=%v delete marker=%v, want %v", tc.cred.AccessKey,
				dopts.ReplicationRequest, dopts.DeleteMarker, tc.want)
		}
	}

	// 4. Replication status is never taken from query parameters and
	//    stored only for replicators.
	resp, body = do(user, http.MethodPut, objURL(bucket, "status-query", url.Values{xhttp.AmzBucketReplicationStatus: {"REPLICA"}}), data, nil)
	expectStatus("PutObject status query", resp, body, http.StatusOK)
	resp, body = do(user, http.MethodPut, objURL(bucket, "status-header", nil), data, map[string]string{xhttp.AmzBucketReplicationStatus: "COMPLETED"})
	expectStatus("PutObject status header", resp, body, http.StatusOK)
	resp, body = do(user, http.MethodPut, objURL(bucket, "status-copy", nil), nil, map[string]string{
		xhttp.AmzCopySource:              "/" + bucket + "/status-header",
		xhttp.AmzBucketReplicationStatus: "COMPLETED",
	})
	expectStatus("CopyObject status", resp, body, http.StatusOK)
	for _, object := range []string{"status-query", "status-header", "status-copy"} {
		oi, err := s.testServer.Obj.GetObjectInfo(ctx, bucket, object, ObjectOptions{})
		if err != nil {
			c.Fatal(err)
		}
		if v, ok := oi.UserDefined[xhttp.AmzBucketReplicationStatus]; ok {
			c.Fatalf("%s: replication status %q stored", object, v)
		}
		if v, ok := oi.UserDefined[ReservedMetadataPrefixLower+ReplicaStatus]; ok {
			c.Fatalf("%s: replica status %q stored", object, v)
		}
		if !oi.ReplicationStatus.Empty() {
			c.Fatalf("%s: replication status %q reported", object, oi.ReplicationStatus)
		}
	}
	resp, body = do(user, http.MethodPut, objURL(bucket, "status-copy-replica", nil), nil, map[string]string{
		xhttp.AmzCopySource:              "/" + bucket + "/status-header",
		xhttp.AmzBucketReplicationStatus: "REPLICA",
	})
	expectStatus("CopyObject REPLICA by user", resp, body, http.StatusForbidden)
	resp, body = do(replicator, http.MethodPut, objURL(bucket, "status-replica", nil), data, merge(sourceRepl, map[string]string{
		xhttp.AmzBucketReplicationStatus: "REPLICA",
	}))
	expectStatus("PutObject REPLICA by replicator", resp, body, http.StatusOK)
	resp, body = do(user, http.MethodHead, objURL(bucket, "status-replica", nil), nil, nil)
	expectStatus("HEAD replica", resp, body, http.StatusOK)
	if got := resp.Header.Get(xhttp.AmzBucketReplicationStatus); got != "REPLICA" {
		c.Fatalf("replica: want replication status REPLICA, got %q", got)
	}

	// SSE-C request headers
	ssecKey := make([]byte, 32)
	rand.Read(ssecKey)
	keyMD5 := md5.Sum(ssecKey)
	ssec := map[string]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: "AES256",
		xhttp.AmzServerSideEncryptionCustomerKey:       base64.StdEncoding.EncodeToString(ssecKey),
		xhttp.AmzServerSideEncryptionCustomerKeyMD5:    base64.StdEncoding.EncodeToString(keyMD5[:]),
	}

	// 5. SSE-C parts are encrypted unless uploaded by a replicator.
	{
		object := "ssec-mp"
		resp, body = do(user, http.MethodPost, objURL(bucket, object, url.Values{"uploads": {""}}), nil, ssec)
		expectStatus("NewMultipartUpload SSE-C", resp, body, http.StatusOK)
		var ir struct {
			UploadID string `xml:"UploadId"`
		}
		if err := xml.Unmarshal(body, &ir); err != nil {
			c.Fatal(err)
		}
		resp, body = do(user, http.MethodPut, objURL(bucket, object, url.Values{"uploadId": {ir.UploadID}, "partNumber": {"1"}}), data, merge(ssec, sourceRepl))
		expectStatus("PutObjectPart SSE-C with replication header", resp, body, http.StatusOK)
		cmu := CompleteMultipartUpload{Parts: []CompletePart{{PartNumber: 1, ETag: resp.Header.Get(xhttp.ETag)}}}
		cbody, err := xml.Marshal(cmu)
		if err != nil {
			c.Fatal(err)
		}
		resp, body = do(user, http.MethodPost, objURL(bucket, object, url.Values{"uploadId": {ir.UploadID}}), cbody, ssec)
		expectStatus("CompleteMultipartUpload SSE-C", resp, body, http.StatusOK)
		resp, body = do(user, http.MethodGet, objURL(bucket, object, nil), nil, ssec)
		expectStatus("GET SSE-C multipart", resp, body, http.StatusOK)
		if !bytes.Equal(body, data) {
			c.Fatal("GET SSE-C multipart: content mismatch")
		}
	}

	// 6. SSE-C objects are not readable or copyable without the key,
	//    except raw access by replicators.
	resp, body = do(user, http.MethodPut, objURL(bucket, "ssec", nil), data, ssec)
	expectStatus("PutObject SSE-C", resp, body, http.StatusOK)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		resp, body = do(user, method, objURL(bucket, "ssec", nil), nil, sourceRepl)
		expectStatus(method+" SSE-C without key by user", resp, body, http.StatusBadRequest)
	}
	resp, body = do(user, http.MethodPut, objURL(bucket, "ssec-copy", nil), nil, merge(sourceRepl, map[string]string{
		xhttp.AmzCopySource: "/" + bucket + "/ssec",
	}))
	expectStatus("CopyObject SSE-C without key by user", resp, body, http.StatusBadRequest)
	oi, err := s.testServer.Obj.GetObjectInfo(ctx, bucket, "ssec", ObjectOptions{})
	if err != nil {
		c.Fatal(err)
	}
	for _, tc := range []struct {
		cred    madmin.Credentials
		wantErr error
	}{{user, errEncryptedObject}, {replicator, nil}} {
		req, err := newTestSignedRequestV4(http.MethodGet, objURL(bucket, "ssec", nil), 0, nil, tc.cred.AccessKey, tc.cred.SecretKey, sourceRepl)
		if err != nil {
			c.Fatal(err)
		}
		info := oi.Clone()
		if _, err = DecryptObjectInfo(&info, req); err != tc.wantErr {
			c.Fatalf("%s: DecryptObjectInfo without key: want %v, got %v", tc.cred.AccessKey, tc.wantErr, err)
		}
	}
}

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
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/minio/minio-go/v7/pkg/signer"
)

// unsignedTrailerUpload builds an unsigned-trailer PUT with a CRC32 trailer,
// the way minio-go sends it. With credentials it is signed with SigV4 in the
// Authorization header; without, it carries no credentials.
func (s *TestSuiteCommon) unsignedTrailerUpload(c *check, urlStr string, body []byte, header http.Header, signed bool) *http.Request {
	c.Helper()
	req, err := http.NewRequest(http.MethodPut, urlStr, bytes.NewReader(body))
	c.Assert(err, nil)
	req.ContentLength = int64(len(body))
	for k, v := range header {
		req.Header[k] = v
	}

	sum := make([]byte, 4)
	binary.BigEndian.PutUint32(sum, crc32.ChecksumIEEE(body))
	trailer := http.Header{}
	trailer.Set("x-amz-checksum-crc32", base64.StdEncoding.EncodeToString(sum))

	req.Header.Set("X-Amz-Content-Sha256", unsignedPayloadTrailer)
	if signed {
		return signer.SignV4Trailer(*req, s.accessKey, s.secretKey, "", globalMinioDefaultRegion, trailer)
	}
	return signer.UnsignedTrailer(*req, trailer)
}

// objectExists reports whether a signed HEAD finds the object.
func (s *TestSuiteCommon) objectExists(c *check, bucket, object string) bool {
	c.Helper()
	req, err := newTestSignedRequest(http.MethodHead, getHeadObjectURL(s.endPoint, bucket, object), 0, nil, s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)
	resp, err := s.client.Do(req)
	c.Assert(err, nil)
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func snowballArchive(c *check, name string, content []byte) []byte {
	c.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	c.Assert(tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content))}), nil)
	_, err := tw.Write(content)
	c.Assert(err, nil)
	c.Assert(tw.Close(), nil)
	return buf.Bytes()
}

// TestUnsignedTrailerUploads checks that unsigned-trailer uploads are accepted
// only with a valid header signature (GHSA-hv4r-mvr4-25vw,
// GHSA-9c4q-hq6p-c237), and that correctly signed uploads keep working.
func (s *TestSuiteCommon) TestUnsignedTrailerUploads(c *check) {
	c.Helper()
	bucket := getRandomBucketName()
	req, err := newTestSignedRequest(http.MethodPut, getMakeBucketURL(s.endPoint, bucket), 0, nil, s.accessKey, s.secretKey, s.signer)
	c.Assert(err, nil)
	resp, err := s.client.Do(req)
	c.Assert(err, nil)
	resp.Body.Close()
	c.Assert(resp.StatusCode, http.StatusOK)

	content := []byte("unsigned trailer payload\n")
	snowball := http.Header{"X-Amz-Meta-Snowball-Auto-Extract": {"true"}}

	// A correctly signed upload is stored.
	resp, err = s.client.Do(s.unsignedTrailerUpload(c, getPutObjectURL(s.endPoint, bucket, "signed.txt"), content, nil, true))
	c.Assert(err, nil)
	resp.Body.Close()
	c.Assert(resp.StatusCode, http.StatusOK)
	c.Assert(s.objectExists(c, bucket, "signed.txt"), true)

	// A correctly signed snowball upload is extracted.
	resp, err = s.client.Do(s.unsignedTrailerUpload(c, getPutObjectURL(s.endPoint, bucket, "signed.tar"), snowballArchive(c, "extracted-signed.txt", content), snowball, true))
	c.Assert(err, nil)
	resp.Body.Close()
	c.Assert(resp.StatusCode, http.StatusOK)
	c.Assert(s.objectExists(c, bucket, "extracted-signed.txt"), true)

	// An access key named only in the query string is not accepted.
	queryCred := s.unsignedTrailerUpload(c, getPutObjectURL(s.endPoint, bucket, "query-credential.txt"), content, nil, false)
	queryCred.URL.RawQuery = url.Values{"X-Amz-Credential": {queryCredential(s.accessKey)}}.Encode()
	resp, err = s.client.Do(queryCred)
	c.Assert(err, nil)
	resp.Body.Close()
	c.Assert(resp.StatusCode >= http.StatusBadRequest, true)
	c.Assert(s.objectExists(c, bucket, "query-credential.txt"), false)

	// A snowball upload with a signature that does not verify is not extracted.
	forged := s.unsignedTrailerUpload(c, getPutObjectURL(s.endPoint, bucket, "forged.tar"), snowballArchive(c, "extracted-forged.txt", content), snowball, true)
	authz := forged.Header.Get("Authorization")
	i := strings.LastIndex(authz, "Signature=") + len("Signature=")
	forged.Header.Set("Authorization", authz[:i]+strings.Repeat("0", len(authz)-i))
	resp, err = s.client.Do(forged)
	c.Assert(err, nil)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	c.Assert(resp.StatusCode, http.StatusForbidden)
	c.Assert(s.objectExists(c, bucket, "extracted-forged.txt"), false)
}

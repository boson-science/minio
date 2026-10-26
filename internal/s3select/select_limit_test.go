// Copyright (c) 2015-2021 MinIO, Inc.
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

package s3select

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"

	"github.com/klauspost/compress/gzip"
)

// repeatReader lazily produces n copies of c without holding them in memory.
type repeatReader struct {
	c byte
	n int64
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.n {
		p = p[:r.n]
	}
	for i := range p {
		p[i] = r.c
	}
	r.n -= int64(len(p))
	return len(p), nil
}

type countingWriter struct{ n int64 }

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return len(p), nil
}

// writeGzip compresses prefix followed by n bytes of 'a' into w.
func writeGzip(w io.Writer, prefix string, n int64) error {
	gw, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
	if err != nil {
		return err
	}
	if _, err = io.Copy(gw, io.MultiReader(strings.NewReader(prefix), &repeatReader{c: 'a', n: n})); err != nil {
		return err
	}
	return gw.Close()
}

// newGzipLongLineRSC returns an object whose content is a gzip stream of
// prefix followed by n bytes of 'a' without any newline.
// The stream is generated on the fly and never held in memory.
func newGzipLongLineRSC(t *testing.T, prefix string, n int64) io.ReadSeekCloser {
	t.Helper()
	var size countingWriter
	if err := writeGzip(&size, prefix, n); err != nil {
		t.Fatal(err)
	}
	t.Logf("compressed size of %d byte line: %d bytes", n, size.n)
	segmentReader := func(offset int64) (io.ReadCloser, error) {
		if offset != 0 {
			return nil, errors.New("unexpected offset")
		}
		pr, pw := io.Pipe()
		go func() {
			// Fails once the reader is closed.
			pw.CloseWithError(writeGzip(pw, prefix, n))
		}()
		return pr, nil
	}
	return NewObjectReadSeekCloser(segmentReader, size.n)
}

func longLineRequest(input string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<SelectObjectContentRequest>
    <Expression>SELECT * from S3Object</Expression>
    <ExpressionType>SQL</ExpressionType>
    <InputSerialization>
        <CompressionType>GZIP</CompressionType>
        ` + input + `
    </InputSerialization>
    <OutputSerialization>
        <JSON>
        </JSON>
    </OutputSerialization>
    <RequestProgress>
        <Enabled>FALSE</Enabled>
    </RequestProgress>
</SelectObjectContentRequest>`
}

func totalAlloc() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.TotalAlloc
}

// TestS3SelectGzipLongLine verifies that a small compressed object that
// decompresses to a very long line does not cause unbounded allocations
// (GHSA-h749-fxx7-pwpg).
func TestS3SelectGzipLongLine(t *testing.T) {
	const lineSize = 256 << 20
	// Generous bounds; reading the whole line would exceed both by far.
	const maxDecompressed = 16 << 20
	const maxAllocated = 128 << 20

	cases := []struct {
		name   string
		input  string
		prefix string
	}{
		{"csv-use", `<CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV>`, ""},
		{"csv-none", `<CSV><FileHeaderInfo>NONE</FileHeaderInfo></CSV>`, ""},
		{"csv-custom-delimiter", `<CSV><FileHeaderInfo>NONE</FileHeaderInfo><RecordDelimiter>;</RecordDelimiter></CSV>`, ""},
		{"json-lines", `<JSON><Type>LINES</Type></JSON>`, `{"a":"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rsc := newGzipLongLineRSC(t, c.prefix, lineSize)
			s3Select, err := NewS3Select(strings.NewReader(longLineRequest(c.input)))
			if err != nil {
				t.Fatal(err)
			}

			runtime.GC()
			before := totalAlloc()
			var code string
			if err = s3Select.Open(rsc); err != nil {
				var serr SelectError
				if !errors.As(err, &serr) {
					t.Fatalf("Open: unexpected error %v", err)
				}
				code = serr.ErrorCode()
			} else {
				w := &testResponseWriter{}
				s3Select.Evaluate(w)
				s3Select.Close()
				if bytes.Contains(w.response, []byte("OverMaxRecordSize")) {
					code = "OverMaxRecordSize"
				}
			}
			allocated := totalAlloc() - before
			_, decompressed := s3Select.progressReader.Stats()
			t.Logf("decompressed %d bytes, allocated %d bytes", decompressed, allocated)

			if code != "OverMaxRecordSize" {
				t.Fatalf("expected OverMaxRecordSize, got %q (err %v)", code, err)
			}
			if decompressed > maxDecompressed {
				t.Fatalf("decompressed %d bytes, want <= %d", decompressed, maxDecompressed)
			}
			if allocated > maxAllocated {
				t.Fatalf("allocated %d bytes, want <= %d", allocated, maxAllocated)
			}
		})
	}
}

// TestS3SelectLongLineAfterRecords verifies the error is reported with the
// OverMaxRecordSize code when it occurs after records have been sent.
func TestS3SelectLongLineAfterRecords(t *testing.T) {
	var input bytes.Buffer
	input.WriteString("a,b\n")
	for i := 0; input.Len() < 1<<20; i++ {
		fmt.Fprintf(&input, "%d,x\n", i)
	}
	input.Write(bytes.Repeat([]byte("a"), 2<<20))

	req := strings.Replace(longLineRequest(`<CSV><FileHeaderInfo>USE</FileHeaderInfo></CSV>`),
		"<CompressionType>GZIP</CompressionType>", "<CompressionType>NONE</CompressionType>", 1)
	s3Select, err := NewS3Select(strings.NewReader(req))
	if err != nil {
		t.Fatal(err)
	}
	if err = s3Select.Open(newBytesRSC(input.Bytes())); err != nil {
		t.Fatal(err)
	}
	w := &testResponseWriter{}
	s3Select.Evaluate(w)
	s3Select.Close()
	if !bytes.Contains(w.response, []byte("OverMaxRecordSize")) || bytes.Contains(w.response, []byte("InternalError")) {
		t.Fatal("expected response to end with OverMaxRecordSize error")
	}
	if !bytes.Contains(w.response, []byte(`{"a":"0","b":"x"}`)) {
		t.Fatal("expected records before the oversized record")
	}
}

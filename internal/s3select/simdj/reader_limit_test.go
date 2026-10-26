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

package simdj

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/minio/minio/internal/s3select/json"
	"github.com/minio/minio/internal/s3select/sql"
	"github.com/minio/simdjson-go"
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

// countingReader counts the bytes read from r.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func requireOverMaxRecordSize(t *testing.T, err error) {
	t.Helper()
	var serr *s3Error
	if !errors.As(err, &serr) || serr.ErrorCode() != "OverMaxRecordSize" {
		t.Fatalf("expected OverMaxRecordSize error, got %v", err)
	}
}

func readAll(r *Reader) (int, error) {
	var rec sql.Record
	var err error
	for n := 0; ; n++ {
		if rec, err = r.Read(rec); err != nil {
			return n, err
		}
	}
}

// TestReaderLongLine verifies that JSON LINES input without a newline is not
// buffered without limit (GHSA-h749-fxx7-pwpg).
func TestReaderLongLine(t *testing.T) {
	if !simdjson.SupportedCPU() {
		t.Skip("Unsupported cpu")
	}
	// simdjson.ParseNDStream reads in chunks of up to 10 MiB before
	// scanning for the next newline.
	const parseChunk = 10 << 20
	cr := &countingReader{r: io.MultiReader(
		strings.NewReader(`{"a":"`),
		&repeatReader{c: 'a', n: 64 << 20},
	)}
	r := NewReader(io.NopCloser(cr), &json.ReaderArgs{ContentType: "lines"})
	_, err := readAll(r)
	r.Close()
	requireOverMaxRecordSize(t, err)
	if limit := int64(parseChunk + maxRecordSize); cr.n > limit {
		t.Fatalf("consumed %d bytes, want <= %d", cr.n, limit)
	}
}

func TestReaderMaxRecordSize(t *testing.T) {
	if !simdjson.SupportedCPU() {
		t.Skip("Unsupported cpu")
	}
	for _, c := range []struct {
		size    int
		wantErr bool
	}{
		{maxRecordSize - 1, false},
		{maxRecordSize, false},
		{maxRecordSize + 1, true},
	} {
		const prefix, suffix = `{"a":"`, `"}`
		rec := prefix + strings.Repeat("a", c.size-len(prefix)-len(suffix)) + suffix
		input := `{"b":1}` + "\n" + rec + "\n" + `{"c":2}` + "\n"
		r := NewReader(io.NopCloser(strings.NewReader(input)), &json.ReaderArgs{ContentType: "lines"})
		n, err := readAll(r)
		r.Close()
		if c.wantErr {
			requireOverMaxRecordSize(t, err)
			continue
		}
		if err != io.EOF || n != 3 {
			t.Fatalf("size %d: got %d records, err %v", c.size, n, err)
		}
	}
}

func TestLineLimitReader(t *testing.T) {
	for _, c := range []struct {
		name    string
		chunks  []string
		wantErr bool
	}{
		{"short", []string{"a\nb\n", "c\n"}, false},
		{"max-split", []string{"x\n" + strings.Repeat("a", maxRecordSize/2), strings.Repeat("a", maxRecordSize/2) + "\n"}, false},
		{"over-split", []string{"x\n" + strings.Repeat("a", maxRecordSize/2), strings.Repeat("a", maxRecordSize/2+1) + "\n"}, true},
		{"over-middle", []string{"x\n" + strings.Repeat("a", maxRecordSize+1) + "\ny\n"}, true},
		{"over-no-newline", []string{strings.Repeat("a", maxRecordSize+1)}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			readers := make([]io.Reader, len(c.chunks))
			for i, s := range c.chunks {
				readers[i] = strings.NewReader(s)
			}
			l := &lineLimitReader{r: io.MultiReader(readers...)}
			buf := make([]byte, 4*maxRecordSize)
			var err error
			for err == nil {
				_, err = l.Read(buf)
			}
			if c.wantErr {
				requireOverMaxRecordSize(t, err)
			} else if err != io.EOF {
				t.Fatalf("unexpected error %v", err)
			}
		})
	}
}

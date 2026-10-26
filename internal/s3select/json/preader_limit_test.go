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

package json

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/minio/minio/internal/s3select/sql"
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

func readAllP(r *PReader) (int, error) {
	var rec sql.Record
	var err error
	for n := 0; ; n++ {
		if rec, err = r.Read(rec); err != nil {
			return n, err
		}
	}
}

func linesArgs() *ReaderArgs {
	return &ReaderArgs{ContentType: "lines", unmarshaled: true}
}

// TestPReaderLongLine verifies that JSON LINES input without a newline is not
// buffered without limit (GHSA-h749-fxx7-pwpg).
func TestPReaderLongLine(t *testing.T) {
	const bufSize = jsonSplitSize * 2 // bufio.Reader size used by NewPReader
	cr := &countingReader{r: io.MultiReader(
		strings.NewReader(`{"a":"`),
		&repeatReader{c: 'a', n: 64 << 20},
	)}
	r := NewPReader(io.NopCloser(cr), linesArgs())
	_, err := readAllP(r)
	r.Close()
	requireOverMaxRecordSize(t, err)
	if limit := int64(jsonSplitSize + maxRecordSize + bufSize); cr.n > limit {
		t.Fatalf("consumed %d bytes, want <= %d", cr.n, limit)
	}
}

// TestPReaderLongLineAfterRecords verifies that records before an oversized
// record are returned, followed by the error.
func TestPReaderLongLineAfterRecords(t *testing.T) {
	const line = `{"a":1}` + "\n"
	nLines := 3 * jsonSplitSize / len(line)
	input := io.MultiReader(
		strings.NewReader(strings.Repeat(line, nLines)),
		&repeatReader{c: ' ', n: 64 << 20},
	)
	r := NewPReader(io.NopCloser(input), linesArgs())
	defer r.Close()
	n, err := readAllP(r)
	requireOverMaxRecordSize(t, err)
	if n > nLines {
		t.Fatalf("got %d records, want at most %d", n, nLines)
	}
}

func TestPReaderMaxRecordSize(t *testing.T) {
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
		r := NewPReader(io.NopCloser(strings.NewReader(input)), linesArgs())
		n, err := readAllP(r)
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

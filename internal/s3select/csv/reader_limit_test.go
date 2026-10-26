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

package csv

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

func limitTestArgs(fileHeaderInfo, recordDelimiter string) *ReaderArgs {
	return &ReaderArgs{
		FileHeaderInfo:       fileHeaderInfo,
		RecordDelimiter:      recordDelimiter,
		FieldDelimiter:       defaultFieldDelimiter,
		QuoteCharacter:       defaultQuoteCharacter,
		QuoteEscapeCharacter: defaultQuoteEscapeCharacter,
		CommentCharacter:     defaultCommentCharacter,
		unmarshaled:          true,
	}
}

func requireOverMaxRecordSize(t *testing.T, err error) {
	t.Helper()
	var serr *s3Error
	if !errors.As(err, &serr) || serr.ErrorCode() != "OverMaxRecordSize" {
		t.Fatalf("expected OverMaxRecordSize error, got %v", err)
	}
}

// readAll reads all records, returning a copy of them and the terminating error.
func readAll(r *Reader) ([][]string, error) {
	var out [][]string
	var rec sql.Record
	var err error
	for {
		rec, err = r.Read(rec)
		if err != nil {
			return out, err
		}
		out = append(out, append([]string(nil), rec.(*Record).csvRecord...))
	}
}

// TestReaderLongLine verifies that input without a newline is not buffered
// without limit (GHSA-h749-fxx7-pwpg).
func TestReaderLongLine(t *testing.T) {
	const inputSize = 64 << 20
	const bufSize = csvSplitSize * 2 // bufio.Reader size used by NewReader
	cases := []struct {
		name            string
		fileHeaderInfo  string
		recordDelimiter string
		skip            int64 // bytes read before the line is scanned
	}{
		{"use", use, "\n", 0},
		{"ignore", ignore, "\n", 0},
		{"none", none, "\n", csvSplitSize},
		{"use-custom-delimiter", use, "\t", 0},
		{"none-custom-delimiter", none, "\r\n", csvSplitSize},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cr := &countingReader{r: &repeatReader{c: 'a', n: inputSize}}
			r, err := NewReader(io.NopCloser(cr), limitTestArgs(c.fileHeaderInfo, c.recordDelimiter))
			if err == nil {
				_, err = readAll(r)
			}
			r.Close()
			requireOverMaxRecordSize(t, err)
			if limit := c.skip + maxRecordSize + bufSize; cr.n > limit {
				t.Fatalf("consumed %d bytes, want <= %d", cr.n, limit)
			}
		})
	}
}

// TestReaderLongLineAfterRecords verifies that records before an oversized
// record are returned intact, followed by the error.
func TestReaderLongLineAfterRecords(t *testing.T) {
	const line = "1,2,3\n"
	nLines := 3 * csvSplitSize / len(line)
	input := io.MultiReader(
		strings.NewReader(strings.Repeat(line, nLines)),
		&repeatReader{c: 'a', n: 64 << 20},
	)
	r, err := NewReader(io.NopCloser(input), limitTestArgs(none, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	records, err := readAll(r)
	requireOverMaxRecordSize(t, err)
	if len(records) > nLines {
		t.Fatalf("got %d records, want at most %d", len(records), nLines)
	}
	for i, rec := range records {
		if strings.Join(rec, ",")+"\n" != line {
			t.Fatalf("record %d: got %q, want %q", i, rec, line)
		}
	}
}

func TestReaderMaxRecordSize(t *testing.T) {
	for _, c := range []struct {
		size    int
		wantErr bool
	}{
		{maxRecordSize - 1, false},
		{maxRecordSize, false},
		{maxRecordSize + 1, true},
	} {
		for _, fhi := range []string{use, none} {
			input := "h\n" + strings.Repeat("a", c.size) + "\nb\n"
			r, err := NewReader(io.NopCloser(strings.NewReader(input)), limitTestArgs(fhi, "\n"))
			var records [][]string
			if err == nil {
				records, err = readAll(r)
			}
			r.Close()
			if c.wantErr {
				requireOverMaxRecordSize(t, err)
				continue
			}
			if err != io.EOF {
				t.Fatalf("size %d, %s: unexpected error %v", c.size, fhi, err)
			}
			if fhi == none {
				records = records[1:]
			}
			if len(records) != 2 || len(records[0][0]) != c.size || records[1][0] != "b" {
				t.Fatalf("size %d, %s: unexpected records", c.size, fhi)
			}
		}
	}
}

func TestReaderQuotedMultiLineField(t *testing.T) {
	input := "a,b\n\"x\ny\nz\",2\n3,4\n"
	r, err := NewReader(io.NopCloser(strings.NewReader(input)), limitTestArgs(use, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	records, err := readAll(r)
	if err != io.EOF {
		t.Fatal(err)
	}
	want := [][]string{{"x\ny\nz", "2"}, {"3", "4"}}
	if len(records) != len(want) {
		t.Fatalf("got %q, want %q", records, want)
	}
	for i := range want {
		if strings.Join(records[i], "|") != strings.Join(want[i], "|") {
			t.Fatalf("got %q, want %q", records, want)
		}
	}
}

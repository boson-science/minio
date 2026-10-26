// Copyright (c) 2015-2025 MinIO, Inc.
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
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/uuid"
)

const (
	pathValidationBucket   = "bucket"
	pathValidationSentinel = "SENTINEL-OUTSIDE-DRIVE"
)

// pathValidationFileInfo returns a minimal FileInfo usable with WriteMetadata.
func pathValidationFileInfo(volume, name string) FileInfo {
	return FileInfo{
		Name:      name,
		Volume:    volume,
		VersionID: uuid.New().String(),
		ModTime:   UTCNow(),
		Size:      4,
		Fresh:     true,
		Erasure: ErasureInfo{
			Algorithm:    erasureAlgorithm,
			DataBlocks:   1,
			ParityBlocks: 1,
			BlockSize:    blockSizeV2,
			Index:        1,
			Distribution: []int{0, 1},
		},
		Parts: []ObjectPartInfo{{Number: 1, Size: 4}},
	}
}

// pathValidationDir returns the parent "directory/" of name, or "" at the top
// level, the same way listing code derives base directories.
func pathValidationDir(name string) string {
	return baseDirFromPrefix(name)
}

// pathValidationSetup creates <root>/drive as the drive and places fixtures
// directly under <root>, i.e. outside of the drive:
//
//	<root>/sentinel       - plain file
//	<root>/outobj/xl.meta - a valid xl.meta of a foreign object
//
// It returns the storage, the root and a function that resets the outside
// fixtures and a function that verifies they are untouched.
func pathValidationSetup(t *testing.T) (s *xlStorage, root string, reset func(), verify func(op string)) {
	t.Helper()
	root = t.TempDir()
	drive := filepath.Join(root, "drive")
	if err := os.Mkdir(drive, 0o755); err != nil {
		t.Fatal(err)
	}
	var err error
	s, err = newLocalXLStorage(drive)
	if err != nil {
		t.Fatalf("unable to create xlStorage: %v", err)
	}
	ctx := t.Context()
	if err = s.MakeVol(ctx, pathValidationBucket); err != nil {
		t.Fatal(err)
	}

	// Produce a valid xl.meta through the API, then copy it outside the drive.
	if err = s.WriteMetadata(ctx, "", pathValidationBucket, "seed", pathValidationFileInfo(pathValidationBucket, "seed")); err != nil {
		t.Fatal(err)
	}
	xlMeta, err := os.ReadFile(filepath.Join(drive, pathValidationBucket, "seed", xlStorageFormatFile))
	if err != nil {
		t.Fatal(err)
	}

	outside := func() map[string]string {
		got := map[string]string{}
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if p == drive {
				return filepath.SkipDir
			}
			rel, _ := filepath.Rel(root, p)
			if d.IsDir() {
				got[rel] = "<dir>"
				return nil
			}
			b, _ := os.ReadFile(p)
			got[rel] = string(b)
			return nil
		})
		return got
	}

	reset = func() {
		entries, _ := os.ReadDir(root)
		for _, e := range entries {
			if e.Name() != "drive" {
				os.RemoveAll(filepath.Join(root, e.Name()))
			}
		}
		if err := os.WriteFile(filepath.Join(root, "sentinel"), []byte(pathValidationSentinel), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(root, "outobj"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "outobj", xlStorageFormatFile), xlMeta, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "outobj", "part.1.meta"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	reset()
	want := outside()

	verify = func(op string) {
		t.Helper()
		got := outside()
		if len(got) != len(want) {
			t.Errorf("%s: files outside the drive changed: want %v, got %v", op, want, got)
			return
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s: %q outside the drive changed or removed", op, k)
			}
		}
	}
	return s, root, reset, verify
}

// TestXLStoragePathTraversalRejected verifies that caller-supplied file paths
// (as received from storage REST and grid request bodies) cannot escape the
// volume directory of a drive.
func TestXLStoragePathTraversalRejected(t *testing.T) {
	if runtime.GOOS == globalWindowsOSName {
		t.Skip("path layout of this test is unix specific")
	}

	// All templates are relative to <root>/drive/bucket; "%s" is replaced
	// by a name directly under <root>, which is outside the drive.
	badPaths := []string{
		"../../%s",
		"a/../../../%s",
		"a/b/../../../../%s",
		"/../../%s",
		"//../../%s",
		`..\..\%s`,
		`a\..\..\..\%s`,
		" ../../%s",
		" .. / .. /%s",
		"..\t/..\t/%s",
		"./../../%s",
	}

	s, _, reset, verify := pathValidationSetup(t)
	ctx := t.Context()
	bucket := pathValidationBucket

	type op struct {
		name string
		fn   func(tmpl string) error
	}
	p := fmt.Sprintf

	ops := []op{
		{"ReadAll", func(tmpl string) error {
			buf, err := s.ReadAll(ctx, bucket, p(tmpl, "sentinel"))
			if bytes.Contains(buf, []byte(pathValidationSentinel)) {
				t.Errorf("ReadAll(%q) leaked file outside drive", p(tmpl, "sentinel"))
			}
			return err
		}},
		{"ReadFile", func(tmpl string) error {
			buf := make([]byte, len(pathValidationSentinel))
			_, err := s.ReadFile(ctx, bucket, p(tmpl, "sentinel"), 0, buf, nil)
			if bytes.Contains(buf, []byte(pathValidationSentinel)) {
				t.Errorf("ReadFile(%q) leaked file outside drive", p(tmpl, "sentinel"))
			}
			return err
		}},
		{"ReadFileStream", func(tmpl string) error {
			rc, err := s.ReadFileStream(ctx, bucket, p(tmpl, "sentinel"), 0, -1)
			if rc != nil {
				rc.Close()
				t.Errorf("ReadFileStream(%q) opened file outside drive", p(tmpl, "sentinel"))
			}
			return err
		}},
		{"StatInfoFile", func(tmpl string) error {
			_, err := s.StatInfoFile(ctx, bucket, p(tmpl, "sentinel"), false)
			return err
		}},
		{"ListDir", func(tmpl string) error {
			_, err := s.ListDir(ctx, "", bucket, p(tmpl, ""), -1)
			return err
		}},
		{"WalkDir", func(tmpl string) error {
			return s.WalkDir(ctx, WalkDirOptions{Bucket: bucket, BaseDir: p(tmpl, ""), Recursive: true}, io.Discard)
		}},
		{"ReadXL", func(tmpl string) error {
			_, err := s.ReadXL(ctx, bucket, p(tmpl, "outobj"), true)
			return err
		}},
		{"ReadVersion", func(tmpl string) error {
			_, err := s.ReadVersion(ctx, "", bucket, p(tmpl, "outobj"), "", ReadOptions{ReadData: true})
			return err
		}},
		{"ReadParts", func(tmpl string) error {
			_, err := s.ReadParts(ctx, bucket, p(tmpl, "outobj/part.1.meta"))
			return err
		}},
		{"CheckParts", func(tmpl string) error {
			_, err := s.CheckParts(ctx, bucket, p(tmpl, "outobj"), pathValidationFileInfo(bucket, "x"))
			return err
		}},
		{"CheckParts/DataDir", func(tmpl string) error {
			fi := pathValidationFileInfo(bucket, "x")
			fi.DataDir = p(tmpl, "outobj")
			_, err := s.CheckParts(ctx, bucket, "seed", fi)
			return err
		}},
		{"VerifyFile", func(tmpl string) error {
			_, err := s.VerifyFile(ctx, bucket, p(tmpl, "outobj"), pathValidationFileInfo(bucket, "x"))
			return err
		}},
		{"VerifyFile/DataDir", func(tmpl string) error {
			fi := pathValidationFileInfo(bucket, "x")
			fi.DataDir = p(tmpl, "outobj")
			_, err := s.VerifyFile(ctx, bucket, "seed", fi)
			return err
		}},
		{"WriteAll", func(tmpl string) error {
			return s.WriteAll(ctx, bucket, p(tmpl, "planted"), []byte("x"))
		}},
		{"CreateFile", func(tmpl string) error {
			return s.CreateFile(ctx, "", bucket, p(tmpl, "planted"), 1, bytes.NewReader([]byte("x")))
		}},
		{"AppendFile", func(tmpl string) error {
			return s.AppendFile(ctx, bucket, p(tmpl, "planted"), []byte("x"))
		}},
		{"WriteMetadata", func(tmpl string) error {
			return s.WriteMetadata(ctx, "", bucket, p(tmpl, "planted"), pathValidationFileInfo(bucket, "x"))
		}},
		{"UpdateMetadata", func(tmpl string) error {
			fi := pathValidationFileInfo(bucket, "x")
			fi.Metadata = map[string]string{"k": "v"}
			return s.UpdateMetadata(ctx, bucket, p(tmpl, "outobj"), fi, UpdateMetadataOpts{})
		}},
		{"DeleteVersion", func(tmpl string) error {
			return s.DeleteVersion(ctx, bucket, p(tmpl, "outobj"), FileInfo{Deleted: true}, true, DeleteOptions{})
		}},
		{"DeleteVersion/OldDataDir", func(tmpl string) error {
			return s.DeleteVersion(ctx, bucket, "seed", FileInfo{VersionID: uuid.New().String()}, false,
				DeleteOptions{UndoWrite: true, OldDataDir: p(tmpl, "outobj")})
		}},
		{"DeleteVersions", func(tmpl string) error {
			errs := s.DeleteVersions(ctx, bucket, []FileInfoVersions{{
				Volume:   bucket,
				Name:     p(tmpl, "outobj"),
				Versions: []FileInfo{{Deleted: true}},
			}}, DeleteOptions{})
			return errs[0]
		}},
		{"Delete", func(tmpl string) error {
			return s.Delete(ctx, bucket, p(tmpl, "sentinel"), DeleteOptions{Recursive: true, Immediate: true})
		}},
		{"DeleteBulk", func(tmpl string) error {
			return s.DeleteBulk(ctx, bucket, p(tmpl, "sentinel"))
		}},
		{"CleanAbandonedData", func(tmpl string) error {
			return s.CleanAbandonedData(ctx, bucket, p(tmpl, "outobj"))
		}},
		{"RenameFile/src", func(tmpl string) error {
			return s.RenameFile(ctx, bucket, p(tmpl, "sentinel"), bucket, "stolen")
		}},
		{"RenameFile/dst", func(tmpl string) error {
			if err := s.WriteAll(ctx, bucket, "src-file", []byte("x")); err != nil {
				t.Fatal(err)
			}
			return s.RenameFile(ctx, bucket, "src-file", bucket, p(tmpl, "planted"))
		}},
		{"RenamePart/src", func(tmpl string) error {
			return s.RenamePart(ctx, bucket, p(tmpl, "sentinel"), bucket, "stolen-part", []byte("m"), "")
		}},
		{"RenamePart/dst", func(tmpl string) error {
			if err := s.WriteAll(ctx, bucket, "src-part", []byte("x")); err != nil {
				t.Fatal(err)
			}
			return s.RenamePart(ctx, bucket, "src-part", bucket, p(tmpl, "planted"), []byte("m"), "")
		}},
		{"RenameData/src", func(tmpl string) error {
			fi := pathValidationFileInfo(bucket, "stolen-obj")
			fi.Fresh = false
			_, err := s.RenameData(ctx, bucket, p(tmpl, "outobj"), fi, bucket, "stolen-obj", RenameOptions{})
			return err
		}},
		{"RenameData/dst", func(tmpl string) error {
			fi := pathValidationFileInfo(bucket, "seed")
			fi.Fresh = false
			if err := s.WriteMetadata(ctx, "", bucket, "src-obj", pathValidationFileInfo(bucket, "src-obj")); err != nil {
				t.Fatal(err)
			}
			_, err := s.RenameData(ctx, bucket, "src-obj", fi, bucket, p(tmpl, "planted"), RenameOptions{})
			return err
		}},
		{"RenameData/DataDir", func(tmpl string) error {
			fi := pathValidationFileInfo(bucket, "stolen-obj")
			fi.Fresh = false
			fi.DataDir = p(tmpl, "outobj")
			if err := s.WriteMetadata(ctx, "", bucket, "src-obj2", pathValidationFileInfo(bucket, "src-obj2")); err != nil {
				t.Fatal(err)
			}
			_, err := s.RenameData(ctx, bucket, "src-obj2", fi, bucket, "stolen-obj2", RenameOptions{})
			return err
		}},
	}

	for _, o := range ops {
		for _, tmpl := range badPaths {
			name := fmt.Sprintf("%s(%q)", o.name, tmpl)
			reset()
			err := o.fn(tmpl)
			if !errors.Is(err, errFileAccessDenied) {
				t.Errorf("%s: expected %v, got %v", name, errFileAccessDenied, err)
			}
			verify(name)
		}
	}
}

// TestXLStoragePathValidationAllowsValidPaths is a positive control: nested
// object names, names with dots that are not "." or ".." components, and
// internal .minio.sys paths must keep working.
func TestXLStoragePathValidationAllowsValidPaths(t *testing.T) {
	s, _, reset, verify := pathValidationSetup(t)
	ctx := t.Context()
	bucket := pathValidationBucket

	for _, vol := range []string{minioMetaBucket, minioMetaTmpBucket, minioMetaMultipartBucket} {
		if err := s.MakeVol(ctx, vol); err != nil && !errors.Is(err, errVolumeExists) {
			t.Fatal(err)
		}
	}

	objects := []struct{ volume, path string }{
		{bucket, "object"},
		{bucket, "prefix/nested/deeper/object"},
		{bucket, "dir/.hidden/..dots/.../file..name."},
		{bucket, "with space/ x /tail"},
		{minioMetaBucket, "config/iam/users/u1/identity.json"},
		{minioMetaBucket, "buckets/" + bucket + "/.metacache/" + uuid.New().String() + "/block-0.s2"},
		{minioMetaTmpBucket, uuid.New().String() + "/" + uuid.New().String() + "/part.1"},
		{minioMetaMultipartBucket, "abcdef/" + uuid.New().String() + "/" + uuid.New().String() + "/part.1"},
	}

	for _, o := range objects {
		data := []byte("data:" + o.path)
		if err := s.WriteAll(ctx, o.volume, o.path, data); err != nil {
			t.Fatalf("WriteAll(%s, %s): %v", o.volume, o.path, err)
		}
		got, err := s.ReadAll(ctx, o.volume, o.path)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("ReadAll(%s, %s): %v %q", o.volume, o.path, err, got)
		}
		if _, err = s.StatInfoFile(ctx, o.volume, o.path, false); err != nil {
			t.Fatalf("StatInfoFile(%s, %s): %v", o.volume, o.path, err)
		}
		if _, err = s.ListDir(ctx, "", o.volume, pathValidationDir(o.path), -1); err != nil {
			t.Fatalf("ListDir(%s, %s): %v", o.volume, pathValidationDir(o.path), err)
		}
		if err = s.AppendFile(ctx, o.volume, o.path+".append", data); err != nil {
			t.Fatalf("AppendFile(%s, %s): %v", o.volume, o.path, err)
		}
		if err = s.CreateFile(ctx, "", o.volume, o.path+".create", int64(len(data)), bytes.NewReader(data)); err != nil {
			t.Fatalf("CreateFile(%s, %s): %v", o.volume, o.path, err)
		}
		rc, err := s.ReadFileStream(ctx, o.volume, o.path+".create", 0, int64(len(data)))
		if err != nil {
			t.Fatalf("ReadFileStream(%s, %s): %v", o.volume, o.path, err)
		}
		rc.Close()
		if err = s.RenameFile(ctx, o.volume, o.path+".append", bucket, "renamed/"+o.path); err != nil {
			t.Fatalf("RenameFile(%s, %s): %v", o.volume, o.path, err)
		}
		if err = s.RenamePart(ctx, o.volume, o.path+".create", bucket, "parts/"+o.path, []byte("meta"), ""); err != nil {
			t.Fatalf("RenamePart(%s, %s): %v", o.volume, o.path, err)
		}
		if err = s.DeleteBulk(ctx, bucket, "parts/"+o.path, "parts/"+o.path+".meta"); err != nil {
			t.Fatalf("DeleteBulk(%s): %v", o.path, err)
		}
		if err = s.Delete(ctx, o.volume, o.path, DeleteOptions{}); err != nil {
			t.Fatalf("Delete(%s, %s): %v", o.volume, o.path, err)
		}
	}

	// Object metadata operations on nested object names.
	for _, name := range []string{"meta-object", "a/b/c/meta-object", "dir/.hidden/..dots/obj"} {
		fi := pathValidationFileInfo(bucket, name)
		if err := s.WriteMetadata(ctx, "", bucket, name, fi); err != nil {
			t.Fatalf("WriteMetadata(%s): %v", name, err)
		}
		if _, err := s.ReadXL(ctx, bucket, name, true); err != nil {
			t.Fatalf("ReadXL(%s): %v", name, err)
		}
		if _, err := s.ReadVersion(ctx, "", bucket, name, fi.VersionID, ReadOptions{}); err != nil {
			t.Fatalf("ReadVersion(%s): %v", name, err)
		}
		fi.Metadata = map[string]string{"k": "v"}
		if err := s.UpdateMetadata(ctx, bucket, name, fi, UpdateMetadataOpts{}); err != nil {
			t.Fatalf("UpdateMetadata(%s): %v", name, err)
		}
		if _, err := s.CheckParts(ctx, bucket, name, fi); err != nil {
			t.Fatalf("CheckParts(%s): %v", name, err)
		}
		if err := s.WalkDir(ctx, WalkDirOptions{Bucket: bucket, BaseDir: pathValidationDir(name)}, io.Discard); err != nil {
			t.Fatalf("WalkDir(%s): %v", name, err)
		}
		if err := s.CleanAbandonedData(ctx, bucket, name); err != nil {
			t.Fatalf("CleanAbandonedData(%s): %v", name, err)
		}
		if err := s.DeleteVersion(ctx, bucket, name, FileInfo{Name: name, Volume: bucket, VersionID: fi.VersionID}, false, DeleteOptions{}); err != nil {
			t.Fatalf("DeleteVersion(%s): %v", name, err)
		}
	}

	// Absolute paths without traversal stay confined to the volume.
	reset()
	if err := s.WriteAll(ctx, bucket, "/abs/object", []byte("abs")); err != nil {
		t.Fatalf("WriteAll(/abs/object): %v", err)
	}
	if got, err := s.ReadAll(ctx, bucket, "abs/object"); err != nil || string(got) != "abs" {
		t.Fatalf("absolute path not confined to volume: %v %q", err, got)
	}
	verify("absolute path")
}

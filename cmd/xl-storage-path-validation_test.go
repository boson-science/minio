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
	"github.com/minio/madmin-go/v3"
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
		Parts: []ObjectPartInfo{{Number: 1, Size: 4, ActualSize: 4}},
	}
}

// pathValidationDir returns the parent "directory/" of name, or "" at the top
// level, the same way listing code derives base directories.
func pathValidationDir(name string) string {
	return baseDirFromPrefix(name)
}

type pathValidationEnv struct {
	s    *xlStorage
	root string
	// seed is the FileInfo of the object whose xl.meta is copied outside the
	// drive to <root>/outobj, so its VersionID and DataDir match that copy.
	seed FileInfo
	// bkpDir is a directory under <root>/outobj holding an xl.meta backup.
	bkpDir string
	reset  func()
	verify func(op string)
}

// pathValidationSetup creates <root>/drive as the drive and places fixtures
// directly under <root>, i.e. outside of the drive:
//
//	<root>/sentinel                       - plain file
//	<root>/outobj/xl.meta                 - copy of a valid xl.meta (seed object)
//	<root>/outobj/<seed.DataDir>/part.1   - data dir of that version
//	<root>/outobj/part.1.meta             - part metadata
//	<root>/outobj/<bkpDir>/xl.meta.bkp    - xl.meta backup
//	<root>/outdir/part.1                  - target of crafted legacy DataDir
//
// reset restores these fixtures and removes anything else outside the drive,
// verify reports any difference.
func pathValidationSetup(t *testing.T) *pathValidationEnv {
	t.Helper()
	env := &pathValidationEnv{root: t.TempDir(), bkpDir: uuid.New().String()}
	root := env.root
	drive := filepath.Join(root, "drive")
	if err := os.Mkdir(drive, 0o755); err != nil {
		t.Fatal(err)
	}
	var err error
	env.s, err = newLocalXLStorage(drive)
	if err != nil {
		t.Fatalf("unable to create xlStorage: %v", err)
	}
	ctx := t.Context()
	if err = env.s.MakeVol(ctx, pathValidationBucket); err != nil {
		t.Fatal(err)
	}

	// Produce a valid xl.meta through the API, then copy it outside the drive.
	env.seed = pathValidationFileInfo(pathValidationBucket, "seed")
	env.seed.DataDir = uuid.New().String()
	if err = env.s.WriteMetadata(ctx, "", pathValidationBucket, "seed", env.seed); err != nil {
		t.Fatal(err)
	}
	xlMeta, err := os.ReadFile(filepath.Join(drive, pathValidationBucket, "seed", xlStorageFormatFile))
	if err != nil {
		t.Fatal(err)
	}

	files := map[string]string{
		"sentinel":                               pathValidationSentinel,
		"outobj/" + xlStorageFormatFile:          string(xlMeta),
		"outobj/" + env.seed.DataDir + "/part.1": pathValidationSentinel,
		"outobj/part.1.meta":                     "x",
		"outobj/" + env.bkpDir + "/" + xlStorageFormatFileBackup: string(xlMeta),
		"outdir/part.1": pathValidationSentinel,
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

	env.reset = func() {
		entries, _ := os.ReadDir(root)
		for _, e := range entries {
			if e.Name() != "drive" {
				os.RemoveAll(filepath.Join(root, e.Name()))
			}
		}
		for name, content := range files {
			p := filepath.Join(root, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	env.reset()
	want := outside()

	env.verify = func(op string) {
		t.Helper()
		got := outside()
		for k, v := range want {
			if g, ok := got[k]; !ok {
				t.Errorf("%s: %q outside the drive was removed", op, k)
			} else if g != v {
				t.Errorf("%s: %q outside the drive was modified", op, k)
			}
		}
		for k := range got {
			if _, ok := want[k]; !ok {
				t.Errorf("%s: %q was created outside the drive", op, k)
			}
		}
	}
	return env
}

// TestXLStoragePathTraversalRejected verifies that caller-supplied file paths
// (as received from storage REST and grid request bodies) cannot escape the
// volume directory of a drive.
//
// Where possible the operations target real data outside the drive (matching
// version IDs, data dirs and backups) so that a missing check results in
// files outside the drive being read, modified or removed, which is asserted
// independently of the returned error.
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

	env := pathValidationSetup(t)
	s := env.s
	ctx := t.Context()
	bucket := pathValidationBucket
	p := fmt.Sprintf
	// sub formats a template that is joined one level below the volume
	// (e.g. a data dir under an object), so it needs one more "..".
	sub := func(tmpl, name string) string { return "../" + p(tmpl, name) }

	seedVersion := func() FileInfo {
		return FileInfo{Name: "x", Volume: bucket, VersionID: env.seed.VersionID}
	}
	writeObj := func(name string) FileInfo {
		fi := pathValidationFileInfo(bucket, name)
		if err := s.WriteMetadata(ctx, "", bucket, name, fi); err != nil {
			t.Fatal(err)
		}
		return fi
	}
	writeFile := func(name string) {
		if err := s.WriteAll(ctx, bucket, name, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	noLeak := func(op string, b []byte) {
		if bytes.Contains(b, []byte(pathValidationSentinel)) {
			t.Errorf("%s leaked data from outside the drive", op)
		}
	}

	type op struct {
		name string
		fn   func(tmpl string) error
	}
	ops := []op{
		{"ReadAll", func(tmpl string) error {
			buf, err := s.ReadAll(ctx, bucket, p(tmpl, "sentinel"))
			noLeak("ReadAll", buf)
			return err
		}},
		{"ReadFile", func(tmpl string) error {
			buf := make([]byte, len(pathValidationSentinel))
			_, err := s.ReadFile(ctx, bucket, p(tmpl, "sentinel"), 0, buf, nil)
			noLeak("ReadFile", buf)
			return err
		}},
		{"ReadFileStream", func(tmpl string) error {
			rc, err := s.ReadFileStream(ctx, bucket, p(tmpl, "sentinel"), 0, -1)
			if rc != nil {
				b, _ := io.ReadAll(rc)
				rc.Close()
				noLeak("ReadFileStream", b)
			}
			return err
		}},
		{"StatInfoFile", func(tmpl string) error {
			_, err := s.StatInfoFile(ctx, bucket, p(tmpl, "sentinel"), false)
			return err
		}},
		{"ListDir", func(tmpl string) error {
			entries, err := s.ListDir(ctx, "", bucket, p(tmpl, ""), -1)
			for _, e := range entries {
				if e == "sentinel" {
					t.Errorf("ListDir listed outside the drive")
				}
			}
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
			fi, err := s.ReadVersion(ctx, "", bucket, p(tmpl, "outobj"), env.seed.VersionID, ReadOptions{ReadData: true})
			noLeak("ReadVersion", fi.Data)
			return err
		}},
		{"ReadParts", func(tmpl string) error {
			_, err := s.ReadParts(ctx, bucket, p(tmpl, "outobj/part.1.meta"))
			return err
		}},
		{"ReadParts/second", func(tmpl string) error {
			writeFile("rp/part.1.meta")
			_, err := s.ReadParts(ctx, bucket, "rp/part.1.meta", p(tmpl, "outobj/part.1.meta"))
			return err
		}},
		{"CheckParts", func(tmpl string) error {
			_, err := s.CheckParts(ctx, bucket, p(tmpl, "outobj"), env.seed)
			return err
		}},
		{"CheckParts/DataDir", func(tmpl string) error {
			fi := env.seed
			fi.DataDir = sub(tmpl, "outobj/"+env.seed.DataDir)
			_, err := s.CheckParts(ctx, bucket, "seed", fi)
			return err
		}},
		{"VerifyFile", func(tmpl string) error {
			_, err := s.VerifyFile(ctx, bucket, p(tmpl, "outobj"), env.seed)
			return err
		}},
		{"VerifyFile/DataDir", func(tmpl string) error {
			fi := env.seed
			fi.DataDir = sub(tmpl, "outobj/"+env.seed.DataDir)
			_, err := s.VerifyFile(ctx, bucket, "seed", fi)
			return err
		}},
		{"WriteAll", func(tmpl string) error {
			return s.WriteAll(ctx, bucket, p(tmpl, "planted"), []byte("x"))
		}},
		{"writeAll", func(tmpl string) error {
			return s.writeAll(ctx, bucket, p(tmpl, "planted"), []byte("x"), false, "")
		}},
		{"writeAllMeta", func(tmpl string) error {
			return s.writeAllMeta(ctx, bucket, p(tmpl, "planted"), []byte("x"), false)
		}},
		{"CreateFile", func(tmpl string) error {
			return s.CreateFile(ctx, "", bucket, p(tmpl, "planted"), 1, bytes.NewReader([]byte("x")))
		}},
		{"AppendFile", func(tmpl string) error {
			return s.AppendFile(ctx, bucket, p(tmpl, "planted"), []byte("x"))
		}},
		{"WriteMetadata/fresh", func(tmpl string) error {
			return s.WriteMetadata(ctx, "", bucket, p(tmpl, "planted"), pathValidationFileInfo(bucket, "x"))
		}},
		{"WriteMetadata/existing", func(tmpl string) error {
			fi := pathValidationFileInfo(bucket, "x")
			fi.Fresh = false
			return s.WriteMetadata(ctx, "", bucket, p(tmpl, "outobj"), fi)
		}},
		{"UpdateMetadata", func(tmpl string) error {
			fi := env.seed
			fi.Metadata = map[string]string{"k": "v"}
			return s.UpdateMetadata(ctx, bucket, p(tmpl, "outobj"), fi, UpdateMetadataOpts{})
		}},
		{"DeleteVersion", func(tmpl string) error {
			// Matching version with a data dir: an unchecked path moves
			// <root>/outobj/<DataDir> to the trash.
			return s.DeleteVersion(ctx, bucket, p(tmpl, "outobj"), seedVersion(), false, DeleteOptions{})
		}},
		{"DeleteVersion/forceDelMarker", func(tmpl string) error {
			return s.DeleteVersion(ctx, bucket, p(tmpl, "planted"), FileInfo{Deleted: true, ModTime: UTCNow()}, true, DeleteOptions{})
		}},
		{"DeleteVersion/OldDataDir", func(tmpl string) error {
			// An unchecked OldDataDir renames <root>/outobj/<bkpDir>/xl.meta.bkp.
			fi := writeObj("undo")
			return s.DeleteVersion(ctx, bucket, "undo", FileInfo{Name: "undo", Volume: bucket, VersionID: fi.VersionID}, false,
				DeleteOptions{UndoWrite: true, OldDataDir: sub(tmpl, "outobj/"+env.bkpDir)})
		}},
		{"DeleteVersions", func(tmpl string) error {
			errs := s.DeleteVersions(ctx, bucket, []FileInfoVersions{{
				Volume:   bucket,
				Name:     p(tmpl, "outobj"),
				Versions: []FileInfo{seedVersion()},
			}}, DeleteOptions{})
			return errs[0]
		}},
		{"Delete", func(tmpl string) error {
			return s.Delete(ctx, bucket, p(tmpl, "sentinel"), DeleteOptions{Recursive: true, Immediate: true})
		}},
		{"DeleteBulk", func(tmpl string) error {
			return s.DeleteBulk(ctx, bucket, p(tmpl, "sentinel"))
		}},
		{"DeleteBulk/second", func(tmpl string) error {
			writeFile("bulk-first")
			return s.DeleteBulk(ctx, bucket, "bulk-first", p(tmpl, "sentinel"))
		}},
		{"CleanAbandonedData", func(tmpl string) error {
			return s.CleanAbandonedData(ctx, bucket, p(tmpl, "outobj"))
		}},
		{"RenameFile/src", func(tmpl string) error {
			return s.RenameFile(ctx, bucket, p(tmpl, "sentinel"), bucket, "stolen")
		}},
		{"RenameFile/dst", func(tmpl string) error {
			writeFile("src-file")
			return s.RenameFile(ctx, bucket, "src-file", bucket, p(tmpl, "planted"))
		}},
		{"RenamePart/src", func(tmpl string) error {
			return s.RenamePart(ctx, bucket, p(tmpl, "sentinel"), bucket, "stolen-part", []byte("m"), "")
		}},
		{"RenamePart/dst", func(tmpl string) error {
			writeFile("src-part")
			return s.RenamePart(ctx, bucket, "src-part", bucket, p(tmpl, "planted"), []byte("m"), "")
		}},
		{"RenamePart/skipParent", func(tmpl string) error {
			writeFile("src-part2")
			return s.RenamePart(ctx, bucket, "src-part2", bucket, "dst-part2", []byte("m"), p(tmpl, ""))
		}},
		{"RenameData/src", func(tmpl string) error {
			fi := env.seed
			fi.Fresh = false
			_, err := s.RenameData(ctx, bucket, p(tmpl, "outobj"), fi, bucket, "stolen-obj", RenameOptions{})
			return err
		}},
		{"RenameData/dst", func(tmpl string) error {
			src := writeObj("src-obj")
			src.Fresh = false
			_, err := s.RenameData(ctx, bucket, "src-obj", src, bucket, p(tmpl, "planted"), RenameOptions{})
			return err
		}},
		{"RenameData/DataDir", func(tmpl string) error {
			src := writeObj("src-obj2")
			src.Fresh = false
			src.DataDir = sub(tmpl, "outobj/"+env.seed.DataDir)
			_, err := s.RenameData(ctx, bucket, "src-obj2", src, bucket, "stolen-obj2", RenameOptions{})
			return err
		}},
	}

	for _, o := range ops {
		for _, tmpl := range badPaths {
			name := fmt.Sprintf("%s(%q)", o.name, tmpl)
			env.reset()
			err := o.fn(tmpl)
			if !errors.Is(err, errFileAccessDenied) {
				t.Errorf("%s: expected %v, got %v", name, errFileAccessDenied, err)
			}
			env.verify(name)
		}
	}
}

// TestXLStorageNSScannerPathTraversal verifies a remotely supplied scanner
// cache name cannot point the scanner outside the drive.
func TestXLStorageNSScannerPathTraversal(t *testing.T) {
	env := pathValidationSetup(t)
	for _, name := range []string{"../..", "../../outobj", "bucket/../..", `..\..`} {
		updates := make(chan dataUsageEntry, 1)
		cache := dataUsageCache{Info: dataUsageCacheInfo{Name: name}}
		_, err := env.s.NSScanner(t.Context(), cache, updates, madmin.HealNormalScan, func() bool { return false })
		if !errors.Is(err, errFileAccessDenied) {
			t.Errorf("NSScanner(%q): expected %v, got %v", name, errFileAccessDenied, err)
		}
		env.verify("NSScanner " + name)
	}
}

// pathValidationLegacyXLMeta returns an xl.meta with a single legacy (v1)
// version whose DataDir is set to dataDir without any validation, like a
// crafted file written to the drive by a malicious caller.
func pathValidationLegacyXLMeta(t *testing.T, dataDir string) []byte {
	t.Helper()
	m := &xlMetaV1Object{
		Version: xlMetaVersion101,
		Format:  xlMetaFormat,
		Stat:    StatInfo{Size: 4, ModTime: UTCNow()},
		Erasure: ErasureInfo{
			Algorithm:    erasureAlgorithm,
			DataBlocks:   1,
			ParityBlocks: 1,
			BlockSize:    blockSizeV2,
			Index:        1,
			Distribution: []int{1, 2},
		},
		Parts:     []ObjectPartInfo{{Number: 1, Size: 4, ActualSize: 4}},
		VersionID: nullVersionID,
		DataDir:   dataDir,
	}
	ver := xlMetaV2Version{Type: LegacyType, ObjectV1: m, WrittenByVersion: globalVersionUnix}
	enc, err := ver.MarshalMsg(nil)
	if err != nil {
		t.Fatal(err)
	}
	var x xlMetaV2
	x.versions = []xlMetaV2ShallowVersion{{header: ver.header(), meta: enc}}
	buf, err := x.AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

// TestXLStorageCraftedLegacyDataDir verifies that a data dir read back from
// a crafted on-disk xl.meta is not used to build paths outside the drive.
func TestXLStorageCraftedLegacyDataDir(t *testing.T) {
	if runtime.GOOS == globalWindowsOSName {
		t.Skip("path layout of this test is unix specific")
	}
	env := pathValidationSetup(t)
	s := env.s
	ctx := t.Context()
	bucket := pathValidationBucket

	// <root>/drive/bucket/crafted/../../../outdir == <root>/outdir
	const object = "crafted"
	plant := func(dataDir string) {
		env.reset()
		if err := s.WriteAll(ctx, bucket, object+"/"+xlStorageFormatFile, pathValidationLegacyXLMeta(t, dataDir)); err != nil {
			t.Fatal(err)
		}
	}

	for _, dataDir := range []string{"../../../outdir", "a/../../../../outdir", "/../../../outdir", "..", "."} {
		plant(dataDir)
		err := s.DeleteVersion(ctx, bucket, object, FileInfo{Name: object, Volume: bucket}, false, DeleteOptions{})
		if err == nil {
			t.Errorf("DeleteVersion with DataDir %q: expected error", dataDir)
		}
		env.verify("DeleteVersion DataDir " + dataDir)

		plant(dataDir)
		errs := s.DeleteVersions(ctx, bucket, []FileInfoVersions{{
			Volume: bucket, Name: object, Versions: []FileInfo{{Name: object, Volume: bucket}},
		}}, DeleteOptions{})
		if errs[0] == nil {
			t.Errorf("DeleteVersions with DataDir %q: expected error", dataDir)
		}
		env.verify("DeleteVersions DataDir " + dataDir)

		plant(dataDir)
		fi, err := s.ReadVersion(ctx, "", bucket, object, "", ReadOptions{ReadData: true})
		if err == nil {
			t.Errorf("ReadVersion with DataDir %q: expected error", dataDir)
		}
		if bytes.Contains(fi.Data, []byte(pathValidationSentinel)) {
			t.Errorf("ReadVersion with DataDir %q leaked data from outside the drive", dataDir)
		}
		env.verify("ReadVersion DataDir " + dataDir)

		plant(dataDir)
		if _, err = s.ReadXL(ctx, bucket, object, true); err != nil {
			t.Errorf("ReadXL of crafted object should still return raw metadata, got %v", err)
		}
		if err = s.CleanAbandonedData(ctx, bucket, object); err == nil {
			t.Errorf("CleanAbandonedData with DataDir %q: expected error", dataDir)
		}
		env.verify("CleanAbandonedData DataDir " + dataDir)
	}

	// Positive control: legitimate legacy data dirs still work.
	for _, dataDir := range []string{"", legacyDataDir, uuid.New().String()} {
		plant(dataDir)
		if _, err := s.ReadVersion(ctx, "", bucket, object, "", ReadOptions{}); err != nil {
			t.Errorf("ReadVersion with valid legacy DataDir %q: %v", dataDir, err)
		}
		if err := s.DeleteVersion(ctx, bucket, object, FileInfo{Name: object, Volume: bucket}, false, DeleteOptions{}); err != nil {
			t.Errorf("DeleteVersion with valid legacy DataDir %q: %v", dataDir, err)
		}
		env.verify("valid legacy DataDir " + dataDir)
	}
}

// TestXLStoragePathValidationAllowsValidPaths is a positive control: nested
// object names, names with dots that are not "." or ".." components, and
// internal .minio.sys paths must keep working.
func TestXLStoragePathValidationAllowsValidPaths(t *testing.T) {
	env := pathValidationSetup(t)
	s := env.s
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
		fi.DataDir = uuid.New().String()
		if err := s.WriteMetadata(ctx, "", bucket, name, fi); err != nil {
			t.Fatalf("WriteMetadata(%s): %v", name, err)
		}
		if err := s.WriteAll(ctx, bucket, name+"/"+fi.DataDir+"/part.1", []byte("data")); err != nil {
			t.Fatalf("WriteAll(%s part.1): %v", name, err)
		}
		if _, err := s.ReadXL(ctx, bucket, name, true); err != nil {
			t.Fatalf("ReadXL(%s): %v", name, err)
		}
		if _, err := s.ReadVersion(ctx, "", bucket, name, fi.VersionID, ReadOptions{ReadData: true}); err != nil {
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
	env.reset()
	if err := s.WriteAll(ctx, bucket, "/abs/object", []byte("abs")); err != nil {
		t.Fatalf("WriteAll(/abs/object): %v", err)
	}
	if got, err := s.ReadAll(ctx, bucket, "abs/object"); err != nil || string(got) != "abs" {
		t.Fatalf("absolute path not confined to volume: %v %q", err, got)
	}
	env.verify("absolute path")
}

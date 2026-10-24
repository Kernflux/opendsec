// Package release packs, verifies and unpacks OpenDsec release tarballs
// (spec §28.5). A release is a directory named after its version:
//
//	<version>/bin/        opendsec-* binaries, opendsecctl, firecracker, jailer
//	<version>/agents/     opendsec-aether, opendsec-chronus (static, run in sandboxes)
//	<version>/units/      systemd unit files
//	<version>/vm/         guest kernels
//	<version>/licenses/   OpenDsec's and third-party licenses (NOTICE): opendsec/, go/, firecracker/, linux/
//	<version>/deps.lock   pinned runtime dependencies (spec §28.12)
//	<version>/SHA256SUMS  "<sha256>  <path>" for every other file
//
// The same layout is what opendsecops ships to /opt/opendsec/releases.
package release

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const SumsFile = "SHA256SUMS"

// ValidVersion reports whether v can name a release directory.
func ValidVersion(v string) bool {
	if v == "" || len(v) > 64 || v == "." || v == ".." {
		return false
	}
	return strings.Trim(v, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_+") == ""
}

// parseSums reads a SHA256SUMS file: path -> hex digest.
func parseSums(b []byte) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		sum, p, ok := strings.Cut(line, "  ")
		if !ok || len(sum) != 64 {
			return nil, fmt.Errorf("%s: bad line %q", SumsFile, line)
		}
		p = strings.TrimPrefix(p, "*")
		if !fs.ValidPath(p) {
			return nil, fmt.Errorf("%s: bad path %q", SumsFile, p)
		}
		out[p] = sum
	}
	return out, sc.Err()
}

// Deps parses deps.lock: "name version source sha256 path" per line, '#'
// comments; it returns name -> version.
func Deps(b []byte) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 5 {
			return nil, fmt.Errorf("deps.lock: want 5 fields: %q", line)
		}
		out[f[0]] = f[1]
	}
	return out, nil
}

// Info describes a verified release.
type Info struct {
	Version string
	Deps    map[string]string // from deps.lock (empty if the release has none)
}

// VerifyTarball checks a release tarball: one top directory (the version),
// a SHA256SUMS that covers every regular file, each matching, and only
// regular files and directories with relative paths inside it.
func VerifyTarball(r io.Reader) (*Info, error) {
	z, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(z)
	info := &Info{Deps: map[string]string{}}
	got := map[string]string{}
	var sums []byte
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		name := strings.TrimSuffix(path.Clean(h.Name), "/")
		top, rest, _ := strings.Cut(name, "/")
		if !fs.ValidPath(name) || !ValidVersion(top) {
			return nil, fmt.Errorf("bad path %q in release", h.Name)
		}
		if info.Version == "" {
			info.Version = top
		} else if top != info.Version {
			return nil, fmt.Errorf("release has two top directories: %s, %s", info.Version, top)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
		default:
			return nil, fmt.Errorf("%s: only files and directories are allowed in a release", h.Name)
		}
		hs := sha256.New()
		var buf bytes.Buffer
		w := io.Writer(hs)
		if rest == SumsFile || rest == "deps.lock" {
			w = io.MultiWriter(hs, &buf)
		}
		if _, err := io.Copy(w, tr); err != nil {
			return nil, err
		}
		switch rest {
		case SumsFile:
			sums = buf.Bytes()
		case "deps.lock":
			if info.Deps, err = Deps(buf.Bytes()); err != nil {
				return nil, err
			}
			fallthrough
		default:
			got[rest] = hex.EncodeToString(hs.Sum(nil))
		}
	}
	if info.Version == "" {
		return nil, errors.New("empty release")
	}
	if sums == nil {
		return nil, fmt.Errorf("release %s has no %s", info.Version, SumsFile)
	}
	want, err := parseSums(sums)
	if err != nil {
		return nil, err
	}
	if err := compare(want, got); err != nil {
		return nil, fmt.Errorf("release %s: %w", info.Version, err)
	}
	return info, nil
}

func compare(want, got map[string]string) error {
	for p, sum := range want {
		g, ok := got[p]
		if !ok {
			return fmt.Errorf("%s listed in %s but missing", p, SumsFile)
		}
		if g != sum {
			return fmt.Errorf("%s: sha256 %s, want %s", p, g, sum)
		}
	}
	for p := range got {
		if _, ok := want[p]; !ok {
			return fmt.Errorf("%s is not covered by %s", p, SumsFile)
		}
	}
	return nil
}

// VerifyDir checks an unpacked release directory against its SHA256SUMS.
func VerifyDir(dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, SumsFile))
	if err != nil {
		return err
	}
	want, err := parseSums(b)
	if err != nil {
		return err
	}
	got := map[string]string{}
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if rel == SumsFile {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", rel)
		}
		sum, err := fileSum(p)
		got[rel] = sum
		return err
	})
	if err != nil {
		return err
	}
	return compare(want, got)
}

func fileSum(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// WriteSums writes dir/SHA256SUMS covering every regular file in dir.
func WriteSums(dir string) error {
	var lines []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if rel == SumsFile {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", rel)
		}
		sum, err := fileSum(p)
		lines = append(lines, sum+"  "+rel)
		return err
	})
	if err != nil {
		return err
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i][66:] < lines[j][66:] })
	return os.WriteFile(filepath.Join(dir, SumsFile), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

// Pack writes dir (whose base name is the version) as a release tarball.
func Pack(dir string, w io.Writer) error {
	dir = filepath.Clean(dir)
	version := filepath.Base(dir)
	if !ValidVersion(version) {
		return fmt.Errorf("%s: directory name %q is not a release version", dir, version)
	}
	if err := VerifyDir(dir); err != nil {
		return err
	}
	z := gzip.NewWriter(w)
	tw := tar.NewWriter(z)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(filepath.Dir(dir), p)
		fi, err := d.Info()
		if err != nil {
			return err
		}
		h, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(rel)
		if d.IsDir() {
			h.Name += "/"
		}
		h.Uid, h.Gid, h.Uname, h.Gname = 0, 0, "", ""
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return z.Close()
}

// Unpack extracts a release tarball into parent/<version>, through a
// temporary directory, and verifies it there before the final rename. An
// existing, valid parent/<version> is left alone.
func Unpack(r io.Reader, parent, version string) error {
	final := filepath.Join(parent, version)
	if VerifyDir(final) == nil {
		return nil
	}
	tmp, err := os.MkdirTemp(parent, "."+version+".")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	z, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	tr := tar.NewReader(z)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(path.Clean(h.Name), "/")
		top, rest, _ := strings.Cut(name, "/")
		if !fs.ValidPath(name) || top != version {
			return fmt.Errorf("bad path %q in release %s", h.Name, version)
		}
		if rest == "" {
			continue
		}
		dst := filepath.Join(tmp, filepath.FromSlash(rest))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(h.Mode)&0o755)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, tr)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s: only files and directories are allowed in a release", h.Name)
		}
	}
	if err := VerifyDir(tmp); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	os.RemoveAll(final) // an invalid leftover
	return os.Rename(tmp, final)
}

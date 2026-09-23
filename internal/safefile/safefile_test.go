package safefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(p, []byte("new"), 0o640); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	fi, _ := os.Stat(p)
	if string(b) != "new" || fi.Mode().Perm() != 0o640 {
		t.Fatalf("got %q %v", b, fi.Mode().Perm())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("temporary file left: %v", entries)
	}
	if err := WriteAtomic(filepath.Join(dir, "missing", "f"), nil, 0o600); err == nil {
		t.Fatal("no error for a missing directory")
	}
	// Renaming over a directory fails and leaves no temporary file.
	sub := filepath.Join(dir, "sub")
	_ = os.Mkdir(sub, 0o700)
	_ = os.WriteFile(filepath.Join(sub, "x"), nil, 0o600)
	if err := WriteAtomic(sub, []byte("x"), 0o600); err == nil {
		t.Fatal("replaced a non-empty directory")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Fatalf("temporary file left after failure: %v", entries)
	}
}

func TestWriteNew(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	old := umask(0)
	defer umask(old)
	if err := WriteNew(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if err := WriteNew(p, []byte("y"), 0o600); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("err = %v, want ErrExist", err)
	}
}

func TestMkdirPrivate(t *testing.T) {
	d := filepath.Join(t.TempDir(), "a", "b")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := MkdirPrivate(d); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(d); fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestZshLock(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".zsh_history")
	unlock, err := LockZshHistory(p, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(p + ".LOCK")
	if err != nil || len(target) < len("/pid-1/host-") || target[:5] != "/pid-" {
		t.Fatalf("lock target %q, %v", target, err)
	}
	start := time.Now()
	if _, err := LockZshHistory(p, 150*time.Millisecond); !errors.Is(err, ErrLocked) {
		t.Fatalf("err = %v, want ErrLocked", err)
	}
	if time.Since(start) < 150*time.Millisecond {
		t.Fatal("did not wait before giving up")
	}
	unlock()
	if _, err := os.Lstat(p + ".LOCK"); !os.IsNotExist(err) {
		t.Fatal("lock not removed")
	}
	if _, err := LockZshHistory(filepath.Join(t.TempDir(), "missing", "h"), time.Second); err == nil {
		t.Fatal("no error when the directory is missing")
	}
}

func TestLockHistory(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "h")
	f, unlock, err := LockHistory(p, true, time.Second)
	if err != nil || f != nil {
		t.Fatalf("missing file: %v, %v", f, err)
	}
	unlock()
	_ = os.WriteFile(p, []byte("data"), 0o600)
	f, unlock, err = LockHistory(p, true, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ReadAll(f)
	if err != nil || string(b) != "data" {
		t.Fatalf("ReadAll = %q, %v", b, err)
	}
	unlock()
	if _, err := os.Lstat(p + ".LOCK"); !os.IsNotExist(err) {
		t.Fatal("zsh lock not released")
	}
}

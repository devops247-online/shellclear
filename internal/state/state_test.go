package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devops247-online/shellclear/internal/history"
)

func newDir(t *testing.T) (Dir, history.File) {
	t.Helper()
	root := t.TempDir()
	src := filepath.Join(root, "src", ".zsh_history")
	return Dir{Root: filepath.Join(root, "state")}, history.File{Path: src, RealPath: src, Shell: history.Zsh}
}

func TestBackupNamesAndListing(t *testing.T) {
	d, f := newDir(t)
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	b1, err := d.CreateBackup(f, []byte("one\n"), now)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := d.CreateBackup(f, []byte("two\n"), now)
	b3, _ := d.CreateBackup(f, []byte("three\n"), now.Add(time.Minute))
	if b1.Name != "zsh/.zsh_history.20260923T100000.bak" || b2.Name != "zsh/.zsh_history.20260923T100000-1.bak" {
		t.Fatalf("names %q %q", b1.Name, b2.Name)
	}
	list, err := d.Backups()
	if err != nil || len(list) != 3 || list[0].Name != b3.Name || list[1].Name != b2.Name {
		t.Fatalf("list = %+v, %v", list, err)
	}
	// Files without a sidecar are ignored.
	_ = os.WriteFile(filepath.Join(d.Root, "backups", "zsh", "stray.bak"), nil, 0o600)
	if list, _ := d.Backups(); len(list) != 3 {
		t.Fatalf("stray file listed: %d", len(list))
	}
}

func TestResolveBackup(t *testing.T) {
	d, f := newDir(t)
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	b, _ := d.CreateBackup(f, []byte("x\n"), now)
	other := history.File{Path: "/x/.zsh_history", RealPath: "/x/.zsh_history", Shell: history.Bash}
	_, _ = d.CreateBackup(other, []byte("y\n"), now)

	if got, err := d.ResolveBackup(b.Name); err != nil || got.Path != b.Path {
		t.Fatalf("by name: %+v, %v", got, err)
	}
	if _, err := d.ResolveBackup(".zsh_history.20260923T100000.bak"); err == nil {
		t.Fatal("ambiguous file name accepted")
	}
	for _, bad := range []string{"", "../x", "/etc/passwd", `zsh\x`, "zsh/none.bak"} {
		if _, err := d.ResolveBackup(bad); err == nil {
			t.Errorf("ResolveBackup(%q) accepted", bad)
		}
	}
}

func TestAppendAndVerify(t *testing.T) {
	d, f := newDir(t)
	b, _ := d.CreateBackup(f, []byte("a\n"), time.Now())
	b, err := d.AppendBackup(b, []byte("b\n"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := d.ReadBackup(b)
	if err != nil || string(data) != "a\nb\n" || b.Meta.Size != 4 {
		t.Fatalf("ReadBackup = %q, %v", data, err)
	}
	_ = os.WriteFile(b.Path, []byte("zz\n"), 0o600)
	if _, err := d.ReadBackup(b); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v", err)
	}
	if err := d.RemoveBackup(b); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveBackup(b); err != nil {
		t.Fatalf("second remove: %v", err)
	}
}

func TestPrune(t *testing.T) {
	d, f := newDir(t)
	other := history.File{Path: "/y/.bash_history", RealPath: "/y/.bash_history", Shell: history.Bash}
	base := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		_, _ = d.CreateBackup(f, []byte{byte('a' + i)}, base.Add(time.Duration(i)*time.Minute))
	}
	_, _ = d.CreateBackup(other, []byte("z"), base)
	removed, err := d.Prune(1)
	if err != nil || len(removed) != 2 {
		t.Fatalf("Prune = %d, %v", len(removed), err)
	}
	list, _ := d.Backups()
	if len(list) != 2 {
		t.Fatalf("left %d backups", len(list))
	}
	if data, _ := d.ReadBackup(list[0]); string(data) != "c" {
		t.Fatalf("newest backup not kept: %q", data)
	}
	if removed, _ := d.Prune(0); len(removed) != 2 {
		t.Fatal("Prune(0) must delete everything")
	}
}

func TestEnsureFixesMode(t *testing.T) {
	d, _ := newDir(t)
	if err := os.MkdirAll(d.Root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := d.Ensure(); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(d.Root); fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	file := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(file, nil, 0o600)
	if err := (Dir{Root: file}).Ensure(); err == nil {
		t.Fatal("a file accepted as state directory")
	}
}

func TestLock(t *testing.T) {
	d, _ := newDir(t)
	unlock, err := d.Lock(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	if fi, _ := os.Stat(filepath.Join(d.Root, "lock")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode %v", fi.Mode().Perm())
	}
}

func TestBadMetadataIsReported(t *testing.T) {
	d, f := newDir(t)
	s, err := d.CreateStash(f, []byte("x"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(s.Path+".json", []byte("{"), 0o600)
	if _, err := d.FindStash(f); err == nil {
		t.Fatal("broken sidecar accepted")
	}
}

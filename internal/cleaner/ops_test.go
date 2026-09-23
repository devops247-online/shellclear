package cleaner

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devops247-online/shellclear/internal/history"
	"github.com/devops247-online/shellclear/internal/state"
)

func newOps(e *env) *Ops {
	return &Ops{State: e.state, Now: e.c.Now, LockTimeout: 300 * time.Millisecond}
}

func TestStashAndPop(t *testing.T) {
	e := newEnv(t, Mask)
	o := newOps(e)
	orig := ": 1:0;ls\n: 2:0;secret stuff\n"
	f := e.file(t, "zsh_history", orig, history.Zsh)
	before, _ := os.Stat(f.Path)

	res, err := o.Stash(f)
	if err != nil || res.Empty || res.Stash.Meta.Size != int64(len(orig)) {
		t.Fatalf("Stash = %+v, %v", res, err)
	}
	after, _ := os.Stat(f.Path)
	if after.Size() != 0 || !os.SameFile(before, after) {
		t.Fatal("history not truncated in place")
	}
	if fi, _ := os.Stat(res.Stash.Path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("stash mode %v", fi.Mode().Perm())
	}
	if _, err := o.Stash(f); !errors.Is(err, state.ErrStashExists) {
		t.Fatalf("second stash: %v", err)
	}

	during := ": 3:0;echo while stashed\n"
	if err := os.WriteFile(f.Path, []byte(during), 0o600); err != nil {
		t.Fatal(err)
	}
	pr, err := o.Pop(f)
	if err != nil || pr.Restored != int64(len(orig)) || pr.Kept != int64(len(during)) {
		t.Fatalf("Pop = %+v, %v", pr, err)
	}
	if got := read(t, f.Path); got != orig+during {
		t.Fatalf("got %q", got)
	}
	if _, err := o.Pop(f); !errors.Is(err, state.ErrNoStash) {
		t.Fatalf("second pop: %v", err)
	}
}

func TestPopAddsMissingNewline(t *testing.T) {
	e := newEnv(t, Mask)
	o := newOps(e)
	f := e.file(t, "bash_history", "ls", history.Bash)
	if _, err := o.Stash(f); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(f.Path, []byte("pwd\n"), 0o600)
	if _, err := o.Pop(f); err != nil {
		t.Fatal(err)
	}
	if got := read(t, f.Path); got != "ls\npwd\n" {
		t.Fatalf("got %q", got)
	}
}

func TestStashEmptyFile(t *testing.T) {
	e := newEnv(t, Mask)
	f := e.file(t, "zsh_history", "", history.Zsh)
	res, err := newOps(e).Stash(f)
	if err != nil || !res.Empty {
		t.Fatalf("Stash = %+v, %v", res, err)
	}
	if _, err := e.state.FindStash(f); !errors.Is(err, state.ErrNoStash) {
		t.Fatal("stash created for an empty file")
	}
}

func TestStashMissingFile(t *testing.T) {
	e := newEnv(t, Mask)
	p := filepath.Join(e.dir, "missing")
	if _, err := newOps(e).Stash(history.File{Path: p, RealPath: p, Shell: history.Zsh}); err == nil {
		t.Fatal("no error")
	}
}

func TestStashSameBaseNameDifferentDirs(t *testing.T) {
	e := newEnv(t, Mask)
	o := newOps(e)
	_ = os.MkdirAll(filepath.Join(e.dir, "a"), 0o700)
	_ = os.MkdirAll(filepath.Join(e.dir, "b"), 0o700)
	fa := e.file(t, "a/hist", "one\n", history.Bash)
	fb := e.file(t, "b/hist", "two\n", history.Bash)
	sa, err := o.Stash(fa)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := o.Stash(fb)
	if err != nil || sa.Stash.Path == sb.Stash.Path {
		t.Fatalf("stash b: %+v, %v", sb, err)
	}
	if _, err := o.Pop(fb); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Pop(fa); err != nil {
		t.Fatal(err)
	}
	if read(t, fa.Path) != "one\n" || read(t, fb.Path) != "two\n" {
		t.Fatal("stashes mixed up")
	}
}

func TestPopRejectsCorruptStash(t *testing.T) {
	e := newEnv(t, Mask)
	o := newOps(e)
	f := e.file(t, "zsh_history", "ls\n", history.Zsh)
	res, _ := o.Stash(f)
	_ = os.WriteFile(res.Stash.Path, []byte("tampered\n"), 0o600)
	if _, err := o.Pop(f); !errors.Is(err, state.ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt", err)
	}
}

func TestRestore(t *testing.T) {
	e := newEnv(t, Mask)
	o := newOps(e)
	f := e.file(t, "zsh_history", "old\n", history.Zsh)
	b, err := e.state.CreateBackup(f, []byte("old\n"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(f.Path, []byte("new\n"), 0o640)
	_ = os.Chmod(f.Path, 0o640)

	res, err := o.Restore(b)
	if err != nil || res.Backup == nil {
		t.Fatalf("Restore = %+v, %v", res, err)
	}
	if read(t, f.Path) != "old\n" || read(t, res.Backup.Path) != "new\n" {
		t.Fatal("wrong content after restore")
	}
	if fi, _ := os.Stat(f.Path); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	// Restoring identical content changes nothing.
	res, err = o.Restore(b)
	if err != nil || res.Backup != nil {
		t.Fatalf("second Restore = %+v, %v", res, err)
	}
	// A deleted source is recreated with mode 0600.
	_ = os.Remove(f.Path)
	if _, err := o.Restore(b); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(f.Path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("recreated mode %v", fi.Mode().Perm())
	}
	// A tampered backup is refused.
	_ = os.WriteFile(b.Path, []byte("evil\n"), 0o600)
	if _, err := o.Restore(b); !errors.Is(err, state.ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt", err)
	}
}

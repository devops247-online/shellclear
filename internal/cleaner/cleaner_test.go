package cleaner

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devops247-online/shellclear/internal/history"
	"github.com/devops247-online/shellclear/internal/rules"
	"github.com/devops247-online/shellclear/internal/safefile"
	"github.com/devops247-online/shellclear/internal/scan"
	"github.com/devops247-online/shellclear/internal/state"
)

var token = "ghp_" + strings.Repeat("Q", 36)

type env struct {
	dir   string
	state state.Dir
	c     *Cleaner
}

func newEnv(t *testing.T, mode Mode) *env {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rs, _ := rules.Builtin()
	set, _ := rules.NewSet(nil, rs)
	st := state.Dir{Root: filepath.Join(dir, "state")}
	return &env{dir: dir, state: st, c: &Cleaner{
		Scanner: &scan.Scanner{Rules: set}, Mode: mode, State: st, Backup: true,
		Now:         func() time.Time { return time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC) },
		LockTimeout: 300 * time.Millisecond,
	}}
}

func (e *env) file(t *testing.T, name, content string, shell history.Shell) history.File {
	t.Helper()
	p := filepath.Join(e.dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return history.File{Path: p, RealPath: p, Shell: shell}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const zshData = ": 1:0;ls\n: 2:0;export GITHUB_TOKEN=%s\n: 3:0;echo done\n"

func TestMaskWritesOnlySecrets(t *testing.T) {
	e := newEnv(t, Mask)
	orig := fmt.Sprintf(zshData, token)
	f := e.file(t, "zsh_history", orig, history.Zsh)
	p, err := e.c.Plan(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Changes) != 1 || p.Changes[0].After != "export GITHUB_TOKEN=[REDACTED:github_env_token]" {
		t.Fatalf("plan = %+v", p.Changes)
	}
	out, err := e.c.Apply(p)
	if err != nil || !out.Written || out.Backup == nil {
		t.Fatalf("Apply = %+v, %v", out, err)
	}
	want := ": 1:0;ls\n: 2:0;export GITHUB_TOKEN=[REDACTED:github_env_token]\n: 3:0;echo done\n"
	if got := read(t, f.Path); got != want {
		t.Fatalf("got %q", got)
	}
	if got := read(t, out.Backup.Path); got != orig {
		t.Fatal("backup differs from the original")
	}
	for _, p := range []string{out.Backup.Path, out.Backup.Path + ".json"} {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", p, fi.Mode().Perm())
		}
	}
	for _, d := range []string{e.state.Root, filepath.Join(e.state.Root, "backups"), filepath.Dir(out.Backup.Path)} {
		if fi, _ := os.Stat(d); fi.Mode().Perm() != 0o700 {
			t.Errorf("%s mode %v", d, fi.Mode().Perm())
		}
	}
	if _, err := e.state.ReadBackup(*out.Backup); err != nil {
		t.Fatalf("backup checksum: %v", err)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(e.dir, ".zsh_history.shellclear-*")); len(leftovers) != 0 {
		t.Fatalf("temporary files left: %v", leftovers)
	}
}

func TestUnchangedFileIsNotTouched(t *testing.T) {
	e := newEnv(t, Mask)
	f := e.file(t, "zsh_history", ": 1:0;ls\n", history.Zsh)
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(f.Path, old, old); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(f.Path)
	p, _ := e.c.Plan(f)
	out, err := e.c.Apply(p)
	if err != nil || out.Written || out.Backup != nil {
		t.Fatalf("Apply = %+v, %v", out, err)
	}
	after, _ := os.Stat(f.Path)
	if !os.SameFile(before, after) || !after.ModTime().Equal(old) {
		t.Fatal("file was touched")
	}
	if _, err := os.Stat(e.state.Root); !os.IsNotExist(err) {
		t.Fatal("state directory created for an unchanged file")
	}
}

func TestSymlinkAndModePreserved(t *testing.T) {
	e := newEnv(t, Mask)
	target := e.file(t, "dotfiles_zsh_history", fmt.Sprintf(zshData, token), history.Zsh)
	if err := os.Chmod(target.Path, 0o640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(e.dir, ".zsh_history")
	if err := os.Symlink(target.Path, link); err != nil {
		t.Fatal(err)
	}
	f := history.File{Path: link, RealPath: target.Path, Shell: history.Zsh}
	p, _ := e.c.Plan(f)
	if _, err := e.c.Apply(p); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(link)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink replaced by a regular file")
	}
	ti, _ := os.Stat(target.Path)
	if ti.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, want 0640", ti.Mode().Perm())
	}
	if strings.Contains(read(t, target.Path), token) {
		t.Fatal("target not cleaned")
	}
}

func TestShellAppendedDuringClear(t *testing.T) {
	e := newEnv(t, Mask)
	orig := fmt.Sprintf(zshData, token)
	f := e.file(t, "zsh_history", orig, history.Zsh)
	p, _ := e.c.Plan(f)

	tail := ": 4:0;echo new\n: 5:0;export VAULT_TOKEN=hvs." + strings.Repeat("v", 24) + "\n"
	fh, _ := os.OpenFile(f.Path, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = fh.WriteString(tail)
	_ = fh.Close()

	out, err := e.c.Apply(p)
	if err != nil {
		t.Fatal(err)
	}
	got := read(t, f.Path)
	if strings.Contains(got, token) || strings.Contains(got, "hvs.") || !strings.Contains(got, ": 4:0;echo new\n") {
		t.Fatalf("got %q", got)
	}
	if len(out.TailChanges) != 1 || out.TailChanges[0].Finding.Line != 5 {
		t.Fatalf("tail changes = %+v", out.TailChanges)
	}
	if read(t, out.Backup.Path) != orig+tail {
		t.Fatal("backup does not include the appended commands")
	}
	if _, err := e.state.ReadBackup(*out.Backup); err != nil {
		t.Fatalf("backup metadata not updated: %v", err)
	}
}

func TestFileRewrittenDuringClear(t *testing.T) {
	e := newEnv(t, Mask)
	f := e.file(t, "zsh_history", fmt.Sprintf(zshData, token), history.Zsh)
	p, _ := e.c.Plan(f)
	rewritten := ": 9:0;something else entirely\n"
	if err := os.WriteFile(f.Path, []byte(rewritten), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := e.c.Apply(p)
	if !errors.Is(err, ErrChanged) {
		t.Fatalf("err = %v, want ErrChanged", err)
	}
	if read(t, f.Path) != rewritten {
		t.Fatal("file was written after a conflict")
	}
	if bs, _ := e.state.Backups(); len(bs) != 0 {
		t.Fatalf("backup left after abort: %v", bs)
	}
}

func TestAppendInsideLastRecordIsAConflict(t *testing.T) {
	e := newEnv(t, Mask)
	orig := ": 1:0;export GITHUB_TOKEN=" + token // no final newline
	f := e.file(t, "zsh_history", orig, history.Zsh)
	p, _ := e.c.Plan(f)
	if err := os.WriteFile(f.Path, []byte(orig+" && echo more\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.c.Apply(p); !errors.Is(err, ErrChanged) {
		t.Fatalf("err = %v, want ErrChanged", err)
	}
}

func TestRemoveMode(t *testing.T) {
	e := newEnv(t, Remove)
	f := e.file(t, "bash_history", "#1\nls\n#2\nexport GITHUB_TOKEN="+token+"\n#3\necho done\n", history.Bash)
	p, _ := e.c.Plan(f)
	if _, err := e.c.Apply(p); err != nil {
		t.Fatal(err)
	}
	if got := read(t, f.Path); got != "#1\nls\n#3\necho done\n" {
		t.Fatalf("got %q", got)
	}
}

func TestFishKeepsFormat(t *testing.T) {
	e := newEnv(t, Mask)
	orig := "- cmd: cat ~/" + token + ".txt\n  when: 1\n  paths:\n    - ~/" + token + ".txt\n- cmd: ls\n  when: 2\n"
	f := e.file(t, "fish_history", orig, history.Fish)
	p, _ := e.c.Plan(f)
	if _, err := e.c.Apply(p); err != nil {
		t.Fatal(err)
	}
	want := "- cmd: cat ~/[REDACTED:github_personal_token].txt\n  when: 1\n  paths:\n    - ~/[REDACTED:github_personal_token].txt\n- cmd: ls\n  when: 2\n"
	if got := read(t, f.Path); got != want {
		t.Fatalf("got %q", got)
	}
}

func TestNoBackup(t *testing.T) {
	e := newEnv(t, Mask)
	e.c.Backup = false
	f := e.file(t, "zsh_history", fmt.Sprintf(zshData, token), history.Zsh)
	p, _ := e.c.Plan(f)
	out, err := e.c.Apply(p)
	if err != nil || out.Backup != nil {
		t.Fatalf("Apply = %+v, %v", out, err)
	}
	if bs, _ := e.state.Backups(); len(bs) != 0 {
		t.Fatal("backup written with Backup=false")
	}
}

func TestUneditableRecordIsSkipped(t *testing.T) {
	e := newEnv(t, Mask)
	// A last record without a newline that ends in "\ " cannot be edited:
	// zsh would read the trailing space differently once a newline follows.
	f := e.file(t, "zsh_history", ": 1:0;ls\n: 2:0;echo "+token+" \\ ", history.Zsh)
	p, _ := e.c.Plan(f)
	if len(p.Skipped) != 1 || len(p.Changes) != 0 || !bytes.Equal(p.New, p.Orig) {
		t.Fatalf("plan = %+v", p)
	}
}

func TestZshLockBlocksWriting(t *testing.T) {
	e := newEnv(t, Mask)
	f := e.file(t, "zsh_history", fmt.Sprintf(zshData, token), history.Zsh)
	if err := os.Symlink("/pid-1/host-other", f.Path+".LOCK"); err != nil {
		t.Fatal(err)
	}
	p, _ := e.c.Plan(f)
	if _, err := e.c.Apply(p); !errors.Is(err, safefile.ErrLocked) {
		t.Fatalf("err = %v, want ErrLocked", err)
	}
	if !strings.Contains(read(t, f.Path), token) {
		t.Fatal("file written while locked")
	}
	_ = os.Remove(f.Path + ".LOCK")
	if _, err := e.c.Apply(p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(f.Path + ".LOCK"); !os.IsNotExist(err) {
		t.Fatal("lock not released")
	}
}

// TestHelperHoldLock is run as a subprocess by TestFcntlLockBlocksWriting.
func TestHelperHoldLock(t *testing.T) {
	path := os.Getenv("SHELLCLEAR_HOLD_LOCK")
	if path == "" {
		t.Skip("helper process")
	}
	_, unlock, err := safefile.LockFile(path, time.Second)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	fmt.Println("locked")
	time.Sleep(2 * time.Second)
	unlock()
}

func TestFcntlLockBlocksWriting(t *testing.T) {
	e := newEnv(t, Mask)
	f := e.file(t, "bash_history", "export GITHUB_TOKEN="+token+"\n", history.Bash)
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHoldLock$")
	cmd.Env = append(os.Environ(), "SHELLCLEAR_HOLD_LOCK="+f.Path)
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Wait() }()
	buf := make([]byte, 6)
	if _, err := stdout.Read(buf); err != nil || string(buf) != "locked" {
		t.Fatalf("helper did not lock: %q %v", buf, err)
	}
	p, _ := e.c.Plan(f)
	if _, err := e.c.Apply(p); !errors.Is(err, safefile.ErrLocked) {
		t.Fatalf("err = %v, want ErrLocked", err)
	}
}

func TestApplyMissingFile(t *testing.T) {
	e := newEnv(t, Mask)
	f := e.file(t, "zsh_history", fmt.Sprintf(zshData, token), history.Zsh)
	p, _ := e.c.Plan(f)
	_ = os.Remove(f.Path)
	if _, err := e.c.Apply(p); err == nil {
		t.Fatal("no error for a deleted file")
	}
}

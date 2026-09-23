package motd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devops247-online/shellclear/internal/history"
	"github.com/devops247-online/shellclear/internal/rules"
	"github.com/devops247-online/shellclear/internal/scan"
)

var secretLine = ": 1:0;export GITHUB_TOKEN=ghp_" + strings.Repeat("a", 36) + "\n"

func checker(t *testing.T, ignore ...string) (*Checker, string) {
	t.Helper()
	dir := t.TempDir()
	rs, _ := rules.Builtin()
	set, _ := rules.NewSet(ignore, rs)
	return &Checker{
		Scanner:   &scan.Scanner{Rules: set},
		StateDir:  filepath.Join(dir, "state"),
		RulesHash: RulesHash("test", set, nil),
	}, dir
}

func write(t *testing.T, p, s string) history.File {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return history.File{Path: p, RealPath: p, Shell: history.Zsh}
}

func appendTo(t *testing.T, p, s string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(s)
	_ = f.Close()
}

func TestCountHitIncrementalFull(t *testing.T) {
	c, dir := checker(t)
	f := write(t, filepath.Join(dir, "h"), ": 1:0;ls\n"+secretLine)

	n, st, err := c.Count([]history.File{f})
	if err != nil || n != 1 || st.Full != 1 {
		t.Fatalf("first: %d %+v %v", n, st, err)
	}
	if fi, _ := os.Stat(filepath.Join(c.StateDir, CacheName)); fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode %v", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(filepath.Join(c.StateDir, CacheName))
	if strings.Contains(string(b), "ghp_") || strings.Contains(string(b), "GITHUB") {
		t.Fatal("cache contains command text")
	}

	// A cache hit only needs stat: an unreadable file still gives the count.
	_ = os.Chmod(f.Path, 0)
	n, st, err = c.Count([]history.File{f})
	_ = os.Chmod(f.Path, 0o600)
	if err != nil || n != 1 || st.Hits != 1 {
		t.Fatalf("hit: %d %+v %v", n, st, err)
	}

	appendTo(t, f.Path, ": 2:0;echo x\n"+secretLine)
	n, st, _ = c.Count([]history.File{f})
	if n != 2 || st.Incremental != 1 {
		t.Fatalf("append: %d %+v", n, st)
	}

	// Rewriting the start of the file (same inode) forces a full scan.
	data, _ := os.ReadFile(f.Path)
	rewritten := strings.Replace(string(data), secretLine, ": 9:0;safe command here, same length?\n", 1)
	_ = os.WriteFile(f.Path, []byte(rewritten+": 3:0;ls\n"), 0o600)
	n, st, _ = c.Count([]history.File{f})
	if n != 1 || st.Full != 1 {
		t.Fatalf("rewrite: %d %+v", n, st)
	}
}

func TestIncompleteLastRecordCountedOnce(t *testing.T) {
	c, dir := checker(t)
	p := filepath.Join(dir, "h")
	// The last record continues on the next line (zsh backslash-newline).
	f := write(t, p, ": 1:0;ls\n: 2:0;echo \\\n")
	if n, _, _ := c.Count([]history.File{f}); n != 0 {
		t.Fatalf("n = %d", n)
	}
	appendTo(t, p, "ghp_"+strings.Repeat("b", 36)+"\n")
	n, st, _ := c.Count([]history.File{f})
	if n != 1 || st.Incremental != 1 {
		t.Fatalf("n = %d, %+v", n, st)
	}
	appendTo(t, p, ": 3:0;ls\n")
	if n, _, _ := c.Count([]history.File{f}); n != 1 {
		t.Fatalf("counted twice: %d", n)
	}
}

func TestRulesChangeInvalidates(t *testing.T) {
	c, dir := checker(t)
	f := write(t, filepath.Join(dir, "h"), secretLine)
	if n, _, _ := c.Count([]history.File{f}); n != 1 {
		t.Fatal("setup")
	}
	c2, _ := checker(t, "github_env_token", "github_personal_token", "generic_secret_assignment")
	c2.StateDir = c.StateDir
	n, st, _ := c2.Count([]history.File{f})
	if n != 0 || st.Full != 1 {
		t.Fatalf("stale cache used: %d %+v", n, st)
	}
}

func TestInvalidateAndDroppedFiles(t *testing.T) {
	c, dir := checker(t)
	a := write(t, filepath.Join(dir, "a"), secretLine)
	b := write(t, filepath.Join(dir, "b"), secretLine)
	if n, _, _ := c.Count([]history.File{a, b}); n != 2 {
		t.Fatal("setup")
	}
	if n, st, _ := c.Count([]history.File{a}); n != 1 || st.Hits != 1 {
		t.Fatalf("n=%d %+v", n, st)
	}
	Invalidate(c.StateDir)
	if _, err := os.Stat(filepath.Join(c.StateDir, CacheName)); !os.IsNotExist(err) {
		t.Fatal("cache not removed")
	}
	_ = os.WriteFile(filepath.Join(c.StateDir, CacheName), []byte("{broken"), 0o600)
	if n, st, _ := c.Count([]history.File{a}); n != 1 || st.Full != 1 {
		t.Fatalf("broken cache: %d %+v", n, st)
	}
}

func TestErrors(t *testing.T) {
	c, dir := checker(t)
	if _, _, err := c.Count([]history.File{{Path: "x", RealPath: filepath.Join(dir, "missing"), Shell: history.Zsh}}); err == nil {
		t.Fatal("missing file")
	}
	f := write(t, filepath.Join(dir, "h"), "x\n")
	f.Shell = "tcsh"
	if _, _, err := c.Count([]history.File{f}); err == nil {
		t.Fatal("unknown shell")
	}
}

func TestFinished(t *testing.T) {
	cases := []struct {
		s    history.Shell
		raw  string
		want bool
	}{
		{history.Zsh, "ls\n", true}, {history.Zsh, "ls \\\n", false}, {history.Zsh, "ls", false},
		{history.PowerShell, "a`\r\n", false}, {history.PowerShell, "a\r\n", true}, {history.Bash, "a\n", true},
	}
	for _, c := range cases {
		if got := finished(c.s, []byte(c.raw)); got != c.want {
			t.Errorf("finished(%s, %q) = %v", c.s, c.raw, got)
		}
	}
}

func TestHotPathIsFast(t *testing.T) {
	if testing.Short() {
		t.Skip("timing")
	}
	c, dir := checker(t)
	var b strings.Builder
	for i := 0; i < 50000; i++ {
		b.WriteString(": 1:0;git status\n")
	}
	f := write(t, filepath.Join(dir, "h"), b.String())
	_, _, _ = c.Count([]history.File{f})
	start := time.Now()
	if _, st, _ := c.Count([]history.File{f}); st.Hits != 1 {
		t.Fatal("no cache hit")
	}
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("cached count took %s", d)
	}
}

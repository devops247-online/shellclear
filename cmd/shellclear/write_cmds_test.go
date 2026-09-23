package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func (ta *testApp) read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(ta.home, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (ta *testApp) assertNoLeak(t *testing.T, what string) {
	t.Helper()
	for _, s := range fixtureSecrets {
		if strings.Contains(ta.stdout.String(), s) || strings.Contains(ta.stderr.String(), s) {
			t.Fatalf("%s leaks %q\nstdout:\n%s\nstderr:\n%s", what, s, ta.stdout, ta.stderr)
		}
	}
}

func TestClearDryRun(t *testing.T) {
	ta := newTestApp(t)
	ta.withHistory(t)
	before := ta.read(t, ".zsh_history")
	if code := ta.run("clear", "--dry-run"); code != exitOK {
		t.Fatalf("code %d, %s", code, ta.stderr)
	}
	ta.assertNoLeak(t, "clear --dry-run")
	out := ta.stdout.String()
	for _, want := range []string{"~/.zsh_history (zsh): 1 command to mask", "+ export GITHUB_TOKEN=[REDACTED:github_env_token]", "Dry run: nothing was written."} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if ta.read(t, ".zsh_history") != before {
		t.Fatal("dry run wrote the file")
	}
	if _, err := os.Stat(filepath.Join(ta.home, ".shellclear")); !os.IsNotExist(err) {
		t.Fatal("dry run created the state directory")
	}
}

func TestClearNeedsConfirmation(t *testing.T) {
	ta := newTestApp(t)
	ta.withHistory(t)
	before := ta.read(t, ".bash_history")
	if code := ta.run("clear"); code != exitError || !strings.Contains(ta.stderr.String(), "--yes") {
		t.Fatalf("no TTY: code %d, %q", code, ta.stderr)
	}
	ta.StdinIsTTY = true
	ta.Stdin = strings.NewReader("n\n")
	if code := ta.run("clear"); code != exitOK || !strings.Contains(ta.stdout.String(), "Aborted") {
		t.Fatalf("answer n: code %d, %q", code, ta.stdout)
	}
	ta.Stdin = strings.NewReader("")
	if code := ta.run("clear"); code != exitOK || !strings.Contains(ta.stdout.String(), "Aborted") {
		t.Fatalf("EOF: code %d", code)
	}
	if ta.read(t, ".bash_history") != before {
		t.Fatal("file written without confirmation")
	}
	ta.Stdin = strings.NewReader("y\n")
	if code := ta.run("clear"); code != exitOK {
		t.Fatalf("answer y: code %d, %s", code, ta.stderr)
	}
	ta.assertNoLeak(t, "clear")
	if got := ta.read(t, ".bash_history"); got != "mysql -uroot -p[REDACTED:mysql_password] db\ndocker login -u me -p [REDACTED:registry_login_password] reg\n" {
		t.Fatalf("bash history = %q", got)
	}
}

func TestClearYesAndHints(t *testing.T) {
	ta := newTestApp(t)
	ta.withHistory(t)
	if code := ta.run("clear", "-y"); code != exitOK {
		t.Fatalf("code %d, %s", code, ta.stderr)
	}
	ta.assertNoLeak(t, "clear -y")
	out := ta.stdout.String()
	for _, want := range []string{"~/.zsh_history: masked 1 command", "backup: zsh/.zsh_history.", "exec zsh", "history -c; history -r", "--prune --keep 0"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if code := ta.run("find"); code != exitOK {
		t.Fatalf("find after clear: code %d\n%s", code, ta.stdout)
	}
	if code := ta.run("clear", "-y"); code != exitOK || !strings.Contains(ta.stdout.String(), "No secrets found") {
		t.Fatalf("second clear: code %d, %q", code, ta.stdout)
	}
}

func TestClearRemoveNoBackup(t *testing.T) {
	ta := newTestApp(t)
	ta.withHistory(t)
	if code := ta.run("clear", "--remove", "--no-backup", "--yes"); code != exitOK {
		t.Fatalf("code %d, %s", code, ta.stderr)
	}
	if got := ta.read(t, ".bash_history"); got != "" {
		t.Fatalf("bash history = %q", got)
	}
	if got := ta.read(t, ".zsh_history"); got != ": 1790000001:0;ls\n" {
		t.Fatalf("zsh history = %q", got)
	}
	if strings.Contains(ta.stdout.String(), "backup:") {
		t.Fatal("backup reported with --no-backup")
	}
	if _, err := os.Stat(filepath.Join(ta.home, ".shellclear", "backups")); !os.IsNotExist(err) {
		t.Fatal("backups written with --no-backup")
	}
}

func TestClearReportsUneditable(t *testing.T) {
	ta := newTestApp(t)
	ta.write(t, ".zsh_history", ": 1:0;echo "+fixtureSecrets[0]+" \\ ")
	code := ta.run("clear", "--yes")
	if code != exitFindings || !strings.Contains(ta.stderr.String(), "cannot be edited safely") {
		t.Fatalf("code %d, stderr %q", code, ta.stderr)
	}
	ta.assertNoLeak(t, "clear with uneditable record")
}

func TestStashPopCLI(t *testing.T) {
	ta := newTestApp(t)
	ta.withHistory(t)
	orig := ta.read(t, ".zsh_history")
	if code := ta.run("stash"); code != exitOK || !strings.Contains(ta.stdout.String(), "fc -p") {
		t.Fatalf("stash: code %d, %q %q", code, ta.stdout, ta.stderr)
	}
	if ta.read(t, ".zsh_history") != "" {
		t.Fatal("history not emptied")
	}
	if code := ta.run("stash"); code != exitError || !strings.Contains(ta.stderr.String(), "already exists") {
		t.Fatalf("second stash: code %d, %q", code, ta.stderr)
	}
	ta.write(t, ".zsh_history", ": 1790000002:0;echo new\n")
	if code := ta.run("pop"); code != exitOK || !strings.Contains(ta.stdout.String(), "kept") {
		t.Fatalf("pop: code %d, %q", code, ta.stdout)
	}
	if got := ta.read(t, ".zsh_history"); got != orig+": 1790000002:0;echo new\n" {
		t.Fatalf("after pop: %q", got)
	}
	if code := ta.run("pop"); code != exitOK || !strings.Contains(ta.stdout.String(), "No stash") {
		t.Fatalf("second pop: code %d, %q", code, ta.stdout)
	}
	ta.write(t, ".zsh_history", "")
	if code := ta.run("stash", "--file", filepath.Join(ta.home, ".zsh_history")); code != exitOK || !strings.Contains(ta.stdout.String(), "nothing to stash") {
		t.Fatalf("empty stash: code %d, %q", code, ta.stdout)
	}
}

func TestRestoreCLI(t *testing.T) {
	ta := newTestApp(t)
	ta.withHistory(t)
	orig := ta.read(t, ".zsh_history")
	if code := ta.run("restore"); code != exitOK || !strings.Contains(ta.stdout.String(), "No backups") {
		t.Fatalf("empty list: code %d, %q", code, ta.stdout)
	}
	ta.run("clear", "--yes", "--file", filepath.Join(ta.home, ".zsh_history"))
	ta.run("restore")
	line := strings.SplitN(ta.stdout.String(), "\n", 2)[0]
	name := strings.Fields(line)[0]
	if !strings.HasPrefix(name, "zsh/.zsh_history.") {
		t.Fatalf("list: %q", ta.stdout)
	}
	if code := ta.run("restore", name); code != exitOK || !strings.Contains(ta.stdout.String(), "previous content backed up") {
		t.Fatalf("restore: code %d, %q %q", code, ta.stdout, ta.stderr)
	}
	if ta.read(t, ".zsh_history") != orig {
		t.Fatal("content not restored")
	}
	for _, args := range [][]string{{"restore", "../../x"}, {"restore", "zsh/none.bak"}, {"restore", "--prune"}, {"restore", "--prune", name}} {
		if code := ta.run(args...); code != exitError {
			t.Errorf("%v: code %d", args, code)
		}
	}
	if code := ta.run("restore", "--prune", "--keep", "0"); code != exitOK || !strings.Contains(ta.stdout.String(), "Deleted 2 backups") {
		t.Fatalf("prune: code %d, %q", code, ta.stdout)
	}
	ta.write(t, ".shellclear/config.yaml", "backups: {keep: 3}\n")
	if code := ta.run("restore", "--prune"); code != exitOK || !strings.Contains(ta.stdout.String(), "Deleted 0 backups") {
		t.Fatalf("prune from config: code %d, %q %q", code, ta.stdout, ta.stderr)
	}
}

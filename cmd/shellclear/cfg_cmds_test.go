package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigInitValidatePath(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.run("config", "path"); code != exitOK || strings.TrimSpace(ta.stdout.String()) != filepath.Join(ta.home, ".shellclear") {
		t.Fatalf("path: %d %q", code, ta.stdout)
	}
	if code := ta.run("config", "init"); code != exitOK || strings.Count(ta.stdout.String(), "created") != 2 {
		t.Fatalf("init: %d %q", code, ta.stdout)
	}
	for _, p := range []string{".shellclear/config.yaml", ".shellclear/rules.d/custom.yaml"} {
		fi, err := os.Stat(filepath.Join(ta.home, p))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, fi, err)
		}
	}
	if fi, _ := os.Stat(filepath.Join(ta.home, ".shellclear", "rules.d")); fi.Mode().Perm() != 0o700 {
		t.Fatal("rules.d mode")
	}
	ta.write(t, ".shellclear/config.yaml", "version: 1\nignore: [jwt]\n")
	if code := ta.run("config", "init"); code != exitOK || !strings.Contains(ta.stdout.String(), "left unchanged") {
		t.Fatalf("second init: %d %q", code, ta.stdout)
	}
	if ta.read(t, ".shellclear/config.yaml") != "version: 1\nignore: [jwt]\n" {
		t.Fatal("init overwrote config.yaml")
	}
	if code := ta.run("config", "validate"); code != exitOK || !strings.Contains(ta.stdout.String(), "OK (0 custom rules in 1 file, 1 ignored") {
		t.Fatalf("validate: %d %q %q", code, ta.stdout, ta.stderr)
	}
	ta.write(t, ".shellclear/config.yaml", "ignore: [no_such_rule]\ncolour: red\n")
	if code := ta.run("config", "validate"); code != exitError || !strings.Contains(ta.stderr.String(), "colour") || !strings.Contains(ta.stderr.String(), "no_such_rule") {
		t.Fatalf("invalid: %d %q", code, ta.stderr)
	}
	ta.write(t, ".shellclear/rules.d/bad.yaml", "- {id: x, name: x, test: '('}\n")
	if code := ta.run("config", "validate"); code != exitError || !strings.Contains(ta.stderr.String(), "bad.yaml") {
		t.Fatalf("bad rules: %d %q", code, ta.stderr)
	}
	for _, args := range [][]string{{"config"}, {"config", "nope"}} {
		if code := ta.run(args...); code != exitError {
			t.Errorf("%v: code %d", args, code)
		}
	}
	if code := ta.run("config", "--help"); code != exitOK || !strings.Contains(ta.stdout.String(), "import-legacy") {
		t.Fatalf("help: %d", code)
	}
}

func TestConfigImportLegacy(t *testing.T) {
	ta := newTestApp(t)
	ta.write(t, "shellclear/sensitive-patterns.yaml", "- name: My Company Token\n  test: mycorp_[a-z0-9]{8}\n  secret_group: 0\n")
	ta.write(t, "shellclear/ignores.yaml", "- jwt\n- mail_gun_api_key\n")
	ta.write(t, ".zsh_history", ": 1:0;echo mycorp_abcdef12\n")

	ta.run("find")
	if !strings.Contains(ta.stderr.String(), "--import-legacy") {
		t.Fatalf("no legacy hint: %q", ta.stderr)
	}
	if code := ta.run("config", "init", "--import-legacy"); code != exitOK || strings.Count(ta.stdout.String(), "imported") != 2 {
		t.Fatalf("import: %d %q %q", code, ta.stdout, ta.stderr)
	}
	cfg := ta.read(t, ".shellclear/config.yaml")
	if !strings.Contains(cfg, "  - jwt\n  - mail_gun_api_key") {
		t.Fatalf("ignores not imported:\n%s", cfg)
	}
	if code := ta.run("find", "--format", "json"); code != exitFindings || !strings.Contains(ta.stdout.String(), "my_company_token") {
		t.Fatalf("legacy rule not active: %d %s", code, ta.stdout)
	}
	if strings.Contains(ta.stderr.String(), "--import-legacy") {
		t.Fatal("hint shown after import")
	}

	// Importing into an existing config.yaml merges the ignore list.
	ta2 := newTestApp(t)
	ta2.write(t, "shellclear/ignores.yaml", "- jwt\n")
	ta2.write(t, ".shellclear/config.yaml", "# mine\nversion: 1\nignore: [npm_token]\n")
	if code := ta2.run("config", "init", "--import-legacy"); code != exitOK {
		t.Fatalf("merge: %d %q", code, ta2.stderr)
	}
	merged := ta2.read(t, ".shellclear/config.yaml")
	if !strings.Contains(merged, "# mine") || !strings.Contains(merged, "npm_token") || !strings.Contains(merged, "jwt") {
		t.Fatalf("merged config:\n%s", merged)
	}
	ta3 := newTestApp(t)
	if code := ta3.run("config", "init", "--import-legacy"); code != exitOK || !strings.Contains(ta3.stdout.String(), "nothing to import") {
		t.Fatalf("no legacy: %d %q", code, ta3.stdout)
	}
}

func TestMotd(t *testing.T) {
	ta := newTestApp(t)
	ta.write(t, ".zsh_history", ": 1:0;ls\n")
	if code := ta.run("motd"); code != exitOK || ta.stdout.Len() != 0 || ta.stderr.Len() != 0 {
		t.Fatalf("clean: %d %q %q", code, ta.stdout, ta.stderr)
	}
	ta.withHistory(t)
	if code := ta.run("motd"); code != exitOK || ta.stdout.String() != "⚠ shellclear: 3 sensitive commands found in history — run 'shellclear find'\n" {
		t.Fatalf("dirty: %d %q", code, ta.stdout)
	}
	ta.assertNoLeak(t, "motd")
	if _, err := os.Stat(filepath.Join(ta.home, ".shellclear", "cache.json")); err != nil {
		t.Fatal("no cache written")
	}
	ta.run("-v", "motd")
	if !strings.Contains(ta.stderr.String(), "cached 2") {
		t.Fatalf("second run not cached: %q", ta.stderr)
	}

	// clear invalidates the cache, so motd immediately reports the new state.
	ta.run("clear", "--yes")
	if _, err := os.Stat(filepath.Join(ta.home, ".shellclear", "cache.json")); !os.IsNotExist(err) {
		t.Fatal("clear did not drop the cache")
	}
	if ta.run("motd"); ta.stdout.Len() != 0 {
		t.Fatalf("after clear: %q", ta.stdout)
	}
}

func TestInitShellCompat(t *testing.T) {
	ta := newTestApp(t)
	ta.withHistory(t)
	code := ta.run("--init-shell")
	if code != exitOK || ta.stdout.Len() != 0 || !strings.Contains(ta.stderr.String(), "3 sensitive commands") {
		t.Fatalf("init-shell: %d stdout %q stderr %q", code, ta.stdout, ta.stderr)
	}
	ta.StderrIsTTY = true
	ta.run("--init-shell")
	if !strings.Contains(ta.stderr.String(), "\x1b[1;33m") {
		t.Fatal("no color on a terminal")
	}
}

func TestMotdNeverFails(t *testing.T) {
	ta := newTestApp(t)
	ta.withHistory(t)
	ta.write(t, ".shellclear/config.yaml", "version: 99\n")
	for _, args := range [][]string{{"motd"}, {"--init-shell"}, {"motd", "--bogus"}, {"--shell", "tcsh", "motd"}, {"motd", "--file", "/missing", "--shell", "zsh"}} {
		if code := ta.run(args...); code != exitOK || ta.stdout.Len() != 0 || ta.stderr.Len() != 0 {
			t.Errorf("%v: code %d stdout %q stderr %q", args, code, ta.stdout, ta.stderr)
		}
	}
	ta.run("-v", "motd")
	if !strings.Contains(ta.stderr.String(), "unsupported version") {
		t.Fatalf("verbose error missing: %q", ta.stderr)
	}
}

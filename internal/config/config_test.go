package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDir(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	if got := Dir("", get, "/h"); got != "/h/.shellclear" {
		t.Errorf("default = %q", got)
	}
	env[EnvHome] = "/env"
	if got := Dir("", get, "/h"); got != "/env" {
		t.Errorf("env = %q", got)
	}
	if got := Dir("/flag", get, "/h"); got != "/flag" {
		t.Errorf("flag = %q", got)
	}
}

func TestLoadMissingDir(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "none"))
	if err != nil || len(cfg.CustomRules) != 0 || len(cfg.Warnings) != 0 {
		t.Fatalf("got %+v, %v", cfg, err)
	}
	set, err := cfg.RuleSet()
	if err != nil || len(set.Rules()) < 60 {
		t.Fatalf("RuleSet: %v", err)
	}
}

func TestLoadFull(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, FileName), `version: 1
ignore: [Generic_Secret_Assignment, no_such_rule]
allow:
  - '^export GITHUB_TOKEN=\$\(gh auth token\)$'
backups:
  keep: 5
colour: red
`)
	write(t, filepath.Join(dir, RulesDir, "b.yaml"), "- {id: mine, name: Mine B, test: 'bbbb'}\n")
	write(t, filepath.Join(dir, RulesDir, "a.yaml"), "- {id: mine, name: Mine A, test: 'aaaa'}\n- {id: github_personal_token, name: Override, test: 'ghp_x+', severity: low}\n")
	write(t, filepath.Join(dir, RulesDir, "notes.txt"), "ignored")

	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BackupsKeep != 5 || len(cfg.Allow) != 1 || len(cfg.Ignore) != 2 || cfg.Ignore[0] != "generic_secret_assignment" {
		t.Fatalf("cfg = %+v", cfg)
	}
	if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], `unknown key "colour"`) {
		t.Fatalf("warnings = %q", cfg.Warnings)
	}
	if len(cfg.CustomRules) != 2 || cfg.CustomRules[0][0].Name != "Mine A" {
		t.Fatalf("rules.d not loaded in lexical order: %+v", cfg.CustomRules)
	}

	set, err := cfg.RuleSet()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]string{}
	for _, r := range set.Rules() {
		byID[r.ID] = r.Name
	}
	if byID["mine"] != "Mine B" || byID["github_personal_token"] != "Override" {
		t.Errorf("later files must win: %q %q", byID["mine"], byID["github_personal_token"])
	}
	if _, ok := byID["generic_secret_assignment"]; ok {
		t.Error("ignored rule is active")
	}
	if !strings.Contains(strings.Join(cfg.Warnings, "\n"), `no rule with id "no_such_rule"`) {
		t.Errorf("warnings = %q", cfg.Warnings)
	}

	_, errs := Validate(dir)
	if len(errs) != 2 {
		t.Fatalf("Validate = %v", errs)
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string]string{
		"bad yaml":        "ignore: [\n",
		"not a mapping":   "- a\n",
		"bad version":     "version: 2\n",
		"negative keep":   "backups: {keep: -1}\n",
		"bad allow":       "allow: ['(']\n",
		"ignore not list": "ignore: {a: b}\n",
	}
	for name, content := range cases {
		dir := t.TempDir()
		write(t, filepath.Join(dir, FileName), content)
		if _, err := Load(dir); err == nil {
			t.Errorf("%s: no error", name)
		}
		if _, errs := Validate(dir); len(errs) != 1 {
			t.Errorf("%s: Validate = %v", name, errs)
		}
	}

	dir := t.TempDir()
	write(t, filepath.Join(dir, RulesDir, "bad.yaml"), "- {id: x, name: x, test: '('}\n")
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "bad.yaml") {
		t.Errorf("bad rule file: %v", err)
	}

	dir = t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, FileName), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Error("config.yaml as directory: no error")
	}
}

func TestEmptyConfig(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, FileName), "# nothing yet\n")
	cfg, err := Load(dir)
	if err != nil || len(cfg.Warnings) != 0 {
		t.Fatalf("got %+v, %v", cfg, err)
	}
}

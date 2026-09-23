package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devops247-online/shellclear/internal/history"
)

var fixtureSecrets = []string{
	"ghp_" + strings.Repeat("Q", 36),
	"Sup3rS3cretPass",
	"hunter2hunter2",
}

type testApp struct {
	*App
	home           string
	stdout, stderr *bytes.Buffer
	vars           map[string]string
}

func newTestApp(t *testing.T) *testApp {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ta := &testApp{home: home, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, vars: map[string]string{}}
	ta.App = &App{
		Stdout: ta.stdout, Stderr: ta.stderr, Stdin: strings.NewReader(""),
		Env: history.Env{
			Home: home, GOOS: "linux",
			Getenv:   func(k string) string { return ta.vars[k] },
			Stat:     os.Stat,
			Glob:     filepath.Glob,
			Realpath: filepath.EvalSymlinks,
		},
		Location: time.UTC,
	}
	return ta
}

func (ta *testApp) write(t *testing.T, rel, content string) string {
	t.Helper()
	p := filepath.Join(ta.home, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (ta *testApp) run(args ...string) int {
	ta.stdout.Reset()
	ta.stderr.Reset()
	return ta.Run(args)
}

func (ta *testApp) withHistory(t *testing.T) {
	ta.write(t, ".zsh_history", ": 1790000000:0;export GITHUB_TOKEN="+fixtureSecrets[0]+"\n: 1790000001:0;ls\n")
	ta.write(t, ".bash_history", "mysql -uroot -p"+fixtureSecrets[1]+" db\ndocker login -u me -p "+fixtureSecrets[2]+" reg\n")
}

func TestFindExitCodes(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.run("find"); code != exitOK || !strings.Contains(ta.stderr.String(), "no history files found") {
		t.Fatalf("no files: code %d, stderr %q", code, ta.stderr)
	}
	ta.write(t, ".zsh_history", ": 1:0;ls\n")
	if code := ta.run("find"); code != exitOK || !strings.Contains(ta.stdout.String(), "No secrets found") {
		t.Fatalf("clean: code %d, stdout %q", code, ta.stdout)
	}
	ta.withHistory(t)
	if code := ta.run("find"); code != exitFindings {
		t.Fatalf("findings: code %d", code)
	}
	if code := ta.run("find", "--severity", "high", "--file", filepath.Join(ta.home, ".zsh_history")); code != exitFindings {
		t.Fatalf("zsh high: code %d", code)
	}
}

func TestFindNeverLeaks(t *testing.T) {
	ta := newTestApp(t)
	ta.withHistory(t)
	for _, format := range []string{"text", "table", "json"} {
		for _, extra := range [][]string{nil, {"-v"}} {
			args := append(append([]string{}, extra...), "find", "--format", format)
			ta.run(args...)
			for _, s := range fixtureSecrets {
				if strings.Contains(ta.stdout.String(), s) || strings.Contains(ta.stderr.String(), s) {
					t.Fatalf("%v leaks %q\nstdout:\n%s\nstderr:\n%s", args, s, ta.stdout, ta.stderr)
				}
			}
		}
	}
}

func TestFindJSON(t *testing.T) {
	ta := newTestApp(t)
	ta.withHistory(t)
	ta.run("find", "--format", "json")
	var doc struct {
		Files []struct {
			Path     string `json:"path"`
			Findings []struct {
				RuleID string `json:"rule_id"`
			} `json:"findings"`
		} `json:"files"`
		Summary struct {
			Commands int `json:"commands"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(ta.stdout.Bytes(), &doc); err != nil {
		t.Fatalf("%v: %s", err, ta.stdout)
	}
	if len(doc.Files) != 2 || doc.Summary.Commands != 3 || doc.Files[0].Findings[0].RuleID != "github_env_token" {
		t.Fatalf("doc = %+v", doc)
	}
}

func TestGlobalFlagsBeforeAndAfterCommand(t *testing.T) {
	ta := newTestApp(t)
	p := ta.write(t, "custom/hist.txt", "export GITHUB_TOKEN="+fixtureSecrets[0]+"\n")
	for _, args := range [][]string{
		{"-v", "--file", p, "--shell", "bash", "find"},
		{"find", "-v", "--file", p, "--shell", "bash"},
	} {
		if code := ta.run(args...); code != exitFindings {
			t.Fatalf("%v: code %d, stderr %q", args, code, ta.stderr)
		}
		if !strings.Contains(ta.stderr.String(), "history: "+p+" (bash)") {
			t.Fatalf("%v: verbose output missing: %q", args, ta.stderr)
		}
	}
	if code := ta.run("find", "--file", p); code != exitError || !strings.Contains(ta.stderr.String(), "--shell") {
		t.Fatalf("unknown format: code %d, %q", code, ta.stderr)
	}
}

func TestColor(t *testing.T) {
	ta := newTestApp(t)
	ta.withHistory(t)
	ta.StdoutIsTTY = true
	ta.run("find")
	if !strings.Contains(ta.stdout.String(), "\x1b[") {
		t.Fatal("no colors on a TTY")
	}
	ta.run("find", "--no-color")
	if strings.Contains(ta.stdout.String(), "\x1b[") {
		t.Fatal("colors with --no-color")
	}
	ta.vars["NO_COLOR"] = "1"
	ta.run("find")
	if strings.Contains(ta.stdout.String(), "\x1b[") {
		t.Fatal("colors with NO_COLOR")
	}
}

func TestConfigApplied(t *testing.T) {
	ta := newTestApp(t)
	ta.withHistory(t)
	ta.write(t, ".shellclear/config.yaml", "ignore: [github_env_token, github_personal_token, generic_secret_assignment]\n")
	ta.write(t, ".shellclear/rules.d/mine.yaml", "- {id: mine, name: Mine, test: 'ls', severity: low}\n")
	ta.run("find", "--format", "json")
	out := ta.stdout.String()
	if strings.Contains(out, "github_env_token") || !strings.Contains(out, `"rule_id": "mysql_password"`) {
		t.Fatalf("ignore not applied:\n%s", out)
	}
	// "ls" is shorter than 4 characters, so the custom rule never reports it.
	if strings.Contains(out, `"mine"`) {
		t.Fatal("short value reported")
	}
	ta.vars["SHELLCLEAR_HOME"] = filepath.Join(ta.home, "elsewhere")
	ta.run("find", "--format", "json")
	if !strings.Contains(ta.stdout.String(), "github_env_token") {
		t.Fatal("SHELLCLEAR_HOME not honored")
	}
	ta.write(t, "elsewhere/config.yaml", "version: 9\n")
	if code := ta.run("find"); code != exitError || !strings.Contains(ta.stderr.String(), "unsupported version") {
		t.Fatalf("bad config: code %d, %q", code, ta.stderr)
	}
}

func TestRulesCommand(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.run("rules"); code != exitOK || !strings.Contains(ta.stdout.String(), "github_personal_token") {
		t.Fatalf("rules: code %d", code)
	}
	if code := ta.run("rules", "--format", "json"); code != exitOK || !strings.HasPrefix(ta.stdout.String(), "[") {
		t.Fatalf("rules json: code %d", code)
	}
	if code := ta.run("rules", "--format", "xml"); code != exitError {
		t.Fatalf("rules xml: code %d", code)
	}
}

func TestUsageAndErrors(t *testing.T) {
	ta := newTestApp(t)
	cases := []struct {
		args   []string
		code   int
		stream string
		want   string
	}{
		{nil, exitError, "stderr", "Usage:"},
		{[]string{"--help"}, exitOK, "stdout", "Usage:"},
		{[]string{"help"}, exitOK, "stdout", "Commands:"},
		{[]string{"--version"}, exitOK, "stdout", "shellclear dev"},
		{[]string{"--bogus"}, exitError, "stderr", "--help"},
		{[]string{"bogus"}, exitError, "stderr", `unknown command "bogus"`},
		{[]string{"motd"}, exitError, "stderr", "not available"},
		{[]string{"find", "--help"}, exitOK, "stdout", "-severity"},
		{[]string{"find", "--format", "xml"}, exitError, "stderr", "unknown format"},
		{[]string{"find", "--severity", "urgent"}, exitError, "stderr", "unknown severity"},
		{[]string{"find", "extra"}, exitError, "stderr", "unexpected argument"},
		{[]string{"find", "--nope"}, exitError, "stderr", "--help"},
		{[]string{"--shell", "tcsh", "find"}, exitError, "stderr", "unknown shell"},
		{[]string{"find", "--file", "/does/not/exist", "--shell", "zsh"}, exitError, "stderr", "no such file"},
	}
	for _, c := range cases {
		code := ta.run(c.args...)
		out := ta.stdout.String()
		if c.stream == "stderr" {
			out = ta.stderr.String()
		}
		if code != c.code || !strings.Contains(out, c.want) {
			t.Errorf("%v: code %d, %s %q", c.args, code, c.stream, out)
		}
	}
}

func TestNewOSApp(t *testing.T) {
	app, err := newOSApp()
	if err != nil || app.Env.Home == "" {
		t.Fatalf("newOSApp: %v", err)
	}
}

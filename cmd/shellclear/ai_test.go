package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// withAIHistory writes a Claude Code prompt history and a Codex transcript,
// each with one secret.
func (ta *testApp) withAIHistory(t *testing.T) {
	ta.write(t, ".claude/history.jsonl",
		`{"display":"export GITHUB_TOKEN=`+fixtureSecrets[0]+`","pastedContents":{},"timestamp":1790000000000,"project":"/home/me/app"}`+"\n"+
			`{"display":"fix the tests","pastedContents":{},"timestamp":1790000001000,"project":"/home/me/app"}`+"\n")
	ta.write(t, ".codex/sessions/2026/09/21/rollout-1.jsonl",
		`{"timestamp":"2026-09-21T17:13:00Z","type":"response_item","payload":{"type":"function_call_output","output":"$ cat .env\nMYSQL_PWD=`+fixtureSecrets[1]+`\nPORT=80"}}`+"\n")
}

func TestFindAI(t *testing.T) {
	ta := newTestApp(t)
	ta.withAIHistory(t)
	if code := ta.run("find"); code != exitOK {
		t.Fatalf("without --ai: code %d\n%s", code, ta.stdout)
	}
	if code := ta.run("find", "--ai"); code != exitFindings {
		t.Fatalf("--ai: code %d\n%s%s", code, ta.stdout, ta.stderr)
	}
	ta.assertNoLeak(t, "find --ai")
	out := ta.stdout.String()
	for _, want := range []string{"~/.claude/history.jsonl (claude) — 1 command", "L1 ", "2026-09-21 17:13",
		"~/.codex/sessions/2026/09/21/rollout-1.jsonl (codex) — 1 command", "MYSQL_PWD=Sup3****"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	ta.run("--ai", "find", "--format", "json")
	var doc struct {
		Files []struct {
			Shell, Tool string
		}
	}
	if err := json.Unmarshal(ta.stdout.Bytes(), &doc); err != nil || len(doc.Files) != 2 ||
		doc.Files[0].Shell != "json" || doc.Files[0].Tool != "claude" || doc.Files[1].Tool != "codex" {
		t.Fatalf("json = %+v, %v\n%s", doc, err, ta.stdout)
	}
}

func TestClearAI(t *testing.T) {
	ta := newTestApp(t)
	ta.withAIHistory(t)
	if code := ta.run("clear", "--ai", "-y"); code != exitOK {
		t.Fatalf("code %d\n%s%s", code, ta.stdout, ta.stderr)
	}
	ta.assertNoLeak(t, "clear --ai")
	out := ta.stdout.String()
	for _, want := range []string{"~/.claude/history.jsonl: masked 1 command", "backup: json/history.jsonl.", "Claude Code: restart", "Codex: restart"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	got := ta.read(t, ".claude/history.jsonl")
	want := `{"display":"export GITHUB_TOKEN=[REDACTED:github_env_token]","pastedContents":{},"timestamp":1790000000000,"project":"/home/me/app"}` + "\n" +
		`{"display":"fix the tests","pastedContents":{},"timestamp":1790000001000,"project":"/home/me/app"}` + "\n"
	if got != want {
		t.Fatalf("history.jsonl =\n%s\nwant\n%s", got, want)
	}
	rollout := ta.read(t, ".codex/sessions/2026/09/21/rollout-1.jsonl")
	if !strings.Contains(rollout, `\nMYSQL_PWD=[REDACTED:generic_secret_assignment]\nPORT=80"`) {
		t.Fatalf("rollout = %s", rollout)
	}
	for _, line := range strings.Split(strings.TrimSpace(got+rollout), "\n") {
		if !json.Valid([]byte(line)) {
			t.Fatalf("invalid JSON after clear: %s", line)
		}
	}
	if code := ta.run("find", "--ai"); code != exitOK {
		t.Fatalf("find after clear: code %d\n%s", code, ta.stdout)
	}
}

func TestAIFlagScope(t *testing.T) {
	ta := newTestApp(t)
	ta.withAIHistory(t)
	for _, cmd := range []string{"stash", "pop"} {
		if code := ta.run(cmd, "--ai"); code != exitError || !strings.Contains(ta.stderr.String(), "--ai is not supported") {
			t.Errorf("%s --ai: code %d, %q", cmd, code, ta.stderr)
		}
	}
	// --file replaces detection, --ai included.
	ta.withHistory(t)
	if code := ta.run("find", "--ai", "--file", ta.home+"/.bash_history"); code != exitFindings || strings.Contains(ta.stdout.String(), "claude") {
		t.Fatalf("--file with --ai: code %d\n%s", code, ta.stdout)
	}
	if code := ta.run("motd", "--ai"); code != exitOK || !strings.Contains(ta.stdout.String(), "run 'shellclear find --ai'") {
		t.Fatalf("motd --ai: code %d, %q", code, ta.stdout)
	}
}

func TestClearReplansBeyondMemoryBudget(t *testing.T) {
	defer func(n int) { keepPlanBytes = n }(keepPlanBytes)
	keepPlanBytes = 0
	ta := newTestApp(t)
	ta.withAIHistory(t)
	if code := ta.run("clear", "--ai", "-y"); code != exitOK {
		t.Fatalf("code %d\n%s%s", code, ta.stdout, ta.stderr)
	}
	for _, want := range []string{"~/.claude/history.jsonl: masked 1 command", "rollout-1.jsonl: masked 1 command"} {
		if !strings.Contains(ta.stdout.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, ta.stdout)
		}
	}
	if code := ta.run("find", "--ai"); code != exitOK {
		t.Fatalf("find after clear: code %d\n%s", code, ta.stdout)
	}
}

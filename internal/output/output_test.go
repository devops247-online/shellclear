package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/devops247-online/shellclear/internal/history"
	"github.com/devops247-online/shellclear/internal/rules"
	"github.com/devops247-online/shellclear/internal/scan"
)

var secrets = []string{
	"ghp_" + strings.Repeat("a", 36),
	"S3cretPass12",
	"hunter2",
}

func results(t *testing.T) []scan.Result {
	t.Helper()
	rs, _ := rules.Builtin()
	set, _ := rules.NewSet(nil, rs)
	data := ": 1790000000:0;export GITHUB_TOKEN=" + secrets[0] + " && psql postgres://u:" + secrets[1] + "@db/x\n" +
		": 1790000001:0;ls\n" +
		": 1790000002:0;sshpass -p " + secrets[2] + " ssh host\n"
	sc := &scan.Scanner{Rules: set}
	r, err := sc.ScanBytes(history.File{Path: "/home/u/.zsh_history", Shell: history.Zsh}, []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	empty, _ := sc.ScanBytes(history.File{Path: "/home/u/.bash_history", Shell: history.Bash}, []byte("ls\n"))
	return []scan.Result{r, empty}
}

func TestMaskSecret(t *testing.T) {
	cases := map[string]string{
		"abcd":                           "****",
		"hunter2":                        "****",
		"S3cretPass1":                    "****",
		"S3cretPass12":                   "S3cr****",
		"ghp_" + strings.Repeat("a", 36): "ghp_****aaaa",
		"пароль-секрет-довгий-ключ": "паро****ключ",
	}
	for in, want := range cases {
		if got := MaskSecret(in); got != want {
			t.Errorf("MaskSecret(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSanitize(t *testing.T) {
	in := "echo \x1b[31mred\x1b[0m\nnext\tcol \x7f \xff \u0085"
	want := `echo \x1b[31mred\x1b[0m\nnext` + "\tcol " + `\x7f ` + "\uFFFD " + `\x85`
	if got := Sanitize(in); got != want {
		t.Fatalf("Sanitize = %q, want %q", got, want)
	}
}

func TestMaskCommandIgnoresBadRanges(t *testing.T) {
	ms := []rules.Match{{Start: 5, End: 9, Secret: "abcd"}, {Start: 2, End: 3, Secret: "x"}, {Start: 8, End: 99, Secret: "y"}}
	if got := MaskCommand("0123456789", ms); got != "01234****9" {
		t.Fatalf("got %q", got)
	}
}

func TestFormatsNeverLeakSecrets(t *testing.T) {
	rs := results(t)
	for _, f := range []Format{Text, Table, JSON} {
		for _, color := range []bool{false, true} {
			var buf bytes.Buffer
			if err := Write(&buf, f, rs, Options{Color: color, Location: time.UTC, Home: "/home/u"}); err != nil {
				t.Fatal(err)
			}
			for _, s := range secrets {
				if strings.Contains(buf.String(), s) {
					t.Fatalf("%s output leaks %q:\n%s", f, s, buf.String())
				}
			}
		}
	}
}

func TestJSONSchema(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, JSON, results(t), Options{Location: time.UTC}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version int `json:"version"`
		Files   []struct {
			Path     string `json:"path"`
			Shell    string `json:"shell"`
			Findings []struct {
				Line          int     `json:"line"`
				Time          *string `json:"time"`
				RuleID        string  `json:"rule_id"`
				RuleName      string  `json:"rule_name"`
				Severity      string  `json:"severity"`
				CommandMasked string  `json:"command_masked"`
			} `json:"findings"`
		} `json:"files"`
		Summary Summary `json:"summary"`
	}
	dec := json.NewDecoder(&buf)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != 1 || len(doc.Files) != 2 || doc.Files[1].Findings == nil {
		t.Fatalf("unexpected doc: %+v", doc)
	}
	fs := doc.Files[0].Findings
	if len(fs) != 3 || fs[0].Line != 1 || *fs[0].Time != "2026-09-21T14:13:20Z" || fs[0].RuleID != "github_env_token" {
		t.Fatalf("unexpected findings: %+v", fs)
	}
	want := "export GITHUB_TOKEN=ghp_****aaaa && psql postgres://u:S3cr****@db/x"
	if fs[0].CommandMasked != want || fs[1].CommandMasked != want {
		t.Fatalf("command_masked = %q", fs[0].CommandMasked)
	}
	s := doc.Summary
	if s.FilesScanned != 2 || s.FilesWithFindings != 1 || s.Commands != 2 || s.Findings != 3 || s.BySeverity["high"] != 3 {
		t.Fatalf("summary = %+v", s)
	}
}

func TestTextAndTable(t *testing.T) {
	var buf bytes.Buffer
	opt := Options{Location: time.UTC, Home: "/home/u"}
	if err := Write(&buf, Text, results(t), opt); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"~/.zsh_history (zsh) — 2 commands", "L1 ", "2026-09-21 14:13", "HIGH", "github_env_token,url_basic_auth", "sshpass -p **** ssh host", "2 sensitive commands in 1 file (high: 3, medium: 0, low: 0)."} {
		if !strings.Contains(out, want) {
			t.Errorf("text output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("colors without Color option")
	}
	buf.Reset()
	_ = Write(&buf, Text, results(t), Options{Color: true, Location: time.UTC})
	if !strings.Contains(buf.String(), "\x1b[31m") {
		t.Error("no red for high severity")
	}

	buf.Reset()
	if err := Write(&buf, Table, results(t), opt); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "FILE") || !strings.Contains(lines[2], "sshpass_password") {
		t.Fatalf("table:\n%s", buf.String())
	}

	buf.Reset()
	_ = Write(&buf, Text, results(t)[1:], opt)
	if buf.String() != "No secrets found in 1 history file.\n" {
		t.Fatalf("empty text = %q", buf.String())
	}
}

func TestWriteRules(t *testing.T) {
	rs, _ := rules.Builtin()
	custom, _ := rules.Load(strings.NewReader("- {id: mine, name: Mine, test: 'abcd', severity: low}\n"), "/home/u/.shellclear/rules.d/a.yaml")
	set, _ := rules.NewSet(nil, rs, custom)
	var buf bytes.Buffer
	if err := WriteRules(&buf, Table, set.Rules(), Options{Home: "/home/u"}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "ID") || !strings.Contains(out, "~/.shellclear/rules.d/a.yaml") {
		t.Fatalf("table:\n%s", out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if !strings.HasPrefix(lines[len(lines)-1], "mine") {
		t.Errorf("low severity rule should be last, got %q", lines[len(lines)-1])
	}
	buf.Reset()
	if err := WriteRules(&buf, JSON, set.Rules(), Options{}); err != nil {
		t.Fatal(err)
	}
	var list []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &list); err != nil || len(list) != len(set.Rules()) {
		t.Fatalf("json rules: %v, %d", err, len(list))
	}
}

func TestParseFormat(t *testing.T) {
	for _, s := range []string{"text", "TABLE", "json"} {
		if _, err := ParseFormat(s); err != nil {
			t.Errorf("ParseFormat(%q): %v", s, err)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Error("ParseFormat(xml) should fail")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

func TestWriteErrors(t *testing.T) {
	rs := results(t)
	for _, f := range []Format{Text, Table, JSON} {
		if err := Write(failWriter{}, f, rs, Options{}); err == nil {
			t.Errorf("%s: write error not reported", f)
		}
	}
	all, _ := rules.Builtin()
	set, _ := rules.NewSet(nil, all)
	if err := WriteRules(failWriter{}, Table, set.Rules(), Options{}); err == nil {
		t.Error("rules: write error not reported")
	}
}

func TestBanner(t *testing.T) {
	var buf bytes.Buffer
	if err := Banner(&buf, "v1.2.3", false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "\x1b[") || !strings.Contains(out, `|___/_| |_|\___|_|_|\___|_|\___|\__,_|_| v1.2.3`) {
		t.Fatalf("plain banner:\n%s", out)
	}
	buf.Reset()
	_ = Banner(&buf, "v1.2.3", true)
	if !strings.Contains(buf.String(), "\x1b[1;38;5;51m") || !strings.Contains(buf.String(), "\x1b[1;38;5;99m") {
		t.Fatalf("color banner lacks the gradient: %q", buf.String())
	}
	if err := Banner(failWriter{}, "v", true); err == nil {
		t.Fatal("write error not reported")
	}
}

func TestFancySummary(t *testing.T) {
	var buf bytes.Buffer
	_ = Write(&buf, Text, results(t)[1:], Options{Fancy: true})
	if !strings.HasPrefix(buf.String(), "🎉 Your shell history is clean!") {
		t.Fatalf("clean summary = %q", buf.String())
	}
	buf.Reset()
	_ = Write(&buf, Text, results(t), Options{Fancy: true})
	if !strings.Contains(buf.String(), "🔑 2 sensitive commands") {
		t.Fatalf("summary = %q", buf.String())
	}
}

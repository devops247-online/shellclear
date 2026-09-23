package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type suiteCase struct {
	Name     string `yaml:"name"`
	Test     string `yaml:"test"`
	Expected string `yaml:"expected"`
}

var macroRe = regexp.MustCompile(`\{\{(.+?)\*(\d+)\}\}`)

// expand turns "{{c*n}}" into c repeated n times. Fixtures use it so that no
// token-shaped string is stored in the repository.
func expand(s string) string {
	return macroRe.ReplaceAllStringFunc(s, func(m string) string {
		p := macroRe.FindStringSubmatch(m)
		n, _ := strconv.Atoi(p[2])
		return strings.Repeat(p[1], n)
	})
}

func builtinSet(t *testing.T) *Set {
	t.Helper()
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSet(nil, rs)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func ruleByID(s *Set, id string) *Rule {
	for _, r := range s.Rules() {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// loadSuites reads testdata/{original,builtin}/<rule id>.yaml.
func loadSuites(t *testing.T) map[string][]suiteCase {
	t.Helper()
	out := map[string][]suiteCase{}
	for _, dir := range []string{"original", "builtin"} {
		files, err := filepath.Glob(filepath.Join("testdata", dir, "*.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var cases []suiteCase
			if err := yaml.Unmarshal(b, &cases); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			id := strings.TrimSuffix(filepath.Base(f), ".yaml")
			out[id] = append(out[id], cases...)
		}
	}
	return out
}

func TestBuiltinRules(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) < 60 {
		t.Fatalf("only %d built-in rules", len(rs))
	}
	for _, r := range rs {
		if r.Source != BuiltinSource || r.Name == "" || !idRe.MatchString(r.ID) {
			t.Errorf("bad rule metadata: %+v", r)
		}
	}
}

func TestSuites(t *testing.T) {
	set := builtinSet(t)
	suites := loadSuites(t)
	for id, cases := range suites {
		rule := ruleByID(set, id)
		if rule == nil {
			t.Errorf("suite %s.yaml has no matching rule", id)
			continue
		}
		for _, c := range cases {
			cmd, want := expand(c.Test), expand(c.Expected)
			t.Run(id+"/"+c.Name, func(t *testing.T) {
				got := rule.MatchRule(cmd)
				if want == "" {
					if len(got) != 0 {
						t.Fatalf("rule matched %q, want no match", got)
					}
					return
				}
				if !contains(got, want) {
					t.Fatalf("rule found %q, want %q", got, want)
				}
				// Through the full set (keyword prefilter, merging) the
				// secret must be covered by one reported match.
				covered := false
				for _, m := range set.Find(cmd) {
					for pos := 0; pos <= len(cmd); {
						i := strings.Index(cmd[pos:], want)
						if i < 0 {
							break
						}
						if m.Start <= pos+i && m.End >= pos+i+len(want) {
							covered = true
						}
						pos += i + 1
					}
				}
				if !covered {
					t.Fatalf("set.Find does not cover %q", want)
				}
			})
		}
	}
}

func TestEveryRuleHasPositiveTest(t *testing.T) {
	suites := loadSuites(t)
	for _, r := range builtinSet(t).Rules() {
		ok := false
		for _, c := range suites[r.ID] {
			if c.Expected != "" {
				ok = true
			}
		}
		if !ok {
			t.Errorf("rule %s has no positive test case", r.ID)
		}
	}
}

func TestEveryNewRuleHasNegativeTest(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "builtin", "*.yaml"))
	suites := loadSuites(t)
	for _, f := range files {
		id := strings.TrimSuffix(filepath.Base(f), ".yaml")
		neg := false
		for _, c := range suites[id] {
			if c.Expected == "" {
				neg = true
			}
		}
		if !neg {
			t.Errorf("rule %s has no negative test case", id)
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Commands that must not produce any finding with the full built-in set.
var benign = []string{
	"ls -la",
	"git push origin main",
	"export TOKEN=$VAR",
	"export GITHUB_TOKEN=$(gh auth token)",
	"export GITHUB_TOKEN=`gh auth token`",
	"echo $GITHUB_TOKEN",
	"gh auth token",
	"app --password=<pass>",
	"app --password=********",
	"export API_KEY=[REDACTED:generic_secret_assignment]",
	"docker build --secret id=npmrc,src=$HOME/.npmrc .",
	"docker login -u me --password-stdin",
	"ssh deploy@host",
	"git clone git@github.com:org/repo.git",
	"curl -u user https://example.org",
	"kubectl create secret generic x --from-file=a.txt",
	"export TOKEN_FILE=/tmp/token",
	"mysql -uroot -p db",
	"sshpass -f ~/.pw ssh -p 2222 host",
	"PASSWORD= ./run",
	"echo changeme",
	"export PASSWORD=changeme",
	"export API_KEY=xxxxxxxx",
	"export AWS_SECRET_ACCESS_KEY=your_secret_key",
	"echo привіт світ",
}

func TestBenignCommands(t *testing.T) {
	set := builtinSet(t)
	for _, cmd := range benign {
		if ms := set.Find(cmd); len(ms) != 0 {
			t.Errorf("%q: unexpected finding by %s", cmd, ms[0].Rule.ID)
		}
	}
}

func TestFindAllMatchesAndMerge(t *testing.T) {
	set := builtinSet(t)
	tok := "ghp_" + strings.Repeat("a", 36)
	tok2 := "glpat-" + strings.Repeat("b", 20)

	ms := set.Find("export GITHUB_TOKEN=" + tok + " && echo " + tok + " " + tok2)
	if len(ms) != 3 {
		t.Fatalf("got %d matches, want 3: %+v", len(ms), ms)
	}
	// github_env_token, github_personal_token and generic_secret_assignment
	// overlap on the first token; the first high-severity rule wins.
	if ms[0].Secret != tok || ms[0].Rule.ID != "github_env_token" {
		t.Errorf("first match = %q by %s", ms[0].Secret, ms[0].Rule.ID)
	}
	if ms[1].Secret != tok || ms[1].Rule.ID != "github_personal_token" {
		t.Errorf("second match = %q by %s", ms[1].Secret, ms[1].Rule.ID)
	}
	if ms[2].Secret != tok2 || ms[2].Rule.Severity != High {
		t.Errorf("third match = %q by %s", ms[2].Secret, ms[2].Rule.ID)
	}
	for i := 1; i < len(ms); i++ {
		if ms[i].Start < ms[i-1].End {
			t.Errorf("matches overlap: %+v", ms)
		}
	}
}

func TestMergeUnionAndSeverity(t *testing.T) {
	low, err := Load(strings.NewReader(`
- id: wide_low
  name: wide
  test: 'key=(\S+)'
  secret_group: 1
  severity: low
- id: narrow_high
  name: narrow
  test: 'abcd(efgh)'
  secret_group: 1
  severity: high
`), "custom.yaml")
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewSet(nil, low)
	if err != nil {
		t.Fatal(err)
	}
	ms := set.Find("key=abcdefghij")
	if len(ms) != 1 || ms[0].Secret != "abcdefghij" || ms[0].Rule.ID != "narrow_high" {
		t.Fatalf("got %+v", ms)
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string]string{
		"duplicate id":      "- {id: a_b, name: x, test: 'abcd'}\n- {id: a_b, name: y, test: 'efgh'}\n",
		"bad regex":         "- {id: bad, name: x, test: '(abc'}\n",
		"group too large":   "- {id: grp, name: x, test: 'a(b)', secret_group: 2}\n",
		"negative group":    "- {id: grp, name: x, test: 'a(b)', secret_group: -1}\n",
		"unknown field":     "- {id: unk, name: x, test: 'ab', color: red}\n",
		"bad severity":      "- {id: sev, name: x, test: 'ab', severity: urgent}\n",
		"not a list":        "id: x\n",
		"empty test":        "- {id: empty, name: x, test: ''}\n",
		"invalid id":        "- {id: 'bad id!', name: x, test: 'ab'}\n",
		"no id and no name": "- {test: 'ab'}\n",
		"not a mapping":     "- just a string\n",
		"bad yaml":          "- {id: [\n",
	}
	for name, src := range cases {
		_, err := Load(strings.NewReader(src), "custom.yaml")
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		if !strings.Contains(err.Error(), "custom.yaml") {
			t.Errorf("%s: error %q does not name the file", name, err)
		}
	}
	_, err := Load(strings.NewReader("- {id: grp, name: x, test: 'a(b)', secret_group: 2}\n"), "custom.yaml")
	if !strings.Contains(err.Error(), `"grp"`) || !strings.Contains(err.Error(), "custom.yaml:1") {
		t.Errorf("error lacks id or line: %v", err)
	}
}

func TestLoadOriginalFormat(t *testing.T) {
	// The template written by the original tool: no id, no severity.
	rs, err := Load(strings.NewReader(`# External sensitive patterns file
- name: My Company Token
  test: mycorp_[a-z0-9]{8}
  secret_group: 0
`), "sensitive-patterns.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || rs[0].ID != "my_company_token" || rs[0].Severity != Medium || rs[0].Keywords != nil {
		t.Fatalf("got %+v", rs)
	}
	for _, src := range []string{"", "# only a comment\n", "[]\n"} {
		if rs, err := Load(strings.NewReader(src), "x"); err != nil || len(rs) != 0 {
			t.Errorf("Load(%q) = %v, %v", src, rs, err)
		}
	}
}

func TestNewSetOverrideAndIgnore(t *testing.T) {
	builtin, _ := Builtin()
	custom, err := Load(strings.NewReader(`
- id: github_personal_token
  name: My GitHub rule
  test: 'ghp_[0-9a-zA-Z]{10,}'
  severity: low
`), "custom.yaml")
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewSet([]string{"Generic_Secret_Assignment"}, builtin, custom)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Rules()) != len(builtin)-1 {
		t.Fatalf("got %d rules, want %d", len(set.Rules()), len(builtin)-1)
	}
	r := ruleByID(set, "github_personal_token")
	if r == nil || r.Source != "custom.yaml" || r.Severity != Low {
		t.Fatalf("override not applied: %+v", r)
	}
	if ruleByID(set, "generic_secret_assignment") != nil {
		t.Fatal("ignored rule still active")
	}
	if _, err := NewSet(nil, []Rule{{ID: "raw"}}); err == nil {
		t.Fatal("uncompiled rule accepted")
	}
}

func TestValidSecret(t *testing.T) {
	cases := map[string]bool{
		"S3cretPass": true, `"S3cretPass"`: true, "'abcd'": true, "abcd": true,
		"abc": false, `"abc"`: false, "": false,
		"$VAR": false, "${VAR}": false, "$(cmd)": false, "`cmd`": false, "<pass>": false,
		"****": false, "[REDACTED:x]": false, "redacted": false,
		"xxxxxx": false, "XXXX1234": false, "changeme": false, "ChangeMe": false,
		"AKIAIOSFODNN7EXAMPLE": false, "your_token": false, "your-token": false,
	}
	for in, want := range cases {
		if got := ValidSecret(in); got != want {
			t.Errorf("ValidSecret(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSeverity(t *testing.T) {
	for in, want := range map[string]Severity{"low": Low, "MEDIUM": Medium, "": Medium, " high ": High} {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseSeverity("urgent"); err == nil {
		t.Error("ParseSeverity(urgent) should fail")
	}
	names := map[Severity]string{Low: "low", Medium: "medium", High: "high", 0: "unknown"}
	for s, want := range names {
		if s.String() != want {
			t.Errorf("%d.String() = %q", s, s.String())
		}
	}
}

func TestIDFromName(t *testing.T) {
	for in, want := range map[string]string{"My Company Token": "my_company_token", "  GitHub -- PAT! ": "github_pat", "Ключ": ""} {
		if got := idFromName(in); got != want {
			t.Errorf("idFromName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFindWithLowerMatchesFind(t *testing.T) {
	set := builtinSet(t)
	cmd := "export GITHUB_TOKEN=ghp_" + strings.Repeat("Z", 36)
	a, b := set.Find(cmd), set.FindWithLower(cmd, strings.ToLower(cmd))
	if len(a) != 1 || len(b) != 1 || a[0] != b[0] {
		t.Fatalf("Find %+v != FindWithLower %+v", a, b)
	}
}

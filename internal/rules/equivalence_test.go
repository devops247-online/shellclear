package rules

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// oracleFind is the matching algorithm as it was before the keyword matcher
// and search plans: check the keywords in strings.ToLower(cmd), run every
// applicable regex over the whole command, merge. Find must always return
// exactly what it returns.
func oracleFind(s *Set, cmd string) []Match {
	lower := strings.ToLower(cmd)
	var cands []candidate
	for i, r := range s.rules {
		applies := len(r.Keywords) == 0
		for _, k := range r.Keywords {
			applies = applies || strings.Contains(lower, k)
		}
		if !applies {
			continue
		}
		for _, m := range r.regexp().FindAllStringSubmatchIndex(cmd, -1) {
			start, end := m[2*r.SecretGroup], m[2*r.SecretGroup+1]
			if start < 0 || end <= start {
				continue
			}
			start, end = trimQuotes(cmd, start, end)
			if !ValidSecret(cmd[start:end]) {
				continue
			}
			cands = append(cands, candidate{start, end, i})
		}
	}
	if len(cands) == 0 {
		return nil
	}
	sort.Slice(cands, func(a, b int) bool {
		if cands[a].start != cands[b].start {
			return cands[a].start < cands[b].start
		}
		return cands[a].end > cands[b].end
	})
	var out []Match
	cur := cands[0]
	for _, c := range cands[1:] {
		if c.start < cur.end {
			if c.end > cur.end {
				cur.end = c.end
			}
			if s.better(c.rank, cur.rank) {
				cur.rank = c.rank
			}
			continue
		}
		out = append(out, s.match(cmd, cur))
		cur = c
	}
	return append(out, s.match(cmd, cur))
}

func checkEquivalent(t testing.TB, s *Set, cmd string) {
	t.Helper()
	got, want := s.Find(cmd), oracleFind(s, cmd)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Find differs from the reference algorithm\ncmd:  %q\ngot:  %s\nwant: %s", cmd, describe(got), describe(want))
	}
}

func describe(ms []Match) string {
	var b strings.Builder
	for _, m := range ms {
		fmt.Fprintf(&b, "[%d,%d %s] ", m.Start, m.End, m.Rule.ID)
	}
	return b.String()
}

// TestFoldExotic pins the facts the fast path relies on: the only non-ASCII
// runes that strings.ToLower maps to ASCII, or that case-fold to an ASCII
// letter in a (?i) regex, are the ones hasFoldExotic looks for.
func TestFoldExotic(t *testing.T) {
	want := map[rune]bool{0x130: true, 0x17F: true, 0x212A: true}
	for r := rune(utf8.RuneSelf); r <= unicode.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		exotic := unicode.ToLower(r) < utf8.RuneSelf
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			exotic = exotic || f < utf8.RuneSelf
		}
		if exotic != want[r] {
			t.Errorf("rune %U: exotic=%v, hasFoldExotic expects %v", r, exotic, want[r])
		}
		if exotic && !hasFoldExotic(string(r)) {
			t.Errorf("hasFoldExotic misses %U", r)
		}
	}
	// Invalid UTF-8 lower-cases to U+FFFD, never to ASCII.
	if l := strings.ToLower("\xff\xc4"); strings.ContainsFunc(l, func(r rune) bool { return r < utf8.RuneSelf }) {
		t.Errorf("ToLower of invalid UTF-8 gave ASCII: %q", l)
	}
}

func TestKeywordMatcherAgainstNaive(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alpha := "abcAB-_:/.k s\n\x80"
	for round := 0; round < 300; round++ {
		var kws []string
		for i := 0; i < 1+rng.Intn(12); i++ {
			kws = append(kws, strings.ToLower(randString(rng, alpha, 1+rng.Intn(4))))
		}
		kws = dedupe(kws)
		m := newKeywordMatcher(kws)
		text := randString(rng, alpha, rng.Intn(200))
		hits, high := m.scan(text, nil)
		var got, want []string
		for _, h := range hits {
			got = append(got, fmt.Sprintf("%d@%d", h.kw, h.end))
		}
		folded := asciiFold(text)
		for end := 1; end <= len(text); end++ {
			for i, k := range kws {
				if end >= len(k) && folded[end-len(k):end] == k {
					want = append(want, fmt.Sprintf("%d@%d", i, end))
				}
			}
		}
		sort.Strings(got)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("keywords %q text %q: got %v want %v", kws, text, got, want)
		}
		if high != strings.ContainsFunc(text, func(r rune) bool { return r >= utf8.RuneSelf }) {
			t.Fatalf("high flag wrong for %q", text)
		}
	}
}

func asciiFold(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

func randString(rng *rand.Rand, alpha string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alpha[rng.Intn(len(alpha))]
	}
	return string(b)
}

// corpusPieces is the vocabulary for generated commands: keywords and
// secret-shaped values from the built-in rules, the characters the search
// plans treat as boundaries, and runes that need the slow path.
var corpusPieces = []string{
	" ", " ", "  ", "\t", "\n", "\r\n", "=", " = ", ":", "://", "@", "/", ".", "-", "_", "'", "\"", "`", ";", "|", "&", "<", ">", "$", "(", ")", "\\", "\\n",
	"export ", "curl ", "-u ", "--user ", "-H ", "Authorization: ", "Bearer ", "basic ", "token ", "mysql ", "-p", "docker login ", "--password ", "--token=",
	"--secret ", "machine ", "login ", "password ", "default ", "sshpass -p ", "htpasswd -b ", "wget --password=", "diskutil ", "passphrase ",
	"GITHUB_TOKEN", "AWS_ACCESS_KEY_ID", "aws_secret_access_key", "API_KEY", "my_secret", "PGPASSWORD", "Vault_Token", "TOKEN_2",
	"ghp_", "gho_", "ghs_", "glpat-", "xoxb-", "sk-", "sk-proj-", "sk-ant-", "SK", "AKIA", "AIza", "eyJ", "SG.", "key-", "-us1", "npm_", "hvs.", ".atlasv1.", "ATATT3",
	"AccountKey=", "dop_v1_", "sk_live_", ":AA", "oy2", "EAACEdEose0cBA", "https://hooks.slack.com/services/", "https://user:", "@host.example",
	"-----BEGIN RSA PRIVATE KEY-----", "twitter", "linkedin", "datadog", "heroku", "github_pat_",
	"abcdef0123456789abcdef0123456789", "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", "0123456789", "s3cr3tP4ss", "xxxx", "REDACTED", "$HOME", "<pwd>", "example",
	"ſ", "K", "İ", "é", "Ж", "→", "\xff", "\xc4", "\xe2\x84",
}

func genCommand(rng *rand.Rand) string {
	var b strings.Builder
	n := 1 + rng.Intn(14)
	for i := 0; i < n; i++ {
		p := corpusPieces[rng.Intn(len(corpusPieces))]
		switch rng.Intn(6) {
		case 0:
			p = strings.ToUpper(p)
		case 1:
			p = strings.ToLower(p)
		}
		b.WriteString(p)
	}
	return b.String()
}

func TestEquivalenceGenerated(t *testing.T) {
	if raceEnabled {
		t.Skip("single goroutine; CI runs it without -race in the coverage step")
	}
	set := builtinSet(t)
	rng := rand.New(rand.NewSource(7))
	n := 200000
	if testing.Short() {
		n = 20000
	}
	for i := 0; i < n; i++ {
		checkEquivalent(t, set, genCommand(rng))
	}
}

// TestEquivalenceSuites runs every rule fixture, every history fixture and,
// when SHELLCLEAR_EQUIV_CORPUS names a directory, every line of every file in
// it (for example a copy of ~/.claude/projects).
func TestEquivalenceSuites(t *testing.T) {
	set := builtinSet(t)
	for _, cases := range loadSuites(t) {
		for _, c := range cases {
			cmd := expand(c.Test)
			checkEquivalent(t, set, cmd)
			checkEquivalent(t, set, strings.Repeat("x ", 300)+cmd+" | "+cmd)
		}
	}
	var files []string
	hist, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "history", "*"))
	files = append(files, hist...)
	if dir := os.Getenv("SHELLCLEAR_EQUIV_CORPUS"); dir != "" {
		_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				files = append(files, p)
			}
			return nil
		})
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		checkEquivalent(t, set, string(data))
		for _, line := range strings.Split(string(data), "\n") {
			checkEquivalent(t, set, line)
		}
	}
}

// TestEquivalenceCustomRules covers rule shapes the built-in set does not
// have: anchors, multi-line flags, any-character, empty matches, keywords
// the regex does not contain, non-ASCII keywords and literals.
func TestEquivalenceCustomRules(t *testing.T) {
	if raceEnabled {
		t.Skip("single goroutine; CI runs it without -race in the coverage step")
	}
	const custom = `
- {id: anchored, test: '^export\s+(\w+)=(\S+)$', secret_group: 2, keywords: [export]}
- {id: multiline, test: '(?m)^pass:\s*(\S+)$', secret_group: 1, keywords: [pass]}
- {id: dotall, test: '(?s)begin(.{4,40}?)end', secret_group: 1, keywords: [begin]}
- {id: anychar, test: 'tok.n=(\w{4,})', secret_group: 1, keywords: [tok]}
- {id: unrelated_keyword, test: '\b[A-Z]{3}[0-9]{5}\b', keywords: [ticket]}
- {id: no_keywords, test: '\bQQ[0-9]{6}\b'}
- {id: may_be_empty, test: '(?:key)?([a-z]*)', secret_group: 1, keywords: [key]}
- {id: not_word_boundary, test: '\Bpw([0-9]{4,})', secret_group: 1, keywords: [pw]}
- {id: keyword_with_stop, test: 'id=([0-9]{4,})', secret_group: 1, keywords: ['id=', 'x y']}
- {id: case_sensitive, test: 'Secret([0-9]{4,})', secret_group: 1, keywords: [secret]}
- {id: fold_s, test: '(?i)ſecret([0-9]{4,})', secret_group: 1, keywords: [secret]}
- {id: kelvin, test: "\u212A([0-9]{4,})", secret_group: 1, keywords: [k]}
- {id: optional_keyword, test: '(?:auth)?([0-9a-f]{12,})', secret_group: 1, keywords: [auth]}
- {id: alternation, test: '(?i)(?:alpha|beta)_?(?:x|yy)=(\w{4,})', secret_group: 1, keywords: [alpha, beta]}
- {id: repeat, test: '(?:ab){2,3}c=(\w{4,})', secret_group: 1, keywords: [abab]}
- {id: text_end, test: 'tail=(\w{4,})\z', secret_group: 1, keywords: [tail]}
- {id: text_begin, test: '\Ahead=(\w{4,})', secret_group: 1, keywords: [head]}
- {id: whitespace_inside, test: 'user\s+(\w{4,})', secret_group: 1, keywords: [user]}
- {id: inner_eq, test: '(?i)\b(\w*key[0-9]*)(?:=|\s*=\s*")([a-z0-9]{4,40})', secret_group: 2, keywords: [key]}
- {id: inner_colon, test: '\b([A-Za-z_]+_PW)\s*:\s*(\w{4,12})\b', secret_group: 2}
- {id: inner_anchor, test: '\b(pass)(?:=|\s+=)\s*(\w{4,20})$', secret_group: 2, keywords: [pass]}
`
	rs, err := Load(strings.NewReader(custom), "custom.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cyr, err := Load(strings.NewReader(`- {id: cyrillic, test: '(?i)пароль=(\S{4,})', secret_group: 1, keywords: [пароль]}`), "cyr.yaml")
	if err != nil {
		t.Fatal(err)
	}
	builtin, _ := Builtin()
	sets := map[string]*Set{}
	sets["custom"], _ = NewSet(nil, rs)
	sets["custom+builtin"], _ = NewSet(nil, builtin, rs)
	sets["non-ascii keyword"], _ = NewSet(nil, rs, cyr)

	pieces := append([]string{
		"export ", "pass: ", "begin", "end", "tok", "token=", "toKen=", "ticket ", "ABC12345", "QQ123456", "key", "pw", "xpw", "1234",
		"id=", "x y", "Secret", "secret", "SECRET", "ſecret", "K", "K", "auth", "deadbeef0123", "alpha", "BETA_", "x=", "yy=",
		"abab", "ababab", "c=", "tail=", "head=", "user", "\n", " ", "Пароль=", "пароль", "word", "=",
		"apikey", "KEY1", "key9=", " = \"", "DB_PW", ":", " : ", "pass", "pass =", "x_", "\t",
	}, corpusPieces[:40]...)
	rng := rand.New(rand.NewSource(11))
	for name, set := range sets {
		n := 50000
		if testing.Short() {
			n = 5000
		}
		t.Run(name, func(t *testing.T) {
			for i := 0; i < n; i++ {
				var b strings.Builder
				for j := rng.Intn(10); j >= 0; j-- {
					b.WriteString(pieces[rng.Intn(len(pieces))])
				}
				checkEquivalent(t, set, b.String())
			}
		})
	}
}

func FuzzFindEquivalence(f *testing.F) {
	set, err := NewSet(nil, mustBuiltin(f))
	if err != nil {
		f.Fatal(err)
	}
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 64; i++ {
		f.Add(genCommand(rng))
	}
	f.Add("export GITHUB_TOKEN=ghp_" + strings.Repeat("a", 36))
	f.Add("curl -u admin:s3cr3t https://x | ſ")
	f.Fuzz(func(t *testing.T, cmd string) {
		checkEquivalent(t, set, cmd)
	})
}

func mustBuiltin(tb testing.TB) []Rule {
	rs, err := Builtin()
	if err != nil {
		tb.Fatal(err)
	}
	return rs
}

// TestBuiltinRulesCompile checks what Load checks for custom rules; built-in
// regexes are only compiled on first use.
func TestBuiltinRulesCompile(t *testing.T) {
	for _, r := range mustBuiltin(t) {
		re := r.regexp()
		if r.SecretGroup < 0 || r.SecretGroup > re.NumSubexp() {
			t.Errorf("rule %s: secret_group %d but the regex has %d groups", r.ID, r.SecretGroup, re.NumSubexp())
		}
	}
}

func TestContainsFold(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	alpha := "abAB:-=xX "
	for i := 0; i < 200000; i++ {
		text := randString(rng, alpha, rng.Intn(24))
		lit := strings.ToLower(randString(rng, alpha, 1+rng.Intn(4)))
		if got, want := containsFold(text, lit), strings.Contains(asciiFold(text), lit); got != want {
			t.Fatalf("containsFold(%q, %q) = %v, want %v", text, lit, got, want)
		}
	}
}

// TestEquivalenceInnerPlan stresses the inner-literal plan of
// generic_secret_assignment: assignments with and without keywords,
// whitespace around "=", quotes, words that run into each other, and the
// inputs that would make a naive candidate loop quadratic.
func TestEquivalenceInnerPlan(t *testing.T) {
	if raceEnabled {
		t.Skip("single goroutine; CI runs it without -race in the coverage step")
	}
	set := builtinSet(t)
	pieces := []string{
		"TOKEN", "token", "My_Secret_Key2", "api_key", "APIKEY", "x", "word", "_", "9", "PASSWD", "mysql_pwd", "PGPASSWORD", "access_key",
		"=", "=", " = ", "  =", "= ", "\t=\t", "\n=\n", "'", "\"", "=\"", "='", "s3cr3tval", "v", ";", "|", " ", "\n", "-", ".", "$x", "ſ", "K",
	}
	rng := rand.New(rand.NewSource(13))
	n := 100000
	if testing.Short() {
		n = 10000
	}
	for i := 0; i < n; i++ {
		var b strings.Builder
		for j := rng.Intn(16); j >= 0; j-- {
			b.WriteString(pieces[rng.Intn(len(pieces))])
		}
		checkEquivalent(t, set, b.String())
	}
	for _, s := range []string{
		strings.Repeat("TOKEN ", 3000) + "=",
		strings.Repeat("a_token=", 2000),
		strings.Repeat("token =", 2000),
		strings.Repeat("x=", 5000),
		strings.Repeat("token=\"", 2000),
		"password" + strings.Repeat(" ", 5000) + "=" + strings.Repeat(" ", 5000) + "'v4lue'",
	} {
		checkEquivalent(t, set, s)
	}
}

func TestFoldFinder(t *testing.T) {
	rng := rand.New(rand.NewSource(17))
	alpha := "cuCUrl -;"
	for round := 0; round < 20000; round++ {
		text := randString(rng, alpha, rng.Intn(40))
		lit := strings.ToLower(randString(rng, "curl-", 1+rng.Intn(3)))
		f := newFoldFinder(lit)
		folded := asciiFold(text)
		for from := 0; from <= len(text); from += 1 + rng.Intn(3) {
			want := -1
			if i := strings.Index(folded[from:], lit); i >= 0 {
				want = from + i
			}
			if got := f.next(text, from); got != want {
				t.Fatalf("next(%q, %q, %d) = %d, want %d", text, lit, from, got, want)
			}
		}
	}
}

// TestEquivalencePrefixPlan stresses the prefix plans: commands dense in
// the literals that begin curl, mysql, registry and netrc matches, the lazy
// gap's stop bytes, and custom rules of the same shapes.
func TestEquivalencePrefixPlan(t *testing.T) {
	if raceEnabled {
		t.Skip("single goroutine; CI runs it without -race in the coverage step")
	}
	const custom = `
- {id: lazy_ci, test: '(?i)\bdeploy\s+key\b[^;é]*?\s--pw[= ]([^\s;]{4,})', secret_group: 1, keywords: [deploy]}
- {id: lazy_case, test: '\bTool\b[^|]*?\s-k\s+(\S{4,})', secret_group: 1, keywords: [tool]}
- {id: alt_heads, test: '\b(?:git|hg)\s+(?:push|pull)\b[^;]*?\s(?:--token|-t)=(\w{4,})', secret_group: 1, keywords: [push, pull]}
- {id: no_gap, test: '\bvault\s+login\s+(\S{4,})', secret_group: 1, keywords: [vault]}
`
	rs, err := Load(strings.NewReader(custom), "custom.yaml")
	if err != nil {
		t.Fatal(err)
	}
	builtin := builtinSet(t)
	both, _ := NewSet(nil, mustBuiltin(t), rs)
	pieces := []string{
		"curl", "curl ", "CURL ", "xcurl", "curl_", " -u ", " --user ", "-u", "=", "user:pw", "a:b", ":", "mysql ", "mysqldump", "MYSQL ", " -p", "-pS3cret",
		"docker login ", "helm  registry login", "podman", " login", "--password ", "-p ", "machine ", "Default ", "login ", "password ", "\\n", "x",
		";", "|", "&", " ", "\t", "\n", "'", "\"", "`", "é", "ſ", "\xff", "deploy key ", "Deploy  KEY", " --pw=", "Tool ", "tool ", " -k ", "git push ",
		"hg pull", " --token=", " -t=", "vault login ", "abcd1234",
	}
	rng := rand.New(rand.NewSource(19))
	n := 100000
	if testing.Short() {
		n = 10000
	}
	for i := 0; i < n; i++ {
		var b strings.Builder
		for j := rng.Intn(20); j >= 0; j-- {
			b.WriteString(pieces[rng.Intn(len(pieces))])
		}
		cmd := b.String()
		checkEquivalent(t, builtin, cmd)
		checkEquivalent(t, both, cmd)
	}
	for _, s := range []string{
		strings.Repeat("curl x ", 3000),
		"curl -u " + strings.Repeat("curl;", 3000),
		strings.Repeat("curl -u a;", 3000),
		strings.Repeat("curl -u x ", 3000),
		strings.Repeat("default value ", 3000) + "machine h login u password p4ss",
		strings.Repeat("mysql -h db ", 2000) + "-pS3cret",
		strings.Repeat("docker login registry ", 2000) + "--password s3cret",
	} {
		checkEquivalent(t, builtin, s)
		checkEquivalent(t, both, s)
	}
}

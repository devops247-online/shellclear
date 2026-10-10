package rules

import (
	"fmt"
	"strings"
	"testing"
)

// benchCommands is a shell history's worth of ordinary commands, a few of
// them with secrets.
func benchCommands(n int) []string {
	cmds := make([]string, n)
	for i := range cmds {
		switch {
		case i%100 == 0:
			cmds[i] = fmt.Sprintf("export GITHUB_TOKEN=ghp_%036d", i)
		case i%7 == 0:
			cmds[i] = fmt.Sprintf("curl -s https://api.internal/v1/items/%d | jq '.data[] | .name'", i)
		case i%5 == 0:
			cmds[i] = fmt.Sprintf("kubectl -n app-%d get pods -o wide --sort-by=.metadata.creationTimestamp", i%13)
		case i%3 == 0:
			cmds[i] = fmt.Sprintf("docker run --rm -it -v $PWD:/app -w /app node:20 npm test -- --grep 'task %d'", i)
		default:
			cmds[i] = fmt.Sprintf("git commit -m \"change %d\" && git push origin feature/%d", i, i%31)
		}
	}
	return cmds
}

func BenchmarkFind(b *testing.B) {
	set := builtinSetB(b)
	cmds := benchCommands(10000)
	size := 0
	for _, c := range cmds {
		size += len(c)
	}
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, c := range cmds {
			set.Find(c)
		}
	}
}

// BenchmarkFindLongText is one long AI-transcript-like command: prose with
// words that are keywords of several rules.
func BenchmarkFindLongText(b *testing.B) {
	set := builtinSetB(b)
	text := strings.Repeat("The access token is refreshed by the login task; see https://docs.internal/auth and the password policy. ", 2000)
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set.Find(text)
	}
}

func BenchmarkKeywordScan(b *testing.B) {
	set := builtinSetB(b)
	set.once.Do(set.prepare)
	cmds := benchCommands(10000)
	size := 0
	for _, c := range cmds {
		size += len(c)
	}
	b.SetBytes(int64(size))
	b.ResetTimer()
	var hits []kwHit
	for i := 0; i < b.N; i++ {
		for _, c := range cmds {
			hits, _ = set.km.scan(c, hits[:0])
		}
	}
}

// BenchmarkBuiltin is the start-up cost every command pays, `motd` included.
func BenchmarkBuiltin(b *testing.B) {
	for i := 0; i < b.N; i++ {
		rs, err := Builtin()
		if err != nil {
			b.Fatal(err)
		}
		if _, err := NewSet(nil, rs); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSearchPlans is the one-off cost of compiling every rule and
// analysing it, paid lazily, rule by rule, on first use.
func BenchmarkSearchPlans(b *testing.B) {
	rs := mustBuiltin(b)
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			c := &compiledRule{expr: r.Test, keywords: r.Keywords}
			c.get()
		}
	}
}

func builtinSetB(b *testing.B) *Set {
	s, err := NewSet(nil, mustBuiltin(b))
	if err != nil {
		b.Fatal(err)
	}
	return s
}

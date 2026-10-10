package scan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/devops247-online/shellclear/internal/history"
	"github.com/devops247-online/shellclear/internal/rules"
)

func builtinSet(tb testing.TB) *rules.Set {
	tb.Helper()
	rs, err := rules.Builtin()
	if err != nil {
		tb.Fatal(err)
	}
	s, err := rules.NewSet(nil, rs)
	if err != nil {
		tb.Fatal(err)
	}
	return s
}

func TestScanGolden(t *testing.T) {
	sc := &Scanner{Rules: builtinSet(t)}
	f := history.File{Path: "zsh", RealPath: "../../testdata/history/zsh_extended.hist", Shell: history.Zsh}
	r, err := sc.ScanFile(f)
	if err != nil {
		t.Fatal(err)
	}
	var lines []int
	for _, fd := range r.Findings {
		lines = append(lines, fd.Line)
		if r.Entries[fd.Entry].Line != fd.Line {
			t.Errorf("finding line %d does not match entry %d", fd.Line, fd.Entry)
		}
	}
	if fmt.Sprint(lines) != "[3 4 12]" {
		t.Fatalf("lines = %v", lines)
	}
	if r.Findings[0].MaxSeverity() != rules.High || r.Findings[0].Time.IsZero() {
		t.Errorf("unexpected first finding: %+v", r.Findings[0])
	}
}

// synthetic builds a zsh history with n entries; every 50th has a secret.
func synthetic(n int) []byte {
	var b bytes.Buffer
	for i := 0; i < n; i++ {
		switch {
		case i%50 == 0:
			fmt.Fprintf(&b, ": %d:0;export GITHUB_TOKEN=ghp_%036d\n", 1700000000+i, i)
		case i%7 == 0:
			fmt.Fprintf(&b, ": %d:0;curl -s https://api.internal/v1/items/%d | jq '.data[] | .name'\n", 1700000000+i, i)
		case i%5 == 0:
			fmt.Fprintf(&b, ": %d:0;kubectl -n app-%d get pods -o wide --sort-by=.metadata.creationTimestamp\n", 1700000000+i, i%13)
		default:
			fmt.Fprintf(&b, ": %d:0;git commit -m \"change %d\" && git push origin feature/%d\n", 1700000000+i, i, i%31)
		}
	}
	return b.Bytes()
}

func TestParallelMatchesSerial(t *testing.T) {
	data := synthetic(20000)
	f := history.File{Path: "x", Shell: history.Zsh}
	set := builtinSet(t)
	serial, _ := (&Scanner{Rules: set, Workers: 1}).ScanBytes(f, data)
	parallel, _ := (&Scanner{Rules: set, Workers: 8}).ScanBytes(f, data)
	if len(serial.Findings) != 400 || len(parallel.Findings) != len(serial.Findings) {
		t.Fatalf("serial %d, parallel %d findings", len(serial.Findings), len(parallel.Findings))
	}
	for i := range serial.Findings {
		if serial.Findings[i].Entry != parallel.Findings[i].Entry {
			t.Fatalf("finding %d differs", i)
		}
	}
}

func TestAllowAndFilter(t *testing.T) {
	data := []byte(": 1:0;export GITHUB_TOKEN=ghp_" + strings.Repeat("a", 36) + "\n" +
		": 2:0;aws configure set aws_access_key_id AKIA" + strings.Repeat("Z", 16) + "\n")
	f := history.File{Shell: history.Zsh}
	sc := &Scanner{Rules: builtinSet(t)}
	r, _ := sc.ScanBytes(f, data)
	if len(r.Findings) != 2 {
		t.Fatalf("got %d findings", len(r.Findings))
	}
	if got := FilterSeverity(r.Findings, rules.High); len(got) != 1 || got[0].Line != 1 {
		t.Fatalf("FilterSeverity(high) = %+v", got)
	}
	sc.Allow = []*regexp.Regexp{regexp.MustCompile(`^export GITHUB_TOKEN=`)}
	r, _ = sc.ScanBytes(f, data)
	if len(r.Findings) != 1 || r.Findings[0].Line != 2 {
		t.Fatalf("allow list not applied: %+v", r.Findings)
	}
}

func TestSkipsOpaqueAndEmpty(t *testing.T) {
	sc := &Scanner{Rules: builtinSet(t)}
	r, err := sc.ScanBytes(history.File{Shell: history.Fish}, []byte("GITHUB_TOKEN=ghp_"+strings.Repeat("a", 36)+"\n- cmd:\n"))
	if err != nil || len(r.Findings) != 0 {
		t.Fatalf("got %+v, %v", r.Findings, err)
	}
}

func TestErrors(t *testing.T) {
	sc := &Scanner{Rules: builtinSet(t)}
	if _, err := sc.ScanFile(history.File{Path: "missing", RealPath: filepath.Join(t.TempDir(), "missing"), Shell: history.Zsh}); err == nil {
		t.Error("missing file: no error")
	}
	if _, err := sc.ScanBytes(history.File{Shell: "tcsh"}, nil); err == nil {
		t.Error("unknown shell: no error")
	}
}

func BenchmarkScan100k(b *testing.B) {
	data := synthetic(100000)
	f := history.File{Shell: history.Zsh}
	sc := &Scanner{Rules: builtinSet(b)}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sc.ScanBytes(f, data); err != nil {
			b.Fatal(err)
		}
	}
}

// syntheticJSONL builds n lines shaped like an AI assistant session
// transcript: long JSON lines whose string values hold prose, code and command
// output, with words such as "token", "password" and "key" in ordinary text
// and, on every 97th line, a real-looking token.
func syntheticJSONL(n int) []byte {
	prose := []string{
		"The token bucket refills every second; the password policy requires rotation.",
		"Run the migration, then check that the API key header is forwarded by the proxy.",
		"I updated the config so the secret store is read lazily and the cache key includes the tenant.",
		"Let me look at how the login flow handles the access token refresh on expiry.",
		"The test failed because the private key fixture was regenerated with a different curve.",
	}
	code := []string{
		"func (s *Server) auth(r *http.Request) error {\n\ttok := r.Header.Get(\"Authorization\")\n\tif tok == \"\" {\n\t\treturn errNoToken\n\t}\n\treturn s.verify(tok)\n}",
		"const config = { apiKey: process.env.API_KEY, timeout: 3000, retries: 2 };\nexport default config;",
		"$ kubectl get secret app-secrets -o yaml | grep -c data\n4\n$ curl -s https://api.internal/v1/health | jq .status\n\"ok\"",
		"SELECT id, email, password_hash FROM users WHERE last_login < now() - interval '90 days';",
	}
	var b bytes.Buffer
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, `{"type":"assistant","timestamp":"2026-09-21T17:13:%02d.000Z","uuid":"%08x-0000","message":{"role":"assistant","content":[`, i%60, i)
		for j := 0; j < 1+i%7; j++ {
			if j > 0 {
				b.WriteByte(',')
			}
			text := prose[(i+j)%len(prose)]
			if (i+j)%3 == 0 {
				text = code[(i+j)%len(code)]
			}
			text = strings.Repeat(text+" ", 1+(i+j)%9)
			if i%97 == 0 && j == 0 {
				text = fmt.Sprintf("export GITHUB_TOKEN=ghp_%036d", i)
			}
			quoted, _ := json.Marshal(text)
			fmt.Fprintf(&b, `{"type":"text","text":%s}`, quoted)
		}
		b.WriteString("]}}\n")
	}
	return b.Bytes()
}

func BenchmarkScanJSONL(b *testing.B) {
	data := syntheticJSONL(20000)
	f := history.File{Shell: history.JSON}
	sc := &Scanner{Rules: builtinSet(b)}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sc.ScanBytes(f, data); err != nil {
			b.Fatal(err)
		}
	}
}

func TestSyntheticJSONLFindings(t *testing.T) {
	r, err := (&Scanner{Rules: builtinSet(t)}).ScanBytes(history.File{Shell: history.JSON}, syntheticJSONL(2000))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 21 { // every 97th line carries a token
		t.Fatalf("got %d findings", len(r.Findings))
	}
}

func TestMain(m *testing.M) { os.Exit(m.Run()) }

func TestScanFilesOrderAndFirstError(t *testing.T) {
	dir := t.TempDir()
	var files []history.File
	for i := 0; i < 40; i++ {
		p := filepath.Join(dir, fmt.Sprintf("h%02d", i))
		content := fmt.Sprintf(": %d:0;echo %d\n", 1700000000+i, i)
		if i%3 == 0 {
			content += ": 1:0;export GITHUB_TOKEN=ghp_" + strings.Repeat("a", 36) + "\n"
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, history.File{Path: p, RealPath: p, Shell: history.Zsh})
	}
	sc := &Scanner{Rules: builtinSet(t), Workers: 8}
	got := make([]int, len(files))
	if err := sc.ScanFiles(files, func(i int, r Result) { got[i] = len(r.Findings) }); err != nil {
		t.Fatal(err)
	}
	for i, n := range got {
		if want := map[bool]int{true: 1, false: 0}[i%3 == 0]; n != want {
			t.Fatalf("file %d: %d findings, want %d", i, n, want)
		}
	}

	// Two missing files: the error is always the first one's, as in a loop.
	bad := append([]history.File(nil), files...)
	for _, i := range []int{7, 23} {
		bad[i] = history.File{Path: fmt.Sprintf("missing%d", i), RealPath: filepath.Join(dir, fmt.Sprintf("missing%d", i)), Shell: history.Zsh}
	}
	for round := 0; round < 20; round++ {
		err := sc.ScanFiles(bad, func(int, Result) {})
		if err == nil || !strings.Contains(err.Error(), "missing7") {
			t.Fatalf("round %d: err = %v, want the error for missing7", round, err)
		}
	}
}

func TestBudget(t *testing.T) {
	b := NewBudget(100)
	if got := b.Acquire(500); got != 100 {
		t.Fatalf("oversized request took %d", got)
	}
	done := make(chan struct{})
	go func() { b.Acquire(10); close(done) }()
	time.Sleep(20 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("Acquire did not wait for a full budget")
	default:
	}
	b.Release(100)
	<-done
}

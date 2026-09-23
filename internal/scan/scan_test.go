package scan

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

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

func TestMain(m *testing.M) { os.Exit(m.Run()) }

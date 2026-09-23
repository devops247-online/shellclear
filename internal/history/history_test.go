package history

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testdataDir = "../../testdata/history"

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(testdataDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustCodec(t testing.TB, s Shell) Codec {
	t.Helper()
	c, err := CodecFor(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func concatRaw(entries []Entry) []byte {
	var b bytes.Buffer
	for _, e := range entries {
		b.Write(e.Raw)
	}
	return b.Bytes()
}

func commands(entries []Entry) []string {
	var out []string
	for _, e := range entries {
		if !e.Opaque {
			out = append(out, e.Command)
		}
	}
	return out
}

// The zsh and bash golden files were written by zsh 5.9 (print -rs + fc -W)
// and bash 5.3 (history -s + history -w). The expected commands below are
// exactly the strings passed to those builtins.
var goldenCases = []struct {
	file  string
	shell Shell
	want  []string
	lines []int
}{
	{
		file:  "zsh_extended.hist",
		shell: Zsh,
		want: []string{
			"echo привіт Р світ",
			"echo 🚀 done",
			"export GITHUB_TOKEN=ghp_aaaaBBBBccccDDDDeeeeFFFFgggg1234abcd",
			"curl -H \"Authorization: Bearer abc.def.ghi\" \\\n  https://example.org/api",
			"cat <<EOF\nline one\nEOF",
			"echo trailing\\",
			"echo two\\\\  ",
			": colon start",
			"mysql -uroot -pSup3rS3cret db",
		},
		lines: []int{1, 2, 3, 4, 6, 9, 10, 11, 12},
	},
	{
		file:  "zsh_plain.hist",
		shell: Zsh,
		want:  []string{"ls -la", ": plain colon", "echo кирилиця", "multi\nline"},
		lines: []int{1, 2, 3, 4},
	},
	{
		file:  "bash_plain.hist",
		shell: Bash,
		want:  []string{"ls -la", "docker login -u me -p hunter2hunter2 registry.example.org", "echo done"},
		lines: []int{1, 2, 3},
	},
	{
		file:  "bash_timestamps.hist",
		shell: Bash,
		want: []string{
			"ls -la",
			"export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
			"for i in 1 2; do\n  echo $i\ndone",
			"echo привіт",
		},
		lines: []int{1, 3, 5, 9},
	},
	{
		file:  "fish_history",
		shell: Fish,
		want: []string{
			"ls -la",
			"export GITHUB_TOKEN=ghp_aaaaBBBBccccDDDDeeeeFFFFgggg1234abcd",
			"cat ~/secret-ghp_aaaaBBBBccccDDDDeeeeFFFFgggg1234abcd.txt",
			"echo \"a\\\\b\"\nfor x in 1 2\n  echo $x\nend",
			"echo привіт 🚀",
		},
		lines: []int{1, 3, 5, 9, 12},
	},
	{
		file:  "fish_preamble",
		shell: Fish,
		want:  []string{"echo one", "echo two"},
		lines: []int{1, 3, 6},
	},
	{
		file:  "ConsoleHost_history.txt",
		shell: PowerShell,
		want: []string{
			"Get-ChildItem",
			`$env:GITHUB_TOKEN = "ghp_aaaaBBBBccccDDDDeeeeFFFFgggg1234abcd"`,
			"Invoke-RestMethod -Uri https://example.org \n  -Headers @{Authorization = \"Bearer abc\"}\nWrite-Host done",
			"echo привіт",
		},
		lines: []int{1, 2, 3, 6},
	},
	{
		file:  "ConsoleHost_history_crlf.txt",
		shell: PowerShell,
		want:  []string{"Get-Date", "Write-Host \n  \"multi\"", "exit"},
		lines: []int{1, 2, 4},
	},
}

func TestGoldenRoundTrip(t *testing.T) {
	for _, tc := range goldenCases {
		t.Run(tc.file, func(t *testing.T) {
			data := readGolden(t, tc.file)
			entries := mustCodec(t, tc.shell).Parse(data)
			if got := concatRaw(entries); !bytes.Equal(got, data) {
				t.Fatalf("concat(Raw) differs from input")
			}
			got := commands(entries)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d commands, want %d: %q", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("command %d:\n got %q\nwant %q", i, got[i], tc.want[i])
				}
			}
			var lines []int
			for _, e := range entries {
				lines = append(lines, e.Line)
			}
			if !equalInts(lines, tc.lines) {
				t.Errorf("lines = %v, want %v", lines, tc.lines)
			}
		})
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestZshMixedWithoutFinalNewline(t *testing.T) {
	data := readGolden(t, "zsh_mixed_nofinalnl.hist")
	if data[len(data)-1] == '\n' {
		t.Fatal("fixture must not end with a newline")
	}
	entries := zshCodec{}.Parse(data)
	if !bytes.Equal(concatRaw(entries), data) {
		t.Fatal("concat(Raw) differs from input")
	}
	got := commands(entries)
	if len(got) != 13 {
		t.Fatalf("got %d entries, want 13", len(got))
	}
	if got[0] != "ls -la" || got[4] != "echo привіт Р світ" || got[12] != "mysql -uroot -pSup3rS3cret db" {
		t.Errorf("unexpected commands: %q", got)
	}
	if !entries[0].Time.IsZero() || entries[4].Time.IsZero() {
		t.Errorf("plain entries must have no time, extended ones must have one")
	}
}

func TestZshMetafiedBytesOnDisk(t *testing.T) {
	// "і" is U+0456 = D1 96; zsh stores 0x96 as Meta, 0x96^0x20.
	data := readGolden(t, "zsh_extended.hist")
	if !bytes.Contains(data, []byte{0xD1, 0x83, 0xB6}) {
		t.Fatal("fixture is expected to contain a metafied byte")
	}
	if got := (zshCodec{}).EncodeLiteral("і"); !bytes.Equal(got, []byte{0xD1, 0x83, 0xB6}) {
		t.Fatalf("EncodeLiteral(і) = % x", got)
	}
}

func TestTimes(t *testing.T) {
	cases := []struct {
		file  string
		shell Shell
		idx   int
		want  int64
	}{
		{"zsh_extended.hist", Zsh, 0, 1790175980},
		{"bash_timestamps.hist", Bash, 2, 1790175980},
		{"fish_history", Fish, 3, 1790170003},
	}
	for _, tc := range cases {
		e := mustCodec(t, tc.shell).Parse(readGolden(t, tc.file))[tc.idx]
		if !e.Time.Equal(time.Unix(tc.want, 0)) {
			t.Errorf("%s[%d].Time = %v, want %d", tc.file, tc.idx, e.Time, tc.want)
		}
	}
	if e := (bashCodec{}).Parse(readGolden(t, "bash_plain.hist"))[0]; !e.Time.IsZero() {
		t.Errorf("bash plain entry has time %v", e.Time)
	}
}

// replaceFile applies Replace to every entry that contains old.
func replaceFile(t *testing.T, c Codec, data []byte, old, repl string) []byte {
	t.Helper()
	var out bytes.Buffer
	for _, e := range c.Parse(data) {
		if e.Opaque || !strings.Contains(e.Command, old) {
			out.Write(e.Raw)
			continue
		}
		r, err := c.Replace(e.Raw, old, repl)
		if err != nil {
			t.Fatalf("Replace line %d: %v", e.Line, err)
		}
		out.Write(r)
	}
	return out.Bytes()
}

const ghToken = "ghp_aaaaBBBBccccDDDDeeeeFFFFgggg1234abcd"

func TestReplaceKeepsEverythingElse(t *testing.T) {
	for _, tc := range []struct {
		file  string
		shell Shell
	}{
		{"zsh_extended.hist", Zsh},
		{"fish_history", Fish},
		{"ConsoleHost_history.txt", PowerShell},
	} {
		t.Run(tc.file, func(t *testing.T) {
			c := mustCodec(t, tc.shell)
			data := readGolden(t, tc.file)
			got := replaceFile(t, c, data, ghToken, "[REDACTED:github_personal_token]")
			// The token is ASCII, so the byte-level result is a plain substitution.
			want := bytes.ReplaceAll(data, []byte(ghToken), []byte("[REDACTED:github_personal_token]"))
			if !bytes.Equal(got, want) {
				t.Fatalf("unexpected result:\n%s", got)
			}
			if bytes.Contains(got, []byte(ghToken)) {
				t.Fatal("token still present")
			}
		})
	}
}

func TestReplaceFishKeepsPathsAndFormat(t *testing.T) {
	c := fishCodec{}
	data := readGolden(t, "fish_history")
	got := replaceFile(t, c, data, ghToken, "[REDACTED:x]")
	for _, want := range []string{
		"- cmd: cat ~/secret-[REDACTED:x].txt\n  when: 1790170002\n  paths:\n    - ~/secret-[REDACTED:x].txt\n",
		"  added_when: 1790169999\n",
	} {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("result lacks %q", want)
		}
	}
	if bytes.Contains(got, []byte("---")) {
		t.Error("result contains a YAML document marker")
	}
	entries := c.Parse(got)
	if len(entries) != 5 {
		t.Fatalf("got %d entries after edit, want 5", len(entries))
	}
}

func TestReplaceNeverTouchesPrefixes(t *testing.T) {
	cases := []struct {
		shell Shell
		raw   string
		old   string
		want  string
	}{
		{Zsh, ": 1790175980:0;echo 1790175980\n", "1790175980", ": 1790175980:0;echo X\n"},
		{Bash, "#1790175980\necho 1790175980\n", "1790175980", "#1790175980\necho X\n"},
		{Fish, "- cmd: echo 1790170000\n  when: 1790170000\n", "1790170000", "- cmd: echo X\n  when: 1790170000\n"},
		{Fish, "- cmd: echo cmd\n  when: 1\n", "cmd", "- cmd: echo X\n  when: 1\n"},
	}
	for _, tc := range cases {
		got, err := mustCodec(t, tc.shell).Replace([]byte(tc.raw), tc.old, "X")
		if err != nil {
			t.Fatalf("%s: %v", tc.shell, err)
		}
		if string(got) != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.shell, got, tc.want)
		}
	}
}

func TestReplaceMetafiedSecret(t *testing.T) {
	c := zshCodec{}
	raw := append([]byte(": 1:0;export PASS="), zshMetafy([]byte("пароль-секрет-ІЇЄ"))...)
	raw = append(raw, '\n')
	got, err := c.Replace(raw, "пароль-секрет-ІЇЄ", "[REDACTED:x]")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != ": 1:0;export PASS=[REDACTED:x]\n" {
		t.Fatalf("got %q", got)
	}
}

func TestReplaceFallsBackOnMisalignedLiteral(t *testing.T) {
	// zsh: decoded "\x83 \xa3" is stored as 83 A3 20 A3. Replacing "\xa3" at
	// byte level would also hit the second half of the Meta pair.
	c := zshCodec{}
	raw := []byte("\x83\xa3 \xa3\n")
	got, err := c.Replace(raw, "\xa3", "R")
	if err != nil {
		t.Fatal(err)
	}
	if want := "\x83\xa3 R\n"; string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	// fish: replacing "n" must not break the "\n" escape.
	f := fishCodec{}
	got, err = f.Replace([]byte("- cmd: an\\nb\n  when: 1\n"), "n", "X")
	if err != nil {
		t.Fatal(err)
	}
	if want := "- cmd: aX\\nb\n  when: 1\n"; string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestReplaceRefusesUnsafeResult(t *testing.T) {
	// A replacement that ends in a backslash would join the zsh record with
	// the next line.
	_, err := zshCodec{}.Replace([]byte(": 1:0;echo secret\n"), "secret", `x\`)
	if err != nil {
		t.Fatalf("protective space handling should still decode correctly: %v", err)
	}
	// Opaque chunks are never edited.
	_, err = fishCodec{}.Replace([]byte("garbage\n"), "garbage", "x")
	if !errors.Is(err, ErrUnsafeEdit) {
		t.Fatalf("err = %v, want ErrUnsafeEdit", err)
	}
	// A newline inside a bash command would split the record.
	_, err = bashCodec{}.Replace([]byte("echo secret\n"), "secret", "a\nb")
	if !errors.Is(err, ErrUnsafeEdit) {
		t.Fatalf("err = %v, want ErrUnsafeEdit", err)
	}
}

func TestReplaceNoMatchReturnsInput(t *testing.T) {
	for _, s := range Shells {
		raw := []byte("- cmd: echo hi\n")
		got, err := mustCodec(t, s).Replace(raw, "absent", "x")
		if err != nil || !bytes.Equal(got, raw) {
			t.Errorf("%s: got %q, %v", s, got, err)
		}
	}
}

func TestParseShell(t *testing.T) {
	names := map[string]Shell{"zsh": Zsh, "BASH": Bash, "\tfish\n": Fish, "pwsh": PowerShell, "powershell": PowerShell}
	for in, want := range names {
		if got, err := ParseShell(in); err != nil || got != want {
			t.Errorf("ParseShell(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseShell("tcsh"); err == nil {
		t.Error("ParseShell(tcsh) should fail")
	}
	if _, err := CodecFor("tcsh"); err == nil {
		t.Error("CodecFor(tcsh) should fail")
	}
}

func TestEmptyInput(t *testing.T) {
	for _, s := range Shells {
		if got := mustCodec(t, s).Parse(nil); len(got) != 0 {
			t.Errorf("%s: Parse(nil) = %d entries", s, len(got))
		}
	}
}

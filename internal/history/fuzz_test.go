package history

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedGolden adds every golden file and a few hand-picked edge cases.
func seedGolden(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join(testdataDir, "*"))
	for _, p := range files {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(b)
		}
	}
	for _, s := range []string{
		"", "\n", "\\", "\\\n", "a\\\n", ":", ": 1", ": 1:2", ": 1:2;", "\\:x\n",
		"\x83", "\x83\n", "#1\n", "#1\n#2\n", "#1\n\n\nx\n", "- cmd", "- cmd:\n  - x\n",
		"`", "a`\n", "a`\r\nb\r\n", "\xef\xbb\xbf", "x\\ \n", "\r\n\r\n",
	} {
		f.Add([]byte(s))
	}
}

func fuzzInvariant(f *testing.F, s Shell) {
	seedGolden(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		c := mustCodec(t, s)
		entries := c.Parse(data)
		if got := concatRaw(entries); !bytes.Equal(got, data) {
			t.Fatalf("concat(Raw) != input\n in: %q\nout: %q", data, got)
		}
		for _, e := range entries {
			if len(e.Raw) == 0 {
				t.Fatal("empty entry")
			}
			if e.Opaque {
				continue
			}
			// Every edit either fails safely or yields the expected command.
			for _, old := range []string{e.Command, firstWord(e.Command)} {
				if old == "" {
					continue
				}
				r, err := c.Replace(e.Raw, old, "[REDACTED:x]")
				if errors.Is(err, ErrUnsafeEdit) {
					continue
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				after := c.Parse(r)
				if len(after) != 1 || after[0].Command != strings.ReplaceAll(e.Command, old, "[REDACTED:x]") {
					t.Fatalf("bad edit of %q: %q", e.Raw, r)
				}
			}
		}
	})
}

func firstWord(s string) string {
	if i := strings.IndexAny(s, " \n"); i > 0 {
		return s[:i]
	}
	return ""
}

func FuzzZshParse(f *testing.F)        { fuzzInvariant(f, Zsh) }
func FuzzBashParse(f *testing.F)       { fuzzInvariant(f, Bash) }
func FuzzFishParse(f *testing.F)       { fuzzInvariant(f, Fish) }
func FuzzPowerShellParse(f *testing.F) { fuzzInvariant(f, PowerShell) }

// zshWrite mirrors savehistfile() in zsh Src/hist.c for EXTENDED_HISTORY.
func zshWrite(cmd string) []byte {
	var b bytes.Buffer
	b.WriteString(": 1790000000:0;")
	endBackslashes := false
	for _, c := range zshMetafy([]byte(cmd)) {
		if c == '\n' {
			b.WriteByte('\\')
		}
		endBackslashes = c == '\\' || (endBackslashes && c == ' ')
		b.WriteByte(c)
	}
	if endBackslashes {
		b.WriteByte(' ')
	}
	b.WriteByte('\n')
	return b.Bytes()
}

// fishWrite mirrors HistoryItem::write_to in fish src/history/file.rs.
func fishWrite(cmd string) []byte {
	return []byte("- cmd: " + string(fishEscape(cmd)) + "\n  when: 1790000000\n")
}

// psWrite mirrors WriteHistoryRange in PSReadLine/History.cs on Unix.
func psWrite(cmd string) []byte {
	return []byte(strings.ReplaceAll(cmd, "\n", "`\n") + "\n")
}

// bashWrite mirrors history -w with HISTTIMEFORMAT set and lithist on.
func bashWrite(cmd string) []byte {
	return []byte("#1790000000\n" + cmd + "\n")
}

// FuzzShellWriters checks that whatever a shell writes for a command decodes
// back to exactly that command, and that masking it works.
func FuzzShellWriters(f *testing.F) {
	for _, s := range []string{"ls", "a\\", "a\\\\  ", "a\nb", "a\\\nb", ": x", "\x00\x83\xa2", "привіт", "x\n", "`a", "a\\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, cmd string) {
		check := func(s Shell, raw []byte) {
			c := mustCodec(t, s)
			entries := c.Parse(raw)
			if len(entries) != 1 || entries[0].Command != cmd {
				t.Fatalf("%s: %q decoded as %d entries, first %q", s, raw, len(entries), firstCommand(entries))
			}
			r, err := c.Replace(raw, cmd, "[REDACTED:x]")
			if err != nil {
				t.Fatalf("%s: Replace(%q): %v", s, raw, err)
			}
			if got := c.Parse(r); len(got) != 1 || got[0].Command != "[REDACTED:x]" {
				t.Fatalf("%s: masked record %q", s, r)
			}
		}
		if cmd == "" {
			return
		}
		check(Zsh, zshWrite(cmd))
		if !strings.HasPrefix(cmd, " ") && !strings.HasPrefix(cmd, "\t") {
			check(Fish, fishWrite(cmd))
		}
		if !strings.ContainsRune(cmd, '\r') && !strings.HasSuffix(cmd, "`") &&
			!strings.HasPrefix(cmd, "\xef\xbb\xbf") {
			check(PowerShell, psWrite(cmd))
		}
		if bashSafe(cmd) {
			check(Bash, bashWrite(cmd))
		}
	})
}

func firstCommand(e []Entry) string {
	if len(e) == 0 {
		return ""
	}
	return e[0].Command
}

// bashSafe excludes commands bash itself cannot round-trip: carriage returns,
// leading blank lines and lines that look like timestamps.
func bashSafe(cmd string) bool {
	if strings.ContainsRune(cmd, '\r') || strings.HasPrefix(cmd, "\n") {
		return false
	}
	for _, l := range strings.Split(cmd, "\n") {
		if bashIsTimestamp([]byte(l)) {
			return false
		}
	}
	return true
}

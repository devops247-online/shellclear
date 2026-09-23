package history

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// Records shaped like the ones Claude Code, Codex CLI and Gemini CLI write.
const (
	claudePrompt = `{"display":"export GITHUB_TOKEN=ghp_x","pastedContents":{},"timestamp":1790000000123,"project":"/home/me/app"}` + "\n"
	codexPrompt  = `{"session_id":"0199","ts":1790000000,"text":"curl -H \"Authorization: Bearer t0k\" x"}` + "\n"
	claudeTool   = `{"type":"user","message":{"content":[{"type":"tool_result","content":"DB_PASSWORD=hunter2\nPORT=80"}]},"timestamp":"2026-09-21T17:13:00.5Z"}` + "\n"
	geminiLogs   = "[\n  {\n    \"sessionId\": \"s1\",\n    \"message\": \"mysql -psecret db\",\n    \"timestamp\": \"2026-09-21T17:13:00Z\"\n  }\n]"
)

func TestJSONParse(t *testing.T) {
	c := mustCodec(t, JSON)
	data := []byte(claudePrompt + codexPrompt + claudeTool + "\n" + `{"truncated":"ab`)
	entries := c.Parse(data)
	if !bytes.Equal(concatRaw(entries), data) {
		t.Fatal("concat(Raw) != input")
	}
	want := []string{
		"export GITHUB_TOKEN=ghp_x\n/home/me/app",
		"0199\ncurl -H \"Authorization: Bearer t0k\" x",
		"user\ntool_result\nDB_PASSWORD=hunter2\nPORT=80\n2026-09-21T17:13:00.5Z",
	}
	if got := commands(entries); !equalStrings(got, want) {
		t.Fatalf("commands = %q", got)
	}
	if len(entries) != 5 || !entries[3].Opaque || !entries[4].Opaque {
		t.Fatalf("blank and truncated lines must be opaque: %+v", entries)
	}
	times := []time.Time{
		time.UnixMilli(1790000000123),
		time.Unix(1790000000, 0),
		time.Date(2026, 9, 21, 17, 13, 0, 5e8, time.UTC),
	}
	for i, ts := range times {
		if !entries[i].Time.Equal(ts) || entries[i].Line != i+1 {
			t.Errorf("entry %d: time %v line %d", i, entries[i].Time, entries[i].Line)
		}
	}
}

func TestJSONParsePretty(t *testing.T) {
	entries := mustCodec(t, JSON).Parse([]byte(geminiLogs))
	var got []string
	for _, e := range entries {
		if !e.Opaque {
			got = append(got, e.Command)
		}
	}
	if !equalStrings(got, []string{"s1", "mysql -psecret db", "2026-09-21T17:13:00Z"}) {
		t.Fatalf("commands = %q", got)
	}
	if e := entries[3]; e.Line != 4 || e.Command != "mysql -psecret db" {
		t.Fatalf("entry = %+v", e)
	}
	if !entries[4].Time.Equal(time.Date(2026, 9, 21, 17, 13, 0, 0, time.UTC)) {
		t.Fatalf("time = %v", entries[4].Time)
	}
}

func TestJSONTimeIgnoresNestedAndBadValues(t *testing.T) {
	for _, line := range []string{
		`{"a":{"b":{"timestamp":1790000000}},"x":"y"}`,
		`{"timestamp":"yesterday","x":"y"}`,
		`{"ts":-1,"x":"y"}`,
	} {
		if e := mustCodec(t, JSON).Parse([]byte(line)); !e[0].Time.IsZero() {
			t.Errorf("%s: time = %v", line, e[0].Time)
		}
	}
}

func TestJSONReplace(t *testing.T) {
	c := mustCodec(t, JSON)
	cases := []struct{ raw, old, want string }{
		{claudePrompt, "ghp_x", strings.Replace(claudePrompt, "ghp_x", "[REDACTED:r]", 1)},
		{codexPrompt, `Bearer t0k`, strings.Replace(codexPrompt, `Bearer t0k`, "[REDACTED:r]", 1)},
		// The secret is followed by an escaped newline.
		{claudeTool, "hunter2", strings.Replace(claudeTool, "hunter2", "[REDACTED:r]", 1)},
		// A secret that contains a quote is matched in its escaped form.
		{`{"k":"pw=a\"b end"}` + "\n", `a"b`, `{"k":"pw=[REDACTED:r] end"}` + "\n"},
		// Keys are never edited, only values.
		{`{"hunter2":"hunter2"}`, "hunter2", `{"hunter2":"[REDACTED:r]"}`},
	}
	for _, tc := range cases {
		got, err := c.Replace([]byte(tc.raw), tc.old, "[REDACTED:r]")
		if err != nil || string(got) != tc.want {
			t.Errorf("Replace(%q, %q) = %q, %v; want %q", tc.raw, tc.old, got, err, tc.want)
			continue
		}
		if !json.Valid(bytes.TrimSpace(got)) {
			t.Errorf("result is not valid JSON: %q", got)
		}
	}
}

func TestJSONReplaceUnsafe(t *testing.T) {
	c := mustCodec(t, JSON)
	for _, tc := range []struct{ raw, old string }{
		// Text across two values cannot be masked as one secret.
		{`{"a":"x","b":"y"}`, "x\ny"},
		// A is not how the text would be written back.
		{"{\"a\":\"pw \\u0041BC\"}", "ABC"},
		// Opaque lines are never edited.
		{`{"a":"unterminated`, "unterminated"},
	} {
		if _, err := c.Replace([]byte(tc.raw), tc.old, "[REDACTED:r]"); !errors.Is(err, ErrUnsafeEdit) {
			t.Errorf("Replace(%q, %q): err = %v, want ErrUnsafeEdit", tc.raw, tc.old, err)
		}
	}
}

func TestJSONEscapeMatchesEncoders(t *testing.T) {
	for _, s := range []string{"plain", `q"b\s`, "nl\nt\tcr\r\x00\x1f\b\f", "привіт <&> \u2028"} {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(s); err != nil {
			t.Fatal(err)
		}
		want := strings.TrimSuffix(strings.TrimSpace(b.String()), `"`)[1:]
		// Go escapes U+2028 where JSON.stringify and serde_json do not.
		want = strings.ReplaceAll(want, "\\u2028", "\u2028")
		if got := string(jsonEscape(s)); got != want {
			t.Errorf("jsonEscape(%q) = %q, want %q", s, got, want)
		}
		if got := (jsonCodec{}).decodeSpan(jsonEscape(s)); got != s {
			t.Errorf("round trip of %q = %q", s, got)
		}
	}
}

func FuzzJSONParse(f *testing.F) {
	for _, s := range []string{claudePrompt, codexPrompt, claudeTool, geminiLogs, `{"a":"\u00`, `"\\"`, `{"a":"b\"`} {
		f.Add([]byte(s))
	}
	fuzzInvariant(f, JSON)
}

// FuzzJSONWriter checks that whatever JSON.stringify writes for a string
// decodes back to it and can be masked.
func FuzzJSONWriter(f *testing.F) {
	for _, s := range []string{"ls", `a"b`, "a\nb", `\`, "\x00", "привіт"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if s == "" || strings.ContainsRune(s, '�') || !utf8Valid(s) {
			return
		}
		raw := []byte(`{"display":"` + string(jsonEscape(s)) + `","timestamp":1}` + "\n")
		c := mustCodec(t, JSON)
		if e := c.Parse(raw); len(e) != 1 || e[0].Command != s {
			t.Fatalf("%q decoded as %+v", raw, e)
		}
		got, err := c.Replace(raw, s, "[REDACTED:x]")
		if err != nil {
			t.Fatalf("Replace(%q): %v", raw, err)
		}
		if e := c.Parse(got); len(e) != 1 || e[0].Command != "[REDACTED:x]" || !json.Valid(bytes.TrimSpace(got)) {
			t.Fatalf("masked record %q", got)
		}
	})
}

func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "") == s }

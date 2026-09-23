package history

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// jsonCodec handles the chat histories and session transcripts that AI coding
// assistants keep: JSON Lines (Claude Code, Codex CLI) and pretty-printed
// JSON (Gemini CLI, Qwen Code).
//
// Both are handled line by line. JSON escapes newlines inside strings, so
// every string literal starts and ends on the same line in both layouts:
//   - Each line is one entry. Its Command is the decoded text of every string
//     value on the line (object keys excluded), joined with "\n".
//   - A line that has no string value, or whose quotes do not balance, is
//     opaque and never edited.
//   - Time comes from a "timestamp" or "ts" key near the top of the line:
//     RFC 3339 text, or Unix seconds or milliseconds.
//   - Edits touch only the bytes between the quotes of a string value and are
//     escaped the way JSON.stringify and serde_json escape. A line that was
//     valid JSON must still be valid JSON after the edit.
type jsonCodec struct{}

func (jsonCodec) Shell() Shell { return JSON }

func (jsonCodec) Parse(data []byte) []Entry {
	var entries []Entry
	it := lineIter{data: data}
	line := 1
	for {
		l, ok := it.next()
		if !ok {
			break
		}
		raw := l[:len(l):len(l)]
		e := Entry{Raw: raw, Line: line, Opaque: true}
		if toks, ok := jsonTokens(trimEOL(raw)); ok {
			if cmd, n := jsonCommand(raw, toks); n > 0 {
				e.Command, e.Opaque = cmd, false
				e.Time = jsonTime(raw, toks)
			}
		}
		entries = append(entries, e)
		line++
	}
	return entries
}

func (jsonCodec) EncodeLiteral(s string) []byte { return jsonEscape(s) }

func (c jsonCodec) Replace(raw []byte, old, repl string) ([]byte, error) {
	// A line without string values has nothing to edit.
	if e := c.Parse(raw); len(e) == 1 && e[0].Opaque && !bytes.Contains(raw, []byte(old)) {
		return raw, nil
	}
	res, err := replaceInSpans(c, raw, old, repl)
	if err != nil {
		return nil, err
	}
	if json.Valid(trimEOL(raw)) && !json.Valid(trimEOL(res)) {
		return nil, ErrUnsafeEdit
	}
	return res, nil
}

func (jsonCodec) spans(raw []byte) []span {
	toks, ok := jsonTokens(trimEOL(raw))
	if !ok {
		return nil
	}
	var out []span
	for _, t := range toks {
		if !t.key {
			out = append(out, t.span)
		}
	}
	return out
}

func (jsonCodec) decodeSpan(b []byte) string {
	if bytes.IndexByte(b, '\\') < 0 {
		return string(b)
	}
	quoted := make([]byte, 0, len(b)+2)
	quoted = append(append(append(quoted, '"'), b...), '"')
	var s string
	if err := json.Unmarshal(quoted, &s); err != nil {
		// Keep broken escapes literally so the text is still scanned.
		return string(b)
	}
	return s
}

func (jsonCodec) encodeSpan(s string) []byte { return jsonEscape(s) }

// jsonToken is one string literal on a line.
type jsonToken struct {
	span       // the bytes between the quotes
	key   bool // followed by ':', so it names an object member
	depth int  // brackets opened before it on the same line
}

// jsonTokens finds the string literals on one line. It reports false when a
// string is not closed before the end of the line.
func jsonTokens(line []byte) ([]jsonToken, bool) {
	var toks []jsonToken
	depth := 0
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		case '"':
			j := i + 1
			for j < len(line) && line[j] != '"' {
				if line[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(line) {
				return nil, false
			}
			k := j + 1
			for k < len(line) && (line[k] == ' ' || line[k] == '\t') {
				k++
			}
			toks = append(toks, jsonToken{span: span{i + 1, j}, key: k < len(line) && line[k] == ':', depth: depth})
			i = j
		}
	}
	return toks, true
}

// jsonCommand joins the decoded string values of a line and returns how many
// there were.
func jsonCommand(raw []byte, toks []jsonToken) (string, int) {
	var b strings.Builder
	n := 0
	for _, t := range toks {
		if t.key {
			continue
		}
		if n > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(jsonCodec{}.decodeSpan(raw[t.start:t.end]))
		n++
	}
	return b.String(), n
}

// jsonTime reads the first "timestamp" or "ts" member at depth 0 or 1.
func jsonTime(raw []byte, toks []jsonToken) time.Time {
	for i, t := range toks {
		if !t.key || t.depth > 1 {
			continue
		}
		if name := string(raw[t.start:t.end]); name != "timestamp" && name != "ts" {
			continue
		}
		// Skip the closing quote, blanks and the colon.
		v := bytes.TrimLeft(raw[t.end+1:], " \t")
		v = bytes.TrimLeft(bytes.TrimPrefix(v, []byte(":")), " \t")
		if len(v) > 0 && v[0] == '"' {
			if i+1 < len(toks) {
				next := toks[i+1]
				if ts, err := time.Parse(time.RFC3339Nano, string(raw[next.start:next.end])); err == nil {
					return ts
				}
			}
			return time.Time{}
		}
		end := 0
		for end < len(v) && v[end] >= '0' && v[end] <= '9' {
			end++
		}
		n, err := strconv.ParseInt(string(v[:end]), 10, 64)
		switch {
		case err != nil || n <= 0:
			return time.Time{}
		case n >= 1e12:
			return time.UnixMilli(n)
		}
		return time.Unix(n, 0)
	}
	return time.Time{}
}

// jsonEscape encodes s as the inside of a JSON string, the way
// JSON.stringify and serde_json do: only '"', '\' and control characters are
// escaped.
func jsonEscape(s string) []byte {
	const hex = "0123456789abcdef"
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		var esc string
		switch c {
		case '"':
			esc = `\"`
		case '\\':
			esc = `\\`
		case '\n':
			esc = `\n`
		case '\r':
			esc = `\r`
		case '\t':
			esc = `\t`
		case '\b':
			esc = `\b`
		case '\f':
			esc = `\f`
		default:
			if c >= 0x20 {
				if b != nil {
					b = append(b, c)
				}
				continue
			}
			esc = `\u00` + string(hex[c>>4]) + string(hex[c&0xf])
		}
		if b == nil {
			b = append(make([]byte, 0, len(s)+8), s[:i]...)
		}
		b = append(b, esc...)
	}
	if b == nil {
		return []byte(s)
	}
	return b
}

package history

import (
	"bytes"
	"strconv"
	"time"
)

// fishCodec handles fish_history (the "fish 2.0" pseudo-YAML format).
//
// Behaviour mirrors fish src/history/yaml_backend.rs and file.rs:
//   - A record starts at a column-0 line beginning with "- cmd". Every
//     following line up to the next such line belongs to the record,
//     including "  when:", "  added_when:" and "  paths:" items.
//   - Values are escaped with "\\" for a backslash and "\n" for a newline;
//     paths use the same escaping.
//   - The command value follows the first ':' with leading blanks removed.
//
// Unlike fish, which stops decoding at an unknown escape sequence, unknown
// escapes are kept literally so that text after them is still scanned.
// Bytes before the first record are returned as one opaque entry.
type fishCodec struct{}

var fishCmdPrefix = []byte("- cmd")

func (fishCodec) Shell() Shell { return Fish }

func (c fishCodec) Parse(data []byte) []Entry {
	var entries []Entry
	it := lineIter{data: data}
	curStart, curLine, line := 0, 1, 1
	curOpaque := true
	flush := func(end int) {
		if end <= curStart {
			return
		}
		raw := data[curStart:end:end]
		e := Entry{Raw: raw, Line: curLine, Opaque: curOpaque}
		if !curOpaque {
			e.Command, e.Time = fishDecode(raw)
		}
		entries = append(entries, e)
	}
	for {
		l, ok := it.next()
		if !ok {
			break
		}
		if bytes.HasPrefix(l, fishCmdPrefix) {
			start := it.pos - len(l)
			flush(start)
			curStart, curLine, curOpaque = start, line, false
		}
		line++
	}
	flush(len(data))
	return entries
}

func (fishCodec) EncodeLiteral(s string) []byte { return fishEscape(s) }

func (c fishCodec) Replace(raw []byte, old, repl string) ([]byte, error) {
	return replaceInSpans(c, raw, old, repl)
}

func (fishCodec) spans(raw []byte) []span {
	var out []span
	it := lineIter{data: raw}
	first, ok := it.next()
	if !ok || !bytes.HasPrefix(first, fishCmdPrefix) {
		return nil
	}
	if s, e, ok := fishCmdValue(first); ok && s < e {
		out = append(out, span{s, e})
	}
	for {
		l, ok := it.next()
		if !ok {
			break
		}
		base := it.pos - len(l)
		body := bytes.TrimRight(l, "\n")
		trimmed := bytes.TrimLeft(body, " ")
		if len(trimmed) == len(body) || !bytes.HasPrefix(trimmed, []byte("- ")) {
			continue
		}
		s := base + (len(body) - len(trimmed)) + 2
		e := base + len(body)
		if s < e {
			out = append(out, span{s, e})
		}
	}
	return out
}

func (fishCodec) decodeSpan(b []byte) string { return fishUnescape(b) }

func (fishCodec) encodeSpan(s string) []byte { return fishEscape(s) }

// fishCmdValue returns the range of the value on a "- cmd: value" line.
func fishCmdValue(line []byte) (int, int, bool) {
	body := bytes.TrimRight(line, "\n")
	colon := bytes.IndexByte(body, ':')
	if colon < 0 {
		return 0, 0, false
	}
	s := colon + 1
	for s < len(body) && (body[s] == ' ' || body[s] == '\t') {
		s++
	}
	return s, len(body), true
}

func fishDecode(raw []byte) (string, time.Time) {
	it := lineIter{data: raw}
	first, _ := it.next()
	var cmd string
	if s, e, ok := fishCmdValue(first); ok {
		cmd = fishUnescape(first[s:e])
	}
	var ts time.Time
	for {
		l, ok := it.next()
		if !ok {
			break
		}
		v, found := bytes.CutPrefix(bytes.TrimLeft(trimEOL(l), " "), []byte("when:"))
		if !found {
			continue
		}
		if n, err := strconv.ParseInt(string(bytes.TrimSpace(v)), 10, 64); err == nil && n > 0 {
			ts = time.Unix(n, 0)
		}
		break
	}
	return cmd, ts
}

func fishEscape(s string) []byte {
	b := []byte(s)
	if bytes.IndexByte(b, '\\') < 0 && bytes.IndexByte(b, '\n') < 0 {
		return b
	}
	b = bytes.ReplaceAll(b, []byte(`\`), []byte(`\\`))
	return bytes.ReplaceAll(b, []byte("\n"), []byte(`\n`))
}

func fishUnescape(b []byte) string {
	if bytes.IndexByte(b, '\\') < 0 {
		return string(b)
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == '\\' && i+1 < len(b) {
			switch b[i+1] {
			case '\\':
				out = append(out, '\\')
				i++
				continue
			case 'n':
				out = append(out, '\n')
				i++
				continue
			}
		}
		out = append(out, b[i])
	}
	return string(out)
}

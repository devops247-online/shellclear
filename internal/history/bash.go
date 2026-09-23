package history

import (
	"bytes"
	"strconv"
	"time"
)

// bashCodec handles ~/.bash_history.
//
// Behaviour mirrors bash lib/readline/histfile.c (read_history_range):
//   - A timestamp line is '#' followed by a digit (HIST_TIMESTAMP_START).
//     It belongs to the command that follows it.
//   - When the file starts with a timestamp, bash treats every line up to
//     the next timestamp as part of one entry (multi-line entries written
//     with `shopt -s lithist`). Otherwise every line is its own entry.
//   - Blank lines right after a timestamp are skipped.
//   - "\r\n" line endings are accepted.
type bashCodec struct{}

func (bashCodec) Shell() Shell { return Bash }

func bashIsTimestamp(line []byte) bool {
	return len(line) >= 2 && line[0] == '#' && line[1] >= '0' && line[1] <= '9'
}

func (c bashCodec) Parse(data []byte) []Entry {
	var entries []Entry
	it := lineIter{data: data}
	first, _ := (&lineIter{data: data}).next()
	grouped := bashIsTimestamp(first)

	curStart, curLine := -1, 1
	curTS, curContent := false, false
	line := 1
	flush := func(end int) {
		if curStart < 0 {
			return
		}
		raw := data[curStart:end:end]
		cmd, ts := bashDecode(raw)
		entries = append(entries, Entry{Raw: raw, Command: cmd, Line: curLine, Time: ts})
		curStart = -1
	}
	for {
		l, ok := it.next()
		if !ok {
			break
		}
		start := it.pos - len(l)
		switch {
		case bashIsTimestamp(l):
			flush(start)
			curStart, curLine, curTS, curContent = start, line, true, false
		case curStart >= 0 && curTS && (!curContent || grouped):
			curContent = true
		default:
			flush(start)
			curStart, curLine, curTS, curContent = start, line, false, true
		}
		line++
	}
	flush(len(data))
	return entries
}

func (bashCodec) EncodeLiteral(s string) []byte { return []byte(s) }

func (c bashCodec) Replace(raw []byte, old, repl string) ([]byte, error) {
	return replaceInSpans(c, raw, old, repl)
}

func (bashCodec) spans(raw []byte) []span {
	s, e := bashCommandRange(raw)
	if s >= e {
		return nil
	}
	return []span{{s, e}}
}

func (bashCodec) decodeSpan(b []byte) string {
	if bytes.IndexByte(b, '\r') < 0 {
		return string(b)
	}
	return string(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")))
}

func (bashCodec) encodeSpan(s string) []byte { return []byte(s) }

// bashCommandRange returns the byte range of the command text in raw: after
// the timestamp line and any blank lines that follow it, up to the final
// line terminator.
func bashCommandRange(raw []byte) (int, int) {
	it := lineIter{data: raw}
	start := 0
	l, ok := it.next()
	if ok && bashIsTimestamp(l) {
		start = it.pos
		for {
			l, ok = it.next()
			if !ok || len(trimEOL(l)) != 0 {
				break
			}
			start = it.pos
		}
	}
	end := len(raw) - eolLen(raw)
	if start > end {
		start = end
	}
	return start, end
}

func bashDecode(raw []byte) (string, time.Time) {
	var ts time.Time
	if first, ok := (&lineIter{data: raw}).next(); ok && bashIsTimestamp(first) {
		if n, err := strconv.ParseInt(string(trimEOL(first)[1:]), 10, 64); err == nil && n > 0 {
			ts = time.Unix(n, 0)
		}
	}
	s, e := bashCommandRange(raw)
	return bashCodec{}.decodeSpan(raw[s:e]), ts
}

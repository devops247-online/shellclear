package history

import (
	"bytes"
	"time"
)

// powershellCodec handles PSReadLine's ConsoleHost_history.txt.
//
// Behaviour mirrors PSReadLine/History.cs:
//   - WriteHistoryRange stores CommandLine.Replace("\n", "`\n") followed by
//     WriteLine, so records end with "\r\n" on Windows and "\n" elsewhere.
//   - UpdateHistoryFromFile joins a line ending in a backtick with the next
//     line, replacing the backtick with a newline.
//
// A UTF-8 byte order mark at the start of the file is kept in Raw and is not
// part of the first command.
type powershellCodec struct{}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

func (powershellCodec) Shell() Shell { return PowerShell }

func (c powershellCodec) Parse(data []byte) []Entry {
	var entries []Entry
	it := lineIter{data: data}
	line := 1
	for {
		first, ok := it.next()
		if !ok {
			break
		}
		start := it.pos - len(first)
		last := first
		for eolLen(last) > 0 && bytes.HasSuffix(trimEOL(last), []byte("`")) {
			nxt, ok := it.next()
			if !ok {
				break
			}
			last = nxt
		}
		raw := data[start:it.pos:it.pos]
		entries = append(entries, Entry{Raw: raw, Command: psDecode(raw), Line: line, Time: time.Time{}})
		line += countLines(raw)
	}
	return entries
}

func (powershellCodec) EncodeLiteral(s string) []byte { return psEncode(s) }

func (c powershellCodec) Replace(raw []byte, old, repl string) ([]byte, error) {
	return replaceInSpans(c, raw, old, repl)
}

func (powershellCodec) spans(raw []byte) []span {
	s, e := psCommandRange(raw)
	if s >= e {
		return nil
	}
	return []span{{s, e}}
}

func (powershellCodec) decodeSpan(b []byte) string {
	if bytes.IndexByte(b, '\n') < 0 && bytes.IndexByte(b, '\r') < 0 {
		return string(b)
	}
	lines := bytes.Split(b, []byte("\n"))
	var out []byte
	for i, l := range lines {
		l = bytes.TrimSuffix(l, []byte("\r"))
		if i < len(lines)-1 {
			l = bytes.TrimSuffix(l, []byte("`"))
		}
		out = append(out, l...)
		if i < len(lines)-1 {
			out = append(out, '\n')
		}
	}
	return string(out)
}

func (powershellCodec) encodeSpan(s string) []byte { return psEncode(s) }

func psEncode(s string) []byte {
	b := []byte(s)
	if bytes.IndexByte(b, '\n') < 0 {
		return b
	}
	return bytes.ReplaceAll(b, []byte("\n"), []byte("`\n"))
}

func psCommandRange(raw []byte) (int, int) {
	start := 0
	if bytes.HasPrefix(raw, utf8BOM) {
		start = len(utf8BOM)
	}
	end := len(raw) - eolLen(raw)
	if start > end {
		start = end
	}
	return start, end
}

func psDecode(raw []byte) string {
	s, e := psCommandRange(raw)
	return powershellCodec{}.decodeSpan(raw[s:e])
}

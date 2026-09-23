package history

import (
	"bytes"
	"time"
)

// zshCodec handles $HISTFILE written by zsh, in plain or EXTENDED_HISTORY
// format, including files that mix both.
//
// Behaviour mirrors zsh 5.9 Src/hist.c:
//   - readhistline: a line whose last byte before '\n' is '\' continues on
//     the next line (no parity check), and the '\' stands for a newline.
//     When the final line ends in '\' followed by spaces, one trailing space
//     is dropped; savehistfile adds that space to protect real backslashes.
//   - readhistfile: a record starting with ':' carries ": <start>:<elapsed>;"
//     and the command follows the first ';' after the second ':'. Otherwise
//     a leading "\:" is unescaped to ":".
//   - Command text is metafied (Src/utils.c metafy, Src/init.c inittyptab).
type zshCodec struct{}

const zshMeta = 0x83

// zshIsMeta reports whether zsh stores b as a Meta pair: 0x00, Meta (0x83),
// the token range Pound (0x84) .. Nularg (0xA1), and Marker (0xA2).
func zshIsMeta(b byte) bool { return b == 0 || (b >= 0x83 && b <= 0xA2) }

func (zshCodec) Shell() Shell { return Zsh }

func (c zshCodec) Parse(data []byte) []Entry {
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
		for bytes.HasSuffix(last, []byte("\\\n")) {
			nxt, ok := it.next()
			if !ok {
				break
			}
			last = nxt
		}
		raw := data[start:it.pos:it.pos]
		cmd, ts := zshDecode(raw)
		entries = append(entries, Entry{Raw: raw, Command: cmd, Line: line, Time: ts})
		line += countLines(raw)
	}
	return entries
}

func (zshCodec) EncodeLiteral(s string) []byte {
	return zshContinue(zshMetafy([]byte(s)))
}

func (c zshCodec) Replace(raw []byte, old, repl string) ([]byte, error) {
	return replaceInSpans(c, raw, old, repl)
}

// spans covers the command including the protective trailing space, so an
// edit can add or drop that space. decodeSpan and encodeSpan apply the same
// rule as zsh's reader and writer. A last record without a newline does not
// get the rule in zsh, so such a record ending in "\ " is not editable.
func (zshCodec) spans(raw []byte) []span {
	l := zshLayout(raw)
	if !l.hasNL && zshProtectedEnd(raw[:l.bodyEnd]) {
		return nil
	}
	if l.cmdStart >= l.bodyEnd {
		return nil
	}
	return []span{{l.cmdStart, l.bodyEnd}}
}

func (zshCodec) decodeSpan(b []byte) string {
	if zshProtectedEnd(b) {
		b = b[:len(b)-1]
	}
	return zshDecodeCommand(b)
}

func (zshCodec) encodeSpan(s string) []byte {
	b := zshMetafy([]byte(s))
	if zshNeedsProtection(b) {
		b = append(b[:len(b):len(b)], ' ')
	}
	return zshContinue(b)
}

// zshDecodeCommand joins continuation lines and unmetafies.
func zshDecodeCommand(b []byte) string {
	return string(zshUnmetafy(bytes.ReplaceAll(b, []byte("\\\n"), []byte("\n"))))
}

// zshProtectedEnd reports whether b ends in a backslash followed by at least
// one space, in which case zsh's reader drops one trailing space.
func zshProtectedEnd(b []byte) bool {
	i := len(b) - 1
	for i >= 0 && b[i] == ' ' {
		i--
	}
	return i != len(b)-1 && i >= 0 && b[i] == '\\'
}

// zshNeedsProtection mirrors end_backslashes in savehistfile: the metafied
// command ends in a backslash, optionally followed by spaces.
func zshNeedsProtection(b []byte) bool {
	end := false
	for _, c := range b {
		end = c == '\\' || (end && c == ' ')
	}
	return end
}

// zshLayoutInfo describes where the command lives inside one record.
type zshLayoutInfo struct {
	cmdStart, cmdEnd int // command bytes, raw (metafied, with continuations)
	bodyEnd          int // end of the record before its final newline
	start            int64
	extended         bool
	hasNL            bool
}

func zshLayout(raw []byte) zshLayoutInfo {
	body := raw
	hasNL := bytes.HasSuffix(body, []byte("\n"))
	if hasNL {
		body = body[:len(body)-1]
	}
	end := len(body)
	if hasNL && zshProtectedEnd(body) {
		// Drop the protective space written after trailing backslashes.
		end--
	}

	info := zshLayoutInfo{cmdEnd: end, bodyEnd: len(body), hasNL: hasNL}
	switch {
	case len(body) > 0 && body[0] == ':':
		info.extended = true
		info.start = zshStrtol(body[1:])
		p := 1
		for p < len(body) && body[p] != ':' {
			p++
		}
		if p < len(body) {
			p++
			for p < len(body) && body[p] != ';' {
				p++
			}
			if p < len(body) {
				p++
			}
		}
		info.cmdStart = p
	case len(body) > 1 && body[0] == '\\' && body[1] == ':':
		info.cmdStart = 1
	}
	if info.cmdStart > info.cmdEnd {
		info.cmdStart = info.cmdEnd
	}
	return info
}

func zshDecode(raw []byte) (string, time.Time) {
	l := zshLayout(raw)
	var cmd string
	if l.cmdStart < l.cmdEnd {
		cmd = zshDecodeCommand(raw[l.cmdStart:l.cmdEnd])
	}
	var ts time.Time
	if l.extended && l.start > 0 {
		ts = time.Unix(l.start, 0)
	}
	return cmd, ts
}

// zshStrtol parses a leading decimal number the way zstrtol does for base 0
// digits in history timestamps: leading blanks are skipped, parsing stops at
// the first non-digit.
func zshStrtol(b []byte) int64 {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t') {
		i++
	}
	var n int64
	for ; i < len(b) && b[i] >= '0' && b[i] <= '9'; i++ {
		if n > (1<<62)/10 {
			return 0
		}
		n = n*10 + int64(b[i]-'0')
	}
	return n
}

func zshMetafy(b []byte) []byte {
	n := 0
	for _, c := range b {
		if zshIsMeta(c) {
			n++
		}
	}
	if n == 0 {
		return b
	}
	out := make([]byte, 0, len(b)+n)
	for _, c := range b {
		if zshIsMeta(c) {
			out = append(out, zshMeta, c^0x20)
		} else {
			out = append(out, c)
		}
	}
	return out
}

// zshUnmetafy mirrors unmetafy(): Meta followed by a byte becomes that byte
// XOR 0x20. A trailing Meta without a following byte is kept as is.
func zshUnmetafy(b []byte) []byte {
	i := bytes.IndexByte(b, zshMeta)
	if i < 0 {
		return b
	}
	out := make([]byte, 0, len(b))
	out = append(out, b[:i]...)
	for ; i < len(b); i++ {
		if b[i] == zshMeta && i+1 < len(b) {
			i++
			out = append(out, b[i]^0x20)
			continue
		}
		out = append(out, b[i])
	}
	return out
}

// zshContinue writes each newline as backslash-newline.
func zshContinue(b []byte) []byte {
	if bytes.IndexByte(b, '\n') < 0 {
		return b
	}
	return bytes.ReplaceAll(b, []byte("\n"), []byte("\\\n"))
}

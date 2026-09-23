// Package history reads and edits shell history files without ever changing
// bytes that do not belong to an edited command.
//
// Every codec keeps one invariant: concatenating Raw of all parsed entries
// yields exactly the input. Edits are applied to Raw through Replace, which
// only touches the regions where the command text is stored and verifies the
// result by decoding it again.
package history

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Shell identifies a history file format.
type Shell string

// Supported history formats.
const (
	Zsh        Shell = "zsh"
	Bash       Shell = "bash"
	Fish       Shell = "fish"
	PowerShell Shell = "powershell"
	// JSON is not a shell: it is the JSON Lines and JSON files where AI
	// coding assistants keep prompts and session transcripts.
	JSON Shell = "json"
)

// Shells lists every supported format in a stable order.
var Shells = []Shell{Zsh, Bash, Fish, PowerShell, JSON}

// ParseShell converts a user-supplied name into a Shell.
func ParseShell(name string) (Shell, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "zsh":
		return Zsh, nil
	case "bash":
		return Bash, nil
	case "fish":
		return Fish, nil
	case "powershell", "pwsh":
		return PowerShell, nil
	case "json", "jsonl":
		return JSON, nil
	}
	return "", fmt.Errorf("unknown shell %q (want zsh, bash, fish, powershell or json)", name)
}

// Entry is one history record.
type Entry struct {
	// Raw holds the exact bytes of the record, including its line terminator
	// and any service lines such as bash timestamps or fish metadata.
	Raw []byte
	// Command is the decoded command text. It may contain invalid UTF-8.
	Command string
	// Line is the 1-based line number of the first byte of Raw.
	Line int
	// Time is the command start time, or the zero value when unknown.
	Time time.Time
	// Opaque marks chunks that are not commands (for example text before the
	// first fish record). They are kept verbatim and never edited.
	Opaque bool
}

// ErrUnsafeEdit is returned by Replace when the edited record would not decode
// to the expected command. The caller must leave the record unchanged.
var ErrUnsafeEdit = errors.New("record cannot be edited safely")

// Codec parses and edits one history format.
type Codec interface {
	// Shell returns the format this codec handles.
	Shell() Shell
	// Parse splits data into entries. concat(Raw) == data always holds.
	Parse(data []byte) []Entry
	// EncodeLiteral returns how the decoded text s is stored inside Raw.
	EncodeLiteral(s string) []byte
	// Replace substitutes every occurrence of old with repl in the editable
	// regions of one entry's Raw. It returns raw unchanged when old does not
	// occur, and ErrUnsafeEdit when the result would not decode to the
	// command with old replaced.
	Replace(raw []byte, old, repl string) ([]byte, error)
}

// CodecFor returns the codec for a shell.
func CodecFor(s Shell) (Codec, error) {
	switch s {
	case Zsh:
		return zshCodec{}, nil
	case Bash:
		return bashCodec{}, nil
	case Fish:
		return fishCodec{}, nil
	case PowerShell:
		return powershellCodec{}, nil
	case JSON:
		return jsonCodec{}, nil
	}
	return nil, fmt.Errorf("unsupported shell %q", s)
}

// span is a half-open byte range [start, end) inside Raw.
type span struct{ start, end int }

// regionCodec is the internal contract that lets replaceInSpans implement
// Replace once for every format.
type regionCodec interface {
	Codec
	// spans returns the editable regions of raw in ascending order.
	spans(raw []byte) []span
	// decodeSpan turns one region's bytes into text.
	decodeSpan(b []byte) string
	// encodeSpan is the inverse of decodeSpan for canonical data.
	encodeSpan(s string) []byte
}

// replaceInSpans edits every span of raw that contains old, then checks that
// the whole record still parses as a single entry whose command equals the
// original command with old replaced.
//
// Each span is first edited at the byte level by replacing the encoded
// literal, which keeps any non-canonical bytes around it untouched. If that
// does not decode to the expected text (for example when the encoded literal
// matches across an escape sequence), the span is re-encoded from the
// expected text, but only when the original span was canonical.
func replaceInSpans(c regionCodec, raw []byte, old, repl string) ([]byte, error) {
	if old == "" {
		return raw, nil
	}
	orig := c.Parse(raw)
	if len(orig) != 1 || orig[0].Opaque {
		return nil, ErrUnsafeEdit
	}

	spans := c.spans(raw)
	encOld, encNew := c.EncodeLiteral(old), c.EncodeLiteral(repl)

	var out bytes.Buffer
	out.Grow(len(raw))
	prev, changed := 0, false
	for _, sp := range spans {
		seg := raw[sp.start:sp.end]
		text := c.decodeSpan(seg)
		if !strings.Contains(text, old) {
			continue
		}
		want := strings.ReplaceAll(text, old, repl)
		edited := bytes.ReplaceAll(seg, encOld, encNew)
		if c.decodeSpan(edited) != want {
			if !bytes.Equal(c.encodeSpan(text), seg) {
				return nil, ErrUnsafeEdit
			}
			edited = c.encodeSpan(want)
			if c.decodeSpan(edited) != want {
				return nil, ErrUnsafeEdit
			}
		}
		out.Write(raw[prev:sp.start])
		out.Write(edited)
		prev, changed = sp.end, true
	}
	if !changed {
		if strings.Contains(orig[0].Command, old) {
			// The text is in the command but in no editable region.
			return nil, ErrUnsafeEdit
		}
		return raw, nil
	}
	out.Write(raw[prev:])
	res := out.Bytes()

	after := c.Parse(res)
	if len(after) != 1 || after[0].Opaque ||
		after[0].Command != strings.ReplaceAll(orig[0].Command, old, repl) {
		return nil, ErrUnsafeEdit
	}
	return res, nil
}

// lineIter walks data line by line. Each line includes its trailing '\n' when
// present, so concatenating all lines gives back data.
type lineIter struct {
	data []byte
	pos  int
}

func (it *lineIter) next() ([]byte, bool) {
	if it.pos >= len(it.data) {
		return nil, false
	}
	rest := it.data[it.pos:]
	n := bytes.IndexByte(rest, '\n')
	if n < 0 {
		n = len(rest)
	} else {
		n++
	}
	it.pos += n
	return rest[:n], true
}

// trimEOL removes a trailing "\n" or "\r\n".
func trimEOL(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	return bytes.TrimSuffix(b, []byte("\r"))
}

// eolLen returns the length of the line terminator at the end of b.
func eolLen(b []byte) int {
	switch {
	case bytes.HasSuffix(b, []byte("\r\n")):
		return 2
	case bytes.HasSuffix(b, []byte("\n")):
		return 1
	}
	return 0
}

// countLines returns the number of '\n' bytes in b.
func countLines(b []byte) int { return bytes.Count(b, []byte("\n")) }

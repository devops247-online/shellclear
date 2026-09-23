// Package cleaner masks or removes secrets in history files without ever
// leaving a file half-written or silently dropping commands a shell appended
// meanwhile.
package cleaner

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/devops247-online/shellclear/internal/history"
	"github.com/devops247-online/shellclear/internal/rules"
	"github.com/devops247-online/shellclear/internal/safefile"
	"github.com/devops247-online/shellclear/internal/scan"
	"github.com/devops247-online/shellclear/internal/state"
)

// Mode selects what happens to a command that contains a secret.
type Mode int

// Modes.
const (
	Mask   Mode = iota // replace each secret with [REDACTED:<rule_id>]
	Remove             // drop the whole record
)

// ErrChanged means the file was rewritten (not just appended to) between
// reading and writing. Nothing was written.
var ErrChanged = errors.New("history changed during operation, retry")

// Replacement returns the text that replaces a secret found by ruleID.
func Replacement(ruleID string) string { return "[REDACTED:" + ruleID + "]" }

// Change is one command that will be (or was) edited.
type Change struct {
	Finding scan.Finding
	After   string // command after masking; empty for Remove
}

// Plan is the computed result for one file. It holds no open handles.
type Plan struct {
	File    history.File
	Orig    []byte
	New     []byte
	Changes []Change
	Skipped []scan.Finding // commands that could not be edited safely
}

// Cleaner builds and applies plans.
type Cleaner struct {
	Scanner     *scan.Scanner
	Mode        Mode
	State       state.Dir
	Backup      bool
	Now         func() time.Time
	LockTimeout time.Duration
}

func (c *Cleaner) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Cleaner) lockTimeout() time.Duration {
	if c.LockTimeout > 0 {
		return c.LockTimeout
	}
	return 10 * time.Second
}

// Plan reads f and computes its cleaned content.
func (c *Cleaner) Plan(f history.File) (*Plan, error) {
	res, err := c.Scanner.ScanFile(f)
	if err != nil {
		return nil, err
	}
	codec, err := history.CodecFor(f.Shell)
	if err != nil {
		return nil, err
	}
	newData, changes, skipped := c.edit(codec, res.Entries, res.Findings)
	return &Plan{File: f, Orig: res.Data, New: newData, Changes: changes, Skipped: skipped}, nil
}

// edit rewrites entries according to findings (whose Entry indexes refer to
// entries) and returns the concatenated result.
func (c *Cleaner) edit(codec history.Codec, entries []history.Entry, findings []scan.Finding) ([]byte, []Change, []scan.Finding) {
	byEntry := make(map[int]scan.Finding, len(findings))
	for _, f := range findings {
		byEntry[f.Entry] = f
	}
	var out bytes.Buffer
	var changes []Change
	var skipped []scan.Finding
	for i, e := range entries {
		f, ok := byEntry[i]
		if !ok {
			out.Write(e.Raw)
			continue
		}
		if c.Mode == Remove {
			changes = append(changes, Change{Finding: f})
			continue
		}
		raw, after, err := maskEntry(codec, e, f)
		if err != nil {
			skipped = append(skipped, f)
			out.Write(e.Raw)
			continue
		}
		out.Write(raw)
		changes = append(changes, Change{Finding: f, After: after})
	}
	return out.Bytes(), changes, skipped
}

// maskEntry replaces every secret of f in the record. Longer secrets go
// first so that a secret contained in another one cannot break it apart.
func maskEntry(codec history.Codec, e history.Entry, f scan.Finding) ([]byte, string, error) {
	ms := make([]rules.Match, len(f.Matches))
	copy(ms, f.Matches)
	sort.SliceStable(ms, func(i, j int) bool { return len(ms[i].Secret) > len(ms[j].Secret) })
	raw := e.Raw
	for _, m := range ms {
		var err error
		raw, err = codec.Replace(raw, m.Secret, Replacement(m.Rule.ID))
		if err != nil {
			return nil, "", err
		}
	}
	after := codec.Parse(raw)
	if len(after) != 1 {
		return nil, "", history.ErrUnsafeEdit
	}
	for _, m := range f.Matches {
		if bytes.Contains([]byte(after[0].Command), []byte(m.Secret)) {
			return nil, "", history.ErrUnsafeEdit
		}
	}
	return raw, after[0].Command, nil
}

// Outcome reports what Apply did.
type Outcome struct {
	Written     bool
	Backup      *state.Backup
	TailChanges []Change       // edits in commands appended while we worked
	TailSkipped []scan.Finding // appended commands that could not be edited
}

// Apply writes the plan following the safe write sequence:
//
//  1. resolve symlinks, so a link to the history file stays a link;
//  2. skip files whose content does not change;
//  3. take the shellclear lock and the shell's own history lock;
//  4. back up the original content (unless disabled);
//  5. re-read the file: if a shell appended to it, clean the new tail too;
//     if it was rewritten, abort without writing;
//  6. write a temporary file in the same directory with the original mode,
//     fsync it, rename it over the file and fsync the directory.
func (c *Cleaner) Apply(p *Plan) (Outcome, error) {
	var out Outcome
	if bytes.Equal(p.New, p.Orig) {
		return out, nil
	}
	target, err := filepath.EvalSymlinks(p.File.Path)
	if err != nil {
		return out, err
	}
	unlockState, err := c.State.Lock(c.lockTimeout())
	if err != nil {
		return out, err
	}
	defer unlockState()
	fh, unlockHist, err := safefile.LockHistory(target, p.File.Shell == history.Zsh, c.lockTimeout())
	if err != nil {
		return out, err
	}
	defer unlockHist()
	if fh == nil {
		return out, fmt.Errorf("%s: %w", p.File.Path, os.ErrNotExist)
	}
	fi, err := fh.Stat()
	if err != nil {
		return out, err
	}

	if c.Backup {
		b, err := c.State.CreateBackup(history.File{Path: p.File.Path, RealPath: target, Shell: p.File.Shell}, p.Orig, c.now())
		if err != nil {
			return out, err
		}
		out.Backup = &b
	}
	abort := func(err error) (Outcome, error) {
		if out.Backup != nil {
			_ = c.State.RemoveBackup(*out.Backup)
			out.Backup = nil
		}
		return out, err
	}

	cur, err := safefile.ReadAll(fh)
	if err != nil {
		return abort(err)
	}
	newData := p.New
	if !bytes.Equal(cur, p.Orig) {
		if !bytes.HasPrefix(cur, p.Orig) {
			return abort(ErrChanged)
		}
		tail, changes, skipped, err := c.editTail(p.File.Shell, cur, len(p.Orig))
		if err != nil {
			return abort(err)
		}
		newData = append(append([]byte(nil), p.New...), tail...)
		out.TailChanges, out.TailSkipped = changes, skipped
		if out.Backup != nil {
			b, err := c.State.AppendBackup(*out.Backup, cur[len(p.Orig):])
			if err != nil {
				return abort(err)
			}
			out.Backup = &b
		}
	}

	if err := safefile.WriteAtomic(target, newData, fi.Mode().Perm()); err != nil {
		return abort(err)
	}
	out.Written = true
	return out, nil
}

// editTail cleans the records that start at offset in cur. The appended data
// must begin on a record boundary of the whole file; otherwise it continues
// a record we already edited and the file counts as changed.
func (c *Cleaner) editTail(shell history.Shell, cur []byte, offset int) ([]byte, []Change, []scan.Finding, error) {
	codec, err := history.CodecFor(shell)
	if err != nil {
		return nil, nil, nil, err
	}
	entries := codec.Parse(cur)
	pos, k := 0, -1
	for i, e := range entries {
		if pos == offset {
			k = i
			break
		}
		pos += len(e.Raw)
	}
	if k < 0 {
		return nil, nil, nil, ErrChanged
	}
	tailEntries := entries[k:]
	findings := c.Scanner.ScanEntries(tailEntries)
	data, changes, skipped := c.edit(codec, tailEntries, findings)
	return data, changes, skipped, nil
}

package cleaner

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/devops247-online/shellclear/internal/history"
	"github.com/devops247-online/shellclear/internal/safefile"
	"github.com/devops247-online/shellclear/internal/state"
)

// Ops runs stash, pop and restore with the same locking as Apply.
type Ops struct {
	State       state.Dir
	Now         func() time.Time
	LockTimeout time.Duration
}

func (o *Ops) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o *Ops) timeout() time.Duration {
	if o.LockTimeout > 0 {
		return o.LockTimeout
	}
	return 10 * time.Second
}

// locked runs fn with the shellclear lock and the history lock held. fh is
// nil when the history file does not exist.
func (o *Ops) locked(f history.File, fn func(target string, fh *os.File) error) error {
	unlockState, err := o.State.Lock(o.timeout())
	if err != nil {
		return err
	}
	defer unlockState()
	target, err := filepath.EvalSymlinks(f.Path)
	if errors.Is(err, fs.ErrNotExist) {
		target = f.RealPath
	} else if err != nil {
		return err
	}
	fh, unlock, err := safefile.LockHistory(target, f.Shell == history.Zsh, o.timeout())
	if err != nil {
		return err
	}
	defer unlock()
	return fn(target, fh)
}

// StashResult reports a stash operation.
type StashResult struct {
	Stash state.Stash
	Empty bool // nothing to stash
}

// Stash moves the content of f into the state directory and truncates f.
// It refuses when f already has a stash.
func (o *Ops) Stash(f history.File) (StashResult, error) {
	var res StashResult
	err := o.locked(f, func(target string, fh *os.File) error {
		if fh == nil {
			return fmt.Errorf("%s: %w", f.Path, os.ErrNotExist)
		}
		if _, err := o.State.FindStash(f); err == nil {
			return state.ErrStashExists
		} else if !errors.Is(err, state.ErrNoStash) {
			return err
		}
		data, err := safefile.ReadAll(fh)
		if err != nil {
			return err
		}
		if len(data) == 0 {
			res.Empty = true
			return nil
		}
		s, err := o.State.CreateStash(history.File{Path: f.Path, RealPath: target, Shell: f.Shell}, data, o.now())
		if err != nil {
			return err
		}
		// Truncate in place (same inode) through the locked descriptor.
		if err := fh.Truncate(0); err != nil {
			_ = o.State.DropStash(s)
			return err
		}
		if err := fh.Sync(); err != nil {
			return err
		}
		res.Stash = s
		return nil
	})
	return res, err
}

// PopResult reports a pop operation.
type PopResult struct {
	Restored int64 // bytes taken from the stash
	Kept     int64 // bytes written to the history while it was stashed
}

// Pop writes stash + current content back to f and deletes the stash, so
// commands run while the history was stashed are kept. Concatenation is a
// valid history for every supported format; a newline is inserted only when
// the stash does not end with one.
func (o *Ops) Pop(f history.File) (PopResult, error) {
	var res PopResult
	err := o.locked(f, func(target string, fh *os.File) error {
		s, err := o.State.FindStash(f)
		if err != nil {
			return err
		}
		stashed, err := o.State.ReadStash(s)
		if err != nil {
			return err
		}
		var cur []byte
		perm := os.FileMode(0o600)
		if fh != nil {
			if cur, err = safefile.ReadAll(fh); err != nil {
				return err
			}
			fi, err := fh.Stat()
			if err != nil {
				return err
			}
			perm = fi.Mode().Perm()
		}
		data := append([]byte(nil), stashed...)
		if len(cur) > 0 && !bytes.HasSuffix(data, []byte("\n")) {
			data = append(data, '\n')
		}
		data = append(data, cur...)
		if err := safefile.WriteAtomic(target, data, perm); err != nil {
			return err
		}
		res = PopResult{Restored: int64(len(stashed)), Kept: int64(len(cur))}
		return o.State.DropStash(s)
	})
	return res, err
}

// RestoreResult reports a restore operation.
type RestoreResult struct {
	Target string
	Backup *state.Backup // backup of the content that was replaced
}

// Restore replaces the backup's source file with the backup content. The
// current content is backed up first.
func (o *Ops) Restore(b state.Backup) (RestoreResult, error) {
	data, err := o.State.ReadBackup(b)
	if err != nil {
		return RestoreResult{}, err
	}
	f := history.File{Path: b.Meta.Source, RealPath: b.Meta.Source, Shell: b.Meta.Shell}
	res := RestoreResult{Target: b.Meta.Source}
	err = o.locked(f, func(target string, fh *os.File) error {
		perm := os.FileMode(0o600)
		if fh != nil {
			cur, err := safefile.ReadAll(fh)
			if err != nil {
				return err
			}
			fi, err := fh.Stat()
			if err != nil {
				return err
			}
			perm = fi.Mode().Perm()
			if bytes.Equal(cur, data) {
				return nil
			}
			nb, err := o.State.CreateBackup(history.File{Path: target, RealPath: target, Shell: f.Shell}, cur, o.now())
			if err != nil {
				return err
			}
			res.Backup = &nb
		}
		res.Target = target
		return safefile.WriteAtomic(target, data, perm)
	})
	return res, err
}

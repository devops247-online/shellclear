// Package state manages the shellclear state directory: backups, stashes and
// the process lock.
//
//	<root>/backups/<shell>/<basename>.<YYYYMMDDTHHMMSS>[-N].bak (+ .json)
//	<root>/stash/<shell>/<basename>[.<hash>]                  (+ .json)
//	<root>/lock
//
// Directories are 0700 and files 0600 regardless of the umask.
package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/devops247-online/shellclear/internal/history"
	"github.com/devops247-online/shellclear/internal/safefile"
)

const (
	backupsDir = "backups"
	stashDir   = "stash"
	lockName   = "lock"
	sidecarExt = ".json"
	backupExt  = ".bak"
	stampFmt   = "20060102T150405"
	filePerm   = 0o600
)

// Errors reported to the user.
var (
	ErrStashExists = errors.New("a stash already exists; run 'shellclear pop' first")
	ErrNoStash     = errors.New("no stash found")
	ErrCorrupt     = errors.New("checksum mismatch")
)

// Dir is the state directory.
type Dir struct {
	Root string
}

// Meta is the sidecar stored next to every backup and stash.
type Meta struct {
	Source  string        `json:"source"`
	Shell   history.Shell `json:"shell"`
	Created time.Time     `json:"created"`
	SHA256  string        `json:"sha256"`
	Size    int64         `json:"size"`
}

// Backup describes one backup file.
type Backup struct {
	Name string // "<shell>/<file name>", as shown to the user
	Path string
	Meta Meta
}

// Ensure creates the root directory with mode 0700.
func (d Dir) Ensure() error {
	return safefile.MkdirPrivate(d.Root)
}

func (d Dir) sub(parts ...string) (string, error) {
	if err := d.Ensure(); err != nil {
		return "", err
	}
	p := d.Root
	for _, part := range parts {
		p = filepath.Join(p, part)
		if err := safefile.MkdirPrivate(p); err != nil {
			return "", err
		}
	}
	return p, nil
}

// Lock prevents two shellclear processes from changing files at once.
func (d Dir) Lock(timeout time.Duration) (safefile.Unlock, error) {
	if err := d.Ensure(); err != nil {
		return nil, err
	}
	p := filepath.Join(d.Root, lockName)
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, filePerm)
	if err != nil {
		return nil, err
	}
	_ = f.Close()
	_, unlock, err := safefile.LockFile(p, timeout)
	if err != nil {
		return nil, fmt.Errorf("another shellclear is running: %w", err)
	}
	return unlock, nil
}

func newMeta(f history.File, data []byte, now time.Time) Meta {
	sum := sha256.Sum256(data)
	return Meta{Source: f.RealPath, Shell: f.Shell, Created: now, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
}

func writeMeta(path string, m Meta, replace bool) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if replace {
		return safefile.WriteAtomic(path, b, filePerm)
	}
	return safefile.WriteNew(path, b, filePerm)
}

func readMeta(path string) (Meta, error) {
	var m Meta
	b, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

// readVerified reads path and checks it against its metadata.
func readVerified(path string, m Meta) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != m.SHA256 || int64(len(data)) != m.Size {
		return nil, fmt.Errorf("%s: %w", path, ErrCorrupt)
	}
	return data, nil
}

// CreateBackup stores data as a new backup of f.
func (d Dir) CreateBackup(f history.File, data []byte, now time.Time) (Backup, error) {
	dir, err := d.sub(backupsDir, string(f.Shell))
	if err != nil {
		return Backup{}, err
	}
	base := filepath.Base(f.RealPath) + "." + now.Format(stampFmt)
	for n := 0; ; n++ {
		name := base
		if n > 0 {
			name += "-" + strconv.Itoa(n)
		}
		p := filepath.Join(dir, name+backupExt)
		err := safefile.WriteNew(p, data, filePerm)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return Backup{}, fmt.Errorf("write backup: %w", err)
		}
		m := newMeta(f, data, now)
		if err := writeMeta(p+sidecarExt, m, false); err != nil {
			_ = os.Remove(p)
			return Backup{}, fmt.Errorf("write backup metadata: %w", err)
		}
		return Backup{Name: string(f.Shell) + "/" + filepath.Base(p), Path: p, Meta: m}, nil
	}
}

// AppendBackup adds tail to an existing backup and updates its metadata.
func (d Dir) AppendBackup(b Backup, tail []byte) (Backup, error) {
	f, err := os.OpenFile(b.Path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return b, err
	}
	if _, err := f.Write(tail); err != nil {
		_ = f.Close()
		return b, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return b, err
	}
	if err := f.Close(); err != nil {
		return b, err
	}
	data, err := os.ReadFile(b.Path)
	if err != nil {
		return b, err
	}
	m := newMeta(history.File{RealPath: b.Meta.Source, Shell: b.Meta.Shell}, data, b.Meta.Created)
	if err := writeMeta(b.Path+sidecarExt, m, true); err != nil {
		return b, err
	}
	b.Meta = m
	return b, nil
}

// RemoveBackup deletes a backup and its metadata.
func (d Dir) RemoveBackup(b Backup) error {
	err1 := os.Remove(b.Path)
	err2 := os.Remove(b.Path + sidecarExt)
	return errors.Join(ignoreMissing(err1), ignoreMissing(err2))
}

func ignoreMissing(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// Backups lists backups, newest first.
func (d Dir) Backups() ([]Backup, error) {
	paths, err := filepath.Glob(filepath.Join(d.Root, backupsDir, "*", "*"+backupExt))
	if err != nil {
		return nil, err
	}
	var out []Backup
	for _, p := range paths {
		m, err := readMeta(p + sidecarExt)
		if err != nil {
			continue // not ours or incomplete
		}
		shell := filepath.Base(filepath.Dir(p))
		out = append(out, Backup{Name: shell + "/" + filepath.Base(p), Path: p, Meta: m})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].Meta.Created.Equal(out[j].Meta.Created) {
			return out[i].Meta.Created.After(out[j].Meta.Created)
		}
		return backupSeq(out[i].Path) > backupSeq(out[j].Path)
	})
	return out, nil
}

// backupSeq returns N for "<name>.<stamp>-N.bak" and 0 without a suffix.
func backupSeq(path string) int {
	name := strings.TrimSuffix(filepath.Base(path), backupExt)
	i := strings.LastIndexByte(name, '-')
	if i < 0 {
		return 0
	}
	n, err := strconv.Atoi(name[i+1:])
	if err != nil {
		return 0
	}
	return n
}

// ResolveBackup finds a backup by its listed name ("zsh/.zsh_history.….bak")
// or by its file name when that is unique. Paths are never used directly.
func (d Dir) ResolveBackup(name string) (Backup, error) {
	if name == "" || strings.Contains(name, "..") || filepath.IsAbs(name) || strings.Contains(name, `\`) {
		return Backup{}, fmt.Errorf("invalid backup name %q", name)
	}
	all, err := d.Backups()
	if err != nil {
		return Backup{}, err
	}
	var found []Backup
	for _, b := range all {
		if b.Name == name || filepath.Base(b.Path) == name {
			found = append(found, b)
		}
	}
	switch len(found) {
	case 0:
		return Backup{}, fmt.Errorf("no backup named %q; run 'shellclear restore' to list them", name)
	case 1:
		return found[0], nil
	}
	return Backup{}, fmt.Errorf("backup name %q is ambiguous; use the <shell>/<file> form", name)
}

// ReadBackup returns the backup content after checking its checksum.
func (d Dir) ReadBackup(b Backup) ([]byte, error) { return readVerified(b.Path, b.Meta) }

// Prune keeps the newest keep backups per source file and deletes the rest.
func (d Dir) Prune(keep int) ([]Backup, error) {
	all, err := d.Backups()
	if err != nil {
		return nil, err
	}
	count := map[string]int{}
	var removed []Backup
	for _, b := range all {
		count[b.Meta.Source]++
		if count[b.Meta.Source] <= keep {
			continue
		}
		if err := d.RemoveBackup(b); err != nil {
			return removed, err
		}
		removed = append(removed, b)
	}
	return removed, nil
}

// Stash describes a stashed history file.
type Stash struct {
	Path string
	Meta Meta
}

// stashPath returns where f is (or would be) stashed. Two files with the same
// base name get distinct stash names by a hash of the source path.
func (d Dir) stashPath(f history.File) (string, error) {
	dir, err := d.sub(stashDir, string(f.Shell))
	if err != nil {
		return "", err
	}
	plain := filepath.Join(dir, filepath.Base(f.RealPath))
	m, err := readMeta(plain + sidecarExt)
	if errors.Is(err, fs.ErrNotExist) || (err == nil && m.Source == f.RealPath) {
		return plain, nil
	}
	sum := sha256.Sum256([]byte(f.RealPath))
	return plain + "." + hex.EncodeToString(sum[:4]), nil
}

// FindStash returns the stash of f.
func (d Dir) FindStash(f history.File) (Stash, error) {
	p, err := d.stashPath(f)
	if err != nil {
		return Stash{}, err
	}
	m, err := readMeta(p + sidecarExt)
	if errors.Is(err, fs.ErrNotExist) {
		return Stash{}, ErrNoStash
	}
	if err != nil {
		return Stash{}, err
	}
	return Stash{Path: p, Meta: m}, nil
}

// CreateStash stores data as the stash of f. It fails with ErrStashExists
// when f already has one.
func (d Dir) CreateStash(f history.File, data []byte, now time.Time) (Stash, error) {
	p, err := d.stashPath(f)
	if err != nil {
		return Stash{}, err
	}
	if _, err := os.Lstat(p + sidecarExt); err == nil {
		return Stash{}, ErrStashExists
	}
	if err := safefile.WriteNew(p, data, filePerm); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return Stash{}, ErrStashExists
		}
		return Stash{}, err
	}
	m := newMeta(f, data, now)
	if err := writeMeta(p+sidecarExt, m, false); err != nil {
		_ = os.Remove(p)
		return Stash{}, err
	}
	return Stash{Path: p, Meta: m}, nil
}

// ReadStash returns the stash content after checking its checksum.
func (d Dir) ReadStash(s Stash) ([]byte, error) { return readVerified(s.Path, s.Meta) }

// DropStash deletes a stash and its metadata.
func (d Dir) DropStash(s Stash) error {
	return errors.Join(ignoreMissing(os.Remove(s.Path)), ignoreMissing(os.Remove(s.Path+sidecarExt)))
}

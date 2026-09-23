// Package safefile writes files atomically and coordinates with shells that
// write the same history file.
package safefile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

// WriteAtomic replaces path with data. The data goes to a temporary file in
// the same directory, which is synced, given perm, and renamed over path;
// then the directory is synced. path must not be a symlink: callers resolve
// symlinks first so the link itself is preserved.
func WriteAtomic(path string, data []byte, perm fs.FileMode) (err error) {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, "."+base+".shellclear-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err = tmp.Chmod(perm); err != nil {
		return fmt.Errorf("chmod temporary file: %w", err)
	}
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return SyncDir(dir)
}

// WriteNew creates path with data and perm. It fails if path exists. The
// file is synced before returning. perm is applied explicitly so the umask
// cannot widen it.
func WriteNew(path string, data []byte, perm fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(path))
}

// MkdirPrivate creates dir and its parents with mode 0700 and makes sure the
// final directory has exactly that mode.
func MkdirPrivate(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if fi.Mode().Perm() != 0o700 {
		return os.Chmod(dir, 0o700)
	}
	return nil
}

// SyncDir flushes directory metadata (the rename) to disk. It is a no-op on
// Windows, where directories cannot be opened for syncing.
func SyncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return fmt.Errorf("sync directory %s: %w", dir, err)
	}
	return nil
}

// ErrLocked means another process holds a lock for longer than we waited.
var ErrLocked = errors.New("locked by another process")

// Unlock releases a lock.
type Unlock func()

// staleLockAge mirrors zsh: a .LOCK older than this is considered stale.
const staleLockAge = 10 * time.Second

// LockZshHistory takes the lock zsh uses for $HISTFILE (see lockhistfile in
// zsh Src/hist.c): a symlink named <path>.LOCK pointing to
// "/pid-<pid>/host-<host>". A lock older than 10 seconds is removed, as zsh
// does. It waits up to timeout.
func LockZshHistory(path string, timeout time.Duration) (Unlock, error) {
	lockfile := path + ".LOCK"
	host, _ := os.Hostname()
	target := "/pid-" + strconv.Itoa(os.Getpid()) + "/host-" + host
	deadline := time.Now().Add(timeout)
	sleep := 20 * time.Millisecond
	for {
		err := os.Symlink(target, lockfile)
		if err == nil {
			return func() { _ = os.Remove(lockfile) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("lock %s: %w", lockfile, err)
		}
		if fi, err := os.Lstat(lockfile); err == nil && time.Since(fi.ModTime()) > staleLockAge {
			_ = os.Remove(lockfile)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%s: %w (a running zsh is writing history; try again)", lockfile, ErrLocked)
		}
		time.Sleep(sleep)
		if sleep < 200*time.Millisecond {
			sleep *= 2
		}
	}
}

// LockFile takes an exclusive advisory lock (fcntl on Unix) on path, which
// must exist, and returns the locked file opened for reading. zsh with
// HIST_FCNTL_LOCK uses the same kind of lock.
//
// POSIX drops every fcntl lock a process holds on a file as soon as the
// process closes any descriptor of that file, so while the lock is held the
// caller must read the file only through the returned *os.File.
func LockFile(path string, timeout time.Duration) (*os.File, Unlock, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		ok, err := tryLock(f)
		if err != nil {
			_ = f.Close()
			return nil, nil, fmt.Errorf("lock %s: %w", path, err)
		}
		if ok {
			return f, func() { unlock(f); _ = f.Close() }, nil
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, nil, fmt.Errorf("%s: %w", path, ErrLocked)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// ReadAll reads f from the beginning.
func ReadAll(f *os.File) ([]byte, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}

// LockHistory locks a history file for a read-modify-write cycle: the zsh
// .LOCK symlink when zsh is true, then an fcntl lock on the file itself. It
// returns the locked file for reading, or nil when path does not exist.
func LockHistory(path string, zsh bool, timeout time.Duration) (*os.File, Unlock, error) {
	var unlockZsh Unlock = func() {}
	if zsh {
		u, err := LockZshHistory(path, timeout)
		if err != nil {
			return nil, nil, err
		}
		unlockZsh = u
	}
	f, unlockFile, err := LockFile(path, timeout)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, unlockZsh, nil
	}
	if err != nil {
		unlockZsh()
		return nil, nil, err
	}
	return f, func() { unlockFile(); unlockZsh() }, nil
}

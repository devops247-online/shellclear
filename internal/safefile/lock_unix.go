//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package safefile

import (
	"errors"
	"os"
	"syscall"
)

func tryLock(f *os.File) (bool, error) {
	lk := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &lk)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EACCES) {
		return false, nil
	}
	return false, err
}

func unlock(f *os.File) {
	lk := syscall.Flock_t{Type: syscall.F_UNLCK}
	_ = syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &lk)
}

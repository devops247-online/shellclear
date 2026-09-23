//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package safefile

import "syscall"

func umask(m int) int { return syscall.Umask(m) }

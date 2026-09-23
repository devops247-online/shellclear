//go:build !(darwin || linux || freebsd || netbsd || openbsd || dragonfly)

package safefile

func umask(m int) int { return m }

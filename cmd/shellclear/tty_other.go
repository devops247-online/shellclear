//go:build !(darwin || linux || freebsd || netbsd || openbsd || dragonfly)

package main

import "os"

// isTerminal falls back to the character-device check where termios is not
// available.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

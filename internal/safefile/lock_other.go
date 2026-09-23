//go:build !(darwin || linux || freebsd || netbsd || openbsd || dragonfly)

package safefile

import "os"

// Advisory locks are not used on this platform; PowerShell does not lock its
// history file either.
func tryLock(*os.File) (bool, error) { return true, nil }

func unlock(*os.File) {}

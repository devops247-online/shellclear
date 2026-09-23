//go:build !(darwin || linux || freebsd || netbsd || openbsd || dragonfly)

package motd

import "io/fs"

func fileID(fs.FileInfo) string { return "" }

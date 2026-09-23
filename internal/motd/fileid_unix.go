//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package motd

import (
	"io/fs"
	"strconv"
	"syscall"
)

// fileID identifies the inode, so an atomic replacement is always noticed.
func fileID(fi fs.FileInfo) string {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return strconv.FormatUint(uint64(st.Dev), 10) + ":" + strconv.FormatUint(st.Ino, 10)
}

//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package motd

import (
	"fmt"
	"io/fs"
	"syscall"
)

// fileID identifies the inode, so an atomic replacement is always noticed.
// Stat_t field types differ between platforms, so they are formatted rather
// than converted.
func fileID(fi fs.FileInfo) string {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino)
}

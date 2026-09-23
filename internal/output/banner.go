package output

import (
	"fmt"
	"io"
	"strings"
)

var bannerLines = []string{
	`     _          _ _      _`,
	` ___| |__   ___| | | ___| | ___  __ _ _ __`,
	`/ __| '_ \ / _ \ | |/ __| |/ _ \/ _` + "`" + ` | '__|`,
	`\__ \ | | |  __/ | | (__| |  __/ (_| | |`,
	`|___/_| |_|\___|_|_|\___|_|\___|\__,_|_|`,
}

// bannerGradient is a 256-color ramp from cyan to violet, one per line.
var bannerGradient = []int{51, 45, 39, 69, 99}

// Banner writes the logo with the version on its last line. With color on,
// each line gets the next color of a cyan-to-violet gradient.
func Banner(w io.Writer, version string, color bool) error {
	var b strings.Builder
	b.WriteByte('\n')
	for i, line := range bannerLines {
		if color {
			fmt.Fprintf(&b, "\x1b[1;38;5;%dm%s\x1b[0m", bannerGradient[i], line)
		} else {
			b.WriteString(line)
		}
		if i == len(bannerLines)-1 {
			if color {
				fmt.Fprintf(&b, " \x1b[2m%s\x1b[0m", version)
			} else {
				b.WriteString(" " + version)
			}
		}
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	_, err := io.WriteString(w, b.String())
	return err
}

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

// Colors of the Ukrainian flag in the 256-color palette: blue 25 (#005FAF,
// the closest to #0057B7) and yellow 220 (#FFD700).
const (
	flagBlue   = 25
	flagYellow = 220
)

// bannerColors paints the upper half of the letters blue and the lower half
// yellow, like the flag.
var bannerColors = []int{flagBlue, flagBlue, flagBlue, flagYellow, flagYellow}

// Banner writes the logo with the version on its last line. With color on,
// the logo is drawn in the colors of the Ukrainian flag.
func Banner(w io.Writer, version string, color bool) error {
	var b strings.Builder
	b.WriteByte('\n')
	for i, line := range bannerLines {
		if color {
			fmt.Fprintf(&b, "\x1b[1;38;5;%dm%s\x1b[0m", bannerColors[i], line)
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

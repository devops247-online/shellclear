// Command shellclear finds and removes secrets from shell history files.
package main

import (
	"os"
)

// Set at build time with -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "dev"
	commit  = "none"
)

func main() {
	app, err := newOSApp()
	if err != nil {
		os.Stderr.WriteString("shellclear: " + err.Error() + "\n")
		os.Exit(exitError)
	}
	os.Exit(app.Run(os.Args[1:]))
}

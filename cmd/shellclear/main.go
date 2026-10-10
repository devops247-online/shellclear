// Command shellclear finds and removes secrets from shell history files.
package main

import (
	"os"
	"runtime/debug"
)

// Set at build time with -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "dev"
	commit  = "none"
)

func main() {
	// A scan allocates freely and lives for a second at most; collecting
	// half as often saves 10-15% of the time of a large scan for a few dozen
	// MB more peak memory. GOGC still decides when it is set.
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(200)
	}
	app, err := newOSApp()
	if err != nil {
		os.Stderr.WriteString("shellclear: " + err.Error() + "\n")
		os.Exit(exitError)
	}
	os.Exit(app.Run(os.Args[1:]))
}

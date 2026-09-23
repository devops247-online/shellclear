package main

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/devops247-online/shellclear/internal/config"
	"github.com/devops247-online/shellclear/internal/history"
	"github.com/devops247-online/shellclear/internal/motd"
	"github.com/devops247-online/shellclear/internal/scan"
)

const configUsage = `Usage:
  shellclear config init [--import-legacy]   create config.yaml and rules.d/ (never overwrites)
  shellclear config validate                 check config.yaml and every rules.d/*.yaml
  shellclear config path                     print the config directory
`

func (a *App) cmdConfig(g *globals, args []string) (int, error) {
	if len(args) == 0 {
		return exitError, usageError{"config: missing subcommand (init, validate or path)"}
	}
	sub, rest := args[0], args[1:]
	var dir string
	switch sub {
	case "-h", "--help", "help":
		fmt.Fprint(a.Stdout, configUsage)
		return exitOK, nil
	case "path":
		if help, err := parseCommand("config path", g, rest, func(*flag.FlagSet) {}, a.Stdout); help || err != nil {
			return exitOK, err
		}
		fmt.Fprintln(a.Stdout, config.Dir(g.configDir, a.Env.Getenv, a.Env.Home))
		return exitOK, nil
	case "init":
		var legacy bool
		help, err := parseCommand("config init", g, rest, func(fs *flag.FlagSet) {
			fs.BoolVar(&legacy, "import-legacy", false, "import ~/shellclear/sensitive-patterns.yaml and ignores.yaml from the original shellclear")
		}, a.Stdout)
		if help || err != nil {
			return exitOK, err
		}
		dir = config.Dir(g.configDir, a.Env.Getenv, a.Env.Home)
		res, err := config.Init(dir, a.Env.Home, legacy)
		if err != nil {
			return exitError, err
		}
		for _, p := range res.Created {
			fmt.Fprintf(a.Stdout, "created  %s\n", displayPath(p, a.Env.Home))
		}
		for _, p := range res.Existing {
			fmt.Fprintf(a.Stdout, "exists   %s (left unchanged)\n", displayPath(p, a.Env.Home))
		}
		for _, p := range res.Imported {
			fmt.Fprintf(a.Stdout, "imported %s\n", displayPath(p, a.Env.Home))
		}
		if legacy && len(res.Imported) == 0 {
			fmt.Fprintf(a.Stdout, "nothing to import from %s\n", displayPath(config.LegacyDir(a.Env.Home), a.Env.Home))
		}
		return exitOK, nil
	case "validate":
		if help, err := parseCommand("config validate", g, rest, func(*flag.FlagSet) {}, a.Stdout); help || err != nil {
			return exitOK, err
		}
		dir = config.Dir(g.configDir, a.Env.Getenv, a.Env.Home)
		cfg, errs := config.Validate(dir)
		for _, e := range errs {
			fmt.Fprintf(a.Stderr, "shellclear: %v\n", e)
		}
		if len(errs) > 0 {
			return exitError, nil
		}
		custom := 0
		for _, l := range cfg.CustomRules {
			custom += len(l)
		}
		fmt.Fprintf(a.Stdout, "%s: OK (%d custom %s in %d %s, %d ignored, %d allow %s)\n",
			displayPath(dir, a.Env.Home), custom, pluralize(custom, "rule", "rules"),
			len(cfg.CustomRules), pluralize(len(cfg.CustomRules), "file", "files"), len(cfg.Ignore),
			len(cfg.Allow), pluralize(len(cfg.Allow), "pattern", "patterns"))
		return exitOK, nil
	}
	return exitError, usageError{fmt.Sprintf("config: unknown subcommand %q", sub)}
}

// cmdMotd prints a one-line reminder when history contains secrets. It never
// fails: problems are reported only with --verbose, and the exit code is 0,
// so a shell start-up file cannot break.
func (a *App) cmdMotd(g *globals, args []string, w io.Writer, isTTY bool) int {
	if help, err := parseCommand("motd", g, args, func(*flag.FlagSet) {}, a.Stdout); help || err != nil {
		if err != nil {
			a.verbosef(g, "motd: %v", err)
		}
		return exitOK
	}
	start := time.Now()
	dir := config.Dir(g.configDir, a.Env.Getenv, a.Env.Home)
	cfg, err := config.Load(dir)
	if err != nil {
		a.verbosef(g, "motd: %v", err)
		return exitOK
	}
	set, err := cfg.RuleSet()
	if err != nil {
		a.verbosef(g, "motd: %v", err)
		return exitOK
	}
	var shell history.Shell
	if g.shell != "" {
		if shell, err = history.ParseShell(g.shell); err != nil {
			a.verbosef(g, "motd: %v", err)
			return exitOK
		}
	}
	files, err := detectFiles(a.Env, g, shell)
	if err != nil {
		a.verbosef(g, "motd: %v", err)
		return exitOK
	}
	checker := &motd.Checker{
		Scanner:   &scan.Scanner{Rules: set, Allow: cfg.Allow},
		StateDir:  dir,
		RulesHash: motd.RulesHash(version, set, cfg.AllowRaw),
	}
	n, st, err := checker.Count(files)
	if err != nil {
		a.verbosef(g, "motd: %v", err)
		return exitOK
	}
	a.verbosef(g, "motd: %d files (cached %d, incremental %d, full %d) in %s",
		len(files), st.Hits, st.Incremental, st.Full, time.Since(start).Round(time.Microsecond))
	if n == 0 {
		return exitOK
	}
	yellow, reset := "", ""
	if isTTY && !g.noColor && a.Env.Getenv("NO_COLOR") == "" {
		yellow, reset = "\x1b[1;33m", "\x1b[0m"
	}
	findCmd := "shellclear find"
	if g.ai {
		findCmd += " --ai"
	}
	fmt.Fprintf(w, "%s⚠ shellclear: %d sensitive %s found in history — run '%s'%s\n",
		yellow, n, pluralize(n, "command", "commands"), findCmd, reset)
	return exitOK
}

// invalidateCache drops the motd cache after history files were rewritten.
func (a *App) invalidateCache(g *globals) {
	motd.Invalidate(config.Dir(g.configDir, a.Env.Getenv, a.Env.Home))
}

// legacyHint points users of the original tool at the import command.
func (a *App) legacyHint(g *globals) {
	dir := config.Dir(g.configDir, a.Env.Getenv, a.Env.Home)
	if !config.HasLegacy(a.Env.Home) {
		return
	}
	if _, err := a.Env.Stat(filepath.Join(dir, config.FileName)); err == nil {
		return
	}
	fmt.Fprintf(a.Stderr, "shellclear: note: custom files of the original shellclear found in %s; import them with 'shellclear config init --import-legacy'\n",
		displayPath(config.LegacyDir(a.Env.Home), a.Env.Home))
}

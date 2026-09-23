package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/devops247-online/shellclear/internal/cleaner"
	"github.com/devops247-online/shellclear/internal/config"
	"github.com/devops247-online/shellclear/internal/history"
	"github.com/devops247-online/shellclear/internal/output"
	"github.com/devops247-online/shellclear/internal/scan"
	"github.com/devops247-online/shellclear/internal/state"
)

// errSecretsRemain makes clear exit with 1 when some commands could not be
// edited safely.
var errSecretsRemain = errors.New("some secrets could not be removed")

func (a *App) stateDir(g *globals) state.Dir {
	return state.Dir{Root: config.Dir(g.configDir, a.Env.Getenv, a.Env.Home)}
}

// restartHints tells the user how to stop running shells from writing the
// old history back from memory.
var restartHints = map[history.Shell]string{
	history.Zsh:        "zsh: run 'exec zsh' in every open terminal",
	history.Bash:       "bash: run 'history -c; history -r' in every open terminal",
	history.Fish:       "fish: run 'history merge' in every open terminal",
	history.PowerShell: "PowerShell: restart open sessions",
}

// memoryHints clears the in-memory history of the current shell after stash.
var memoryHints = map[history.Shell]string{
	history.Zsh:        "zsh: fc -p",
	history.Bash:       "bash: history -c",
	history.Fish:       "fish: history clear-session",
	history.PowerShell: "PowerShell: [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()",
}

func sortedShells(set map[history.Shell]bool) []history.Shell {
	var out []history.Shell
	for s := range set {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (a *App) confirm(question string) (bool, error) {
	if !a.StdinIsTTY {
		return false, usageError{"stdin is not a terminal; pass --yes to confirm"}
	}
	fmt.Fprintf(a.Stdout, "%s [y/N] ", question)
	line, err := bufio.NewReader(a.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

func (a *App) cmdClear(g *globals, args []string) (int, error) {
	var remove, dryRun, noBackup, yes bool
	help, err := parseCommand("clear", g, args, func(fs *flag.FlagSet) {
		fs.BoolVar(&remove, "remove", false, "remove whole commands instead of masking the secrets")
		fs.BoolVar(&dryRun, "dry-run", false, "show what would change and write nothing")
		fs.BoolVar(&noBackup, "no-backup", false, "do not back up history files before changing them")
		fs.BoolVar(&yes, "yes", false, "do not ask for confirmation")
		fs.BoolVar(&yes, "y", false, "shorthand for --yes")
	}, a.Stdout)
	if help || err != nil {
		return exitOK, err
	}
	cfg, set, err := a.loadConfig(g)
	if err != nil {
		return exitError, err
	}
	files, err := a.detect(g)
	if err != nil {
		return exitError, err
	}
	mode, verb := cleaner.Mask, "mask"
	if remove {
		mode, verb = cleaner.Remove, "remove"
	}
	cl := &cleaner.Cleaner{
		Scanner: &scan.Scanner{Rules: set, Allow: cfg.Allow},
		Mode:    mode, State: a.stateDir(g), Backup: !noBackup, Now: a.Now,
	}

	var plans []*cleaner.Plan
	total := 0
	for _, f := range files {
		p, err := cl.Plan(f)
		if err != nil {
			return exitError, err
		}
		if len(p.Changes) == 0 && len(p.Skipped) == 0 {
			continue
		}
		plans = append(plans, p)
		total += len(p.Changes)
	}
	home := a.Env.Home
	if len(plans) == 0 {
		fmt.Fprintf(a.Stdout, "No secrets found in %d history %s.\n", len(files), pluralize(len(files), "file", "files"))
		return exitOK, nil
	}

	for _, p := range plans {
		fmt.Fprintf(a.Stdout, "%s (%s): %d %s to %s\n", displayPath(p.File.Path, home), p.File.Shell,
			len(p.Changes), pluralize(len(p.Changes), "command", "commands"), verb)
		if dryRun {
			for _, c := range p.Changes {
				fmt.Fprintf(a.Stdout, "  L%-6d %s\n", c.Finding.Line, strings.Join(ruleIDs(c.Finding), ","))
				fmt.Fprintf(a.Stdout, "    - %s\n", output.MaskCommand(c.Finding.Command, c.Finding.Matches))
				if mode == cleaner.Mask {
					fmt.Fprintf(a.Stdout, "    + %s\n", output.Sanitize(c.After))
				} else {
					fmt.Fprintf(a.Stdout, "    + (removed)\n")
				}
			}
		}
		for _, s := range p.Skipped {
			fmt.Fprintf(a.Stderr, "shellclear: warning: %s line %d cannot be edited safely and will be left as is\n", displayPath(p.File.Path, home), s.Line)
		}
	}
	if dryRun {
		fmt.Fprintln(a.Stdout, "Dry run: nothing was written.")
		return exitOK, nil
	}
	if total == 0 {
		return exitFindings, errSecretsRemain
	}
	if !yes {
		ok, err := a.confirm(fmt.Sprintf("%s %d %s?", capitalize(verb), total, pluralize(total, "command", "commands")))
		if err != nil {
			return exitError, err
		}
		if !ok {
			fmt.Fprintln(a.Stdout, "Aborted; nothing was written.")
			return exitOK, nil
		}
	}

	touched := map[history.Shell]bool{}
	remaining := 0
	for _, p := range plans {
		out, err := cl.Apply(p)
		if err != nil {
			return exitError, fmt.Errorf("%s: %w", displayPath(p.File.Path, home), err)
		}
		n := len(p.Changes) + len(out.TailChanges)
		remaining += len(p.Skipped) + len(out.TailSkipped)
		if !out.Written {
			continue
		}
		touched[p.File.Shell] = true
		past := map[cleaner.Mode]string{cleaner.Mask: "masked", cleaner.Remove: "removed"}[mode]
		fmt.Fprintf(a.Stdout, "%s: %s %d %s", displayPath(p.File.Path, home), past, n, pluralize(n, "command", "commands"))
		if len(out.TailChanges) > 0 {
			fmt.Fprintf(a.Stdout, " (%d appended while running)", len(out.TailChanges))
		}
		fmt.Fprintln(a.Stdout)
		if out.Backup != nil {
			fmt.Fprintf(a.Stdout, "  backup: %s\n", out.Backup.Name)
		}
	}
	if len(touched) > 0 {
		fmt.Fprintln(a.Stdout, "\nRunning shells keep the old history in memory and may write it back:")
		for _, s := range sortedShells(touched) {
			fmt.Fprintf(a.Stdout, "  %s\n", restartHints[s])
		}
		if !noBackup {
			fmt.Fprintln(a.Stdout, "Backups still contain the secrets; delete them with 'shellclear restore --prune --keep 0'.")
		}
	}
	if remaining > 0 {
		return exitFindings, errSecretsRemain
	}
	return exitOK, nil
}

func (a *App) ops(g *globals) *cleaner.Ops {
	return &cleaner.Ops{State: a.stateDir(g), Now: a.Now}
}

func (a *App) cmdStash(g *globals, args []string) (int, error) {
	help, err := parseCommand("stash", g, args, func(*flag.FlagSet) {}, a.Stdout)
	if help || err != nil {
		return exitOK, err
	}
	files, err := a.detect(g)
	if err != nil {
		return exitError, err
	}
	ops := a.ops(g)
	// Check every file first, so a conflict on the second file does not
	// leave the first one stashed.
	st := a.stateDir(g)
	for _, f := range files {
		if _, err := st.FindStash(f); err == nil {
			return exitError, fmt.Errorf("%s: %w", displayPath(f.Path, a.Env.Home), state.ErrStashExists)
		}
	}
	shells := map[history.Shell]bool{}
	for _, f := range files {
		res, err := ops.Stash(f)
		if err != nil {
			return exitError, fmt.Errorf("%s: %w", displayPath(f.Path, a.Env.Home), err)
		}
		if res.Empty {
			fmt.Fprintf(a.Stdout, "%s: empty, nothing to stash\n", displayPath(f.Path, a.Env.Home))
			continue
		}
		shells[f.Shell] = true
		fmt.Fprintf(a.Stdout, "%s: stashed %d bytes\n", displayPath(f.Path, a.Env.Home), res.Stash.Meta.Size)
	}
	if len(shells) > 0 {
		fmt.Fprintln(a.Stdout, "\nThe current shell still remembers its history. Clear it in memory:")
		for _, s := range sortedShells(shells) {
			fmt.Fprintf(a.Stdout, "  %s\n", memoryHints[s])
		}
		fmt.Fprintln(a.Stdout, "Run 'shellclear pop' to bring the history back.")
	}
	return exitOK, nil
}

func (a *App) cmdPop(g *globals, args []string) (int, error) {
	help, err := parseCommand("pop", g, args, func(*flag.FlagSet) {}, a.Stdout)
	if help || err != nil {
		return exitOK, err
	}
	files, err := a.detect(g)
	if err != nil {
		return exitError, err
	}
	ops := a.ops(g)
	popped := 0
	for _, f := range files {
		res, err := ops.Pop(f)
		if errors.Is(err, state.ErrNoStash) {
			continue
		}
		if err != nil {
			return exitError, fmt.Errorf("%s: %w", displayPath(f.Path, a.Env.Home), err)
		}
		popped++
		fmt.Fprintf(a.Stdout, "%s: restored %d bytes", displayPath(f.Path, a.Env.Home), res.Restored)
		if res.Kept > 0 {
			fmt.Fprintf(a.Stdout, ", kept %d bytes written since stash", res.Kept)
		}
		fmt.Fprintln(a.Stdout)
	}
	if popped == 0 {
		fmt.Fprintln(a.Stdout, "No stash to pop.")
	}
	return exitOK, nil
}

func (a *App) cmdRestore(g *globals, args []string) (int, error) {
	var prune bool
	keep := -1
	var name string
	// restore takes an optional positional argument, so flags are parsed
	// around it by hand: "restore [flags] [BACKUP] [flags]".
	var flagArgs []string
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") && name == "" && !expectsValue(flagArgs) {
			name = arg
			continue
		}
		flagArgs = append(flagArgs, arg)
	}
	help, err := parseCommand("restore", g, flagArgs, func(fs *flag.FlagSet) {
		fs.BoolVar(&prune, "prune", false, "delete old backups instead of restoring")
		fs.IntVar(&keep, "keep", -1, "with --prune: backups to keep per history file (default from config.yaml)")
	}, a.Stdout)
	if help || err != nil {
		return exitOK, err
	}
	st := a.stateDir(g)

	if prune {
		if name != "" {
			return exitError, usageError{"restore: --prune takes no backup name"}
		}
		if keep < 0 {
			cfg, err := config.Load(st.Root)
			if err != nil {
				return exitError, err
			}
			if cfg.BackupsKeep == 0 {
				return exitError, usageError{"restore --prune: pass --keep N (config.yaml sets no backups.keep)"}
			}
			keep = cfg.BackupsKeep
		}
		removed, err := st.Prune(keep)
		if err != nil {
			return exitError, err
		}
		fmt.Fprintf(a.Stdout, "Deleted %d %s.\n", len(removed), pluralize(len(removed), "backup", "backups"))
		return exitOK, nil
	}

	if name == "" {
		list, err := st.Backups()
		if err != nil {
			return exitError, err
		}
		if len(list) == 0 {
			fmt.Fprintln(a.Stdout, "No backups.")
			return exitOK, nil
		}
		for _, b := range list {
			fmt.Fprintf(a.Stdout, "%s  %s  %s  %d bytes\n", b.Name, b.Meta.Created.In(a.loc()).Format("2006-01-02 15:04:05"),
				displayPath(b.Meta.Source, a.Env.Home), b.Meta.Size)
		}
		fmt.Fprintln(a.Stdout, "\nRun 'shellclear restore <name>' to restore one.")
		return exitOK, nil
	}

	b, err := st.ResolveBackup(name)
	if err != nil {
		return exitError, err
	}
	res, err := a.ops(g).Restore(b)
	if err != nil {
		return exitError, err
	}
	fmt.Fprintf(a.Stdout, "Restored %s from %s.\n", displayPath(res.Target, a.Env.Home), b.Name)
	if res.Backup != nil {
		fmt.Fprintf(a.Stdout, "  previous content backed up as %s\n", res.Backup.Name)
	}
	fmt.Fprintf(a.Stdout, "  %s\n", restartHints[b.Meta.Shell])
	return exitOK, nil
}

// expectsValue reports whether the last collected flag needs a value, so the
// next argument belongs to it.
func expectsValue(flagArgs []string) bool {
	if len(flagArgs) == 0 {
		return false
	}
	last := strings.TrimLeft(flagArgs[len(flagArgs)-1], "-")
	switch last {
	case "keep", "config-dir", "file", "shell":
		return true
	}
	return false
}

func (a *App) loc() *time.Location {
	if a.Location != nil {
		return a.Location
	}
	return time.Local
}

func ruleIDs(f scan.Finding) []string {
	seen := map[string]bool{}
	var ids []string
	for _, m := range f.Matches {
		if !seen[m.Rule.ID] {
			seen[m.Rule.ID] = true
			ids = append(ids, m.Rule.ID)
		}
	}
	return ids
}

func displayPath(p, home string) string {
	if home != "" && (p == home || strings.HasPrefix(p, home+"/")) {
		return "~" + p[len(home):]
	}
	return p
}

func pluralize(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

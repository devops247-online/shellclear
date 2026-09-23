package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/devops247-online/shellclear/internal/config"
	"github.com/devops247-online/shellclear/internal/history"
	"github.com/devops247-online/shellclear/internal/output"
	"github.com/devops247-online/shellclear/internal/rules"
	"github.com/devops247-online/shellclear/internal/scan"
)

// Exit codes.
const (
	exitOK       = 0
	exitFindings = 1
	exitError    = 2
)

// App holds everything the CLI touches, so tests can run it in isolation.
type App struct {
	Stdout, Stderr io.Writer
	Stdin          io.Reader
	Env            history.Env
	StdoutIsTTY    bool
	StdinIsTTY     bool
	StderrIsTTY    bool
	Location       *time.Location
	Now            func() time.Time // nil means time.Now
}

func newOSApp() (*App, error) {
	env, err := history.OSEnv()
	if err != nil {
		return nil, err
	}
	return &App{
		Stdout: os.Stdout, Stderr: os.Stderr, Stdin: os.Stdin,
		Env: env, StdoutIsTTY: isTerminal(os.Stdout), StdinIsTTY: isTerminal(os.Stdin), StderrIsTTY: isTerminal(os.Stderr), Location: time.Local,
	}, nil
}

// globals are flags accepted before or after the command name.
type globals struct {
	configDir string
	files     multiFlag
	shell     string
	ai        bool
	noColor   bool
	noBanner  bool
	initShell bool
	verbose   bool
	version   bool
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// register defines the global flags on fs. Current values become the
// defaults, so flags given before the command name survive when the command
// parses its own flag set.
func (g *globals) register(fs *flag.FlagSet) {
	fs.StringVar(&g.configDir, "config-dir", g.configDir, "config and state directory (default $SHELLCLEAR_HOME or ~/.shellclear)")
	fs.Var(&g.files, "file", "history file to use instead of auto-detection (repeatable)")
	fs.StringVar(&g.shell, "shell", g.shell, "format of --file: zsh, bash, fish, powershell or json")
	fs.BoolVar(&g.ai, "ai", g.ai, "also check chat histories of AI coding assistants (Claude Code, Codex, Gemini CLI, Qwen Code)")
	fs.BoolVar(&g.noColor, "no-color", g.noColor, "disable colors")
	fs.BoolVar(&g.noBanner, "no-banner", g.noBanner, "do not print the logo")
	fs.BoolVar(&g.initShell, "init-shell", g.initShell, "same as 'motd' but prints to stderr (compatible with the original shellclear)")
	fs.BoolVar(&g.verbose, "verbose", g.verbose, "print progress to stderr")
	fs.BoolVar(&g.verbose, "v", g.verbose, "shorthand for --verbose")
	fs.BoolVar(&g.version, "version", g.version, "print version and exit")
}

// usageError is reported with exit code 2 and a hint to run --help.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

const usageText = `shellclear finds secrets in shell history and removes them safely.

Usage:
  shellclear [global flags] <command> [flags]

Commands:
  find      list commands that contain secrets
  clear     mask secrets (or --remove whole commands); backs up first
  stash     move history aside before screen sharing
  pop       bring stashed history back, keeping commands run since
  restore   list backups, restore one, or --prune old ones
  rules     list active detection rules
  config    init, validate or print the config directory
  motd      one-line reminder for shell start-up; silent when history is clean

Global flags:
  --config-dir DIR   config and state directory (default: $SHELLCLEAR_HOME or ~/.shellclear)
  --file PATH        history file to use instead of auto-detection (repeatable)
  --shell NAME       format of --file: zsh, bash, fish, powershell or json
  --ai               also check chat histories of AI coding assistants
                     (Claude Code, Codex, Gemini CLI, Qwen Code)
  --no-color         disable colors (also honors NO_COLOR)
  --no-banner        do not print the logo
  --init-shell       same as 'motd', printed to stderr (original shellclear style)
  -v, --verbose      print progress to stderr
  --version          print version and exit

Exit codes:
  0  success, no secrets found
  1  find reported secrets
  2  error

Shell start-up reminder (prints nothing when history is clean):
  zsh:  echo 'shellclear motd' >> ~/.zshrc
  bash: echo 'shellclear motd' >> ~/.bashrc
  fish: echo 'shellclear motd' >> ~/.config/fish/config.fish

Run "shellclear <command> --help" for command flags.
`

// Run executes the CLI and returns the exit code.
func (a *App) Run(args []string) int {
	var g globals
	fs := flag.NewFlagSet("shellclear", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	g.register(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(a.Stdout, usageText)
			return exitOK
		}
		return a.fail(usageError{err.Error()})
	}
	if g.version {
		fmt.Fprintf(a.Stdout, "shellclear %s (%s)\n", version, commit)
		return exitOK
	}
	rest := fs.Args()
	if g.initShell {
		return a.cmdMotd(&g, rest, a.Stderr, a.StderrIsTTY)
	}
	if len(rest) == 0 {
		fmt.Fprint(a.Stderr, usageText)
		return exitError
	}

	var code int
	var err error
	switch rest[0] {
	case "find":
		code, err = a.cmdFind(&g, rest[1:])
	case "rules":
		code, err = a.cmdRules(&g, rest[1:])
	case "help":
		fmt.Fprint(a.Stdout, usageText)
		return exitOK
	case "clear":
		code, err = a.cmdClear(&g, rest[1:])
	case "stash":
		code, err = a.cmdStash(&g, rest[1:])
	case "pop":
		code, err = a.cmdPop(&g, rest[1:])
	case "restore":
		code, err = a.cmdRestore(&g, rest[1:])
	case "config":
		code, err = a.cmdConfig(&g, rest[1:])
	case "motd":
		return a.cmdMotd(&g, rest[1:], a.Stdout, a.StdoutIsTTY)
	default:
		err = usageError{fmt.Sprintf("unknown command %q", rest[0])}
	}
	if errors.Is(err, errSecretsRemain) {
		fmt.Fprintf(a.Stderr, "shellclear: %v; edit the lines listed above by hand\n", err)
		return exitFindings
	}
	if err != nil {
		return a.fail(err)
	}
	return code
}

func (a *App) fail(err error) int {
	fmt.Fprintf(a.Stderr, "shellclear: %v\n", err)
	var ue usageError
	if errors.As(err, &ue) {
		fmt.Fprintln(a.Stderr, `Run "shellclear --help" for usage.`)
	}
	return exitError
}

// parseCommand parses command flags; global flags are accepted here too.
func parseCommand(name string, g *globals, args []string, define func(*flag.FlagSet), w io.Writer) (bool, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	g.register(fs)
	define(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(w, "Usage: shellclear %s [flags]\n\nFlags:\n", name)
			fs.SetOutput(w)
			fs.PrintDefaults()
			return true, nil
		}
		return false, usageError{fmt.Sprintf("%s: %v", name, err)}
	}
	if fs.NArg() > 0 {
		return false, usageError{fmt.Sprintf("%s: unexpected argument %q", name, fs.Arg(0))}
	}
	return false, nil
}

func (a *App) colorOn(g *globals) bool {
	return a.StdoutIsTTY && !g.noColor && a.Env.Getenv("NO_COLOR") == ""
}

func (a *App) verbosef(g *globals, format string, args ...any) {
	if g.verbose {
		fmt.Fprintf(a.Stderr, format+"\n", args...)
	}
}

// loadConfig reads the configuration and builds the rule set.
func (a *App) loadConfig(g *globals) (*config.Config, *rules.Set, error) {
	dir := config.Dir(g.configDir, a.Env.Getenv, a.Env.Home)
	cfg, err := config.Load(dir)
	if err != nil {
		return nil, nil, err
	}
	set, err := cfg.RuleSet()
	if err != nil {
		return nil, nil, err
	}
	for _, w := range cfg.Warnings {
		fmt.Fprintf(a.Stderr, "shellclear: warning: %s\n", w)
	}
	a.verbosef(g, "config: %s, %d active rules", dir, len(set.Rules()))
	return cfg, set, nil
}

// detect resolves the history files to work on.
func (a *App) detect(g *globals) ([]history.File, error) {
	var shell history.Shell
	if g.shell != "" {
		s, err := history.ParseShell(g.shell)
		if err != nil {
			return nil, usageError{err.Error()}
		}
		shell = s
	}
	files, err := detectFiles(a.Env, g, shell)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		a.verbosef(g, "history: %s (%s)", f.Path, output.Kind(f))
	}
	return files, nil
}

// detectFiles finds shell histories and, with --ai, AI assistant histories.
// Files given with --file replace both.
func detectFiles(env history.Env, g *globals, shell history.Shell) ([]history.File, error) {
	files, err := history.Detect(env, g.files, shell)
	if err != nil || !g.ai || len(g.files) > 0 {
		return files, err
	}
	seen := map[string]bool{}
	for _, f := range files {
		seen[f.RealPath] = true
	}
	for _, f := range history.DetectAI(env) {
		if !seen[f.RealPath] {
			files = append(files, f)
		}
	}
	return files, nil
}

func (a *App) cmdFind(g *globals, args []string) (int, error) {
	var format, severity string
	help, err := parseCommand("find", g, args, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "format", "text", "output format: text, table or json")
		fs.StringVar(&severity, "severity", "low", "report only this severity and above: high, medium or low")
	}, a.Stdout)
	if help || err != nil {
		return exitOK, err
	}
	f, err := output.ParseFormat(format)
	if err != nil {
		return exitError, usageError{err.Error()}
	}
	minSev, err := rules.ParseSeverity(severity)
	if err != nil {
		return exitError, usageError{err.Error()}
	}

	cfg, set, err := a.loadConfig(g)
	if err != nil {
		return exitError, err
	}
	a.legacyHint(g)
	files, err := a.detect(g)
	if err != nil {
		return exitError, err
	}
	if len(files) == 0 {
		fmt.Fprintln(a.Stderr, "shellclear: warning: no history files found; use --file to point at one")
	}

	sc := &scan.Scanner{Rules: set, Allow: cfg.Allow}
	var results []scan.Result
	for _, hf := range files {
		start := time.Now()
		r, err := sc.ScanFile(hf)
		if err != nil {
			return exitError, err
		}
		r.Findings = scan.FilterSeverity(r.Findings, minSev)
		a.verbosef(g, "scanned %s: %d entries, %d findings in %s", hf.Path, len(r.Entries), len(r.Findings), time.Since(start).Round(time.Millisecond))
		// Only findings are reported. AI transcripts can add up to
		// gigabytes, so do not keep every file in memory.
		r.Data, r.Entries = nil, nil
		results = append(results, r)
	}

	opt := output.Options{Color: a.colorOn(g), Fancy: a.StdoutIsTTY, Location: a.Location, Home: a.Env.Home}
	if f == output.Text && a.StdoutIsTTY && !g.noBanner {
		if err := output.Banner(a.Stdout, version, opt.Color); err != nil {
			return exitError, err
		}
	}
	if err := output.Write(a.Stdout, f, results, opt); err != nil {
		return exitError, err
	}
	if output.Summarize(results).Commands > 0 {
		return exitFindings, nil
	}
	return exitOK, nil
}

func (a *App) cmdRules(g *globals, args []string) (int, error) {
	var format string
	help, err := parseCommand("rules", g, args, func(fs *flag.FlagSet) {
		fs.StringVar(&format, "format", "table", "output format: table or json")
	}, a.Stdout)
	if help || err != nil {
		return exitOK, err
	}
	f, err := output.ParseFormat(format)
	if err != nil {
		return exitError, usageError{err.Error()}
	}
	_, set, err := a.loadConfig(g)
	if err != nil {
		return exitError, err
	}
	opt := output.Options{Color: a.colorOn(g), Home: a.Env.Home}
	return exitOK, output.WriteRules(a.Stdout, f, set.Rules(), opt)
}

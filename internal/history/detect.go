package history

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// File is a history file found on disk.
type File struct {
	Path     string // as given or discovered
	RealPath string // after resolving symlinks
	Shell    Shell
	Tool     string // AI assistant that wrote the file, empty for shells
}

// Env is everything Detect needs from the operating system. Tests replace
// it with a fake rooted in t.TempDir().
type Env struct {
	Home     string
	GOOS     string
	Getenv   func(string) string
	Stat     func(string) (fs.FileInfo, error)
	Glob     func(string) ([]string, error)
	Realpath func(string) (string, error)
	WalkDir  func(string, fs.WalkDirFunc) error // nil means filepath.WalkDir
}

// OSEnv returns an Env backed by the real operating system.
func OSEnv() (Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Env{}, fmt.Errorf("home directory: %w", err)
	}
	return Env{
		Home:     home,
		GOOS:     runtime.GOOS,
		Getenv:   os.Getenv,
		Stat:     os.Stat,
		Glob:     filepath.Glob,
		Realpath: filepath.EvalSymlinks,
		WalkDir:  filepath.WalkDir,
	}, nil
}

// ShellFromName guesses the format from a file path.
func ShellFromName(path string) (Shell, bool) {
	base := strings.ToLower(filepath.Base(path))
	dir := strings.ToLower(filepath.Base(filepath.Dir(path)))
	switch {
	case strings.HasSuffix(base, ".jsonl"), strings.HasSuffix(base, ".json"):
		return JSON, true
	case base == "consolehost_history.txt":
		return PowerShell, true
	case strings.Contains(base, "fish"):
		return Fish, true
	case strings.Contains(base, "zsh"), base == ".histfile",
		dir == ".zsh_sessions" && strings.HasSuffix(base, ".history"):
		return Zsh, true
	case strings.Contains(base, "bash"):
		return Bash, true
	}
	return "", false
}

// shellFromBinary maps $SHELL to a format.
func shellFromBinary(path string) (Shell, bool) {
	switch strings.TrimSuffix(strings.ToLower(filepath.Base(path)), ".exe") {
	case "zsh":
		return Zsh, true
	case "bash":
		return Bash, true
	case "fish":
		return Fish, true
	case "pwsh", "powershell":
		return PowerShell, true
	}
	return "", false
}

// Detect returns history files in priority order, without duplicates.
//
// When explicit paths are given only those are returned; shell then forces
// their format, otherwise it is derived from the file name. Without explicit
// paths the order is: $HISTFILE, zsh files, bash, fish, PowerShell.
func Detect(env Env, explicit []string, shell Shell) ([]File, error) {
	d := detector{env: env, seen: map[string]bool{}}
	if len(explicit) > 0 {
		for _, p := range explicit {
			if err := d.addExplicit(p, shell); err != nil {
				return nil, err
			}
		}
		return d.files, nil
	}

	if hf := env.Getenv("HISTFILE"); hf != "" {
		hf = expandHome(hf, env.Home)
		s, ok := ShellFromName(hf)
		if !ok {
			s, ok = shellFromBinary(env.Getenv("SHELL"))
		}
		if ok {
			d.addIfExists(hf, s)
		}
	}

	if env.GOOS != "windows" {
		d.addIfExists(filepath.Join(env.Home, ".zsh_history"), Zsh)
		d.addIfExists(filepath.Join(env.Home, ".histfile"), Zsh)
		if env.Glob != nil {
			matches, _ := env.Glob(filepath.Join(env.Home, ".zsh_sessions", "*.history"))
			sort.Strings(matches)
			for _, m := range matches {
				d.addIfExists(m, Zsh)
			}
		}
		d.addIfExists(filepath.Join(env.Home, ".bash_history"), Bash)

		data := env.Getenv("XDG_DATA_HOME")
		if data == "" {
			data = filepath.Join(env.Home, ".local", "share")
		}
		d.addIfExists(filepath.Join(data, "fish", "fish_history"), Fish)
		d.addIfExists(filepath.Join(env.Home, ".local", "share", "powershell", "PSReadLine", "ConsoleHost_history.txt"), PowerShell)
	} else if appdata := env.Getenv("APPDATA"); appdata != "" {
		d.addIfExists(filepath.Join(appdata, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"), PowerShell)
	}
	return d.files, nil
}

type detector struct {
	env   Env
	seen  map[string]bool
	files []File
	tool  string // set on files added from now on
}

func (d *detector) addExplicit(p string, shell Shell) error {
	p = expandHome(p, d.env.Home)
	fi, err := d.env.Stat(p)
	if err != nil {
		return fmt.Errorf("history file %s: %w", p, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("history file %s: is a directory", p)
	}
	s := shell
	if s == "" {
		var ok bool
		if s, ok = ShellFromName(p); !ok {
			return fmt.Errorf("cannot tell the shell of %s from its name; pass --shell", p)
		}
	}
	d.add(p, s)
	return nil
}

func (d *detector) addIfExists(p string, s Shell) {
	fi, err := d.env.Stat(p)
	if err != nil || fi.IsDir() {
		return
	}
	d.add(p, s)
}

func (d *detector) add(p string, s Shell) {
	resolved := p
	if d.env.Realpath != nil {
		if r, err := d.env.Realpath(p); err == nil {
			resolved = r
		}
	}
	if abs, err := filepath.Abs(resolved); err == nil {
		resolved = abs
	}
	if d.seen[resolved] {
		return
	}
	d.seen[resolved] = true
	d.files = append(d.files, File{Path: p, RealPath: resolved, Shell: s, Tool: d.tool})
}

func expandHome(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		return filepath.Join(home, p[2:])
	}
	return p
}

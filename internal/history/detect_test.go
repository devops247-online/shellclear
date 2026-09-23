package history

import (
	"os"
	"path/filepath"
	"testing"
)

type fakeHome struct {
	t    *testing.T
	home string
	vars map[string]string
}

func newFakeHome(t *testing.T) *fakeHome {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &fakeHome{t: t, home: home, vars: map[string]string{}}
}

func (h *fakeHome) touch(rel string) string {
	h.t.Helper()
	p := filepath.Join(h.home, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
		h.t.Fatal(err)
	}
	return p
}

func (h *fakeHome) env(goos string) Env {
	return Env{
		Home:     h.home,
		GOOS:     goos,
		Getenv:   func(k string) string { return h.vars[k] },
		Stat:     os.Stat,
		Glob:     filepath.Glob,
		Realpath: filepath.EvalSymlinks,
	}
}

func paths(files []File) []string {
	var out []string
	for _, f := range files {
		out = append(out, f.Path+"|"+string(f.Shell))
	}
	return out
}

func TestDetectOrderAndDedup(t *testing.T) {
	h := newFakeHome(t)
	zshHist := h.touch(".zsh_history")
	h.touch(".histfile")
	s2 := h.touch(".zsh_sessions/B.history")
	s1 := h.touch(".zsh_sessions/A.history")
	h.touch(".zsh_sessions/A.historynew")
	bashHist := h.touch(".bash_history")
	fishHist := h.touch("xdg/fish/fish_history")
	ps := h.touch(".local/share/powershell/PSReadLine/ConsoleHost_history.txt")
	custom := h.touch("custom/history")

	// A symlink to .zsh_history must not produce a second entry.
	link := filepath.Join(h.home, ".zsh_history_link")
	if err := os.Symlink(zshHist, link); err != nil {
		t.Fatal(err)
	}
	h.vars["HISTFILE"] = custom
	h.vars["SHELL"] = "/bin/zsh"
	h.vars["XDG_DATA_HOME"] = filepath.Join(h.home, "xdg")

	got, err := Detect(h.env("darwin"), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		custom + "|zsh",
		zshHist + "|zsh",
		filepath.Join(h.home, ".histfile") + "|zsh",
		s1 + "|zsh",
		s2 + "|zsh",
		bashHist + "|bash",
		fishHist + "|fish",
		ps + "|powershell",
	}
	if g := paths(got); !equalStrings(g, want) {
		t.Fatalf("got\n%q\nwant\n%q", g, want)
	}

	// HISTFILE pointing at a symlink of .zsh_history is deduplicated.
	h.vars["HISTFILE"] = link
	got, _ = Detect(h.env("darwin"), nil, "")
	if got[0].Path != link || got[0].RealPath != zshHist || got[1].Path == zshHist {
		t.Fatalf("symlink not deduplicated: %q", paths(got))
	}
}

func TestDetectHistfileShellFromName(t *testing.T) {
	h := newFakeHome(t)
	p := h.touch("hist/.bash_history_work")
	h.vars["HISTFILE"] = "~/hist/.bash_history_work"
	h.vars["SHELL"] = "/bin/zsh"
	got, _ := Detect(h.env("linux"), nil, "")
	if len(got) != 1 || got[0].Path != p || got[0].Shell != Bash {
		t.Fatalf("got %q", paths(got))
	}
}

func TestDetectHistfileUnknownShellSkipped(t *testing.T) {
	h := newFakeHome(t)
	h.touch("hist/whatever")
	h.vars["HISTFILE"] = filepath.Join(h.home, "hist/whatever")
	h.vars["SHELL"] = "/bin/tcsh"
	got, _ := Detect(h.env("linux"), nil, "")
	if len(got) != 0 {
		t.Fatalf("got %q", paths(got))
	}
}

func TestDetectDefaultXDG(t *testing.T) {
	h := newFakeHome(t)
	p := h.touch(".local/share/fish/fish_history")
	got, _ := Detect(h.env("linux"), nil, "")
	if len(got) != 1 || got[0].Path != p || got[0].Shell != Fish {
		t.Fatalf("got %q", paths(got))
	}
}

func TestDetectWindows(t *testing.T) {
	h := newFakeHome(t)
	h.touch(".zsh_history")
	p := h.touch("AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt")
	h.vars["APPDATA"] = filepath.Join(h.home, "AppData/Roaming")
	got, _ := Detect(h.env("windows"), nil, "")
	if len(got) != 1 || got[0].Path != p || got[0].Shell != PowerShell {
		t.Fatalf("got %q", paths(got))
	}
}

func TestDetectExplicit(t *testing.T) {
	h := newFakeHome(t)
	h.touch(".zsh_history")
	a := h.touch("a/.zsh_history")
	b := h.touch("b/notes.txt")

	got, err := Detect(h.env("darwin"), []string{a, a}, "")
	if err != nil || len(got) != 1 || got[0].Shell != Zsh {
		t.Fatalf("got %q, %v", paths(got), err)
	}
	if _, err := Detect(h.env("darwin"), []string{b}, ""); err == nil {
		t.Fatal("unknown format without --shell must fail")
	}
	got, err = Detect(h.env("darwin"), []string{b}, Fish)
	if err != nil || len(got) != 1 || got[0].Shell != Fish {
		t.Fatalf("got %q, %v", paths(got), err)
	}
	if _, err := Detect(h.env("darwin"), []string{filepath.Join(h.home, "missing")}, Zsh); err == nil {
		t.Fatal("missing file must fail")
	}
	if _, err := Detect(h.env("darwin"), []string{filepath.Join(h.home, "a")}, Zsh); err == nil {
		t.Fatal("directory must fail")
	}
}

func TestShellFromName(t *testing.T) {
	cases := map[string]Shell{
		"/h/.zsh_history":                   "zsh",
		"/h/.histfile":                      "zsh",
		"/h/.zsh_sessions/X.history":        "zsh",
		"/h/.bash_history":                  "bash",
		"/h/.local/share/fish/fish_history": "fish",
		`/h/ConsoleHost_history.txt`:        "powershell",
		"/h/other.history":                  "",
	}
	for p, want := range cases {
		got, ok := ShellFromName(p)
		if got != want || ok != (want != "") {
			t.Errorf("ShellFromName(%q) = %q, %v", p, got, ok)
		}
	}
	for bin, want := range map[string]Shell{"/bin/zsh": Zsh, "/usr/bin/bash": Bash, "fish": Fish, "pwsh.exe": PowerShell, "/bin/sh": ""} {
		got, ok := shellFromBinary(bin)
		if got != want || ok != (want != "") {
			t.Errorf("shellFromBinary(%q) = %q, %v", bin, got, ok)
		}
	}
}

func TestOSEnv(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	env, err := OSEnv()
	if err != nil || env.Home == "" || env.Getenv == nil {
		t.Fatalf("OSEnv() = %+v, %v", env, err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

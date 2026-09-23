package history

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// AI assistants whose histories DetectAI finds. The value is File.Tool.
const (
	ClaudeCode = "claude"
	Codex      = "codex"
	GeminiCLI  = "gemini"
	QwenCode   = "qwen"
)

// DetectAI returns the prompt histories and session transcripts of AI coding
// assistants. Prompts typed into them and the output of commands they run
// (cat .env, env, curl -v, …) end up in these files just like shell history.
//
//   - Claude Code: $CLAUDE_CONFIG_DIR or ~/.claude: history.jsonl and
//     projects/**/*.jsonl (sessions, subagents).
//   - Codex CLI: $CODEX_HOME or ~/.codex: history.jsonl, sessions/**/*.jsonl
//     and archived_sessions/**/*.jsonl.
//   - Gemini CLI (~/.gemini) and Qwen Code (~/.qwen): tmp/<project>/logs.json,
//     tmp/<project>/chats/*.json and tmp/<project>/shell_history, which has
//     one shell command per line.
//
// Files are returned per tool in filepath.WalkDir order, without duplicates.
func DetectAI(env Env) []File {
	d := detector{env: env, seen: map[string]bool{}}

	d.tool = ClaudeCode
	claude := env.Getenv("CLAUDE_CONFIG_DIR")
	if claude == "" {
		claude = filepath.Join(env.Home, ".claude")
	}
	d.addIfExists(filepath.Join(claude, "history.jsonl"), JSON)
	d.walk(filepath.Join(claude, "projects"), ".jsonl")

	d.tool = Codex
	codex := env.Getenv("CODEX_HOME")
	if codex == "" {
		codex = filepath.Join(env.Home, ".codex")
	}
	d.addIfExists(filepath.Join(codex, "history.jsonl"), JSON)
	d.walk(filepath.Join(codex, "sessions"), ".jsonl")
	d.walk(filepath.Join(codex, "archived_sessions"), ".jsonl")

	for _, g := range []struct{ tool, dir string }{{GeminiCLI, ".gemini"}, {QwenCode, ".qwen"}} {
		d.tool = g.tool
		tmp := filepath.Join(env.Home, g.dir, "tmp")
		d.glob(filepath.Join(tmp, "*", "logs.json"), JSON)
		d.glob(filepath.Join(tmp, "*", "chats", "*.json"), JSON)
		d.glob(filepath.Join(tmp, "*", "shell_history"), Bash)
	}
	return d.files
}

func (d *detector) glob(pattern string, s Shell) {
	if d.env.Glob == nil {
		return
	}
	matches, _ := d.env.Glob(pattern)
	sort.Strings(matches)
	for _, m := range matches {
		d.addIfExists(m, s)
	}
}

// walk adds every regular file under root whose name ends in ext. Unreadable
// directories are skipped.
func (d *detector) walk(root, ext string) {
	if fi, err := d.env.Stat(root); err != nil || !fi.IsDir() {
		return
	}
	walk := d.env.WalkDir
	if walk == nil {
		walk = filepath.WalkDir
	}
	_ = walk(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			if e != nil && e.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ext) {
			d.add(p, JSON)
		}
		return nil
	})
}

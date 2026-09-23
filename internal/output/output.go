// Package output renders scan results. Raw secrets never reach a writer:
// every command passes through MaskCommand first.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/devops247-online/shellclear/internal/rules"
	"github.com/devops247-online/shellclear/internal/scan"
)

// Format selects how results are written.
type Format string

// Supported formats.
const (
	Text  Format = "text"
	Table Format = "table"
	JSON  Format = "json"
)

// ParseFormat validates a --format value.
func ParseFormat(s string) (Format, error) {
	switch f := Format(strings.ToLower(s)); f {
	case Text, Table, JSON:
		return f, nil
	}
	return "", fmt.Errorf("unknown format %q (want text, table or json)", s)
}

// Options control rendering.
type Options struct {
	Color    bool
	Fancy    bool           // interactive terminal: emoji in the summary line
	Location *time.Location // for timestamps; nil means time.Local
	Home     string         // replaced with ~ in paths for text output
}

const mask = "****"

// MaskSecret hides a secret for display. The number of asterisks is fixed so
// the length does not leak. Only long secrets keep a hint of their edges:
// 20+ characters show the first and last 4, 12–19 show the first 4.
func MaskSecret(s string) string {
	n := utf8.RuneCountInString(s)
	r := []rune(s)
	switch {
	case n >= 20:
		return string(r[:4]) + mask + string(r[n-4:])
	case n >= 12:
		return string(r[:4]) + mask
	}
	return mask
}

// MaskCommand replaces every match in cmd with its masked form and makes the
// result safe to print on a terminal.
func MaskCommand(cmd string, ms []rules.Match) string {
	var b strings.Builder
	prev := 0
	for _, m := range ms {
		if m.Start < prev || m.End > len(cmd) {
			continue
		}
		b.WriteString(cmd[prev:m.Start])
		b.WriteString(MaskSecret(m.Secret))
		prev = m.End
	}
	b.WriteString(cmd[prev:])
	return Sanitize(b.String())
}

// Sanitize makes text printable: invalid UTF-8 becomes U+FFFD, newlines are
// shown as "\n", and other control characters as "\xNN", so history content
// cannot inject terminal escape sequences.
func Sanitize(s string) string {
	s = strings.ToValidUTF8(s, "�")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteByte('\t')
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Summary counts results.
type Summary struct {
	FilesScanned      int            `json:"files_scanned"`
	FilesWithFindings int            `json:"files_with_findings"`
	Commands          int            `json:"commands"`
	Findings          int            `json:"findings"`
	BySeverity        map[string]int `json:"by_severity"`
}

// Summarize counts findings across results.
func Summarize(results []scan.Result) Summary {
	s := Summary{FilesScanned: len(results), BySeverity: map[string]int{"high": 0, "medium": 0, "low": 0}}
	for _, r := range results {
		if len(r.Findings) > 0 {
			s.FilesWithFindings++
		}
		s.Commands += len(r.Findings)
		for _, f := range r.Findings {
			for _, m := range f.Matches {
				s.Findings++
				s.BySeverity[m.Rule.Severity.String()]++
			}
		}
	}
	return s
}

// Write renders results in the given format.
func Write(w io.Writer, f Format, results []scan.Result, opt Options) error {
	if opt.Location == nil {
		opt.Location = time.Local
	}
	switch f {
	case JSON:
		return writeJSON(w, results, opt)
	case Table:
		return writeTable(w, results, opt)
	default:
		return writeText(w, results, opt)
	}
}

type jsonFinding struct {
	Line          int     `json:"line"`
	Time          *string `json:"time"`
	RuleID        string  `json:"rule_id"`
	RuleName      string  `json:"rule_name"`
	Severity      string  `json:"severity"`
	CommandMasked string  `json:"command_masked"`
}

type jsonFile struct {
	Path     string        `json:"path"`
	Shell    string        `json:"shell"`
	Findings []jsonFinding `json:"findings"`
}

type jsonDoc struct {
	Version int        `json:"version"`
	Files   []jsonFile `json:"files"`
	Summary Summary    `json:"summary"`
}

func writeJSON(w io.Writer, results []scan.Result, opt Options) error {
	doc := jsonDoc{Version: 1, Files: []jsonFile{}, Summary: Summarize(results)}
	for _, r := range results {
		jf := jsonFile{Path: r.File.Path, Shell: string(r.File.Shell), Findings: []jsonFinding{}}
		for _, f := range r.Findings {
			masked := MaskCommand(f.Command, f.Matches)
			var ts *string
			if !f.Time.IsZero() {
				s := f.Time.In(opt.Location).Format(time.RFC3339)
				ts = &s
			}
			for _, m := range f.Matches {
				jf.Findings = append(jf.Findings, jsonFinding{
					Line: f.Line, Time: ts, RuleID: m.Rule.ID, RuleName: m.Rule.Name,
					Severity: m.Rule.Severity.String(), CommandMasked: masked,
				})
			}
		}
		doc.Files = append(doc.Files, jf)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

func writeText(w io.Writer, results []scan.Result, opt Options) error {
	c := palette(opt.Color)
	ew := &errWriter{w: w}
	for _, r := range results {
		if len(r.Findings) == 0 {
			continue
		}
		ew.printf("%s%s%s (%s) — %d %s\n", c.bold, displayPath(r.File.Path, opt.Home), c.reset,
			r.File.Shell, len(r.Findings), plural(len(r.Findings), "command", "commands"))
		for _, f := range r.Findings {
			sev := f.MaxSeverity()
			ew.printf("  %sL%-6d%s %s  %s%-6s%s  %s\n", c.dim, f.Line, c.reset,
				formatTime(f.Time, opt.Location), c.sev(sev), strings.ToUpper(sev.String()), c.reset,
				strings.Join(ruleIDs(f), ","))
			ew.printf("           %s\n", MaskCommand(f.Command, f.Matches))
		}
		ew.printf("\n")
	}
	s := Summarize(results)
	if s.Commands == 0 {
		if opt.Fancy {
			ew.printf("🎉 %sYour shell history is clean!%s No secrets found in %d history %s.\n",
				c.green, c.reset, s.FilesScanned, plural(s.FilesScanned, "file", "files"))
		} else {
			ew.printf("No secrets found in %d history %s.\n", s.FilesScanned, plural(s.FilesScanned, "file", "files"))
		}
	} else {
		icon := ""
		if opt.Fancy {
			icon = "🔑 "
		}
		ew.printf("%s%s%d sensitive %s%s in %d %s (high: %d, medium: %d, low: %d).\n",
			icon, c.bold, s.Commands, plural(s.Commands, "command", "commands"), c.reset,
			s.FilesWithFindings, plural(s.FilesWithFindings, "file", "files"),
			s.BySeverity["high"], s.BySeverity["medium"], s.BySeverity["low"])
	}
	return ew.err
}

func writeTable(w io.Writer, results []scan.Result, opt Options) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	ew := &errWriter{w: tw}
	ew.printf("FILE\tLINE\tTIME\tSEVERITY\tRULE\tCOMMAND\n")
	for _, r := range results {
		for _, f := range r.Findings {
			ew.printf("%s\t%d\t%s\t%s\t%s\t%s\n", displayPath(r.File.Path, opt.Home), f.Line,
				formatTime(f.Time, opt.Location), f.MaxSeverity(), strings.Join(ruleIDs(f), ","),
				strings.ReplaceAll(MaskCommand(f.Command, f.Matches), "\t", " "))
		}
	}
	if ew.err != nil {
		return ew.err
	}
	return tw.Flush()
}

// WriteRules lists rules as a table or JSON.
func WriteRules(w io.Writer, f Format, rs []*rules.Rule, opt Options) error {
	if f == JSON {
		type jr struct {
			ID       string   `json:"id"`
			Name     string   `json:"name"`
			Severity string   `json:"severity"`
			Source   string   `json:"source"`
			Keywords []string `json:"keywords,omitempty"`
		}
		out := make([]jr, 0, len(rs))
		for _, r := range rs {
			out = append(out, jr{r.ID, r.Name, r.Severity.String(), r.Source, r.Keywords})
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	sorted := append([]*rules.Rule(nil), rs...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Severity != sorted[j].Severity {
			return sorted[i].Severity > sorted[j].Severity
		}
		return sorted[i].ID < sorted[j].ID
	})
	c := palette(opt.Color)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	ew := &errWriter{w: tw}
	ew.printf("ID\tSEVERITY\tNAME\tSOURCE\n")
	for _, r := range sorted {
		// Color codes would break tabwriter alignment, so only the
		// padding-free last column may be colored.
		src := r.Source
		if src != rules.BuiltinSource {
			src = c.bold + displayPath(src, opt.Home) + c.reset
		}
		ew.printf("%s\t%s\t%s\t%s\n", r.ID, r.Severity, r.Name, src)
	}
	if ew.err != nil {
		return ew.err
	}
	return tw.Flush()
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

func formatTime(t time.Time, loc *time.Location) string {
	if t.IsZero() {
		return "-               "
	}
	return t.In(loc).Format("2006-01-02 15:04")
}

// displayPath shortens the home directory to ~.
func displayPath(p, home string) string {
	if home != "" && (p == home || strings.HasPrefix(p, home+"/")) {
		return "~" + p[len(home):]
	}
	return p
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

type colors struct {
	bold, dim, reset, red, yellow, cyan, green string
}

func (c colors) sev(s rules.Severity) string {
	switch s {
	case rules.High:
		return c.red
	case rules.Medium:
		return c.yellow
	}
	return c.cyan
}

func palette(on bool) colors {
	if !on {
		return colors{}
	}
	return colors{bold: "\x1b[1m", dim: "\x1b[2m", reset: "\x1b[0m", red: "\x1b[31m", yellow: "\x1b[33m", cyan: "\x1b[36m", green: "\x1b[1;32m"}
}

type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err == nil {
		_, e.err = fmt.Fprintf(e.w, format, args...)
	}
}

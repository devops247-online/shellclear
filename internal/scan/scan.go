// Package scan runs detection rules over parsed history files.
package scan

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/devops247-online/shellclear/internal/history"
	"github.com/devops247-online/shellclear/internal/rules"
)

// A worker handles up to chunkSize entries or chunkBytes of command text at
// a time. The byte limit spreads files with few but long entries, such as AI
// session transcripts, across workers too.
const (
	chunkSize  = 2048
	chunkBytes = 256 << 10
)

// Finding is one command that contains at least one secret.
type Finding struct {
	Entry   int // index into Result.Entries
	Line    int
	Time    time.Time
	Command string        // decoded command; in memory only, never print it
	Matches []rules.Match // every secret in the command, by position
}

// MaxSeverity returns the highest severity among the matches.
func (f Finding) MaxSeverity() rules.Severity {
	var s rules.Severity
	for _, m := range f.Matches {
		if m.Rule.Severity > s {
			s = m.Rule.Severity
		}
	}
	return s
}

// Result holds one scanned file.
type Result struct {
	File     history.File
	Data     []byte
	Entries  []history.Entry
	Findings []Finding
}

// Scanner finds secrets in history files.
type Scanner struct {
	Rules   *rules.Set
	Allow   []*regexp.Regexp // commands matching any of these are skipped
	Workers int              // <= 0 means runtime.NumCPU()
}

// ScanFile reads and scans one history file.
func (s *Scanner) ScanFile(f history.File) (Result, error) {
	data, err := os.ReadFile(f.RealPath)
	if err != nil {
		return Result{}, fmt.Errorf("read %s: %w", f.Path, err)
	}
	return s.ScanBytes(f, data)
}

// ScanBytes scans history data in the format of f.Shell.
func (s *Scanner) ScanBytes(f history.File, data []byte) (Result, error) {
	codec, err := history.CodecFor(f.Shell)
	if err != nil {
		return Result{}, err
	}
	entries := codec.Parse(data)
	return Result{File: f, Data: data, Entries: entries, Findings: s.ScanEntries(entries)}, nil
}

// ScanEntries returns findings for entries, ordered by entry index.
func (s *Scanner) ScanEntries(entries []history.Entry) []Finding {
	matches := make([][]rules.Match, len(entries))
	workers := s.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	chunks := chunkStarts(entries)
	if workers > len(chunks) {
		workers = len(chunks)
	}

	if workers <= 1 {
		s.scanRange(entries, matches, 0, len(entries))
	} else {
		next := make(chan int)
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range next {
					end := len(entries)
					if i+1 < len(chunks) {
						end = chunks[i+1]
					}
					s.scanRange(entries, matches, chunks[i], end)
				}
			}()
		}
		for i := range chunks {
			next <- i
		}
		close(next)
		wg.Wait()
	}

	var out []Finding
	for i, ms := range matches {
		if len(ms) == 0 {
			continue
		}
		e := entries[i]
		out = append(out, Finding{Entry: i, Line: e.Line, Time: e.Time, Command: e.Command, Matches: ms})
	}
	return out
}

// chunkStarts splits entries into chunks and returns the first index of each.
func chunkStarts(entries []history.Entry) []int {
	var starts []int
	n, size := 0, 0
	for i := range entries {
		if i == 0 || n == chunkSize || size >= chunkBytes {
			starts = append(starts, i)
			n, size = 0, 0
		}
		n++
		size += len(entries[i].Command)
	}
	return starts
}

func (s *Scanner) scanRange(entries []history.Entry, out [][]rules.Match, start, end int) {
	for i := start; i < end; i++ {
		e := &entries[i]
		if e.Opaque || e.Command == "" {
			continue
		}
		ms := s.Rules.FindWithLower(e.Command, strings.ToLower(e.Command))
		if len(ms) == 0 || s.allowed(e.Command) {
			continue
		}
		out[i] = ms
	}
}

func (s *Scanner) allowed(cmd string) bool {
	for _, re := range s.Allow {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

// FilterSeverity keeps findings with at least one match of severity >= minSev.
// Every match is kept so that masking still hides all secrets.
func FilterSeverity(fs []Finding, minSev rules.Severity) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.MaxSeverity() >= minSev {
			out = append(out, f)
		}
	}
	return out
}

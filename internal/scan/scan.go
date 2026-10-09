// Package scan runs detection rules over parsed history files.
package scan

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
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

// MaxInFlightBytes bounds how much file data is held at once when files are
// read concurrently. AI transcripts can add up to gigabytes; a file larger
// than this is handled on its own.
const MaxInFlightBytes = 256 << 20

// ScanFiles reads and scans files, up to Workers files at a time and up to
// MaxInFlightBytes of them, and calls done with each result as soon as it is
// ready. done may run concurrently for different files; i is the file's
// index, so results can be stored in input order. After a failure no further
// file is started, and the error returned is the one of the first failing
// file in input order: the same error a one-by-one loop over ScanFile would
// return.
func (s *Scanner) ScanFiles(files []history.File, done func(i int, r Result)) error {
	workers := s.workers()
	if workers > len(files) {
		workers = len(files)
	}
	mem := NewBudget(MaxInFlightBytes)
	errs := make([]error, len(files))
	var next atomic.Int64
	var stopAt atomic.Int64 // index of the first failure seen so far
	stopAt.Store(int64(len(files)))
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= len(files) || int64(i) > stopAt.Load() {
					return
				}
				var size int64
				if fi, err := os.Stat(files[i].RealPath); err == nil {
					size = fi.Size()
				}
				size = mem.Acquire(size)
				r, err := s.ScanFile(files[i])
				if err == nil {
					done(i, r)
				}
				mem.Release(size)
				if err != nil {
					errs[i] = err
					for {
						cur := stopAt.Load()
						if int64(i) >= cur || stopAt.CompareAndSwap(cur, int64(i)) {
							break
						}
					}
				}
			}
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// Budget is a counting semaphore over bytes.
type Budget struct {
	mu    sync.Mutex
	cond  *sync.Cond
	limit int64
	used  int64
}

// NewBudget returns a budget of limit bytes.
func NewBudget(limit int64) *Budget {
	b := &Budget{limit: limit}
	b.cond = sync.NewCond(&b.mu)
	return b
}

// Acquire waits until n bytes are free and takes them. A request larger than
// the limit takes the whole budget. It returns what it took, which is what
// Release must be given back.
func (b *Budget) Acquire(n int64) int64 {
	n = min(max(n, 0), b.limit)
	b.mu.Lock()
	for b.used+n > b.limit {
		b.cond.Wait()
	}
	b.used += n
	b.mu.Unlock()
	return n
}

// Release returns bytes taken by Acquire.
func (b *Budget) Release(n int64) {
	b.mu.Lock()
	b.used -= n
	b.mu.Unlock()
	b.cond.Broadcast()
}

func (s *Scanner) workers() int {
	if s.Workers <= 0 {
		return runtime.NumCPU()
	}
	return s.Workers
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
	workers := s.workers()
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
		ms := s.Rules.Find(e.Command)
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

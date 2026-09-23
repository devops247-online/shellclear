// Package motd counts sensitive commands for the shell start-up reminder,
// fast enough to run on every new terminal.
//
// Results are cached per history file in <state>/cache.json, keyed by real
// path, size, modification time and file identity. When a file only grew and
// the 4 KiB before the previously scanned end are unchanged, only the new
// records are scanned. The cache holds counts and hashes, never commands.
package motd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/devops247-online/shellclear/internal/history"
	"github.com/devops247-online/shellclear/internal/rules"
	"github.com/devops247-online/shellclear/internal/safefile"
	"github.com/devops247-online/shellclear/internal/scan"
)

// CacheName is the cache file inside the state directory.
const CacheName = "cache.json"

const (
	cacheVersion = 1
	windowSize   = 4096
)

type cacheEntry struct {
	Size     int64  `json:"size"`
	MtimeNS  int64  `json:"mtime_ns"`
	FileID   string `json:"file_id,omitempty"`
	Scanned  int64  `json:"scanned_bytes"`
	TailHash string `json:"tail_sha256"`
	Count    int    `json:"count"`
}

type cacheFile struct {
	Version   int                    `json:"version"`
	RulesHash string                 `json:"rules_hash"`
	Files     map[string]*cacheEntry `json:"files"`
}

// Checker counts sensitive commands using the cache.
type Checker struct {
	Scanner   *scan.Scanner
	StateDir  string
	RulesHash string // changes whenever rules, ignores or the allow list change
}

// Stats says how each file was handled; used by tests and --verbose.
type Stats struct {
	Hits, Incremental, Full int
}

// Count returns the number of commands with secrets across files.
func (c *Checker) Count(files []history.File) (int, Stats, error) {
	var st Stats
	cache := c.load()
	changed := false
	total := 0
	seen := map[string]bool{}
	for _, f := range files {
		seen[f.RealPath] = true
		n, how, err := c.countFile(f, cache)
		if err != nil {
			return 0, st, err
		}
		switch how {
		case hit:
			st.Hits++
		case incremental:
			st.Incremental++
			changed = true
		default:
			st.Full++
			changed = true
		}
		total += n
	}
	for p := range cache.Files {
		if !seen[p] {
			delete(cache.Files, p)
			changed = true
		}
	}
	if changed {
		c.save(cache)
	}
	return total, st, nil
}

type method int

const (
	hit method = iota
	incremental
	full
)

func (c *Checker) countFile(f history.File, cache *cacheFile) (int, method, error) {
	fi, err := os.Stat(f.RealPath)
	if err != nil {
		return 0, full, err
	}
	id := fileID(fi)
	e := cache.Files[f.RealPath]
	if e != nil && e.Size == fi.Size() && e.MtimeNS == fi.ModTime().UnixNano() && e.FileID == id {
		return e.Count, hit, nil
	}
	codec, err := history.CodecFor(f.Shell)
	if err != nil {
		return 0, full, err
	}

	fh, err := os.Open(f.RealPath)
	if err != nil {
		return 0, full, err
	}
	defer fh.Close()

	if e != nil && e.FileID == id && fi.Size() > e.Scanned && e.Scanned > 0 {
		start := max(0, e.Scanned-windowSize)
		buf := make([]byte, fi.Size()-start)
		if _, err := fh.ReadAt(buf, start); err == nil || errors.Is(err, io.EOF) {
			window := buf[:e.Scanned-start]
			if hashBytes(window) == e.TailHash {
				tail := buf[e.Scanned-start:]
				n, done := c.scan(codec, tail)
				scanned := e.Scanned + done
				cache.Files[f.RealPath] = &cacheEntry{
					Size: fi.Size(), MtimeNS: fi.ModTime().UnixNano(), FileID: id,
					Scanned: scanned, TailHash: hashBytes(buf[max(0, scanned-windowSize-start) : scanned-start]),
					Count: e.Count + n,
				}
				return e.Count + n, incremental, nil
			}
		}
	}

	data, err := io.ReadAll(fh)
	if err != nil {
		return 0, full, err
	}
	n, done := c.scan(codec, data)
	cache.Files[f.RealPath] = &cacheEntry{
		Size: fi.Size(), MtimeNS: fi.ModTime().UnixNano(), FileID: id,
		Scanned: done, TailHash: hashBytes(data[max(0, done-windowSize):done]), Count: n,
	}
	return n, full, nil
}

// scan counts findings in the complete records of data and returns how many
// bytes those records span. A last record that may still grow (no final
// newline, or a continuation) is left for the next run.
func (c *Checker) scan(codec history.Codec, data []byte) (int, int64) {
	entries := codec.Parse(data)
	complete := len(entries)
	if complete > 0 && !finished(codec.Shell(), entries[complete-1].Raw) {
		complete--
	}
	findings := c.Scanner.ScanEntries(entries[:complete])
	var done int64
	for _, e := range entries[:complete] {
		done += int64(len(e.Raw))
	}
	return len(findings), done
}

func finished(s history.Shell, raw []byte) bool {
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return false
	}
	body := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	switch s {
	case history.Zsh:
		return !strings.HasSuffix(body, `\`)
	case history.PowerShell:
		return !strings.HasSuffix(body, "`")
	}
	return true
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (c *Checker) path() string { return filepath.Join(c.StateDir, CacheName) }

func (c *Checker) load() *cacheFile {
	fresh := &cacheFile{Version: cacheVersion, RulesHash: c.RulesHash, Files: map[string]*cacheEntry{}}
	b, err := os.ReadFile(c.path())
	if err != nil {
		return fresh
	}
	var cf cacheFile
	if json.Unmarshal(b, &cf) != nil || cf.Version != cacheVersion || cf.RulesHash != c.RulesHash || cf.Files == nil {
		return fresh
	}
	return &cf
}

// save writes the cache; failures are ignored because the cache is only an
// optimization.
func (c *Checker) save(cf *cacheFile) {
	b, err := json.Marshal(cf)
	if err != nil {
		return
	}
	if safefile.MkdirPrivate(c.StateDir) != nil {
		return
	}
	_ = safefile.WriteAtomic(c.path(), b, 0o600)
}

// Invalidate deletes the cache; commands that rewrite history call it.
func Invalidate(stateDir string) {
	_ = os.Remove(filepath.Join(stateDir, CacheName))
}

// RulesHash fingerprints everything that affects detection results.
func RulesHash(version string, set *rules.Set, allow []string) string {
	h := sha256.New()
	write := func(parts ...string) {
		for _, p := range parts {
			h.Write([]byte(p))
			h.Write([]byte{0})
		}
	}
	write("v", version)
	for _, r := range set.Rules() {
		write(r.ID, r.Test, strconv.Itoa(r.SecretGroup), r.Severity.String(), strings.Join(r.Keywords, ","))
	}
	sorted := append([]string(nil), allow...)
	sort.Strings(sorted)
	write(sorted...)
	return hex.EncodeToString(h.Sum(nil))
}

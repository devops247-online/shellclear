# shellclear — Design

Status: accepted. Open questions in §8 are resolved as recommended.

## 1. Goals and non-goals

**Goal.** Find secrets in shell history files and mask or remove them without
ever corrupting the file. Secondary: `stash`/`pop` before screen sharing and a
fast one-line reminder (`motd`) at shell start-up.

**Non-goals.** Protecting secrets that live in the memory of running shells,
terminal scrollback, tmux logs, Time Machine or other backups. Real-time
interception of commands (that is a shell hook, not a history cleaner).

**Hard invariants** (each one is covered by a test):

| # | Invariant |
|---|-----------|
| I1 | `concat(Parse(data)[i].Raw) == data` for every codec and every input (fuzzed). |
| I2 | An unmodified entry is written back byte-for-byte. |
| I3 | A file with no changes is never opened for writing (inode and mtime unchanged). |
| I4 | Every write is atomic (temp file in the same dir → fsync → rename → fsync dir). |
| I5 | A backup exists before any write, unless `--no-backup` is given explicitly. |
| I6 | A raw secret never reaches stdout, stderr, logs, JSON, cache or error text. |
| I7 | After an edit, re-parsing the new entry yields exactly the expected command. Otherwise the edit is aborted. |

## 2. Verified format facts

Everything below was checked against upstream sources (September 2026 master
branches): zsh `Src/{zsh.h,init.c,hist.c,utils.c}`, fish
`src/history/{file.rs,yaml_backend.rs}`, bash `lib/readline/histfile.c`,
PSReadLine `PSReadLine/History.cs`.

### zsh

- **Metafied bytes** (`init.c`, `inittyptab`): `0x00`, `Meta` = `0x83`, and
  `Pound` = `0x84` … `Nularg` = `0xA1`, plus `Marker` = `0xA2`. So the set is
  exactly `0x00` and `0x83–0xA2`. Encoding is `0x83, b^0x20` (`utils.c`,
  `metafy`). The history file stores the metafied form: `savehistfile` writes
  `he->node.nam` byte by byte, and that string is metafied.
- **Line continuation** (`hist.c`, `savehistfile`): each `\n` inside a command
  is written as `\` + `\n`. **The reader (`readhistline`) continues on a single
  trailing `\`, no parity check.** A command that really ends in backslashes
  (optionally followed by spaces) gets one extra trailing space on write, and
  the reader strips it again. See open question Q1.
- **Extended format**: `: <start>:<elapsed>;<command>`. A plain-format command
  that starts with `:` is written as `\:`; the reader strips that `\`.
- **Locking**: zsh locks with `<HISTFILE>.LOCK` (symlink or link-based,
  `lockhistfile`) and, with `HIST_FCNTL_LOCK`, also with `fcntl(F_SETLKW)` on
  the history file itself. See Q6.

### bash

- A timestamp line is `history_comment_char` followed by a digit
  (`HIST_TIMESTAMP_START`: `#` + `isdigit(s[1])`). Entry boundaries follow
  exactly this rule. `Time` is filled only when everything after `#` is
  digits.
- **When the file contains timestamps, bash treats every line up to the next
  timestamp as part of the same entry** (`_hs_append_history_line` when
  `history_multiline_entries` is set, i.e. `shopt -s lithist cmdhist`). See Q2.
- bash tolerates `\r\n`. We keep `\r` in `Raw` and strip it from `Command`.

### fish

- Write format (`file.rs`, `HistoryItem::write_to`):
  ```
  - cmd: <escaped>
    when: <epoch>
    added_when: <epoch>     # only when first_added != last_added
    paths:
      - <escaped path>
  ```
- Escaping: `\` → `\\`, newline → `\n`. The reader only decodes `\\` and `\n`.
  Paths use the same escaping.
- The reader starts an item at any column-0 line beginning with `- cmd`, and it
  skips lines starting with `%`, `---`, `...`, a NUL byte, or other column-0
  garbage. Our parser therefore uses "a column-0 line beginning with `- cmd`"
  as the entry boundary.
- fish stops decoding a value at an unknown escape sequence. We keep unknown
  escapes literally instead, so text after them is still scanned. Such values
  are only edited at the byte level and then verified. Everything before the first entry becomes one raw,
  never-edited entry.
- **Secrets can also appear in `paths:`**, because fish stores arguments that
  look like existing paths. Editing must cover the `cmd:` line and the `paths:`
  items, and nothing else (never `when:`).

### PowerShell (PSReadLine)

- Writer: `CommandLine.Replace("\n", "`\n")`, then `WriteLine` (which emits
  `\r\n` on Windows). Reader: a line ending in a backtick continues. `Raw` keeps
  `\r\n`, `Command` has `\r` stripped and a backtick+newline turned into `\n`.

### Original shellclear (rusty-ferris-club, v0.4.8)

- 39 patterns, fields `name`, `test`, `secret_group`, `id`.
- Custom config lives in `~/shellclear/` (`sensitive-patterns.yaml`,
  `ignores.yaml`). State lives in `~/.shellclear/` (`backups/`, `stash/`).
- Test suites use `name`, `test`, `expected`. **Some expected values are shell
  expansions** (`$SECRET_VAR`, `$(cat /tmp/secret)`, `` `cat /tmp/secret` ``).
  Our shared validation rejects these on purpose. See Q3.

## 3. Package layout and interfaces

```
cmd/shellclear/        main: flag parsing, wiring, exit codes
internal/history/      codecs + detect
internal/rules/        embedded patterns, loading, Find, validation
internal/scan/         file → findings, worker pool
internal/cleaner/      plan edits, safe write, concurrent-append handling
internal/state/        ~/.shellclear layout: backups, stash, cache, locking
internal/config/       custom patterns, ignores, legacy import
internal/output/       text / table / json, masking for display
```

Dependency direction: `main → {scan, cleaner, state, config, output} → {rules, history}`.
`rules` and `history` do not import each other.

No package-level mutable state. The filesystem, home dir, env, clock and
stdin/stdout are passed in through small structs.

### 3.1 `internal/history`

```go
type Shell string

const (
    Zsh        Shell = "zsh"
    Bash       Shell = "bash"
    Fish       Shell = "fish"
    PowerShell Shell = "powershell"
)

type Entry struct {
    Raw     []byte    // exact bytes, including newline and service lines
    Command string    // decoded command (may contain invalid UTF-8)
    Line    int       // 1-based line of the first byte of Raw
    Time    time.Time // zero if unknown
    Opaque  bool      // true for non-entry chunks (fish preamble); never edited
}

type Codec interface {
    Shell() Shell
    // Parse splits data into entries. Invariant: concat(Raw) == data.
    Parse(data []byte) []Entry
    // EncodeLiteral returns how the decoded string s appears inside Raw.
    EncodeLiteral(s string) []byte
    // Replace substitutes old with repl inside the editable regions of raw
    // only (command body; fish cmd + paths). It never touches prefixes such
    // as ": 1700000000:0;" or "  when: ...". It returns ErrUnsafeEdit when
    // the result would not decode to the command with old replaced, or when
    // old is in the command but in no editable region.
    Replace(raw []byte, old, repl string) ([]byte, error)
}

func CodecFor(s Shell) (Codec, error)

type File struct {
    Path     string // as given or discovered
    RealPath string // after EvalSymlinks
    Shell    Shell
}

type Env struct {
    Home     string
    Getenv   func(string) string
    GOOS     string
    Glob     func(string) ([]string, error)
    Stat     func(string) (fs.FileInfo, error)
    Realpath func(string) (string, error)
}

// Detect returns history files in the documented priority order, deduplicated
// by RealPath. explicit comes from --file / --shell.
func Detect(env Env, explicit []string, shell Shell) ([]File, error)
func ShellFromName(path string) (Shell, bool)
```

`Replace` is an addition to the spec interface. It keeps the spec rule
(replace the encoded literal with `bytes.ReplaceAll`) but limits it to the
regions where the command is stored. Without it, a short numeric secret could
match the zsh timestamp prefix or the fish `when:` line.

Each region is edited in two steps. First, the encoded literal is replaced
at the byte level, which leaves non-canonical bytes around it untouched.
If the region then does not decode to the expected text, it is re-encoded
from the expected text, but only when the original region was canonical.
Finally the whole record is parsed again (invariant I7). The byte-level step
alone can go wrong: an encoded literal can match the second byte of a zsh
Meta pair or the `n` of a fish `\n` escape.

The zsh region includes the protective trailing space, so masking a command
that ended in `\` also removes that space.

### 3.2 `internal/rules`

```go
type Severity int // Low < Medium < High; YAML: "low" | "medium" | "high"

type Rule struct {
    ID          string
    Name        string
    Test        string
    SecretGroup int
    Severity    Severity // default Medium
    Keywords    []string // lower-cased at load time
    Source      string   // "builtin" or the file path
    re          *regexp.Regexp
}

type Match struct {
    Start, End int      // byte offsets in Command of the secret
    Rule       *Rule    // winner after merging overlaps
    Secret     string   // raw secret; never leaves the process
}

type Set struct{ /* compiled rules, keyword index */ }

func Builtin() (*Set, error)
func Load(r io.Reader, source string) ([]Rule, error)
func NewSet(rules []Rule, ignoreIDs []string) (*Set, error)
func (s *Set) Find(cmd string) []Match // all matches, merged, validated
func (s *Set) Rules() []Rule
func ValidSecret(s string) bool
```

- Load errors name the file and the rule id, for example
  `custom.yaml: rule "my_token": secret_group 2 > 1 groups in regex`.
- `Find`: keyword prefilter on `strings.ToLower(cmd)` → `FindAllStringSubmatchIndex`
  → take the `secret_group` span → `ValidSecret` → merge overlapping spans
  (the merged span keeps the rule with the highest severity; on a tie, the
  earlier rule in load order).
- `ValidSecret` trims matching quotes (`'`, `"`) and rejects the secret when it:
  - is empty or shorter than 4 characters;
  - starts with `$`, `${`, `$(`, `<`, or a backtick (the backtick is added, see Q3);
  - is only `*`;
  - contains `REDACTED`;
  - is a placeholder: starts with `xxx` (case-insensitive), equals `changeme`,
    contains `example`, starts with `your_` / `your-`, or looks like `<…>`.

### 3.3 `internal/scan`

```go
type Finding struct {
    File    history.File
    Entry   int            // index into the parsed entries
    Line    int
    Time    time.Time
    Command string         // decoded command, kept in memory only
    Matches []rules.Match
}

type Result struct {
    File     history.File
    Data     []byte           // exactly what was read
    Entries  []history.Entry
    Findings []Finding
}

type Scanner struct {
    Rules   *rules.Set
    Workers int              // default runtime.NumCPU()
}

func (s *Scanner) ScanBytes(f history.File, data []byte) Result
func (s *Scanner) ScanFile(fsys FS, f history.File) (Result, error)
```

Entries are split into chunks of about 2,048. A pool of workers writes into a
pre-sized slice indexed by entry, so the output order is deterministic without
sorting. `BenchmarkScan100k` targets less than 1 s on an Apple M1.

### 3.4 `internal/cleaner`

```go
type Mode int // Mask | Remove

type Plan struct {
    File    history.File
    Orig    []byte
    New     []byte
    Changes []Change // entry index, kind, rule ids; no secrets
}

type Options struct {
    Mode     Mode
    Backup   bool
    DryRun   bool
}

func BuildPlan(r scan.Result, codec history.Codec, mode Mode) (Plan, error)
func Apply(ctx Ctx, p Plan, opt Options) error
```

`BuildPlan`, per entry with findings:

- **Mask**: for every match, `raw = codec.Replace(raw, secret, "[REDACTED:<rule_id>]")`.
  Then run I7: re-parse `raw` and expect exactly one entry whose `Command`
  equals the decoded command with all secrets replaced. On a mismatch, skip
  the entry and report it as "could not be edited safely". Never write a guess.
- **Remove**: drop the whole `Raw` (bash timestamp line and fish `paths` included).

`Apply` follows §5 exactly.

### 3.5 `internal/state`

```go
type Dir struct{ Root string } // ~/.shellclear or $SHELLCLEAR_HOME or --config-dir

func (d Dir) Ensure() error                          // 0700, verifies ownership
func (d Dir) Backup(f history.File, data []byte, now time.Time) (string, error)
func (d Dir) Backups() ([]BackupInfo, error)
func (d Dir) ResolveBackup(name string) (BackupInfo, error) // rejects paths outside backups/
func (d Dir) Stash(f history.File, data []byte) error         // fails if a stash exists
func (d Dir) StashFor(f history.File) (path string, ok bool, err error)
func (d Dir) Lock() (unlock func(), err error)               // one shellclear at a time
func (d Dir) Cache() (*Cache, error)
```

### 3.6 `internal/config`

```go
type Config struct {
    Dir         string
    Ignore      []string     // rule ids to disable
    Allow       []string     // regexes; a command matching one is never reported
    Backups     BackupPolicy // keep N, 0 = unlimited
    CustomRules []rules.Rule // from rules.d/*.yaml
}

func Load(dir string) (Config, error)
func Init(dir string) error                // writes templates, never overwrites
func Validate(dir string) []error
func ImportLegacy(home, dir string) error  // ~/shellclear → rules.d/ + config.yaml, see Q5
```

**Config files.**

`config.yaml` holds settings only, no rules:

```yaml
version: 1
ignore:            # rule ids to disable
  - generic_env_assignment
allow:             # commands matching any of these are never reported
  - '^export GITHUB_TOKEN=\$\(gh auth token\)$'
backups:
  keep: 20         # 0 = keep all
```

`rules.d/*.yaml` holds custom rules, one list per file, in the original
shellclear format (`id`, `name`, `test`, `secret_group`, plus the optional
`severity` and `keywords`). A `sensitive-patterns.yaml` from the original
tool can be dropped into `rules.d/` unchanged. Files are loaded in lexical
order. A custom rule with the same `id` as a built-in rule replaces it, and
`shellclear rules` shows the source.

Unknown keys in `config.yaml` are an error in `config validate` and a warning
everywhere else, so a typo never silently disables protection.

### 3.7 `internal/output`

```go
type Format int // Text | Table | JSON

func MaskSecret(s string) string
func MaskCommand(cmd string, ms []rules.Match) string
func Write(w io.Writer, f Format, results []scan.Result, color bool) error
```

Colors are used only when `NO_COLOR` is unset, `--no-color` is absent, and
stdout is a TTY (checked with `os.File.Stat()` and `ModeCharDevice`, no x/term).

## 4. State directory

```
~/.shellclear/                         0700   ($SHELLCLEAR_HOME, --config-dir)
├── config.yaml                        0600   settings: ignore, allow, backups
├── rules.d/                           0700   custom rules, *.yaml (original format)
├── cache.json                         0600   motd cache
├── lock                               0600   flock/LockFileEx while writing
├── backups/<shell>/<basename>.<YYYYMMDDTHHMMSS>[-N].bak       0600
├── backups/<shell>/<basename>.<YYYYMMDDTHHMMSS>[-N].bak.json  0600
├── stash/<shell>/<basename>           0600
└── stash/<shell>/<basename>.json      0600
```

- `-N` is added when two backups land in the same second.
- The backup sidecar has `{"source","shell","created","sha256","size"}`.
  The stash sidecar has the same fields, so `pop` knows the exact source path.
- The cache holds, per history file: `realpath`, `size`, `mtime_ns`,
  `scanned_bytes`, the `sha256` of the last 4 KiB before `scanned_bytes`, and
  `count`. No commands, no secrets.
  - `motd` hit: same `size` and `mtime` → print from cache.
  - `motd` append: the file grew and the 4 KiB tail hash still matches →
    scan only the new bytes.
  - Otherwise: full rescan.
- Files are created with `O_EXCL` and mode `0600`, then `chmod`ed again so the
  umask cannot widen them.

## 5. Safe write sequence (`cleaner.Apply`)

1. `real := EvalSymlinks(path)`. All later steps work on `real`, so a
   stow/chezmoi symlink stays a symlink.
2. Read `orig` and `stat` it (`size`, `mtime`, `mode`).
3. Build `new`. If `bytes.Equal(new, orig)`, return without touching anything.
4. Unless `--no-backup`: write the backup and its sidecar (fsync both).
5. Take `state.Lock()`. Re-read the file as `cur`.
   - `cur == orig` → continue.
   - `bytes.HasPrefix(cur, orig)` → parse and scan `tail := cur[len(orig):]`
     with the same codec, apply the same mode, `new = new + editedTail`. The
     backup gets the tail appended too, so it always equals the pre-edit file.
   - Otherwise → abort with `history changed during operation, retry`.
     Nothing is written.
6. `tmp := CreateTemp(dir(real), ".<base>.shellclear-*")`, `chmod(orig mode)`,
   `write`, `fsync`, `close`, `rename(tmp, real)`, `fsync(dir)`. On Windows the
   directory fsync is skipped. Any failure removes `tmp`.
7. Print the "restart your shells" hint for each shell type that was touched.

Locking, as implemented:

- The shellclear lock is an fcntl lock on `<state>/lock`.
- For zsh files, `<HISTFILE>.LOCK` is taken the way zsh's `lockhistfile`
  does it: a symlink to `/pid-<pid>/host-<host>`. A lock older than
  10 seconds is treated as stale, as in zsh.
- Every history file also gets an fcntl lock, for zsh's `HIST_FCNTL_LOCK`.
  POSIX drops a process's fcntl locks when it closes any descriptor of the
  file, so the re-read in step 5 goes through the locked descriptor.
- If a commit to the tail fails after the backup was written, the backup is
  removed again. On `ErrChanged` nothing remains on disk.

## 6. CLI behaviour notes

- `find --severity X` means "X and above".
- No history files found: a warning goes to stderr and the exit code is `0`.
- `clear` confirmation reads one line from stdin. Without a TTY and without
  `--yes` it exits `2` before reading anything.
- The `stash` hint: the current shell still has the history in memory. zsh:
  `fc -p` starts an empty in-memory list in the current session. bash:
  `history -c`. fish: `history clear-session` (fish ≥ 3.6), otherwise
  `exec fish`.
- `restore NAME` accepts only a name listed under `backups/`. Path separators
  and `..` are rejected.
- JSON `time` is RFC 3339 or `null`. `summary` is
  `{"files":N,"findings":N,"by_severity":{"high":N,"medium":N,"low":N}}`.

## 7. Testing map

| Area | Tests |
|------|-------|
| Codecs | golden round-trips in `testdata/`, `FuzzParse<Shell>` for I1, `FuzzReplace<Shell>` for I7, a fish edit that keeps `paths:` |
| Detect | fake `Env`: `$HISTFILE`, `~/.zsh_sessions`, XDG, duplicates via symlink |
| Rules | ported suites (`internal/rules/testdata/original/`), new suites, negatives |
| Cleaner | unchanged inode/mtime, symlink kept, mode kept, concurrent append, concurrent rewrite |
| State | double stash refused, pop keeps new commands, backup name collision, path traversal |
| Output | every fixture secret is absent from stdout, stderr and JSON |
| motd | cache hit, append path, invalidation; timing check behind `-short` |

## 8. Open questions

**Q1. zsh continuation rule.** The spec says "an odd number of trailing `\`".
zsh itself continues on **any** single trailing `\` and protects real trailing
backslashes with an extra space. *Recommendation:* follow zsh exactly. With
the odd-count rule, a line such as `echo \\` followed by a newline would be
read differently from zsh.

**Q2. bash multi-line entries.** The spec says "each line is a separate entry".
In a timestamped file, bash groups all lines up to the next timestamp into one
entry. *Recommendation:* files without timestamps use one entry per line;
files with timestamps use `#ts` plus every line up to the next `#ts`. This
also closes anti-requirement 7 for bash.

**Q3. Porting the original suites.** Several `expected` values in the original
suites are `$VAR`, `$(…)` or backtick expansions, which our validation
rejects by design. *Recommendation:* port them as negative cases (no finding)
with a comment that links the original case. Also add the backtick to the
rejected prefixes.

**Q4. Display mask.** The spec says "first 4 + `*` + last 4, only `*` for
≤ 8 characters". For a 9-character password that shows 8 of 9 characters.
*Recommendation:* show 4+4 only when the secret is ≥ 20 characters, show the
first 4 only for 12–19 characters, and use `****` below that. The asterisk
count is always fixed so the length does not leak.

**Q5. Legacy config location.** The original keeps `sensitive-patterns.yaml`
and `ignores.yaml` in `~/shellclear/`. *Recommendation:* when that directory
exists and `~/.shellclear/config.yaml` does not, print a one-time hint.
`config init --import-legacy` copies `sensitive-patterns.yaml` to
`rules.d/legacy.yaml` and merges `ignores.yaml` into `ignore:` in
`config.yaml`. Never read the legacy path silently.

**Q6. zsh lock.** zsh holds `<HISTFILE>.LOCK` while it writes. If `clear`,
`stash` and `pop` take the same lock (create a `.LOCK` symlink with
`O_EXCL` semantics, wait up to 2 s), zsh sessions pause instead of racing us.
*Recommendation:* yes, for zsh only. Other shells rely on the step-5 check.

**Q7. Backups contain the secrets.** `clear` moves secrets from history into
`backups/`. *Recommendation:* add `restore --prune [--keep N]` and print the
backup path plus a one-line reminder after `clear`. No automatic deletion.

**Q8. Stash name collisions.** `--file` can pass two files with the same
basename from different directories. *Recommendation:* when a collision
happens, name the stash `<basename>.<first 8 hex chars of sha256(realpath)>`.
The sidecar keeps the real source path either way.

**Q9. Go version.** Go 1.27.1 is installed locally. *Recommendation:*
`go 1.22` in `go.mod` as the spec requires, CI on `1.22.x` and `stable`.

### Verification against real shells

- The zsh and bash golden files in `testdata/history/` were written by
  zsh 5.9 (`print -rs` + `fc -W`) and bash 5.3 (`history -s` + `history -w`).
- One real file already disproves the "odd number of backslashes" rule.
  zsh writes `curl … \` followed by a newline as two backslashes and a
  newline, and still reads it as a continuation.
- A read-only check on a copy of a real `~/.zsh_history` (4,923 records)
  matched zsh's own decoding for every record. Only hashes were compared,
  and no commands were printed.
- fish and PowerShell are not installed locally. Their fixtures were written
  by hand from `HistoryItem::write_to` and `WriteHistoryRange`. The fuzz
  target `FuzzShellWriters` reimplements each shell's writer and checks that
  the codec decodes its output back to the same command.

# shellclear

[![CI](https://github.com/devops247-online/shellclear/actions/workflows/ci.yml/badge.svg)](https://github.com/devops247-online/shellclear/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/devops247-online/shellclear)](https://github.com/devops247-online/shellclear/releases)
[![License](https://img.shields.io/github/license/devops247-online/shellclear)](LICENSE)

**Find secrets in your shell history and remove them without breaking the history file.**

Tokens, passwords and keys end up in shell history all the time: `export GITHUB_TOKEN=…`,
`mysql -p…`, `curl -H "Authorization: Bearer …"`, a `printf` into `~/.netrc`.
`shellclear` finds them in zsh, bash, fish and PowerShell history, masks or removes
them, and can hide your history before you share your screen.

```
$ shellclear find

~/.zsh_history (zsh) — 2 commands
  L4983   2026-09-21 17:13  HIGH    atlassian_api_token
           printf 'machine example.atlassian.net\n  login me@example.org\n  password ATAT****C05D\n' >> ~/.netrc
  L5012   2026-09-22 09:41  HIGH    github_env_token
           export GITHUB_TOKEN=ghp_****x1Yz

🔑 2 sensitive commands in 1 file (high: 2, medium: 0, low: 0).

$ shellclear clear
~/.zsh_history (zsh): 2 commands to mask
Mask 2 commands? [y/N] y
~/.zsh_history: masked 2 commands
  backup: zsh/.zsh_history.20260923T185808.bak
```

## Why this rewrite

`shellclear` started as a Go rewrite of
[rusty-ferris-club/shellclear](https://github.com/rusty-ferris-club/shellclear). It keeps
the idea, the commands and the custom pattern format, and puts the safety of your
history file first:

- **Nothing else in the file changes.** Only the bytes of an affected command are
  edited. Every other record is written back byte for byte, including zsh's
  metafied non-ASCII text, fish `paths:` entries, timestamps and multi-line commands.
- **Secrets are masked completely.** Every match in a command is replaced by
  `[REDACTED:<rule_id>]`. Partial masks such as `T87E****` are not used.
- **Writes are atomic.** The new content goes to a temporary file in the same directory,
  which is synced and renamed over the original. Symlinks such as dotfiles managed
  with stow or chezmoi stay symlinks, and file permissions are kept.
- **A backup is always taken** unless you pass `--no-backup`.
- **Running shells are respected.** `shellclear` takes the same lock zsh uses. If a
  shell appends commands while `clear` runs, they are cleaned too. If the file is
  rewritten meanwhile, `clear` stops without writing anything.
- **Files without findings are never touched.** Their modification time and inode stay
  the same.
- **Raw secrets are never printed.** They do not appear on the terminal, in JSON output,
  in logs, in error messages or in the cache.

## Install

**Homebrew** (macOS and Linux, from v0.1.0). The formula builds `shellclear` from the
tagged source, so there is no unsigned binary for Gatekeeper to quarantine:

```sh
brew install devops247-online/tap/shellclear
```

**Go** (1.22 or later):

```sh
go install github.com/devops247-online/shellclear/cmd/shellclear@latest
```

**Prebuilt binaries and packages.** Every
[release](https://github.com/devops247-online/shellclear/releases) includes archives for
macOS, Linux and Windows, plus `.deb`, `.rpm` and `.apk` packages and `checksums.txt`.
Each artifact has a signed build provenance attestation:

```sh
gh attestation verify shellclear_0.1.0_linux_amd64.tar.gz -R devops247-online/shellclear
sudo apt install ./shellclear_0.1.0_amd64.deb
```

macOS marks binaries downloaded with a browser as quarantined. The release binaries are
not notarized, so remove the mark after checking the attestation:
`xattr -d com.apple.quarantine ./shellclear`.

**From source:**

```sh
git clone https://github.com/devops247-online/shellclear
cd shellclear
make build              # ./bin/shellclear
make install            # into $(go env GOPATH)/bin
```

> **Replacing the original shellclear?** Remove the old binary first, for example
> `brew uninstall shellclear` or `sudo rm /usr/local/bin/shellclear`. A line such as
> `eval $(shellclear --init-shell)` in your shell profile keeps working without changes.

## Quick start

```sh
shellclear find              # what is in your history?
shellclear clear --dry-run   # what would change?
shellclear clear             # mask it (asks first, backs up first)
exec zsh                     # restart open shells (see "Limitations")
```

## Commands

| Command | What it does |
|---|---|
| `find` | List commands that contain secrets. |
| `clear` | Mask secrets, or remove whole commands with `--remove`. |
| `stash` / `pop` | Move history aside before a demo or screen share, then bring it back. |
| `restore` | List backups, restore one, or delete old ones. |
| `rules` | List active detection rules. |
| `config` | Create, validate or locate the configuration. |
| `motd` | One-line reminder for shell start-up. Prints nothing when history is clean. |

Global flags work before or after the command name:

```
--file PATH        use this history file instead of auto-detection (repeatable)
--shell NAME       format of --file: zsh, bash, fish or powershell
--config-dir DIR   config and state directory (default: $SHELLCLEAR_HOME or ~/.shellclear)
--no-color         disable colors (NO_COLOR is honored too)
--no-banner        do not print the logo
-v, --verbose      print progress to stderr
```

### find

```sh
shellclear find                         # grouped by file
shellclear find --format table
shellclear find --format json           # stable schema, see below
shellclear find --severity high         # only high severity
shellclear find --file ./old_history --shell bash
```

Secrets are shown masked. Secrets of 20 or more characters keep their first and
last 4 characters. Secrets of 12 to 19 characters keep the first 4. Shorter ones
are fully hidden.

The exit code is `1` when secrets are found, so `find` works in scripts and CI.

JSON output:

```json
{
  "version": 1,
  "files": [
    {
      "path": "/home/me/.zsh_history",
      "shell": "zsh",
      "findings": [
        {
          "line": 5012,
          "time": "2026-09-22T09:41:07+03:00",
          "rule_id": "github_env_token",
          "rule_name": "GitHub Env Token",
          "severity": "high",
          "command_masked": "export GITHUB_TOKEN=ghp_****x1Yz"
        }
      ]
    }
  ],
  "summary": { "files_scanned": 1, "files_with_findings": 1, "commands": 1, "findings": 1,
               "by_severity": { "high": 1, "medium": 0, "low": 0 } }
}
```

### clear

```sh
shellclear clear --dry-run     # show before/after for every command, write nothing
shellclear clear               # mask secrets after a [y/N] prompt
shellclear clear --yes         # no prompt (required when stdin is not a terminal)
shellclear clear --remove      # delete whole commands instead of masking
shellclear clear --no-backup   # skip the backup
```

A command such as `export GITHUB_TOKEN=ghp_…` becomes
`export GITHUB_TOKEN=[REDACTED:github_env_token]`. Some records cannot be edited safely,
for example a malformed last line. `clear` leaves those unchanged, names their line
numbers and exits with `1`.

### stash and pop

```sh
shellclear stash   # history moves to ~/.shellclear/stash, the file becomes empty
# ... demo ...
shellclear pop     # history comes back; commands run in between are kept
```

`stash` refuses to run when a stash already exists, so you cannot lose one. The current
shell still remembers its history in memory. `stash` prints the command that clears it,
for example `fc -p` in zsh.

### restore

```sh
shellclear restore                                          # list backups
shellclear restore zsh/.zsh_history.20260923T185808.bak     # restore one
shellclear restore --prune --keep 3                         # keep the 3 newest per file
shellclear restore --prune --keep 0                         # delete all backups
```

Before restoring, the current content is backed up. The backup is also checked
against its SHA-256 checksum.

## Shell start-up reminder

Add one line to your shell profile. It prints a single line when your history contains
secrets and nothing otherwise:

```sh
# ~/.zshrc or ~/.bashrc
shellclear motd

# ~/.config/fish/config.fish
shellclear motd
```

```
⚠ shellclear: 3 sensitive commands found in history — run 'shellclear find'
```

Repeated runs take a few milliseconds. A per-file cache in
`~/.shellclear/cache.json` holds only sizes, hashes and counts, never commands. When
a history file only grew, only the new records are scanned. `motd` never fails and
always exits with `0`, so it cannot break your shell start-up.

`shellclear --init-shell` does the same and prints to stderr, like the original tool.

## Supported history files

| Shell | Files |
|---|---|
| zsh | `$HISTFILE`, `~/.zsh_history`, `~/.histfile`, `~/.zsh_sessions/*.history` (macOS Terminal) |
| bash | `$HISTFILE`, `~/.bash_history` (with or without `HISTTIMEFORMAT` timestamps) |
| fish | `${XDG_DATA_HOME:-~/.local/share}/fish/fish_history` |
| PowerShell | PSReadLine `ConsoleHost_history.txt` on macOS, Linux and Windows |

The format handling follows the shells' own source code. That includes zsh
metafication, extended history and backslash continuations, bash multi-line records,
fish escaping and PSReadLine backtick continuations.

## Detection rules

There are 60+ built-in rules: all patterns of the original shellclear, plus current
formats. These include GitHub fine-grained and GitLab tokens, AWS, GCP, Azure,
DigitalOcean, Stripe, Slack, Telegram, npm, PyPI, Vault, Terraform Cloud, Atlassian,
OpenAI and Anthropic keys, PEM private keys, JWTs, `Authorization` headers,
credentials in URLs, `.netrc` entries, and password or token flags of common CLIs
(`--password`, `mysql -p…`, `docker login -p`, `sshpass -p`, `htpasswd -b`,
`kubectl --token`, …).

A match is never reported when the value is not a real secret:

- shell expansions such as `$VAR`, `${VAR}`, `$(cmd)` and `` `cmd` ``;
- redirections and placeholders such as `<token>`, `xxx…`, `changeme`, `your_…`, or
  anything containing `example`;
- values that are already masked (`****`, `[REDACTED:…]`);
- values shorter than 4 characters.

```sh
shellclear rules                  # id, severity, name, source
shellclear rules --format json
```

## Configuration

Everything lives in one directory, `~/.shellclear` by default. Override it with
`$SHELLCLEAR_HOME` or `--config-dir`.

```
~/.shellclear/
├── config.yaml        settings
├── rules.d/*.yaml     your own rules
├── backups/           backups with checksums (0600, directory 0700)
├── stash/             stashed history
└── cache.json         motd cache
```

```sh
shellclear config init       # create config.yaml and rules.d/ with examples
shellclear config validate   # check everything, including every rules.d file
shellclear config path
```

`config.yaml`:

```yaml
version: 1
ignore:                 # rule ids to disable
  - jwt
allow:                  # commands matching these are never reported
  - '^export GITHUB_TOKEN=\$\(gh auth token\)$'
backups:
  keep: 10              # default for 'restore --prune'
```

### Custom rules

Put YAML files in `~/.shellclear/rules.d/`. The format is compatible with the original
shellclear. Its `sensitive-patterns.yaml` works unchanged.

```yaml
- id: my_company_token
  name: My Company Token
  test: 'mycorp_[a-z0-9]{32}'     # RE2 syntax (Go regexp)
  secret_group: 0                 # 0 = whole match, N = capture group N
  severity: high                  # high | medium | low (default: medium)
  keywords: [mycorp_]             # optional: run the regex only if one of these is present
```

A rule with the id of a built-in rule replaces the built-in one. To bring over files
from the original tool's `~/shellclear` directory, run:

```sh
shellclear config init --import-legacy
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success, no secrets found. |
| `1` | `find` found secrets, or `clear` left some commands unchanged. |
| `2` | Error: I/O, invalid configuration or invalid arguments. |

## Limitations

- **Running shells keep their history in memory.** `shellclear` edits files, not
  processes. `history` in an open terminal still shows the old commands. A shell may
  also write them back later: zsh with `SHARE_HISTORY` does this when it trims the
  file to `SAVEHIST`. After `clear`, restart every open shell with `exec zsh`, or
  `history -c; history -r` in bash, or `history merge` in fish. This includes IDE
  terminals and tmux panes.
- **Backups contain the secrets.** Delete them with `shellclear restore --prune --keep 0`
  once you are sure.
- **Other copies are out of reach.** Time Machine or other backups, terminal
  scrollback, tmux or screen logs, and remote machines you ssh'd into are not touched.
- **A leaked secret stays leaked.** Removing it from history does not make it safe.
  Rotate it.

## Development

```sh
make test       # go test -race -cover ./...
make lint       # golangci-lint
make fuzz       # fuzz every history codec (FUZZTIME=30s each)
make bench      # BenchmarkScan100k
make snapshot   # build all release artifacts into dist/ without publishing
```

Releases are cut by pushing a `vX.Y.Z` tag. GoReleaser builds the artifacts, the release
workflow attests them and updates the Homebrew formula in
[devops247-online/homebrew-tap](https://github.com/devops247-online/homebrew-tap).

Scanning 100,000 history records with all rules takes about 26 ms on an Apple M4 Max.

The project uses only the Go standard library plus `gopkg.in/yaml.v3`. Commit messages
follow [Conventional Commits](https://www.conventionalcommits.org/).

## Acknowledgements

This project is inspired by
[shellclear](https://github.com/rusty-ferris-club/shellclear) by
**Elad Kaplan** ([@kaplanelad](https://github.com/kaplanelad)) and the
[rusty-ferris-club](https://github.com/rusty-ferris-club) contributors. Thank you for the
idea, the command design and the sensitive pattern collection that this project builds
on. The ported patterns and their test cases are used under the Apache License 2.0; see
[NOTICE](NOTICE).

## License

[Apache License 2.0](LICENSE)

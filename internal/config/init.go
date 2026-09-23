package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/devops247-online/shellclear/internal/safefile"
)

// Legacy file names used by rusty-ferris-club/shellclear in ~/shellclear.
const (
	LegacyDirName  = "shellclear"
	LegacyPatterns = "sensitive-patterns.yaml"
	LegacyIgnores  = "ignores.yaml"
	legacyRules    = "legacy.yaml"
	exampleRules   = "custom.yaml"
)

const configTemplate = `# shellclear configuration.
version: 1

# Rule ids to disable (see 'shellclear rules').
ignore: []

# Regular expressions for commands that must never be reported.
allow: []
#  - '^export GITHUB_TOKEN=\$\(gh auth token\)$'

backups:
  # Backups to keep per history file for 'shellclear restore --prune'
  # (0 = no default; pass --keep).
  keep: 10
`

const rulesTemplate = `# Custom rules. Every *.yaml file in this directory is loaded in name order.
# A rule with the id of a built-in rule replaces it.
#
# - id: my_company_token
#   name: My Company Token
#   test: 'mycorp_[a-z0-9]{32}'
#   secret_group: 0          # 0 = whole match, N = capture group N
#   severity: high           # high | medium | low
#   keywords: [mycorp_]      # optional prefilter, lower case
`

// LegacyDir returns the directory used by the original shellclear.
func LegacyDir(home string) string { return filepath.Join(home, LegacyDirName) }

// HasLegacy reports whether the original tool's custom files exist.
func HasLegacy(home string) bool {
	for _, n := range []string{LegacyPatterns, LegacyIgnores} {
		if _, err := os.Stat(filepath.Join(LegacyDir(home), n)); err == nil {
			return true
		}
	}
	return false
}

// InitResult lists what Init did.
type InitResult struct {
	Created  []string
	Existing []string
	Imported []string
}

// Init creates the config directory, config.yaml and rules.d with templates.
// Existing files are never overwritten. With importLegacy, files from the
// original tool's ~/shellclear are imported: patterns into rules.d/legacy.yaml
// and ignores into the ignore list of config.yaml.
func Init(dir, home string, importLegacy bool) (InitResult, error) {
	var res InitResult
	if err := safefile.MkdirPrivate(dir); err != nil {
		return res, err
	}
	if err := safefile.MkdirPrivate(filepath.Join(dir, RulesDir)); err != nil {
		return res, err
	}
	create := func(path string, data []byte) error {
		err := safefile.WriteNew(path, data, 0o600)
		switch {
		case err == nil:
			res.Created = append(res.Created, path)
		case errors.Is(err, fs.ErrExist):
			res.Existing = append(res.Existing, path)
		default:
			return err
		}
		return nil
	}

	var ignores []string
	if importLegacy {
		legacy := LegacyDir(home)
		if b, err := os.ReadFile(filepath.Join(legacy, LegacyPatterns)); err == nil {
			if _, err := loadRulesBytes(b, filepath.Join(legacy, LegacyPatterns)); err != nil {
				return res, err
			}
			dst := filepath.Join(dir, RulesDir, legacyRules)
			before := len(res.Created)
			if err := create(dst, b); err != nil {
				return res, err
			}
			if len(res.Created) > before {
				res.Imported = append(res.Imported, filepath.Join(legacy, LegacyPatterns))
			}
		}
		if b, err := os.ReadFile(filepath.Join(legacy, LegacyIgnores)); err == nil {
			if err := yaml.Unmarshal(b, &ignores); err != nil {
				return res, fmt.Errorf("%s: %w", filepath.Join(legacy, LegacyIgnores), err)
			}
			res.Imported = append(res.Imported, filepath.Join(legacy, LegacyIgnores))
		}
	}

	cfgPath := filepath.Join(dir, FileName)
	tmpl := configTemplate
	if len(ignores) > 0 {
		tmpl = strings.Replace(tmpl, "ignore: []", "ignore:\n  - "+strings.Join(ignores, "\n  - "), 1)
	}
	before := len(res.Existing)
	if err := create(cfgPath, []byte(tmpl)); err != nil {
		return res, err
	}
	if len(res.Existing) > before && len(ignores) > 0 {
		if err := mergeIgnores(cfgPath, ignores); err != nil {
			return res, err
		}
	}
	if err := create(filepath.Join(dir, RulesDir, exampleRules), []byte(rulesTemplate)); err != nil {
		return res, err
	}
	return res, nil
}

// mergeIgnores adds ids to the ignore list of an existing config.yaml,
// keeping its comments.
func mergeIgnores(path string, ids []string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("%s: expected a mapping", path)
	}
	doc := root.Content[0]
	var list *yaml.Node
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value == "ignore" {
			list = doc.Content[i+1]
		}
	}
	if list == nil {
		list = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		doc.Content = append(doc.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "ignore"}, list)
	}
	if list.Kind != yaml.SequenceNode {
		return fmt.Errorf("%s: ignore must be a list", path)
	}
	have := map[string]bool{}
	for _, n := range list.Content {
		have[n.Value] = true
	}
	list.Style = 0
	for _, id := range ids {
		if !have[id] {
			list.Content = append(list.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: id})
		}
	}
	out, err := yaml.Marshal(&root)
	if err != nil {
		return err
	}
	return safefile.WriteAtomic(path, out, 0o600)
}

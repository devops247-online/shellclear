// Package config loads user settings and custom rules from the state
// directory (by default ~/.shellclear).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/devops247-online/shellclear/internal/rules"
)

// File and directory names inside the config directory.
const (
	FileName  = "config.yaml"
	RulesDir  = "rules.d"
	EnvHome   = "SHELLCLEAR_HOME"
	DirName   = ".shellclear"
	version1  = 1
	rulesGlob = "*.yaml"
)

// Config is the effective user configuration.
type Config struct {
	Dir         string
	Ignore      []string         // rule ids to disable
	Allow       []*regexp.Regexp // commands matching any of these are never reported
	AllowRaw    []string         // the allow patterns as written
	BackupsKeep int              // 0 = keep all
	CustomRules [][]rules.Rule   // one list per file in rules.d, in lexical order
	Warnings    []string         // problems that do not stop the program
}

type fileYAML struct {
	Version int      `yaml:"version"`
	Ignore  []string `yaml:"ignore"`
	Allow   []string `yaml:"allow"`
	Backups struct {
		Keep int `yaml:"keep"`
	} `yaml:"backups"`
}

// Dir resolves the config directory: flag value, then $SHELLCLEAR_HOME, then
// ~/.shellclear.
func Dir(flagValue string, getenv func(string) string, home string) string {
	if flagValue != "" {
		return flagValue
	}
	if v := getenv(EnvHome); v != "" {
		return v
	}
	return filepath.Join(home, DirName)
}

// Load reads config.yaml and rules.d/*.yaml from dir. Missing files are not
// an error. Unknown keys in config.yaml become warnings; use Validate to
// treat them as errors.
func Load(dir string) (*Config, error) {
	cfg := &Config{Dir: dir}
	path := filepath.Join(dir, FileName)
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("read %s: %w", path, err)
	default:
		unknown, err := parse(path, data, cfg)
		if err != nil {
			return nil, err
		}
		for _, k := range unknown {
			cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("%s: unknown key %q is ignored", path, k))
		}
	}

	files, err := filepath.Glob(filepath.Join(dir, RulesDir, rulesGlob))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	for _, f := range files {
		rs, err := loadRules(f)
		if err != nil {
			return nil, err
		}
		cfg.CustomRules = append(cfg.CustomRules, rs)
	}
	return cfg, nil
}

// Validate loads the configuration strictly and returns every problem,
// including ignored ids that match no rule.
func Validate(dir string) (*Config, []error) {
	cfg, err := Load(dir)
	if err != nil {
		return nil, []error{err}
	}
	if _, err := cfg.RuleSet(); err != nil {
		return cfg, []error{err}
	}
	var errs []error
	for _, w := range cfg.Warnings {
		errs = append(errs, errors.New(w))
	}
	return cfg, errs
}

func loadRules(path string) ([]rules.Rule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return loadRulesBytes(b, path)
}

func loadRulesBytes(b []byte, source string) ([]rules.Rule, error) {
	return rules.Load(bytes.NewReader(b), source)
}

// parse fills cfg from config.yaml and returns unknown top-level keys.
func parse(path string, data []byte, cfg *Config) ([]string, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(root.Content) == 0 {
		return nil, nil
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s:%d: expected a mapping", path, doc.Line)
	}
	known := map[string]bool{"version": true, "ignore": true, "allow": true, "backups": true}
	var unknown []string
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if k := doc.Content[i].Value; !known[k] {
			unknown = append(unknown, k)
		}
	}
	var y fileYAML
	if err := doc.Decode(&y); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if y.Version != 0 && y.Version != version1 {
		return nil, fmt.Errorf("%s: unsupported version %d (want %d)", path, y.Version, version1)
	}
	if y.Backups.Keep < 0 {
		return nil, fmt.Errorf("%s: backups.keep must not be negative", path)
	}
	for _, id := range y.Ignore {
		if id = strings.ToLower(strings.TrimSpace(id)); id != "" {
			cfg.Ignore = append(cfg.Ignore, id)
		}
	}
	for _, a := range y.Allow {
		re, err := regexp.Compile(a)
		if err != nil {
			return nil, fmt.Errorf("%s: allow %q: %w", path, a, err)
		}
		cfg.Allow = append(cfg.Allow, re)
		cfg.AllowRaw = append(cfg.AllowRaw, a)
	}
	cfg.BackupsKeep = y.Backups.Keep
	return unknown, nil
}

// RuleSet builds the active rule set: built-in rules, then custom files in
// order (a custom rule replaces a built-in rule with the same id), minus the
// ignored ids. Ignored ids that match no rule become warnings.
func (c *Config) RuleSet() (*rules.Set, error) {
	builtin, err := rules.Builtin()
	if err != nil {
		return nil, fmt.Errorf("built-in rules: %w", err)
	}
	lists := append([][]rules.Rule{builtin}, c.CustomRules...)
	set, err := rules.NewSet(c.Ignore, lists...)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, l := range lists {
		for _, r := range l {
			known[r.ID] = true
		}
	}
	for _, id := range c.Ignore {
		if !known[id] {
			c.Warnings = append(c.Warnings, fmt.Sprintf("ignore: no rule with id %q", id))
		}
	}
	return set, nil
}

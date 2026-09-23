// Package rules loads secret detection rules and finds secrets in commands.
package rules

import (
	_ "embed"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed patterns.yaml
var builtinYAML []byte

// BuiltinSource is the Source of rules compiled into the binary.
const BuiltinSource = "builtin"

// Severity ranks how dangerous a leaked secret is.
type Severity int

// Severity levels, ordered from least to most severe.
const (
	Low Severity = iota + 1
	Medium
	High
)

// ParseSeverity converts "low", "medium" or "high" into a Severity.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return Low, nil
	case "", "medium":
		return Medium, nil
	case "high":
		return High, nil
	}
	return 0, fmt.Errorf("unknown severity %q (want high, medium or low)", s)
}

func (s Severity) String() string {
	switch s {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	}
	return "unknown"
}

// Rule is one compiled detection rule.
type Rule struct {
	ID          string
	Name        string
	Test        string
	SecretGroup int
	Severity    Severity
	Keywords    []string // lower-cased
	Source      string   // BuiltinSource or a file path

	re *regexp.Regexp
}

// Match is one secret found in a command.
type Match struct {
	Start, End int    // byte offsets of the secret in the command
	Rule       *Rule  // the most severe rule that matched this range
	Secret     string // the raw secret; never print or log it
}

// ruleYAML is the on-disk form of a rule.
type ruleYAML struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Test        string   `yaml:"test"`
	SecretGroup int      `yaml:"secret_group"`
	Severity    string   `yaml:"severity"`
	Keywords    []string `yaml:"keywords"`
}

var idRe = regexp.MustCompile(`^[a-z0-9_]+$`)

// Builtin returns the rules compiled into the binary.
func Builtin() ([]Rule, error) {
	return Load(strings.NewReader(string(builtinYAML)), BuiltinSource)
}

// Load reads a list of rules in YAML. Errors name the source, the line and
// the rule id.
func Load(r io.Reader, source string) ([]Rule, error) {
	var doc yaml.Node
	if err := yaml.NewDecoder(r).Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	if len(doc.Content) == 0 {
		return nil, nil
	}
	list := doc.Content[0]
	if list.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%s:%d: expected a list of rules", source, list.Line)
	}

	var out []Rule
	seen := map[string]int{}
	for _, n := range list.Content {
		var y ruleYAML
		if err := decodeStrict(n, &y); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", source, n.Line, err)
		}
		rule, err := compile(y, source)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", source, n.Line, err)
		}
		if line, dup := seen[rule.ID]; dup {
			return nil, fmt.Errorf("%s:%d: rule %q: duplicate id (first defined on line %d)", source, n.Line, rule.ID, line)
		}
		seen[rule.ID] = n.Line
		out = append(out, rule)
	}
	return out, nil
}

// decodeStrict decodes a mapping node and rejects unknown keys.
func decodeStrict(n *yaml.Node, y *ruleYAML) error {
	if n.Kind != yaml.MappingNode {
		return errors.New("rule must be a mapping")
	}
	known := map[string]bool{"id": true, "name": true, "test": true, "secret_group": true, "severity": true, "keywords": true}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if k := n.Content[i].Value; !known[k] {
			return fmt.Errorf("unknown field %q", k)
		}
	}
	return n.Decode(y)
}

func compile(y ruleYAML, source string) (Rule, error) {
	id := strings.ToLower(strings.TrimSpace(y.ID))
	if id == "" {
		id = idFromName(y.Name)
	}
	label := id
	if label == "" {
		label = y.Name
	}
	if id == "" {
		return Rule{}, errors.New("rule needs an id or a name")
	}
	if !idRe.MatchString(id) {
		return Rule{}, fmt.Errorf("rule %q: id must contain only a-z, 0-9 and _", label)
	}
	if strings.TrimSpace(y.Test) == "" {
		return Rule{}, fmt.Errorf("rule %q: test is empty", label)
	}
	re, err := regexp.Compile(y.Test)
	if err != nil {
		return Rule{}, fmt.Errorf("rule %q: invalid regex: %w", label, err)
	}
	if y.SecretGroup < 0 || y.SecretGroup > re.NumSubexp() {
		return Rule{}, fmt.Errorf("rule %q: secret_group %d but the regex has %d groups", label, y.SecretGroup, re.NumSubexp())
	}
	sev, err := ParseSeverity(y.Severity)
	if err != nil {
		return Rule{}, fmt.Errorf("rule %q: %w", label, err)
	}
	var kws []string
	for _, k := range y.Keywords {
		if k = strings.ToLower(k); k != "" {
			kws = append(kws, k)
		}
	}
	name := y.Name
	if name == "" {
		name = id
	}
	return Rule{
		ID: id, Name: name, Test: y.Test, SecretGroup: y.SecretGroup,
		Severity: sev, Keywords: kws, Source: source, re: re,
	}, nil
}

// idFromName derives an id for original-format files that have none.
func idFromName(name string) string {
	var b strings.Builder
	underscore := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			underscore = false
		} else if !underscore && b.Len() > 0 {
			b.WriteByte('_')
			underscore = true
		}
	}
	return strings.TrimSuffix(b.String(), "_")
}

// Set is an ordered collection of rules ready for matching.
type Set struct {
	rules []*Rule
}

// NewSet combines rule lists in order. A later rule with an existing id
// replaces the earlier one in place. Rules whose id is in ignore are dropped.
func NewSet(ignore []string, lists ...[]Rule) (*Set, error) {
	skip := map[string]bool{}
	for _, id := range ignore {
		skip[strings.ToLower(strings.TrimSpace(id))] = true
	}
	var ordered []*Rule
	index := map[string]int{}
	for _, list := range lists {
		for i := range list {
			r := list[i]
			if r.re == nil {
				return nil, fmt.Errorf("rule %q is not compiled", r.ID)
			}
			if at, ok := index[r.ID]; ok {
				ordered[at] = &r
				continue
			}
			index[r.ID] = len(ordered)
			ordered = append(ordered, &r)
		}
	}
	s := &Set{}
	for _, r := range ordered {
		if !skip[r.ID] {
			s.rules = append(s.rules, r)
		}
	}
	return s, nil
}

// Rules returns the active rules in evaluation order.
func (s *Set) Rules() []*Rule { return s.rules }

// candidate is a raw match before overlap merging.
type candidate struct {
	start, end int
	rank       int // index in s.rules
}

// Find returns all secrets in cmd, sorted by position. Overlapping matches
// from different rules are merged into one range credited to the most severe
// rule (the earlier rule on a tie). Matches that fail ValidSecret are dropped.
func (s *Set) Find(cmd string) []Match {
	return s.find(cmd, strings.ToLower(cmd))
}

// FindWithLower is Find for callers that already hold the lower-cased command.
func (s *Set) FindWithLower(cmd, lower string) []Match { return s.find(cmd, lower) }

func (s *Set) find(cmd, lower string) []Match {
	var cands []candidate
	for i, r := range s.rules {
		if !r.applies(lower) {
			continue
		}
		for _, m := range r.re.FindAllStringSubmatchIndex(cmd, -1) {
			start, end := m[2*r.SecretGroup], m[2*r.SecretGroup+1]
			if start < 0 || end <= start {
				continue
			}
			start, end = trimQuotes(cmd, start, end)
			if !ValidSecret(cmd[start:end]) {
				continue
			}
			cands = append(cands, candidate{start, end, i})
		}
	}
	if len(cands) == 0 {
		return nil
	}
	sort.Slice(cands, func(a, b int) bool {
		if cands[a].start != cands[b].start {
			return cands[a].start < cands[b].start
		}
		return cands[a].end > cands[b].end
	})

	var out []Match
	cur := cands[0]
	for _, c := range cands[1:] {
		if c.start < cur.end {
			if c.end > cur.end {
				cur.end = c.end
			}
			if s.better(c.rank, cur.rank) {
				cur.rank = c.rank
			}
			continue
		}
		out = append(out, s.match(cmd, cur))
		cur = c
	}
	return append(out, s.match(cmd, cur))
}

func (s *Set) better(a, b int) bool {
	ra, rb := s.rules[a], s.rules[b]
	if ra.Severity != rb.Severity {
		return ra.Severity > rb.Severity
	}
	return a < b
}

func (s *Set) match(cmd string, c candidate) Match {
	return Match{Start: c.start, End: c.end, Rule: s.rules[c.rank], Secret: cmd[c.start:c.end]}
}

func (r *Rule) applies(lower string) bool {
	if len(r.Keywords) == 0 {
		return true
	}
	for _, k := range r.Keywords {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}

// MatchRule runs a single rule without merging; used by tests and `rules`.
func (r *Rule) MatchRule(cmd string) []string {
	var out []string
	for _, m := range r.re.FindAllStringSubmatchIndex(cmd, -1) {
		start, end := m[2*r.SecretGroup], m[2*r.SecretGroup+1]
		if start < 0 || end <= start {
			continue
		}
		start, end = trimQuotes(cmd, start, end)
		if ValidSecret(cmd[start:end]) {
			out = append(out, cmd[start:end])
		}
	}
	return out
}

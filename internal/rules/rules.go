// Package rules loads secret detection rules and finds secrets in commands.
package rules

import (
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:generate go run gen_builtin.go

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

	c *compiledRule // shared by copies of the rule
}

// compiledRule holds the regex and its search plan. Built-in rules compile on
// first use: a clean history never needs most of them, and `motd` runs at
// every shell start-up. Custom rules compile at load time so that errors are
// reported where the rule is defined.
type compiledRule struct {
	once     sync.Once
	expr     string
	keywords []string
	re       *regexp.Regexp
	plan     searchPlan
}

func (c *compiledRule) get() *compiledRule {
	c.once.Do(func() {
		if c.re == nil {
			// Built-in patterns are compiled and validated by tests.
			c.re = regexp.MustCompile(c.expr)
		}
		c.plan = newSearchPlan(c.expr, c.keywords)
	})
	return c
}

func (r *Rule) regexp() *regexp.Regexp { return r.c.get().re }

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

// Builtin returns the rules compiled into the binary. They come from
// patterns.yaml through builtin_rules.go, which go generate keeps in sync.
func Builtin() ([]Rule, error) {
	out := make([]Rule, 0, len(builtinRules))
	seen := make(map[string]bool, len(builtinRules))
	for _, y := range builtinRules {
		r, err := compile(y, BuiltinSource)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", BuiltinSource, err)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("%s: rule %q: duplicate id", BuiltinSource, r.ID)
		}
		seen[r.ID] = true
		out = append(out, r)
	}
	return out, nil
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
	var re *regexp.Regexp
	if source != BuiltinSource {
		var err error
		if re, err = regexp.Compile(y.Test); err != nil {
			return Rule{}, fmt.Errorf("rule %q: invalid regex: %w", label, err)
		}
		if y.SecretGroup < 0 || y.SecretGroup > re.NumSubexp() {
			return Rule{}, fmt.Errorf("rule %q: secret_group %d but the regex has %d groups", label, y.SecretGroup, re.NumSubexp())
		}
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
		Severity: sev, Keywords: kws, Source: source,
		c: &compiledRule{expr: y.Test, keywords: kws, re: re},
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

	once sync.Once
	// km finds every keyword of every rule in one pass; nil when a keyword
	// is not ASCII, and then each rule checks its keywords on its own.
	km      *keywordMatcher
	kwRules [][]int32 // keyword index -> indexes of the rules that use it
	ruleKWs [][]int32 // rule index -> its keyword indexes
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
			if r.c == nil {
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
//
// A rule runs only when strings.ToLower(cmd) contains one of its keywords.
// All keywords are found in one pass, and where the rule's regex allows it,
// the regex runs only on the parts of cmd around a keyword (see searchPlan).
// The result is always the same as running every applicable regex over the
// whole command.
func (s *Set) Find(cmd string) []Match {
	s.once.Do(s.prepare)
	if s.km == nil || len(cmd) > math.MaxInt32 {
		return s.findPlain(cmd)
	}
	sc := getScratch(len(s.rules))
	defer putScratch(sc)

	var high bool
	sc.hits, high = s.km.scan(cmd, sc.hits[:0])
	if high && hasFoldExotic(cmd) {
		return s.findPlain(cmd)
	}
	for _, h := range sc.hits {
		for _, ri := range s.kwRules[h.kw] {
			sc.mark[ri] = sc.epoch
		}
	}

	var cands []candidate
	for i, r := range s.rules {
		if len(r.Keywords) > 0 && sc.mark[i] != sc.epoch {
			continue
		}
		c := r.c.get()
		if c.plan.segment {
			cands = s.findSegments(cmd, i, c, sc, cands)
		} else if c.plan.satisfies(cmd) {
			cands = appendMatches(cands, cmd, 0, len(cmd), r, c.re, i)
		}
	}
	return s.merge(cmd, cands)
}

// findPlain is Find without the shared keyword pass: each rule checks its
// keywords in the lower-cased command and runs over the whole command.
func (s *Set) findPlain(cmd string) []Match {
	lower := strings.ToLower(cmd)
	var cands []candidate
	for i, r := range s.rules {
		if !r.applies(lower) {
			continue
		}
		cands = appendMatches(cands, cmd, 0, len(cmd), r, r.regexp(), i)
	}
	return s.merge(cmd, cands)
}

// findSegments runs rule ri only on the stretches of cmd between stop bytes
// that contain one of its keywords. No match can cross a stop byte and every
// match contains a keyword, so no match is lost; stop bytes are not word
// characters, so \b sees the same thing at a stretch's edge as in cmd.
func (s *Set) findSegments(cmd string, ri int, c *compiledRule, sc *scratch, cands []candidate) []candidate {
	sc.spans = sc.spans[:0]
	kws := s.ruleKWs[ri]
	for _, h := range sc.hits {
		if slices.Contains(kws, h.kw) {
			end := int(h.end)
			sc.spans = append(sc.spans, span{end - s.km.lens[h.kw], end})
		}
	}
	slices.SortFunc(sc.spans, func(a, b span) int { return a.start - b.start })

	stop := &c.plan.stop
	pos := 0 // cmd[:pos] has been searched or holds no keyword
	for _, sp := range sc.spans {
		if sp.end <= pos {
			continue
		}
		a := max(sp.start, pos)
		for a > pos && !stop[cmd[a-1]] {
			a--
		}
		b := sp.end
		for b < len(cmd) && !stop[cmd[b]] {
			b++
		}
		if c.plan.satisfies(cmd[a:b]) {
			cands = appendMatches(cands, cmd, a, b, s.rules[ri], c.re, ri)
		}
		pos = b
	}
	return cands
}

// appendMatches runs re over cmd[from:to] and appends the valid secrets.
func appendMatches(cands []candidate, cmd string, from, to int, r *Rule, re *regexp.Regexp, rank int) []candidate {
	for _, m := range re.FindAllStringSubmatchIndex(cmd[from:to], -1) {
		start, end := m[2*r.SecretGroup], m[2*r.SecretGroup+1]
		if start < 0 || end <= start {
			continue
		}
		start, end = trimQuotes(cmd, from+start, from+end)
		if !ValidSecret(cmd[start:end]) {
			continue
		}
		cands = append(cands, candidate{start, end, rank})
	}
	return cands
}

// merge sorts candidates and merges overlapping ones.
func (s *Set) merge(cmd string, cands []candidate) []Match {
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

// prepare builds the shared keyword matcher on first use.
func (s *Set) prepare() {
	index := map[string]int32{}
	var keywords []string
	s.ruleKWs = make([][]int32, len(s.rules))
	for i, r := range s.rules {
		for _, k := range r.Keywords {
			if !isASCII(k) {
				return // keep km nil: Find uses findPlain
			}
			ki, ok := index[k]
			if !ok {
				ki = int32(len(keywords))
				index[k] = ki
				keywords = append(keywords, k)
				s.kwRules = append(s.kwRules, nil)
			}
			if !slices.Contains(s.ruleKWs[i], ki) {
				s.ruleKWs[i] = append(s.ruleKWs[i], ki)
				s.kwRules[ki] = append(s.kwRules[ki], int32(i))
			}
		}
	}
	s.km = newKeywordMatcher(keywords)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// hasFoldExotic reports whether s contains a rune that strings.ToLower or a
// case-insensitive regex maps to an ASCII letter although it is not ASCII:
// U+0130 (İ, lower-cases to i), U+017F (ſ, folds to s) and U+212A (Kelvin
// sign, lower-cases and folds to k). Commands with one of them take the plain
// path, where nothing depends on ASCII folding. TestFoldExotic keeps this list
// in sync with the unicode tables.
func hasFoldExotic(s string) bool {
	return strings.Contains(s, "\u0130") || strings.Contains(s, "\u017f") || strings.Contains(s, "\u212a")
}

// span is a half-open byte range [start, end).
type span struct{ start, end int }

// scratch is per-call working memory for Find.
type scratch struct {
	hits  []kwHit
	spans []span
	mark  []uint32 // rule index -> epoch in which a keyword of it was seen
	epoch uint32
}

var scratchPool = sync.Pool{New: func() any { return new(scratch) }}

func getScratch(nrules int) *scratch {
	sc := scratchPool.Get().(*scratch)
	if len(sc.mark) < nrules {
		sc.mark = make([]uint32, nrules)
		sc.epoch = 0
	}
	sc.epoch++
	if sc.epoch == 0 {
		clear(sc.mark)
		sc.epoch = 1
	}
	return sc
}

func putScratch(sc *scratch) {
	if cap(sc.hits) > 1<<16 {
		sc.hits = nil
	}
	if cap(sc.spans) > 1<<16 {
		sc.spans = nil
	}
	scratchPool.Put(sc)
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
	for _, m := range r.regexp().FindAllStringSubmatchIndex(cmd, -1) {
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

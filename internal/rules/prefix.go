package rules

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"
)

// anchored runs a regex at a given position of a text, with the rune before
// that position as context. Go's regexp has no API for it, so the context
// rune is consumed by (?s:.): \b, ^ and the like then see exactly what they
// see in a search over the whole text.
type anchored struct {
	ctx  *regexp.Regexp // \A(?s:.)(?:expr)
	anc0 *regexp.Regexp // \A(?:expr), for position 0
}

func newAnchored(expr string) (anchored, bool) {
	ctx, err := regexp.Compile(`\A(?s:.)(?:` + expr + `)`)
	if err != nil {
		return anchored{}, false
	}
	anc0, err := regexp.Compile(`\A(?:` + expr + `)`)
	if err != nil {
		return anchored{}, false
	}
	return anchored{ctx, anc0}, true
}

// at returns the submatch indexes, in text, of the match that starts at s,
// or nil. s must be at an ASCII byte, so that it is a rune boundary and the
// rune before it has the width DecodeLastRuneInString reports.
func (a *anchored) at(text string, s int) []int {
	if s == 0 {
		return a.anc0.FindStringSubmatchIndex(text)
	}
	_, w := utf8.DecodeLastRuneInString(text[:s])
	m := a.ctx.FindStringSubmatchIndex(text[s-w:])
	if m == nil {
		return nil
	}
	m[0] += w
	for i := range m {
		if m[i] >= 0 {
			m[i] += s - w
		}
	}
	return m
}

// A prefixPlan runs a regex only where a match can begin. It applies when
// every match begins with one of a few ASCII literals (after an optional
// \b): `\bcurl\b[^|;&]*?\s(?:-u|--user)…`, `(?i)\b(?:machine…|default…)…`.
// The literals' occurrences are the candidate starts; the regex runs
// anchored at each, in increasing order, which replays FindAll exactly (the
// matches are never empty, so FindAll always continues at a match's end).
//
// Most such rules continue with a lazy gap, `HEAD X*? REST`, where every
// byte HEAD can consume is in the class X. Then if HEAD matches at p but
// the whole regex does not, no match starts anywhere from HEAD's end to the
// first byte e outside X: such a match would extend one from p, since X*?
// could cover the bytes between. Candidates up to e are skipped, which
// keeps the work linear where `curl` appears many times on one long line.
//
// A text with more candidates than maxPrefixAttempts allows is searched
// the plain way instead.
type prefixPlan struct {
	lits []string // ASCII-folded; every match begins with one of them
	full anchored

	// The lazy-gap skip; head is nil without it.
	head *anchored
	gap  [256]bool // bytes of X
}

// maxPrefixAttempts is the number of anchored runs a text of n bytes may
// use before the plan gives up and the regex runs over the whole text.
func maxPrefixAttempts(n int) int { return 64 + n/64 }

// maxPrefixLits bounds the literals searched for one rule.
const maxPrefixLits = 8

// newPrefixPlan returns the plan for re, or nil when re does not have the
// shape.
func newPrefixPlan(re *syntax.Regexp, expr string, an *analyzer) *prefixPlan {
	subs := flatten(re)
	i := 0
	for i < len(subs) && subs[i].Op == syntax.OpWordBoundary {
		i++
	}
	if i >= len(subs) {
		return nil
	}
	lits := leadingLiterals(subs[i:], an)
	if len(lits) == 0 || len(lits) > maxPrefixLits {
		return nil
	}
	full, ok := newAnchored(expr)
	if !ok {
		return nil
	}
	p := &prefixPlan{lits: lits, full: full}

	// HEAD X*? REST: the first lazy star of a class after the literals.
	for k := i + 1; k < len(subs); k++ {
		st := subs[k]
		if st.Op != syntax.OpStar || st.Flags&syntax.NonGreedy == 0 || st.Sub[0].Op != syntax.OpCharClass {
			continue
		}
		gap := classBytes(st.Sub[0])
		var head [256]bool
		headRe := &syntax.Regexp{Op: syntax.OpConcat, Sub: subs[:k], Flags: re.Flags}
		if !consumes(headRe, &head) {
			break
		}
		for b := 0; b < 256; b++ {
			if head[b] && !gap[b] {
				return p
			}
		}
		if h, ok := newAnchored(headRe.String()); ok {
			p.head, p.gap = &h, gap
		}
		break
	}
	return p
}

// leadingLiterals returns the ASCII-folded literals one of which begins
// every match of the concatenation subs, or nil.
func leadingLiterals(subs []*syntax.Regexp, an *analyzer) []string {
	// The finite language of the leading run of children, when it has one.
	prod := []string{""}
	for _, s := range subs {
		in := an.analyze(s)
		if !in.exactOK {
			break
		}
		next, ok := product(prod, in.exact)
		if !ok {
			break
		}
		prod = next
	}
	if usableLits(prod) {
		return prod
	}
	return firstLiterals(subs[0])
}

// firstLiterals returns the literal each alternative of re begins with.
func firstLiterals(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpCapture:
		return firstLiterals(re.Sub[0])
	case syntax.OpLiteral:
		var b strings.Builder
		for _, r := range re.Rune {
			b.WriteString(foldRune(r, re.Flags&syntax.FoldCase != 0))
		}
		if lits := []string{b.String()}; usableLits(lits) {
			return lits
		}
	case syntax.OpConcat:
		if len(re.Sub) > 0 {
			return firstLiterals(re.Sub[0])
		}
	case syntax.OpAlternate:
		var out []string
		for _, s := range re.Sub {
			l := firstLiterals(s)
			if l == nil {
				return nil
			}
			out = append(out, l...)
		}
		return dedupe(out)
	}
	return nil
}

// usableLits reports whether every literal is non-empty and searchable.
func usableLits(lits []string) bool {
	if len(lits) == 0 || len(lits) > maxPrefixLits {
		return false
	}
	for _, l := range lits {
		if l == "" || strings.Contains(l, nonASCIIMark) {
			return false
		}
	}
	return true
}

// classBytes returns the bytes that are certainly in the class: ASCII bytes
// it contains, and all bytes 0x80-0xFF when it contains every non-ASCII
// rune (bytes of invalid UTF-8 read as U+FFFD).
func classBytes(cc *syntax.Regexp) [256]bool {
	var set [256]bool
	high := rune(utf8.RuneSelf) // next non-ASCII rune not yet covered
	for i := 0; i+1 < len(cc.Rune); i += 2 {
		lo, hi := cc.Rune[i], cc.Rune[i+1]
		for r := lo; r <= hi && r < utf8.RuneSelf; r++ {
			set[r] = true
		}
		if lo <= high && hi >= high {
			high = hi + 1
		}
	}
	if high > utf8.MaxRune {
		for b := utf8.RuneSelf; b < 256; b++ {
			set[b] = true
		}
	}
	return set
}

// find runs the plan over cmd and appends the valid secrets of rule r. It
// returns false, with cands unchanged, when the text has too many
// candidates; the caller then runs the regex over the whole text.
func (p *prefixPlan) find(cands []candidate, cmd string, r *Rule, rank int) ([]candidate, bool) {
	start := len(cands)
	budget := maxPrefixAttempts(len(cmd))
	finders := make([]foldFinder, len(p.lits))
	for k, lit := range p.lits {
		finders[k] = newFoldFinder(lit)
	}
	pos := 0
	skipFrom, skipTo := 0, 0 // no match starts in [skipFrom, skipTo)
	for {
		s := len(cmd)
		for k := range finders {
			if i := finders[k].next(cmd, pos); i >= 0 && i < s {
				s = i
			}
		}
		if s >= len(cmd) {
			return cands, true
		}
		if s >= skipFrom && s < skipTo {
			pos = skipTo
			continue
		}
		if budget--; budget < 0 {
			return cands[:start], false
		}
		if m := p.full.at(cmd, s); m != nil {
			cands = appendMatch(cands, cmd, m, r, rank)
			pos = m[1]
			continue
		}
		pos = s + 1
		if p.head == nil {
			continue
		}
		if h := p.head.at(cmd, s); h != nil {
			e := h[1]
			for e < len(cmd) && p.gap[cmd[e]] {
				e++
			}
			skipFrom, skipTo = h[1], e
		}
	}
}

// foldFinder finds the occurrences of an ASCII-folded literal, comparing
// ASCII letters without case. Searches must come with non-decreasing start
// positions; it remembers where the next spellings of the literal's first
// byte are, so a run of searches over one text stays linear.
type foldFinder struct {
	lit    string
	lo, up byte
	nextLo int // next lo at or after the last search start; len(text) when none
	nextUp int
	result int // last result: the first occurrence at or after the last start
}

func newFoldFinder(lit string) foldFinder {
	f := foldFinder{lit: lit, lo: lit[0], up: lit[0], nextLo: -1, nextUp: -1, result: -2}
	if f.lo >= 'a' && f.lo <= 'z' {
		f.up = f.lo - ('a' - 'A')
	}
	return f
}

// next returns the first index at or after from where text contains the
// literal, or -1.
func (f *foldFinder) next(text string, from int) int {
	if f.result == -1 || f.result >= from {
		// No occurrence at all after an earlier start, or the occurrence
		// found from an earlier start is still the first one.
		return f.result
	}
	last := len(text) - len(f.lit) // last possible start
	for i := from; i <= last; {
		if f.nextLo < i {
			if f.nextLo = indexByteFrom(text[:last+1], f.lo, i); f.nextLo < 0 {
				f.nextLo = len(text)
			}
		}
		if f.nextUp < i {
			if f.nextUp = indexByteFrom(text[:last+1], f.up, i); f.nextUp < 0 {
				f.nextUp = len(text)
			}
		}
		c := min(f.nextLo, f.nextUp)
		if c > last {
			break
		}
		if foldEqualAt(text, c, f.lit) {
			f.result = c
			return c
		}
		i = c + 1
	}
	f.result = -1
	return -1
}

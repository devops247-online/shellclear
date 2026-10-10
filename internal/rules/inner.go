package rules

import (
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

// An innerPlan finds matches through a literal inside the regex instead of
// running the regex over the text, the "reverse inner literal" strategy of
// the Rust regex crate adapted to Go's regexp package, which can only run
// forward. It applies to regexes of the shape
//
//	\b NAME SEP REST
//
// where NAME consumes only ASCII word bytes and is never empty, and every
// alternative of SEP is optional Go whitespace (\s = [\t\n\f\r ]) followed
// by the same byte lit, which is neither a word byte nor whitespace. The
// built-in generic_secret_assignment is one:
//
//	(?i)\b([A-Z0-9_]*(?:SECRET|TOKEN|…)…) (?:=['"]?|\s*=\s*['"]) ([^\s'"`;|&<>]{1,200})
//
// A match then covers a word, optional whitespace and lit, so each lit at i
// has exactly one possible match start: walking back from i over whitespace
// to j and over word bytes to s, \b allows no start inside the word. The
// regex is run anchored at s only, with the true left context (see
// anchored), and the candidates come in increasing order, which replays
// FindAll's leftmost-first, non-overlapping scan exactly. NAME's required
// literals filter the candidates first.
//
// The plan relies on the fast path's guarantee that the text has no U+017F
// or U+212A, the only non-ASCII runes a case-insensitive word class matches.
type innerPlan struct {
	lit     byte
	nameReq [][]string
	full    anchored
}

// maxInnerTail bounds the non-whitespace bytes a match may cover after lit,
// so that every candidate costs a bounded amount of regex work.
const maxInnerTail = 1024

// maxNameReqSet allows larger required sets for NAME than for whole texts:
// they are checked against one word.
const maxNameReqSet = 32

// newInnerPlan returns the plan for re, or nil when re does not have the
// shape. expr is re's source.
func newInnerPlan(re *syntax.Regexp, expr string, an *analyzer) *innerPlan {
	if re.Op != syntax.OpConcat || len(re.Sub) < 3 || re.Sub[0].Op != syntax.OpWordBoundary {
		return nil
	}
	name := re.Sub[1]
	var nameBytes [256]bool
	if !consumes(name, &nameBytes) || minMatchLen(name) < 1 {
		return nil
	}
	for b := 0; b < 256; b++ {
		if nameBytes[b] && (b >= utf8.RuneSelf || !syntax.IsWordChar(rune(b))) {
			return nil
		}
	}

	// What follows NAME, as one sequence per alternative of SEP: either
	// SEP is an alternation, or it is spelled out in the concatenation.
	var branches [][]*syntax.Regexp
	if sep := unwrapCapture(re.Sub[2]); sep.Op == syntax.OpAlternate {
		for _, br := range sep.Sub {
			branches = append(branches, append(flatten(br), re.Sub[3:]...))
		}
	} else {
		branches = [][]*syntax.Regexp{append(flatten(sep), re.Sub[3:]...)}
	}
	lit := -1
	for _, parts := range branches {
		l, tail, ok := sepBranch(parts)
		if !ok || (lit >= 0 && l != lit) || !boundedTail(tail) {
			return nil
		}
		lit = l
	}
	if lit < 0 || syntax.IsWordChar(rune(lit)) || isGoSpace(byte(lit)) {
		return nil
	}

	full, ok := newAnchored(expr)
	if !ok {
		return nil
	}
	return &innerPlan{lit: byte(lit), nameReq: pickRequiredMax(an.analyze(name).reqs, maxNameReqSet), full: full}
}

func unwrapCapture(re *syntax.Regexp) *syntax.Regexp {
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	return re
}

// flatten returns the parts of a concatenation, or re alone.
func flatten(re *syntax.Regexp) []*syntax.Regexp {
	if re.Op == syntax.OpConcat {
		return re.Sub
	}
	return []*syntax.Regexp{re}
}

// sepBranch splits what follows NAME in one alternative into the byte it
// requires after optional whitespace and the rest.
func sepBranch(parts []*syntax.Regexp) (lit int, tail []*syntax.Regexp, ok bool) {
	i := 0
	if i < len(parts) && isSpaceRun(parts[i]) {
		i++
	}
	if i >= len(parts) || parts[i].Op != syntax.OpLiteral || len(parts[i].Rune) == 0 {
		return 0, nil, false
	}
	l := parts[i]
	r := l.Rune[0]
	if r >= utf8.RuneSelf || (l.Flags&syntax.FoldCase != 0 && hasCaseVariant(r)) {
		return 0, nil, false
	}
	tail = append([]*syntax.Regexp(nil), parts[i+1:]...)
	if len(l.Rune) > 1 {
		rest := *l
		rest.Rune = l.Rune[1:]
		tail = append([]*syntax.Regexp{&rest}, tail...)
	}
	return int(r), tail, true
}

func hasCaseVariant(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// isSpaceRun reports whether re is x* or x+ for a class within Go's \s.
func isSpaceRun(re *syntax.Regexp) bool {
	if re.Op != syntax.OpStar && re.Op != syntax.OpPlus {
		return false
	}
	return isSpaceClass(re.Sub[0])
}

func isSpaceClass(re *syntax.Regexp) bool {
	var set [256]bool
	if !consumes(re, &set) {
		return false
	}
	for b := 0; b < 256; b++ {
		if set[b] && (b >= utf8.RuneSelf || !isGoSpace(byte(b))) {
			return false
		}
	}
	return re.Op == syntax.OpCharClass || re.Op == syntax.OpLiteral
}

func isGoSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\f' || b == '\r'
}

// boundedTail reports whether the expressions cover at most maxInnerTail
// bytes that are not whitespace: their only unbounded parts are runs of
// whitespace.
func boundedTail(parts []*syntax.Regexp) bool {
	n := 0
	for _, p := range parts {
		m, ok := maxNonSpace(p)
		if !ok {
			return false
		}
		n += m
	}
	return n <= maxInnerTail
}

// maxNonSpace is the most bytes re can match, not counting runs of
// whitespace, or false when that is unbounded.
func maxNonSpace(re *syntax.Regexp) (int, bool) {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary, syntax.OpNoMatch:
		return 0, true
	case syntax.OpLiteral:
		n := 0
		for _, r := range re.Rune {
			n += utf8.RuneLen(r)
		}
		return n, true
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return utf8.UTFMax, true
	case syntax.OpCapture:
		return maxNonSpace(re.Sub[0])
	case syntax.OpStar, syntax.OpPlus:
		if isSpaceClass(re.Sub[0]) {
			return 0, true
		}
		return 0, false
	case syntax.OpQuest:
		return maxNonSpace(re.Sub[0])
	case syntax.OpRepeat:
		if re.Max < 0 {
			if isSpaceClass(re.Sub[0]) {
				return 0, true
			}
			return 0, false
		}
		m, ok := maxNonSpace(re.Sub[0])
		return m * re.Max, ok
	case syntax.OpConcat:
		n := 0
		for _, s := range re.Sub {
			m, ok := maxNonSpace(s)
			if !ok {
				return 0, false
			}
			n += m
		}
		return n, true
	case syntax.OpAlternate:
		n := 0
		for _, s := range re.Sub {
			m, ok := maxNonSpace(s)
			if !ok {
				return 0, false
			}
			n = max(n, m)
		}
		return n, true
	}
	return 0, false
}

// minMatchLen is the fewest bytes re can match.
func minMatchLen(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpLiteral:
		n := 0
		for _, r := range re.Rune {
			n += utf8.RuneLen(r)
		}
		return n
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 1
	case syntax.OpCapture, syntax.OpPlus:
		return minMatchLen(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min * minMatchLen(re.Sub[0])
	case syntax.OpConcat:
		n := 0
		for _, s := range re.Sub {
			n += minMatchLen(s)
		}
		return n
	case syntax.OpAlternate:
		n := -1
		for _, s := range re.Sub {
			if m := minMatchLen(s); n < 0 || m < n {
				n = m
			}
		}
		return max(n, 0)
	}
	return 0
}

// consumes marks in set every byte a match of re can contain: ASCII bytes
// as themselves and any non-ASCII rune other than U+017F and U+212A (absent
// on the fast path) as all bytes 0x80-0xFF. It reports false for '.'.
func consumes(re *syntax.Regexp, set *[256]bool) bool {
	mark := func(r rune) {
		switch {
		case r < utf8.RuneSelf:
			set[r] = true
		case r == 0x17F || r == 0x212A:
		default:
			for b := utf8.RuneSelf; b < 256; b++ {
				set[b] = true
			}
		}
	}
	switch re.Op {
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return false
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			mark(r)
			if re.Flags&syntax.FoldCase != 0 {
				for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
					mark(f)
				}
			}
		}
	case syntax.OpCharClass:
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			for r := lo; r <= hi && r < utf8.RuneSelf; r++ {
				mark(r)
			}
			if hi < utf8.RuneSelf {
				continue
			}
			// The non-ASCII part of the range counts unless it holds only
			// the two runes that are absent on the fast path.
			lo = max(lo, utf8.RuneSelf)
			n := int(hi - lo + 1)
			for _, absent := range []rune{0x17F, 0x212A} {
				if lo <= absent && absent <= hi {
					n--
				}
			}
			if n > 0 {
				mark(0x80)
			}
		}
	}
	for _, sub := range re.Sub {
		if !consumes(sub, set) {
			return false
		}
	}
	return true
}

// find runs the plan over cmd and appends the valid secrets of rule r.
func (p *innerPlan) find(cands []candidate, cmd string, r *Rule, rank int) []candidate {
	from := 0 // FindAll continues from the end of the last match
	for scan := 0; scan < len(cmd); {
		k := strings.IndexByte(cmd[scan:], p.lit)
		if k < 0 {
			break
		}
		i := scan + k
		scan = i + 1
		j := i
		for j > from && isGoSpace(cmd[j-1]) {
			j--
		}
		s := j
		for s > from && syntax.IsWordChar(rune(cmd[s-1])) {
			s--
		}
		// No word before the whitespace, or a word that began before the
		// last match ended: no match can start here.
		if s == j || (s > 0 && syntax.IsWordChar(rune(cmd[s-1]))) {
			continue
		}
		if !satisfiesAll(cmd[s:j], p.nameReq) {
			continue
		}
		m := p.full.at(cmd, s)
		if m == nil {
			continue
		}
		cands = appendMatch(cands, cmd, m, r, rank)
		from = m[1]
		scan = max(scan, from)
	}
	return cands
}

func satisfiesAll(text string, required [][]string) bool {
	p := searchPlan{required: required}
	return p.satisfies(text)
}

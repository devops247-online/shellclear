package rules

import (
	"regexp/syntax"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A searchPlan says how much of a command a rule's regex has to see. It is
// derived from the regex itself, never from the data, and is only an
// optimisation: Find returns exactly what running the regex over the whole
// command returns. The reasoning follows ripgrep and the Rust regex crate:
// extract literals every match must contain, run the cheap literal search
// first, and run the regex only where a match is still possible.
//
// All literals are compared on ASCII-folded text ('A'-'Z' read as 'a'-'z').
// The analysis treats U+017F (ſ) and U+212A (Kelvin sign), the only non-ASCII
// runes that case-fold to ASCII letters, as absent; Find takes the plain path
// for any command that contains them.
type searchPlan struct {
	// segment is set when every match contains one of the rule's keywords
	// and no match can cross a stop byte. The regex then runs only on the
	// stretches between stop bytes that contain a keyword occurrence.
	segment bool
	stop    [256]bool
	// required lists sets of literals; every match contains at least one
	// literal of every set. A text that lacks one of the sets is skipped.
	required [][]string
	// inner, when set, finds the matches through a literal inside the
	// regex instead (see innerPlan); it takes precedence over segment.
	inner *innerPlan
	// prefix, when set, runs the regex only where one of the literals that
	// begin every match occurs (see prefixPlan); used when segment is not.
	prefix *prefixPlan
}

// Limits that keep the analysis cheap and the literal checks fast.
const (
	maxExactSet  = 64 // strings in an enumerated finite language
	maxExactLen  = 64 // bytes per enumerated string
	maxClassSize = 16 // characters in an enumerated character class
	maxReqSet    = 8  // literals per required set
	maxReqSets   = 3  // required sets checked per text
)

// nonASCIIMark stands for any non-ASCII rune in an enumerated string. It
// never occurs in a keyword, and required sets that contain it are dropped.
const nonASCIIMark = "\x80"

// newSearchPlan analyses a regex that compiled with regexp.Compile.
// keywords are the rule's lower-case ASCII keywords. The parsed tree is used
// as is: Simplify would expand x{1,200} into 200 copies of x.
func newSearchPlan(expr string, keywords []string) searchPlan {
	var p searchPlan
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return p
	}
	an := &analyzer{info: map[*syntax.Regexp]litInfo{}, proven: map[*syntax.Regexp]bool{}, keywords: keywords}
	p.required = pickRequired(an.analyze(re).reqs)
	if p.inner = newInnerPlan(re, expr, an); p.inner != nil {
		return p
	}
	if len(keywords) > 0 && an.proves(re) {
		for b := 0; b < utf8.RuneSelf; b++ {
			p.stop[b] = !syntax.IsWordChar(rune(b))
		}
		if markConsumed(re, &p.stop) {
			p.segment = slices.Contains(p.stop[:utf8.RuneSelf], true)
		}
	}
	if !p.segment {
		p.prefix = newPrefixPlan(re, expr, an)
	}
	return p
}

// markConsumed clears stop[b] for every ASCII byte that some part of re can
// consume. It reports false when re can consume any byte, or uses an
// assertion that does not behave at a stop byte as at the edge of the text:
// only \b and \B do, and only because stop bytes are never word characters.
func markConsumed(re *syntax.Regexp, stop *[256]bool) bool {
	switch re.Op {
	case syntax.OpAnyChar,
		syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText:
		return false
	case syntax.OpAnyCharNotNL:
		// '.' without (?s): only a newline is left as a stop byte.
		for b := 0; b < utf8.RuneSelf; b++ {
			if b != '\n' {
				stop[b] = false
			}
		}
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			for f := r; ; {
				if f < utf8.RuneSelf {
					stop[f] = false
				}
				if re.Flags&syntax.FoldCase == 0 {
					break
				}
				if f = unicode.SimpleFold(f); f == r {
					break
				}
			}
		}
	case syntax.OpCharClass:
		// The parser has already added the case variants to the class.
		for i := 0; i+1 < len(re.Rune) && re.Rune[i] < utf8.RuneSelf; i += 2 {
			for b := re.Rune[i]; b <= re.Rune[i+1] && b < utf8.RuneSelf; b++ {
				stop[b] = false
			}
		}
	}
	for _, sub := range re.Sub {
		if !markConsumed(sub, stop) {
			return false
		}
	}
	return true
}

// litInfo describes what a sub-expression can match.
type litInfo struct {
	// exact, when known (exactOK), is every string the expression can
	// match, ASCII-folded, with non-ASCII runes replaced by nonASCIIMark.
	exact   []string
	exactOK bool
	// reqs: every match contains at least one string of each set.
	reqs [][]string
}

// analyzer memoises the analysis per node: proves asks for the analysis of
// the same subexpressions again and again, and x{1,200} would otherwise be
// analysed once per level of the expression above it.
type analyzer struct {
	info     map[*syntax.Regexp]litInfo
	proven   map[*syntax.Regexp]bool
	keywords []string
}

func (an *analyzer) analyze(re *syntax.Regexp) litInfo {
	if in, ok := an.info[re]; ok {
		return in
	}
	in := an.compute(re)
	an.info[re] = in
	return in
}

func (an *analyzer) compute(re *syntax.Regexp) litInfo {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return exactInfo([]string{""})
	case syntax.OpLiteral:
		var b strings.Builder
		for _, r := range re.Rune {
			b.WriteString(foldRune(r, re.Flags&syntax.FoldCase != 0))
		}
		return exactInfo([]string{b.String()})
	case syntax.OpCharClass:
		var ascii [utf8.RuneSelf]bool
		n, nonASCII := 0, false
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			if hi-lo >= maxClassSize*2 {
				return litInfo{}
			}
			for r := lo; r <= hi; r++ {
				switch {
				case r == 0x17F || r == 0x212A:
					continue // absent from any text that reaches the plan
				case r < utf8.RuneSelf:
					// Fold into a copy: changing r would end the loop
					// early and enumerate [A-Z] as just "a".
					c := r
					if c >= 'A' && c <= 'Z' {
						c += 'a' - 'A'
					}
					if !ascii[c] {
						ascii[c] = true
						n++
					}
				case !nonASCII:
					nonASCII = true
					n++
				}
				if n > maxClassSize {
					return litInfo{}
				}
			}
		}
		out := make([]string, 0, n)
		for c, ok := range ascii {
			if ok {
				out = append(out, string(rune(c)))
			}
		}
		if nonASCII {
			out = append(out, nonASCIIMark)
		}
		return exactInfo(out)
	case syntax.OpCapture:
		return an.analyze(re.Sub[0])
	case syntax.OpPlus:
		return litInfo{reqs: an.analyze(re.Sub[0]).reqs}
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return litInfo{reqs: an.analyze(re.Sub[0]).reqs}
		}
		return litInfo{}
	case syntax.OpQuest:
		sub := an.analyze(re.Sub[0])
		if sub.exactOK {
			return exactInfo(append([]string{""}, sub.exact...))
		}
		return litInfo{}
	case syntax.OpConcat:
		return an.analyzeConcat(re.Sub)
	case syntax.OpAlternate:
		return an.analyzeAlternate(re.Sub)
	}
	// OpAnyChar, OpAnyCharNotNL, OpStar, OpNoMatch: nothing is known.
	return litInfo{}
}

// foldRune maps a rune to its ASCII-folded spelling.
func foldRune(r rune, foldCase bool) string {
	switch {
	case r >= 'A' && r <= 'Z':
		return string(r + 'a' - 'A')
	case r < utf8.RuneSelf:
		return string(r)
	case foldCase && r == 0x17F:
		return "s"
	case foldCase && r == 0x212A:
		return "k"
	}
	return nonASCIIMark
}

func exactInfo(set []string) litInfo {
	set = dedupe(set)
	if len(set) > maxExactSet {
		return litInfo{}
	}
	for _, s := range set {
		if len(s) > maxExactLen {
			return litInfo{}
		}
	}
	info := litInfo{exact: set, exactOK: true}
	if r := nonEmptySet(set); r != nil {
		info.reqs = [][]string{r}
	}
	return info
}

func (an *analyzer) analyzeConcat(subs []*syntax.Regexp) litInfo {
	infos := make([]litInfo, len(subs))
	for i, s := range subs {
		infos[i] = an.analyze(s)
	}
	var out litInfo
	for _, in := range infos {
		out.reqs = append(out.reqs, in.reqs...)
	}
	// Runs of children with known languages: every match contains one of
	// the concatenations of a run.
	for i := 0; i < len(infos); {
		if !infos[i].exactOK {
			i++
			continue
		}
		j := i
		prod := []string{""}
		for j < len(infos) && infos[j].exactOK {
			next, ok := product(prod, infos[j].exact)
			if !ok {
				break
			}
			prod = next
			j++
		}
		if j == i {
			// A single child too large to combine; its own reqs are in.
			i++
			continue
		}
		if r := nonEmptySet(prod); r != nil {
			out.reqs = append(out.reqs, r)
		}
		if i == 0 && j == len(infos) {
			out.exact, out.exactOK = prod, true
		}
		i = j
	}
	return out
}

func (an *analyzer) analyzeAlternate(subs []*syntax.Regexp) litInfo {
	var exact []string
	exactOK := true
	var req []string
	reqOK := true
	for _, s := range subs {
		in := an.analyze(s)
		if exactOK && in.exactOK {
			exact = append(exact, in.exact...)
		} else {
			exactOK = false
		}
		best := bestReq(in.reqs)
		if best == nil {
			reqOK = false
		} else {
			req = append(req, best...)
		}
	}
	if exactOK {
		return exactInfo(exact)
	}
	var out litInfo
	if reqOK {
		if r := nonEmptySet(dedupe(req)); r != nil {
			out.reqs = [][]string{r}
		}
	}
	return out
}

// product concatenates every pair; ok is false when the result is too large.
func product(a, b []string) ([]string, bool) {
	if len(a)*len(b) > maxExactSet {
		return nil, false
	}
	out := make([]string, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			if len(x)+len(y) > maxExactLen {
				return nil, false
			}
			out = append(out, x+y)
		}
	}
	return dedupe(out), true
}

// nonEmptySet returns set when it is usable as a required set: non-empty and
// without the empty string (which every text contains).
func nonEmptySet(set []string) []string {
	if len(set) == 0 {
		return nil
	}
	for _, s := range set {
		if s == "" {
			return nil
		}
	}
	return set
}

// bestReq picks the most selective required set: the one whose shortest
// literal is longest, then the smallest.
func bestReq(reqs [][]string) []string {
	var best []string
	bestMin := -1
	for _, r := range reqs {
		m := minLen(r)
		if m > bestMin || (m == bestMin && len(r) < len(best)) {
			best, bestMin = r, m
		}
	}
	return best
}

func minLen(set []string) int {
	m := -1
	for _, s := range set {
		if m < 0 || len(s) < m {
			m = len(s)
		}
	}
	return m
}

// pickRequired keeps the few most selective required sets that are cheap to
// check. Sets with a literal that stands for a non-ASCII rune are dropped:
// nonASCIIMark is a placeholder, not text that can be searched for.
func pickRequired(reqs [][]string) [][]string { return pickRequiredMax(reqs, maxReqSet) }

// pickRequiredMax is pickRequired with a limit on the literals per set.
func pickRequiredMax(reqs [][]string, maxSet int) [][]string {
	var cands [][]string
	for _, r := range reqs {
		if len(r) > maxSet {
			continue
		}
		searchable := true
		for _, lit := range r {
			searchable = searchable && !strings.Contains(lit, nonASCIIMark)
		}
		if searchable {
			cands = append(cands, dedupe(r))
		}
	}
	var out [][]string
	for len(out) < maxReqSets {
		b := bestReq(cands)
		if b == nil {
			break
		}
		out = append(out, b)
		var rest [][]string
		for _, c := range cands {
			if !slices.Equal(c, b) {
				rest = append(rest, c)
			}
		}
		cands = rest
	}
	return out
}

// proves reports whether every match of re contains at least one of the
// keywords (on ASCII-folded text).
func (an *analyzer) proves(re *syntax.Regexp) bool {
	if p, ok := an.proven[re]; ok {
		return p
	}
	p := an.computeProves(re)
	an.proven[re] = p
	return p
}

func (an *analyzer) computeProves(re *syntax.Regexp) bool {
	if in := an.analyze(re); in.exactOK && an.allContain(in.exact) {
		return true
	}
	switch re.Op {
	case syntax.OpCapture, syntax.OpPlus:
		return an.proves(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min >= 1 && an.proves(re.Sub[0])
	case syntax.OpAlternate:
		for _, s := range re.Sub {
			if !an.proves(s) {
				return false
			}
		}
		return true
	case syntax.OpConcat:
		for _, s := range re.Sub {
			if an.proves(s) {
				return true
			}
		}
		// A keyword may span several children: check every run of
		// children with known languages.
		for i := range re.Sub {
			prod := []string{""}
			for j := i; j < len(re.Sub); j++ {
				in := an.analyze(re.Sub[j])
				if !in.exactOK {
					break
				}
				next, ok := product(prod, in.exact)
				if !ok {
					break
				}
				prod = next
				if an.allContain(prod) {
					return true
				}
			}
		}
	}
	return false
}

// allContain reports whether every string of a non-empty set contains a
// keyword.
func (an *analyzer) allContain(set []string) bool {
	if len(set) == 0 {
		return false
	}
	for _, s := range set {
		found := false
		for _, k := range an.keywords {
			if strings.Contains(s, k) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// dedupe returns the distinct strings of set, sorted, in a new slice.
func dedupe(set []string) []string {
	if len(set) < 2 {
		return set
	}
	out := slices.Clone(set)
	slices.Sort(out)
	return slices.Compact(out)
}

// containsFold reports whether text contains lit, comparing ASCII letters
// without case. lit is ASCII-folded already.
func containsFold(text, lit string) bool {
	if len(lit) == 0 {
		return true
	}
	// Anchor on a byte that has a single spelling when there is one, so
	// that strings.IndexByte (SIMD) finds the candidates.
	for k := 0; k < len(lit); k++ {
		if c := lit[k]; c < 'a' || c > 'z' {
			if !hasLetter(lit) {
				return strings.Contains(text, lit)
			}
			for i := k; i <= len(text)-len(lit)+k; {
				j := strings.IndexByte(text[i:len(text)-len(lit)+k+1], c)
				if j < 0 {
					return false
				}
				i += j
				if foldEqualAt(text, i-k, lit) {
					return true
				}
				i++
			}
			return false
		}
	}
	// Only letters: look for either spelling of the first one.
	lo, up := lit[0], lit[0]-('a'-'A')
	last := len(text) - len(lit) // last possible start
	nextLo, nextUp := -1, -1     // cached positions, -1 = not searched yet
	for i := 0; i <= last; {
		if nextLo < i {
			if nextLo = indexByteFrom(text[:last+1], lo, i); nextLo < 0 {
				nextLo = len(text)
			}
		}
		if nextUp < i {
			if nextUp = indexByteFrom(text[:last+1], up, i); nextUp < 0 {
				nextUp = len(text)
			}
		}
		i = min(nextLo, nextUp)
		if i > last {
			return false
		}
		if foldEqualAt(text, i, lit) {
			return true
		}
		i++
	}
	return false
}

// indexByteFrom is strings.IndexByte on s[from:], as an index into s.
func indexByteFrom(s string, c byte, from int) int {
	if j := strings.IndexByte(s[from:], c); j >= 0 {
		return from + j
	}
	return -1
}

func hasLetter(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'a' && s[i] <= 'z' {
			return true
		}
	}
	return false
}

func foldEqualAt(text string, i int, lit string) bool {
	for j := 0; j < len(lit); j++ {
		b := text[i+j]
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if b != lit[j] {
			return false
		}
	}
	return true
}

// satisfies reports whether text contains a literal of every required set.
func (p *searchPlan) satisfies(text string) bool {
	for _, set := range p.required {
		ok := false
		for _, lit := range set {
			if containsFold(text, lit) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

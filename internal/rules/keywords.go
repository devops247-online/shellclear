package rules

// keywordMatcher finds every occurrence of a set of ASCII keywords in a text
// in a single pass, ignoring ASCII case. It is an Aho-Corasick automaton
// compiled to a full DFA over a reduced alphabet: every byte that occurs in no
// keyword shares one class, so the transition table stays small enough for the
// L1/L2 cache (gitleaks and trufflehog gate their rules the same way).
//
// Matching is done on the ASCII-folded text: 'A'-'Z' are read as 'a'-'z' and
// every other byte as itself, so byte offsets in the text and in the folded
// text are the same.
type keywordMatcher struct {
	class  [256]uint32 // folded byte -> alphabet class; 0 = in no keyword
	nclass int
	// delta[t+class] is the next state for the state at table offset t.
	// States are stored as offsets (state number * nclass), which keeps a
	// multiplication off the per-byte dependency chain, and numbered so
	// that every state at or after firstOut ends a keyword: the per-byte
	// output check is one comparison.
	delta    []uint32
	firstOut uint32
	// out[outIdx[s]:outIdx[s+1]] are the keywords that end in state s,
	// including those reached through dictionary suffix links.
	outIdx []int32
	out    []int32
	lens   []int // keyword lengths
}

// kwHit is one keyword occurrence: text[end-lens[kw]:end].
type kwHit struct {
	kw  int32
	end int32
}

// maxKeywordStates bounds the automaton; a few thousand keyword bytes need
// a few thousand states.
const maxKeywordStates = 1 << 16

// newKeywordMatcher builds the automaton. Every keyword must be non-empty,
// lower-case ASCII. It returns nil when the automaton would be too large.
func newKeywordMatcher(keywords []string) *keywordMatcher {
	m := &keywordMatcher{lens: make([]int, len(keywords))}
	// Alphabet: one class per distinct byte used by any keyword.
	for _, k := range keywords {
		for i := 0; i < len(k); i++ {
			if m.class[k[i]] == 0 {
				m.nclass++
				m.class[k[i]] = uint32(m.nclass)
			}
		}
	}
	m.nclass++ // class 0
	for c := 'A'; c <= 'Z'; c++ {
		m.class[c] = m.class[c+'a'-'A']
	}

	// Trie.
	type node struct {
		next map[uint32]int
		fail int
		out  []int32
	}
	nodes := []node{{next: map[uint32]int{}}}
	for i, k := range keywords {
		m.lens[i] = len(k)
		s := 0
		for j := 0; j < len(k); j++ {
			c := m.class[k[j]]
			t, ok := nodes[s].next[c]
			if !ok {
				t = len(nodes)
				if t >= maxKeywordStates {
					return nil
				}
				nodes = append(nodes, node{next: map[uint32]int{}})
				nodes[s].next[c] = t
			}
			s = t
		}
		nodes[s].out = append(nodes[s].out, int32(i))
	}

	// Breadth-first: failure links, inherited outputs and the full DFA,
	// first in plain state numbers.
	n := len(nodes)
	next := make([]int, n*m.nclass)
	queue := make([]int, 0, n)
	for c := 0; c < m.nclass; c++ {
		if t, ok := nodes[0].next[uint32(c)]; ok {
			next[c] = t
			queue = append(queue, t)
		}
	}
	for qi := 0; qi < len(queue); qi++ {
		s := queue[qi]
		f := nodes[s].fail
		nodes[s].out = append(nodes[s].out, nodes[f].out...)
		for c := 0; c < m.nclass; c++ {
			if t, ok := nodes[s].next[uint32(c)]; ok {
				nodes[t].fail = next[f*m.nclass+c]
				next[s*m.nclass+c] = t
				queue = append(queue, t)
			} else {
				next[s*m.nclass+c] = next[f*m.nclass+c]
			}
		}
	}

	// Renumber: states without output first (the root keeps 0), then the
	// states that end a keyword.
	order := make([]int, 0, n)
	for s := 0; s < n; s++ {
		if len(nodes[s].out) == 0 {
			order = append(order, s)
		}
	}
	m.firstOut = uint32(len(order) * m.nclass)
	for s := 0; s < n; s++ {
		if len(nodes[s].out) > 0 {
			order = append(order, s)
		}
	}
	newID := make([]int, n)
	for id, s := range order {
		newID[s] = id
	}
	m.delta = make([]uint32, n*m.nclass)
	m.outIdx = make([]int32, n+1)
	for id, s := range order {
		for c := 0; c < m.nclass; c++ {
			m.delta[id*m.nclass+c] = uint32(newID[next[s*m.nclass+c]] * m.nclass)
		}
		m.outIdx[id] = int32(len(m.out))
		m.out = append(m.out, nodes[s].out...)
	}
	m.outIdx[n] = int32(len(m.out))
	return m
}

// scan appends every keyword occurrence in text to hits, ordered by end
// offset. It also reports whether text contains any byte >= 0x80.
func (m *keywordMatcher) scan(text string, hits []kwHit) ([]kwHit, bool) {
	var high byte
	var t uint32 // table offset of the current state
	delta, class, firstOut := m.delta, &m.class, m.firstOut
	for i := 0; i < len(text); i++ {
		b := text[i]
		high |= b
		t = delta[t+class[b]]
		if t >= firstOut {
			s := int(t) / m.nclass
			for _, kw := range m.out[m.outIdx[s]:m.outIdx[s+1]] {
				hits = append(hits, kwHit{kw: kw, end: int32(i + 1)})
			}
		}
	}
	return hits, high >= 0x80
}

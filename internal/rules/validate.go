package rules

import "strings"

// minSecretLen is the shortest value treated as a secret.
const minSecretLen = 4

// trimQuotes shrinks [start, end) so it excludes surrounding quotes.
func trimQuotes(s string, start, end int) (int, int) {
	for start < end && isQuote(s[start]) {
		start++
	}
	for end > start && isQuote(s[end-1]) {
		end--
	}
	return start, end
}

func isQuote(c byte) bool { return c == '\'' || c == '"' }

// ValidSecret rejects values that are not real secrets: short values, shell
// expansions, redirections, values that are already masked, and obvious
// placeholders. It applies to every rule, built-in or custom.
func ValidSecret(s string) bool {
	s0, s1 := trimQuotes(s, 0, len(s))
	s = s[s0:s1]
	if len(s) < minSecretLen {
		return false
	}
	switch s[0] {
	case '$', '<', '`':
		// $VAR, ${VAR}, $(cmd), <file or <placeholder>, `cmd`
		return false
	}
	if strings.Trim(s, "*") == "" {
		return false
	}
	lower := strings.ToLower(s)
	switch {
	case strings.Contains(lower, "redacted"),
		strings.HasPrefix(lower, "xxx"),
		lower == "changeme",
		strings.Contains(lower, "example"),
		strings.HasPrefix(lower, "your_"),
		strings.HasPrefix(lower, "your-"):
		return false
	}
	return true
}

package rules

import (
	_ "embed"
	"reflect"
	"strings"
	"testing"
)

//go:embed patterns.yaml
var builtinYAML []byte

// TestBuiltinMatchesYAML keeps builtin_rules.go in sync with patterns.yaml.
func TestBuiltinMatchesYAML(t *testing.T) {
	fromYAML, err := Load(strings.NewReader(string(builtinYAML)), BuiltinSource)
	if err != nil {
		t.Fatal(err)
	}
	built, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	strip := func(rs []Rule) []Rule {
		out := make([]Rule, len(rs))
		for i, r := range rs {
			r.c = nil
			out[i] = r
		}
		return out
	}
	if !reflect.DeepEqual(strip(fromYAML), strip(built)) {
		t.Fatal("builtin_rules.go is out of date: run go generate ./internal/rules")
	}
}

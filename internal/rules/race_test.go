//go:build race

package rules

// raceEnabled shrinks the generated equivalence suites: the race detector
// makes them about ten times slower and adds nothing to them.
const raceEnabled = true

//go:build race

package rules

// raceEnabled skips the generated equivalence suites: they run in a single
// goroutine, so the race detector only makes them ten times slower.
const raceEnabled = true

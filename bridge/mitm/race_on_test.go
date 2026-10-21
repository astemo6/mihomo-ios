//go:build race

package mitm

// raceEnabled: the race detector inflates allocations (allocation-bound tests relax their checks).
const raceEnabled = true

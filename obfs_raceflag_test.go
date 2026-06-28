//go:build race

package main

// raceEnabled is true when the test binary is built with -race. The race
// detector instruments allocations, so per-packet alloc-count assertions are
// meaningless under it and are skipped.
const raceEnabled = true

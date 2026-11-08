//go:build race

package check

// The race detector slows the scans about 17x; the linear bound scales with it.
const timeBudgetFactor = 10

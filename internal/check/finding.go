// Package check implements the repo-standards checks.
package check

import (
	"fmt"
	"sort"
)

// Check identifiers, one per kind of finding.
const (
	MissingFile    = "missing-file"
	StubFile       = "stub-file"
	IndexLink      = "index-link"
	License        = "license"
	PIIDenylist    = "pii-denylist"
	PIIHomePath    = "pii-home-path"
	PIIBannedWord  = "pii-banned-word"
	PIISuppression = "pii-suppression"
)

// Finding is one violation. Msg never contains matched personal data.
type Finding struct {
	Check string
	Path  string
	Line  int // 0 = whole file
	Msg   string
}

// String renders "path[:line]: [check] message".
func (f Finding) String() string {
	loc := f.Path
	if f.Line > 0 {
		loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
	}
	return fmt.Sprintf("%s: [%s] %s", loc, f.Check, f.Msg)
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		return a.Msg < b.Msg
	})
}

package check

import (
	"fmt"
	"regexp"
	"strings"
)

type requirement struct {
	names []string // accepted spellings, first is canonical
	min   int      // minimum size in bytes after trimming whitespace
	// skipPlaceholders skips the template-marker scan (licence texts legitimately
	// contain "[yyyy]" boilerplate; .gitignore has no prose).
	skipPlaceholders bool
}

// requirements is the standard document set. It is identical for public and
// private repositories.
var requirements = []requirement{
	{names: []string{"README.md"}, min: 200},
	{names: []string{"CLAUDE.md"}, min: 100},
	{names: []string{"CHANGELOG.md"}, min: 30},
	{names: []string{"LICENSE", "LICENSE.md", "LICENSE.txt"}, min: 40, skipPlaceholders: true},
	{names: []string{"CONTRIBUTING.md"}, min: 100},
	{names: []string{"SECURITY.md"}, min: 100},
	{names: []string{"CODE_OF_CONDUCT.md"}, min: 150},
	{names: []string{".gitignore"}, min: 1, skipPlaceholders: true},
	{names: []string{"docs/INDEX.md"}, min: 60},
}

// placeholder patterns: text left over from a template.
var placeholders = []struct {
	name string
	re   *regexp.Regexp
}{
	{"TODO marker", regexp.MustCompile(`\bTODO\b`)},
	{"TBD marker", regexp.MustCompile(`\bTBD\b`)},
	{"Lorem ipsum", regexp.MustCompile(`(?i)lorem ipsum`)},
	{"unfilled template field", regexp.MustCompile(`\[INSERT [A-Z ]+\]`)},
	{"template sentence", regexp.MustCompile(`(?i)(project description here|description goes here|your project name|your project title|add (a )?description here|describe your project|insert .{1,40} here|replace this)`)},
}

// found returns the first present spelling of a requirement.
func (r requirement) found(set map[string]bool) (string, bool) {
	for _, n := range r.names {
		if set[n] {
			return n, true
		}
	}
	return "", false
}

func checkRequired(root string, files []string, set map[string]bool, content map[string][]byte) []Finding {
	var out []Finding
	for _, r := range requirements {
		name, ok := r.found(set)
		if !ok {
			msg := "missing required file " + r.names[0]
			if len(r.names) > 1 {
				msg += " (or " + strings.Join(r.names[1:], ", ") + ")"
			}
			out = append(out, Finding{Check: MissingFile, Path: r.names[0], Msg: msg})
			continue
		}
		data, ok := readRegular(root, name, 8<<20)
		if !ok {
			out = append(out, Finding{Check: StubFile, Path: name, Msg: "not a readable regular file"})
			continue
		}
		content[name] = data
		out = append(out, stubFindings(name, data, r)...)
	}
	return out
}

func stubFindings(name string, data []byte, r requirement) []Finding {
	var out []Finding
	text := string(data)
	size := len(strings.TrimSpace(text))
	if name == ".gitignore" {
		size = 0
		for _, l := range strings.Split(text, "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				size++
			}
		}
		if size < r.min {
			out = append(out, Finding{Check: StubFile, Path: name, Msg: "contains no ignore pattern"})
		}
		return out
	}
	if size < r.min {
		out = append(out, Finding{Check: StubFile, Path: name,
			Msg: fmt.Sprintf("stub: %d bytes of content, minimum %d", size, r.min)})
	}
	if r.skipPlaceholders {
		return out
	}
	lines := strings.Split(text, "\n")
	for _, p := range placeholders {
		for i, l := range lines {
			if p.re.MatchString(l) {
				out = append(out, Finding{Check: StubFile, Path: name, Line: i + 1,
					Msg: "template placeholder: " + p.name})
				break
			}
		}
	}
	return out
}

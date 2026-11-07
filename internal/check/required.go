package check

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

type requirement struct {
	names []string // accepted spellings, first is canonical
	min   int      // minimum size in bytes after trimming whitespace
	// skipPlaceholders skips the template-marker scan (licence texts legitimately
	// contain "[yyyy]" boilerplate; .gitignore has no prose; an issue template
	// is itself fill-in scaffolding).
	skipPlaceholders bool
	// dir, when non-empty, adds a directory alternative: the requirement is
	// also satisfied by the first tracked file directly inside it for which
	// dirFile reports true.
	dir     string
	dirFile func(rest string) bool
	dirHint string // how the dir alternative reads in the missing-file message
}

// Canonical names of the requirements whose spelling list or template
// directory init must share with the check: init writes the canonical name
// and keeps a file only when it is one of the accepted spellings.
const (
	IssueTemplateDir    = ".github/ISSUE_TEMPLATE/"
	PullRequestTemplate = ".github/pull_request_template.md"
	LicenceFile         = "LICENSE"
)

const pullTemplateDir = ".github/PULL_REQUEST_TEMPLATE/"

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
	{names: []string{PullRequestTemplate, ".github/PULL_REQUEST_TEMPLATE.md",
		"pull_request_template.md", "PULL_REQUEST_TEMPLATE.md",
		"docs/pull_request_template.md", "docs/PULL_REQUEST_TEMPLATE.md"},
		min: 30, dir: pullTemplateDir, dirFile: isMarkdownFile,
		dirHint: "a .md file directly inside " + pullTemplateDir},
	{names: []string{IssueTemplateDir, "ISSUE_TEMPLATE.md", ".github/ISSUE_TEMPLATE.md",
		"docs/ISSUE_TEMPLATE.md"}, min: 30, skipPlaceholders: true,
		dir: IssueTemplateDir, dirFile: isTemplateFile,
		dirHint: "at least one .yml, .yaml or .md issue template other than config.yml"},
}

// isTemplateFile reports whether the part of a path below an issue-template
// directory names a template: a *.yml, *.yaml or *.md file other than
// config.yml (which holds chooser settings, not a template). Files in
// subdirectories are not templates as far as GitHub is concerned.
func isTemplateFile(rest string) bool {
	if strings.Contains(rest, "/") {
		return false
	}
	if rest == "config.yml" || rest == "config.yaml" {
		return false
	}
	switch strings.ToLower(path.Ext(rest)) {
	case ".yml", ".yaml", ".md":
		return true
	}
	return false
}

// isMarkdownFile reports whether the part of a path below a multi-template
// directory names a template: a Markdown file directly inside it.
func isMarkdownFile(rest string) bool {
	return !strings.Contains(rest, "/") && strings.EqualFold(path.Ext(rest), ".md")
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

// found returns the first present spelling of a requirement, or the first
// file satisfying its directory alternative.
func (r requirement) found(files []string, set map[string]bool) (string, bool) {
	if r.dir != "" {
		for _, f := range files {
			if rest, ok := strings.CutPrefix(f, r.dir); ok && r.dirFile(rest) {
				return f, true
			}
		}
	}
	for _, n := range r.names {
		if set[n] {
			return n, true
		}
	}
	return "", false
}

// FoundPath reports the first path in files that satisfies the requirement
// identified by canonical (its names[0]). It is the existence predicate the
// required-file check itself runs; init calls it on the union of tracked
// files and the work tree so it never claims kept for a spelling the check
// would reject.
func FoundPath(canonical string, files []string) (string, bool) {
	for _, r := range requirements {
		if r.names[0] == canonical {
			set := make(map[string]bool, len(files))
			for _, f := range files {
				set[f] = true
			}
			return r.found(files, set)
		}
	}
	return "", false
}

// AcceptedSpellings lists the accepted spellings of the requirement
// identified by canonical, canonical first; nil for an unknown name.
func AcceptedSpellings(canonical string) []string {
	for _, r := range requirements {
		if r.names[0] == canonical {
			return r.names
		}
	}
	return nil
}

func checkRequired(root string, files []string, set map[string]bool, content map[string][]byte) []Finding {
	var out []Finding
	for _, r := range requirements {
		name, ok := r.found(files, set)
		if !ok {
			msg := "missing required file " + r.names[0]
			alts := append([]string{}, r.names[1:]...)
			if r.dirHint != "" {
				alts = append(alts, r.dirHint)
			}
			if len(alts) > 0 {
				msg += " (or " + strings.Join(alts, ", ") + ")"
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

// RequiredFindings applies the required-file rules to the repository at root
// over the given file set: the missing-file and stub-file findings. Run uses
// checkRequired on the tracked set; init calls this on the tracked set plus
// the files it created, so its report reflects what the check sees once they
// are added.
func RequiredFindings(root string, files []string) []Finding {
	set := make(map[string]bool, len(files))
	for _, f := range files {
		set[f] = true
	}
	return checkRequired(root, files, set, map[string][]byte{})
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

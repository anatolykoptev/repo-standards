package check

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"

	"github.com/anatolykoptev/repo-standards/internal/denylist"
)

// Visibility selects the rule set.
type Visibility string

const (
	Public  Visibility = "public"
	Private Visibility = "private"
)

// ResolveVisibility combines the visibility a caller declares with the one the
// environment reports (GitHub: github.event.repository.private). Either may be
// empty. The environment wins; a declaration may only be as strict or stricter
// (declaring "private" for a public repo would skip the personal-data scan and
// invert the licence rule, so it is an error). With neither, the strictest
// rule set, public, applies.
func ResolveVisibility(declared, detected string) (Visibility, error) {
	for _, v := range []string{declared, detected} {
		if v != "" && v != string(Public) && v != string(Private) {
			return "", fmt.Errorf("visibility must be %q or %q, got %q", Public, Private, v)
		}
	}
	switch {
	case detected == "" && declared == "":
		return Public, nil
	case detected == "":
		return Visibility(declared), nil
	case declared == string(Private) && detected == string(Public):
		return "", fmt.Errorf("declared visibility %q is less strict than the repository's actual visibility %q", declared, detected)
	}
	return Visibility(detected), nil
}

// Options configures Run.
type Options struct {
	Root       string
	Visibility Visibility
	// Denylist is required for public repos and must not be empty.
	Denylist *denylist.List
}

// Result is the outcome of a run.
type Result struct {
	Findings []Finding
	Stats    Stats
	// NotGit is set when root was not a git work tree and every file was scanned.
	NotGit bool
}

// rootDocs are the root documents docs/INDEX.md must link, in addition to
// everything under docs/.
var rootDocs = []string{"README.md", "CLAUDE.md", "CHANGELOG.md", "CONTRIBUTING.md",
	"SECURITY.md", "CODE_OF_CONDUCT.md", "LICENSE", "LICENSE.md", "LICENSE.txt"}

func validate(opts Options) error {
	if opts.Visibility != Public && opts.Visibility != Private {
		return fmt.Errorf("visibility must be %q or %q, got %q", Public, Private, opts.Visibility)
	}
	// An empty list would let every public repo pass the personal-data scan.
	if opts.Visibility == Public && (opts.Denylist == nil || opts.Denylist.Len() == 0) {
		return fmt.Errorf("the denylist is empty: refusing to scan a public repository with nothing to match")
	}
	return nil
}

// Run applies every check to the repository at opts.Root.
func Run(opts Options) (Result, error) {
	if err := validate(opts); err != nil {
		return Result{}, err
	}
	files, notGit, err := repoFiles(opts.Root)
	if err != nil {
		return Result{}, err
	}
	res := Result{NotGit: notGit}
	set := make(map[string]bool, len(files))
	for _, f := range files {
		set[f] = true
	}
	content := map[string][]byte{}

	out := checkRequired(opts.Root, files, set, content)
	out = append(out, checkIndex(files, content)...)
	out = append(out, checkIndexDeadLinks(files, content)...)
	out = append(out, checkClaudeIndex(content)...)
	for _, r := range requirements {
		if r.names[0] != "LICENSE" {
			continue
		}
		if name, ok := r.found(files, set); ok {
			if data, ok := content[name]; ok {
				out = append(out, checkLicense(opts.Visibility, name, data)...)
			}
		}
	}
	if opts.Visibility == Public {
		pii, err := checkPII(opts.Root, files, opts.Denylist, &res.Stats)
		if err != nil {
			return Result{}, err
		}
		out = append(out, pii...)
	}
	sortFindings(out)
	res.Findings = out
	return res, nil
}

// RunHistory scans the text of `git log -p --all` (commit metadata, messages,
// every added and removed line) with the personal-data rules. It is what finds
// a value that was committed and later deleted. Public repositories only.
func RunHistory(opts Options) (Result, error) {
	if err := validate(opts); err != nil {
		return Result{}, err
	}
	if opts.Visibility != Public {
		return Result{}, fmt.Errorf("--history applies to public repositories only")
	}
	// A shallow clone holds only part of the history; scanning it and reporting
	// green would be a silent partial check.
	out, err := exec.Command("git", "-C", opts.Root, "rev-parse", "--is-shallow-repository").Output()
	if err != nil {
		return Result{}, fmt.Errorf("git rev-parse failed: %w", err)
	}
	if strings.TrimSpace(string(out)) == "true" {
		return Result{}, fmt.Errorf("--history needs the full history but this is a shallow clone: fetch with depth 0 (actions/checkout: fetch-depth: 0)")
	}
	cmd := exec.Command("git", "-C", opts.Root, "log", "-p", "--all", "--format=fuller", "--no-color", "--no-ext-diff")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Result{}, err
	}
	if err := cmd.Start(); err != nil {
		return Result{}, err
	}
	var res Result
	res.Findings = scanLines("git-log", "", bufio.NewReaderSize(stdout, 64<<10), opts.Denylist, &res.Stats)
	if err := cmd.Wait(); err != nil {
		return Result{}, fmt.Errorf("git log failed: %w", err)
	}
	sortFindings(res.Findings)
	return res, nil
}

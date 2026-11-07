// Package initfiles implements repo-standards init: it writes the boilerplate
// documents the required-file check mandates, deterministically. It writes
// only files that are missing and never modifies an existing one; the write
// guard is the O_EXCL open flag, not a stat that can race or be refactored
// away. The documents that must come from the project's real code and history
// (README.md, CLAUDE.md, CONTRIBUTING.md, CHANGELOG.md, .gitignore) are never
// written; init reports them as still missing.
package initfiles

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/anatolykoptev/repo-standards/internal/check"
)

// Options configures Run. Visibility is the resolved repository visibility;
// it arrives already validated by check.ResolveVisibility, the same rule
// check applies (--detected wins, a less strict declaration is an error).
type Options struct {
	Root       string
	Visibility check.Visibility
	Holder     string // copyright holder for a generated LICENSE
	Year       string // copyright year or range; defaults to the current year
	License    string // "", "apache-2.0" or "mit"; a public-repository choice
	Repo       string // GitHub "OWNER/NAME"; default: parse the origin remote
	DryRun     bool   // report what would be created, write nothing
}

// Result is what init did and what remains for a human to write.
type Result struct {
	// Lines narrate the run: "created X", "kept X", "would create X" or a
	// "skipped X" note, in write order.
	Lines []string
	// Missing is the required files still absent after the run: the documents
	// init never writes. The file set is the tracked files plus the files this
	// run created, so it is what check will see once they are added.
	Missing []check.Finding
	// Hint, when non-empty, is the follow-up command a maintainer runs next:
	// indexing the documents init leaves for a human.
	Hint string
	// NotGit is set when root was not a git work tree.
	NotGit bool
}

var (
	yearRE = regexp.MustCompile(`^\d{4}(-\d{4})?$`)
	repoRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
)

// slugOK reports whether s is an OWNER/NAME pair where neither part is "." or
// "..": those spell out directory traversal, not a repository.
func slugOK(s string) bool {
	if !repoRE.MatchString(s) {
		return false
	}
	owner, name, _ := strings.Cut(s, "/")
	return owner != "." && owner != ".." && name != "." && name != ".."
}

// Run writes the missing boilerplate under opts.Root and reports the required
// files still absent afterwards. Every planned write is validated before the
// first one lands, so a bad path aborts the run instead of leaving a
// half-written repository; a write that still fails returns the lines
// collected so far.
func Run(opts Options) (res Result, err error) {
	if opts.Visibility != check.Public && opts.Visibility != check.Private {
		return Result{}, fmt.Errorf("visibility must be %q or %q, got %q", check.Public, check.Private, opts.Visibility)
	}
	if opts.License != "" && opts.License != "apache-2.0" && opts.License != "mit" {
		return Result{}, fmt.Errorf("--license must be %q or %q, got %q", "apache-2.0", "mit", opts.License)
	}
	if opts.Visibility == check.Private && opts.License != "" {
		return Result{}, fmt.Errorf("--license applies to public repositories; a private repository takes the proprietary notice")
	}
	year := opts.Year
	if year == "" {
		year = strconv.Itoa(time.Now().Year())
	}
	if !yearRE.MatchString(year) {
		return Result{}, fmt.Errorf("--year must be a year or range like 2026 or 2024-2026, got %q", year)
	}
	if opts.Repo != "" && !slugOK(opts.Repo) {
		return Result{}, fmt.Errorf("--repo must be OWNER/NAME, got %q", opts.Repo)
	}
	// The file universe init decides on is the tracked set the check uses
	// plus the work tree: an untracked file is kept too, but only under its
	// real on-disk spelling.
	files, notGit, err := check.RepoFiles(opts.Root)
	if err != nil {
		return Result{}, err
	}
	res.NotGit = notGit
	resolvedRoot, err := filepath.EvalSymlinks(opts.Root)
	if err != nil {
		return Result{}, err
	}
	all, present, err := fileUniverse(resolvedRoot, files)
	if err != nil {
		return Result{}, err
	}
	// Existence is the check's own predicate over the same universe, so init
	// never claims kept for a spelling the check would reject.
	licenceName, licenceExists := check.FoundPath(check.LicenceFile, all)
	issueName, issueExists := check.FoundPath(check.IssueTemplateDir, all)
	pullName, pullExists := check.FoundPath(check.PullRequestTemplate, all)
	needHolder := !licenceExists &&
		(opts.Visibility == check.Private || opts.License == "mit")
	if needHolder && opts.Holder == "" {
		return Result{}, fmt.Errorf("--holder is required to write LICENSE: it carries the copyright name")
	}
	// The plan is an ordered list of kept notes and writes; rendering is
	// deferred until the repo slug is resolved.
	repo := opts.Repo
	type action struct {
		line   string        // kept/skipped note, when rel is empty
		rel    string        // write target, when non-empty
		render func() []byte // produces the content to write
		data   []byte
	}
	var plan []action
	keep := func(line string) { plan = append(plan, action{line: line}) }
	put := func(rel string, render func() []byte) {
		plan = append(plan, action{rel: rel, render: render})
	}
	putOrKeep := func(rel string, render func() []byte) {
		if present[rel] {
			keep("kept " + rel)
		} else {
			put(rel, render)
		}
	}
	putOrKeep("CODE_OF_CONDUCT.md", func() []byte { return []byte(codeOfConduct) })
	putOrKeep("SECURITY.md", func() []byte { return securityDoc(opts.Visibility, repo) })
	// A repository with its own issue templates — a template file under
	// .github/ISSUE_TEMPLATE/ or a legacy single file — keeps its issue
	// intake exactly as it is; the blank_issues_enabled chooser config would
	// silently change it.
	if issueExists {
		keep("kept issue templates (" + issueName + ")")
	} else {
		putOrKeep(".github/ISSUE_TEMPLATE/bug_report.yml", func() []byte { return []byte(bugReportForm) })
		putOrKeep(".github/ISSUE_TEMPLATE/feature_request.yml", func() []byte { return []byte(featureRequestForm) })
		putOrKeep(".github/ISSUE_TEMPLATE/config.yml", func() []byte { return issueConfig(opts.Visibility, repo) })
	}
	if pullExists {
		keep("kept " + pullName)
	} else {
		putOrKeep(check.PullRequestTemplate, func() []byte { return []byte(pullRequestTemplate) })
	}
	switch lic := licenceText(opts, licenceExists, year); {
	case lic == nil && !licenceExists && opts.Visibility == check.Public:
		keep("skipped LICENSE: choose a licence with --license")
	case lic != nil:
		put(check.AcceptedSpellings(check.LicenceFile)[0], func() []byte { return lic })
	default:
		keep("kept " + licenceName)
	}
	// The advisory links need OWNER/NAME, and only when a file carrying them
	// is actually written: --repo, else the origin remote, else an error
	// before anything is written.
	if repo == "" && opts.Visibility == check.Public {
		for _, a := range plan {
			if a.rel == "SECURITY.md" || a.rel == ".github/ISSUE_TEMPLATE/config.yml" {
				var serr error
				if repo, serr = originSlug(opts.Root); serr != nil {
					return Result{}, fmt.Errorf("cannot build the GitHub advisory links: %v; pass --repo OWNER/NAME", serr)
				}
				break
			}
		}
	}
	written := map[string][]byte{} // content this run produced, for the INDEX
	if !present["docs/INDEX.md"] {
		put("docs/INDEX.md", func() []byte {
			// The index is generated, not templated: it links every target the
			// index check requires, including what this run created.
			var universe []string
			universe = append(universe, files...)
			for _, a := range plan {
				if a.rel != "" {
					universe = append(universe, a.rel)
				}
			}
			sort.Strings(universe)
			return []byte(indexMarkdown(resolvedRoot, universe, written))
		})
	} else {
		keep("kept docs/INDEX.md")
	}
	for i := range plan {
		if plan[i].render == nil {
			continue
		}
		plan[i].data = plan[i].render()
		written[plan[i].rel] = plan[i].data
	}
	// Validate every planned write before the first lands: a parent that is a
	// regular file or a symlink escape aborts the run with nothing written.
	for _, a := range plan {
		if a.rel == "" {
			continue
		}
		if err := checkPath(resolvedRoot, a.rel); err != nil {
			return res, err
		}
	}
	var newPaths []string
	for _, a := range plan {
		if a.rel == "" {
			res.Lines = append(res.Lines, a.line)
			continue
		}
		if opts.DryRun {
			res.Lines = append(res.Lines, "would create "+a.rel)
			newPaths = append(newPaths, a.rel)
			continue
		}
		created, err := writeNew(opts.Root, a.rel, a.data)
		if err != nil {
			return res, err
		}
		if created {
			res.Lines = append(res.Lines, "created "+a.rel)
			newPaths = append(newPaths, a.rel)
		} else {
			res.Lines = append(res.Lines, "kept "+a.rel)
		}
	}
	universe := append(append([]string{}, files...), newPaths...)
	sort.Strings(universe)
	for _, f := range check.RequiredFindings(opts.Root, universe) {
		if f.Check == check.MissingFile {
			res.Missing = append(res.Missing, f)
		}
	}
	if len(res.Missing) > 0 {
		var missing []string
		for _, f := range res.Missing {
			missing = append(missing, f.Path)
		}
		future := append(append([]string{}, universe...), missing...)
		want := map[string]bool{}
		for _, t := range check.IndexTargets(future) {
			want[t.Path] = true
		}
		var pending []string
		for _, f := range res.Missing {
			if want[f.Path] {
				pending = append(pending, f.Path)
			}
		}
		if len(pending) > 0 {
			res.Hint = "run 'repo-standards index' after adding " + strings.Join(pending, ", ")
		}
	}
	return res, nil
}

// fileUniverse merges the tracked files with the work-tree listing under
// resolvedRoot: the set init's kept-decisions run on.
func fileUniverse(resolvedRoot string, files []string) (all []string, present map[string]bool, err error) {
	disk, err := diskFiles(resolvedRoot)
	if err != nil {
		return nil, nil, err
	}
	present = make(map[string]bool, len(files)+len(disk))
	for _, f := range files {
		present[f] = true
	}
	for _, f := range disk {
		present[f] = true
	}
	all = make([]string, 0, len(present))
	for f := range present {
		all = append(all, f)
	}
	sort.Strings(all)
	return all, present, nil
}

// diskFiles returns the work-tree files under resolvedRoot as slash-separated
// relative paths. Names come from directory listings, so they carry the real
// on-disk spelling even on a case-insensitive filesystem — unlike an Lstat of
// a candidate name, which would claim a differently-cased file exists.
func diskFiles(resolvedRoot string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(resolvedRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(resolvedRoot, p)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	return out, err
}

// checkPath verifies a planned write stays inside the repository. Every
// existing component of rel under resolvedRoot must resolve inside the root
// and, for a parent component, be a directory; a component that does not
// exist ends the check, as it and everything below it will be created.
func checkPath(resolvedRoot, rel string) error {
	cur := resolvedRoot
	segs := strings.Split(rel, "/")
	for i, seg := range segs {
		if seg == "." || seg == "" {
			continue
		}
		cur = filepath.Join(cur, seg)
		resolved, err := filepath.EvalSymlinks(cur)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil // to be created; nothing below can exist
			}
			return fmt.Errorf("%s: %v", rel, err)
		}
		inside, err := filepath.Rel(resolvedRoot, resolved)
		if err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
			return fmt.Errorf("%s: %s resolves outside the repository", rel, strings.Join(segs[:i+1], "/"))
		}
		if i == len(segs)-1 {
			return nil
		}
		st, err := os.Stat(resolved)
		if err != nil {
			return err
		}
		if !st.IsDir() {
			return fmt.Errorf("%s: %s is not a directory", rel, strings.Join(segs[:i+1], "/"))
		}
	}
	return nil
}

// securityDoc renders SECURITY.md; the public variant carries the private
// vulnerability reporting URL for repo (OWNER/NAME).
func securityDoc(vis check.Visibility, repo string) []byte {
	if vis == check.Public {
		return []byte(strings.ReplaceAll(securityPublic, "{{REPO}}", repo))
	}
	return []byte(securityPrivate)
}

// issueConfig renders .github/ISSUE_TEMPLATE/config.yml; only a public
// repository gets the security contact link.
func issueConfig(vis check.Visibility, repo string) []byte {
	if vis == check.Public {
		return []byte(strings.ReplaceAll(issueConfigPublic, "{{REPO}}", repo))
	}
	return []byte(issueConfigPrivate)
}

// licenceText renders the LICENSE file, or nil when init should not write
// one: the licence exists, or a public repository chose no licence (choosing
// one is the owner's decision; init never picks one).
func licenceText(opts Options, licenceExists bool, year string) []byte {
	if licenceExists {
		return nil
	}
	if opts.Visibility == check.Private {
		return []byte(fill(proprietaryLicence, year, opts.Holder))
	}
	switch opts.License {
	case "apache-2.0":
		return []byte(apacheText)
	case "mit":
		return []byte(fill(mitText, year, opts.Holder))
	}
	return nil
}

// fill substitutes the copyright placeholders of a licence text.
func fill(tmpl, year, holder string) string {
	return strings.NewReplacer("{{YEAR}}", year, "{{HOLDER}}", holder,
		"<year>", year, "<copyright holders>", holder).Replace(tmpl)
}

// writeNew writes data to root/rel, creating parent directories. An existing
// file is not an error but an outcome: O_EXCL is the guard, so a hand-written
// file can never be truncated or replaced.
func writeNew(root, rel string, data []byte) (created bool, err error) {
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return false, err
	}
	fh, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return false, err
	}
	if _, err := fh.Write(data); err != nil {
		fh.Close()
		return false, err
	}
	return true, fh.Close()
}

// originSlug reads the origin remote and returns its GitHub OWNER/NAME for
// the https and ssh URL forms.
func originSlug(root string) (string, error) {
	out, err := exec.Command("git", "-C", root, "remote", "get-url", "origin").Output()
	if err != nil {
		return "", fmt.Errorf("git remote get-url origin failed")
	}
	return parseGitHubURL(strings.TrimSpace(string(out)))
}

// parseGitHubURL extracts OWNER/NAME from a GitHub remote URL:
// https://github.com/OWNER/NAME, git@github.com:OWNER/NAME or
// ssh://git@github.com/OWNER/NAME, each with an optional .git suffix. The host
// match is case-insensitive. The URL itself is never echoed in an error: it
// can carry a credential.
func parseGitHubURL(u string) (string, error) {
	if host, rest, ok := scpForm(u); ok {
		if !strings.EqualFold(host, "github.com") {
			return "", fmt.Errorf("the origin remote is not a GitHub remote")
		}
		return cleanSlug(rest)
	}
	p, err := url.Parse(u)
	if err != nil {
		return "", fmt.Errorf("the origin remote URL did not parse")
	}
	if (p.Scheme == "https" || p.Scheme == "ssh") && strings.EqualFold(p.Hostname(), "github.com") {
		return cleanSlug(strings.TrimPrefix(p.Path, "/"))
	}
	return "", fmt.Errorf("the origin remote is not a GitHub https or ssh URL")
}

// scpForm parses the scp-like remote form user@host:path, which url.Parse
// cannot read: the colon before any slash makes it an invalid opaque URL.
func scpForm(u string) (host, rest string, ok bool) {
	if strings.Contains(u, "://") {
		return "", "", false
	}
	i := strings.Index(u, "@")
	if i < 0 {
		return "", "", false
	}
	j := strings.Index(u[i+1:], ":")
	if j < 0 {
		return "", "", false
	}
	host = u[i+1 : i+1+j]
	if host == "" || strings.Contains(host, "/") {
		return "", "", false
	}
	return host, u[i+1+j+1:], true
}

func cleanSlug(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git")
	if !slugOK(s) {
		return "", fmt.Errorf("the origin remote path is not OWNER/NAME")
	}
	return s, nil
}

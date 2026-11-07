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
	// NotGit is set when root was not a git work tree.
	NotGit bool
}

var (
	yearRE = regexp.MustCompile(`^\d{4}(-\d{4})?$`)
	repoRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
)

// licenceNames are the spellings the required-file check accepts for the
// licence; init writes the first when none is present.
var licenceNames = []string{"LICENSE", "LICENSE.md", "LICENSE.txt"}

// pullTemplateNames are the spellings GitHub accepts for the pull-request
// template, canonical first.
var pullTemplateNames = []string{".github/pull_request_template.md",
	".github/PULL_REQUEST_TEMPLATE.md", "pull_request_template.md",
	"docs/pull_request_template.md"}

// Run writes the missing boilerplate under opts.Root and reports the required
// files still absent afterwards.
func Run(opts Options) (Result, error) {
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
	if opts.Repo != "" && !repoRE.MatchString(opts.Repo) {
		return Result{}, fmt.Errorf("--repo must be OWNER/NAME, got %q", opts.Repo)
	}
	exists := func(rel string) bool {
		_, err := os.Lstat(filepath.Join(opts.Root, filepath.FromSlash(rel)))
		return err == nil
	}
	licenceExists := exists(licenceNames[0]) || exists(licenceNames[1]) || exists(licenceNames[2])
	needHolder := !licenceExists &&
		(opts.Visibility == check.Private || opts.License == "mit")
	if needHolder && opts.Holder == "" {
		return Result{}, fmt.Errorf("--holder is required to write LICENSE: it carries the copyright name")
	}
	// Resolve every input that can fail before touching the disk, so an error
	// never leaves a half-written repository.
	repo := opts.Repo
	needRepo := opts.Visibility == check.Public &&
		(!exists("SECURITY.md") || !exists(".github/ISSUE_TEMPLATE/config.yml"))
	if needRepo && repo == "" {
		var err error
		if repo, err = originSlug(opts.Root); err != nil {
			return Result{}, fmt.Errorf("cannot build the GitHub advisory links: %v; pass --repo OWNER/NAME", err)
		}
	}
	files, notGit, err := check.RepoFiles(opts.Root)
	if err != nil {
		return Result{}, err
	}
	res := Result{NotGit: notGit}
	var newPaths []string
	written := map[string][]byte{} // content this run produced, for the INDEX
	write := func(rel string, data []byte) error {
		if opts.DryRun {
			if exists(rel) {
				res.Lines = append(res.Lines, "kept "+rel)
			} else {
				res.Lines = append(res.Lines, "would create "+rel)
				newPaths = append(newPaths, rel)
				written[rel] = data
			}
			return nil
		}
		created, err := writeNew(opts.Root, rel, data)
		if err != nil {
			return err
		}
		if created {
			res.Lines = append(res.Lines, "created "+rel)
			newPaths = append(newPaths, rel)
			written[rel] = data
		} else {
			res.Lines = append(res.Lines, "kept "+rel)
		}
		return nil
	}
	// writeAny creates names[0] unless one of the accepted spellings exists,
	// which is kept under its own name.
	writeAny := func(names []string, data []byte) error {
		for _, n := range names {
			if exists(n) {
				res.Lines = append(res.Lines, "kept "+n)
				return nil
			}
		}
		return write(names[0], data)
	}
	filesToWrite := []struct {
		rel  string
		data []byte
	}{
		{"CODE_OF_CONDUCT.md", []byte(codeOfConduct)},
		{"SECURITY.md", securityDoc(opts.Visibility, repo)},
		{".github/ISSUE_TEMPLATE/bug_report.yml", []byte(bugReportForm)},
		{".github/ISSUE_TEMPLATE/feature_request.yml", []byte(featureRequestForm)},
		{".github/ISSUE_TEMPLATE/config.yml", issueConfig(opts.Visibility, repo)},
	}
	for _, f := range filesToWrite {
		if err := write(f.rel, f.data); err != nil {
			return Result{}, err
		}
	}
	if err := writeAny(pullTemplateNames, []byte(pullRequestTemplate)); err != nil {
		return Result{}, err
	}
	switch lic := licenceText(opts, licenceExists, year); {
	case lic == nil && !licenceExists && opts.Visibility == check.Public:
		res.Lines = append(res.Lines, "skipped LICENSE: choose a licence with --license")
	case lic != nil:
		if err := writeAny(licenceNames, lic); err != nil {
			return Result{}, err
		}
	default:
		res.Lines = append(res.Lines, "kept "+firstPresent(licenceNames, exists))
	}
	// docs/INDEX.md is generated, not templated: it must link what this run
	// created, so it goes last.
	if !exists("docs/INDEX.md") {
		universe := append(append([]string{}, files...), newPaths...)
		sort.Strings(universe)
		if err := write("docs/INDEX.md", []byte(indexMarkdown(opts.Root, universe, written))); err != nil {
			return Result{}, err
		}
	} else {
		res.Lines = append(res.Lines, "kept docs/INDEX.md")
	}
	universe := append(append([]string{}, files...), newPaths...)
	sort.Strings(universe)
	for _, f := range check.RequiredFindings(opts.Root, universe) {
		if f.Check == check.MissingFile {
			res.Missing = append(res.Missing, f)
		}
	}
	return res, nil
}

func firstPresent(names []string, exists func(string) bool) string {
	for _, n := range names {
		if exists(n) {
			return n
		}
	}
	return names[0]
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
// ssh://git@github.com/OWNER/NAME, each with an optional .git suffix. The URL
// itself is never echoed in an error: it can carry a credential.
func parseGitHubURL(u string) (string, error) {
	if rest, ok := strings.CutPrefix(u, "git@github.com:"); ok {
		return cleanSlug(rest)
	}
	p, err := url.Parse(u)
	if err != nil {
		return "", fmt.Errorf("the origin remote URL did not parse")
	}
	if (p.Scheme == "https" || p.Scheme == "ssh") && p.Hostname() == "github.com" {
		return cleanSlug(strings.TrimPrefix(p.Path, "/"))
	}
	return "", fmt.Errorf("the origin remote is not a GitHub https or ssh URL")
}

func cleanSlug(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git")
	if !repoRE.MatchString(s) {
		return "", fmt.Errorf("the origin remote path is not OWNER/NAME")
	}
	return s, nil
}

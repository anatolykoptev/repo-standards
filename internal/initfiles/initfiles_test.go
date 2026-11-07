package initfiles

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/anatolykoptev/repo-standards/internal/check"
	"github.com/anatolykoptev/repo-standards/internal/denylist"
)

func filler(title string, lines int) string {
	return "# " + title + "\n\n" + strings.Repeat("This sentence documents real behaviour of the project.\n", lines)
}

// baseRepo is the human-written document set a repository already has before
// init fills in the boilerplate; CLAUDE.md links docs/INDEX.md so the index
// chain holds once the index exists.
func baseRepo() map[string]string {
	return map[string]string{
		"README.md":       filler("Readme", 6),
		"CLAUDE.md":       filler("Agent notes", 4) + "\nAll docs: [index](docs/INDEX.md).\n",
		"CHANGELOG.md":    "# Changelog\n\nNothing released yet.\n",
		"CONTRIBUTING.md": filler("Contributing", 4),
		".gitignore":      "bin/\n",
	}
}

// writeRepo materialises files in a fresh git work tree with everything added.
func writeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitIn(t, root, "init", "-q")
	gitIn(t, root, "add", "-A")
	return root
}

func gitIn(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func runInit(t *testing.T, opts Options) Result {
	t.Helper()
	res, err := Run(opts)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// testList builds a denylist from plaintext with a fixed salt, the way the
// check tests do; the token is an invented word.
func testList(t *testing.T) *denylist.List {
	t.Helper()
	data, _, err := denylist.Generate(strings.NewReader("host:zzqdefaulthost\n"), []byte("0123456789abcdef"), nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := denylist.Parse(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// runCheck runs the real check on the repository, as a maintainer would after
// adding init's output.
func runCheck(t *testing.T, root string, vis check.Visibility) []check.Finding {
	t.Helper()
	res, err := check.Run(check.Options{Root: root, Visibility: vis, Denylist: testList(t)})
	if err != nil {
		t.Fatal(err)
	}
	return res.Findings
}

func hasLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// F1: a maintainer runs init in a repo that already has a hand-written
// SECURITY.md and LICENSE; both stay byte-identical, init prints kept.
func TestInitKeepsExistingFiles(t *testing.T) {
	files := baseRepo()
	sec := "# Our own security doc\n\n" + strings.Repeat("Hand written prose stays. ", 20)
	lic := "Copyright (c) 2024 Hand Holder. All rights reserved.\n"
	files["SECURITY.md"] = sec
	files["LICENSE"] = lic
	root := writeRepo(t, files)
	res := runInit(t, Options{Root: root, Visibility: check.Private, Holder: "Zzq Holder"})
	for name, want := range map[string]string{"SECURITY.md": sec, "LICENSE": lic} {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%s: init modified an existing file", name)
		}
		if !hasLine(res.Lines, "kept "+name) {
			t.Errorf("no %q line in %v", "kept "+name, res.Lines)
		}
	}
}

// F2: init on a fresh git repo that has the human-written documents, then
// git add of the init output, then check: zero findings.
func TestInitThenCheckClean(t *testing.T) {
	cases := []struct {
		name string
		opts Options
		vis  check.Visibility
	}{
		{"private", Options{Visibility: check.Private, Holder: "Zzq Holder", Year: "2026"}, check.Private},
		{"public mit", Options{Visibility: check.Public, License: "mit", Holder: "Zzq Holder", Repo: "zzqowner/zzqrepo", Year: "2026"}, check.Public},
		{"public apache", Options{Visibility: check.Public, License: "apache-2.0", Repo: "zzqowner/zzqrepo"}, check.Public},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.opts.Root = writeRepo(t, baseRepo())
			runInit(t, c.opts)
			gitIn(t, c.opts.Root, "add", "-A")
			if fs := runCheck(t, c.opts.Root, c.vis); len(fs) != 0 {
				t.Fatalf("check after init: %v", fs)
			}
		})
	}
}

// F3: the LICENCE init writes for a private repository is the proprietary
// notice the licence check accepts.
func TestInitPrivateLicenceAccepted(t *testing.T) {
	root := writeRepo(t, baseRepo())
	runInit(t, Options{Root: root, Visibility: check.Private, Holder: "Zzq Holder", Year: "2026"})
	lic, err := os.ReadFile(filepath.Join(root, "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(lic), "Copyright (c) 2026 Zzq Holder. All rights reserved.") {
		t.Fatalf("LICENSE is not the expected notice:\n%s", lic)
	}
	gitIn(t, root, "add", "-A")
	if fs := runCheck(t, root, check.Private); len(fs) != 0 {
		t.Fatalf("check rejected the generated licence: %v", fs)
	}
}

// F4: a repo with docs pages and no docs/INDEX.md gets an index whose rows
// link with correct relative paths.
func TestInitIndexLinksDocs(t *testing.T) {
	files := baseRepo()
	files["docs/guide.md"] = filler("Guide", 3)
	files["docs/deep/inner.md"] = filler("Inner", 3)
	root := writeRepo(t, files)
	runInit(t, Options{Root: root, Visibility: check.Private, Holder: "Zzq Holder"})
	idx, err := os.ReadFile(filepath.Join(root, "docs/INDEX.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"](guide.md)", "](deep/inner.md)", "](../README.md)"} {
		if !strings.Contains(string(idx), want) {
			t.Errorf("generated INDEX lacks link %q:\n%s", want, idx)
		}
	}
	gitIn(t, root, "add", "-A")
	if fs := runCheck(t, root, check.Private); len(fs) != 0 {
		t.Fatalf("generated INDEX fails the index checks: %v", fs)
	}
}

func TestInitDryRunWritesNothing(t *testing.T) {
	root := writeRepo(t, baseRepo())
	res := runInit(t, Options{Root: root, Visibility: check.Private, Holder: "Zzq", DryRun: true})
	if !hasLine(res.Lines, "would create SECURITY.md") || !hasLine(res.Lines, "would create docs/INDEX.md") {
		t.Fatalf("want would-create lines, got %v", res.Lines)
	}
	for _, rel := range []string{"SECURITY.md", "CODE_OF_CONDUCT.md", "LICENSE", "docs/INDEX.md", ".github/pull_request_template.md"} {
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel))); err == nil {
			t.Errorf("dry-run wrote %s", rel)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, ".github")); err == nil {
		t.Error("dry-run created .github")
	}
}

// init never writes the documents that must come from the project's real code
// and history; it lists them as still missing.
func TestInitNeverWritesHumanDocs(t *testing.T) {
	root := writeRepo(t, map[string]string{"go.mod": "module zzq.example/x\n"})
	res := runInit(t, Options{Root: root, Visibility: check.Private, Holder: "Zzq"})
	for _, rel := range []string{"README.md", "CLAUDE.md", "CONTRIBUTING.md", "CHANGELOG.md", ".gitignore"} {
		if _, err := os.Lstat(filepath.Join(root, rel)); err == nil {
			t.Errorf("init wrote %s", rel)
		}
	}
	var missing []string
	for _, f := range res.Missing {
		missing = append(missing, f.Path)
	}
	sort.Strings(missing)
	want := []string{".gitignore", "CHANGELOG.md", "CLAUDE.md", "CONTRIBUTING.md", "README.md"}
	if !equal(missing, want) {
		t.Fatalf("still-missing %v want %v", missing, want)
	}
}

func TestInitRequiresHolder(t *testing.T) {
	root := writeRepo(t, baseRepo())
	if _, err := Run(Options{Root: root, Visibility: check.Private}); err == nil || !strings.Contains(err.Error(), "--holder") {
		t.Fatalf("want a --holder error, got %v", err)
	}
	if _, err := Run(Options{Root: root, Visibility: check.Public, License: "mit", Repo: "o/n"}); err == nil {
		t.Fatal("want a --holder error for mit")
	}
	if _, err := os.Lstat(filepath.Join(root, "SECURITY.md")); err == nil {
		t.Fatal("wrote files before failing on the missing holder")
	}
	// apache-2.0 needs no holder: the text has no filled copyright line.
	root2 := writeRepo(t, baseRepo())
	runInit(t, Options{Root: root2, Visibility: check.Public, License: "apache-2.0", Repo: "o/n"})
	if _, err := os.Lstat(filepath.Join(root2, "LICENSE")); err != nil {
		t.Fatal("apache LICENSE not written")
	}
}

func TestInitSkippedLicence(t *testing.T) {
	root := writeRepo(t, baseRepo())
	res := runInit(t, Options{Root: root, Visibility: check.Public, Repo: "o/n"})
	if !hasLine(res.Lines, "skipped LICENSE: choose a licence with --license") {
		t.Fatalf("want the skipped line, got %v", res.Lines)
	}
	if _, err := os.Lstat(filepath.Join(root, "LICENSE")); err == nil {
		t.Fatal("LICENSE written without --license")
	}
}

func TestInitLicenceOnPrivateIsError(t *testing.T) {
	root := writeRepo(t, baseRepo())
	if _, err := Run(Options{Root: root, Visibility: check.Private, License: "mit", Holder: "Zzq"}); err == nil {
		t.Fatal("--license on a private repository must be an error")
	}
}

// The advisory link needs OWNER/NAME: from --repo, else the origin remote,
// else an error before anything is written.
func TestInitRepoResolution(t *testing.T) {
	root := writeRepo(t, baseRepo())
	if _, err := Run(Options{Root: root, Visibility: check.Public, Holder: "Zzq", License: "mit"}); err == nil || !strings.Contains(err.Error(), "--repo") {
		t.Fatalf("want a --repo error, got %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "SECURITY.md")); err == nil {
		t.Fatal("wrote files before resolving the repo slug")
	}
	for _, remote := range []string{"git@github.com:zzqowner/zzqrepo.git", "https://github.com/zzqowner/zzqrepo.git", "ssh://git@github.com/zzqowner/zzqrepo"} {
		r := writeRepo(t, baseRepo())
		gitIn(t, r, "remote", "add", "origin", remote)
		runInit(t, Options{Root: r, Visibility: check.Public, Holder: "Zzq", License: "mit"})
		sec, err := os.ReadFile(filepath.Join(r, "SECURITY.md"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(sec), "https://github.com/zzqowner/zzqrepo/security/advisories/new") {
			t.Errorf("%s: SECURITY.md has no advisory link:\n%s", remote, sec)
		}
	}
	if _, err := Run(Options{Root: writeRepo(t, baseRepo()), Visibility: check.Public, Repo: "bogus", License: "apache-2.0"}); err == nil {
		t.Fatal("a malformed --repo must be an error")
	}
	if _, err := Run(Options{Root: writeRepo(t, baseRepo()), Visibility: check.Public, Repo: "o/n", Year: "20x6", License: "apache-2.0"}); err == nil {
		t.Fatal("a malformed --year must be an error")
	}
}

// R1: a repository with its own issue templates — a file in the template
// directory or a legacy single file — keeps its issue intake: none of the
// generated forms or the chooser config is written, and the check passes
// once the files are added.
func TestInitKeepsOwnIssueTemplates(t *testing.T) {
	for _, c := range []struct{ name, file string }{
		{"dir template", ".github/ISSUE_TEMPLATE/custom.md"},
		{"legacy root", "ISSUE_TEMPLATE.md"},
		{"legacy .github", ".github/ISSUE_TEMPLATE.md"},
		{"legacy docs", "docs/ISSUE_TEMPLATE.md"},
	} {
		t.Run(c.name, func(t *testing.T) {
			files := baseRepo()
			files[c.file] = filler("Issue", 3)
			root := writeRepo(t, files)
			res := runInit(t, Options{Root: root, Visibility: check.Private, Holder: "Zzq Holder"})
			if !hasLine(res.Lines, "kept issue templates ("+c.file+")") {
				t.Fatalf("no kept-issue-templates line in %v", res.Lines)
			}
			for _, rel := range []string{".github/ISSUE_TEMPLATE/bug_report.yml",
				".github/ISSUE_TEMPLATE/feature_request.yml", ".github/ISSUE_TEMPLATE/config.yml"} {
				if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel))); err == nil {
					t.Errorf("init wrote %s over the repository's own templates", rel)
				}
			}
			gitIn(t, root, "add", "-A")
			if fs := runCheck(t, root, check.Private); len(fs) != 0 {
				t.Fatalf("check after init: %v", fs)
			}
		})
	}
}

// A config.yml alone does not satisfy the template requirement: init adds
// the missing forms and keeps the existing config.
func TestInitFillsTemplatesBesideConfig(t *testing.T) {
	files := baseRepo()
	files[".github/ISSUE_TEMPLATE/config.yml"] = "blank_issues_enabled: false\n"
	root := writeRepo(t, files)
	res := runInit(t, Options{Root: root, Visibility: check.Private, Holder: "Zzq Holder"})
	if !hasLine(res.Lines, "kept .github/ISSUE_TEMPLATE/config.yml") {
		t.Fatalf("config not kept: %v", res.Lines)
	}
	for _, rel := range []string{".github/ISSUE_TEMPLATE/bug_report.yml", ".github/ISSUE_TEMPLATE/feature_request.yml"} {
		if !hasLine(res.Lines, "created "+rel) {
			t.Errorf("no created line for %s in %v", rel, res.Lines)
		}
	}
}

// R2: the spellings init accepts for a pull-request template are the check's
// own list — an upper-case root file or a .md inside the multi-template
// directory is kept, the canonical file is not written, and the check agrees.
func TestInitPullTemplateMatchesCheck(t *testing.T) {
	for _, name := range []string{".github/pull_request_template.md",
		"PULL_REQUEST_TEMPLATE.md", "pull_request_template.md",
		".github/PULL_REQUEST_TEMPLATE.md", ".github/PULL_REQUEST_TEMPLATE/bugfix.md",
		"docs/pull_request_template.md", "docs/PULL_REQUEST_TEMPLATE.md"} {
		t.Run(name, func(t *testing.T) {
			files := baseRepo()
			files[name] = filler("Pull request", 2)
			root := writeRepo(t, files)
			res := runInit(t, Options{Root: root, Visibility: check.Private, Holder: "Zzq Holder"})
			if !hasLine(res.Lines, "kept "+name) {
				t.Fatalf("no kept line for %s in %v", name, res.Lines)
			}
			gitIn(t, root, "add", "-A")
			if fs := runCheck(t, root, check.Private); len(fs) != 0 {
				t.Fatalf("check after init: %v", fs)
			}
		})
	}
}

// R4: a parent directory that is a symlink out of the repository makes init
// refuse the whole run before anything is written — inside or outside.
func TestInitRefusesSymlinkEscape(t *testing.T) {
	root := writeRepo(t, baseRepo())
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".github")); err != nil {
		t.Fatal(err)
	}
	_, err := Run(Options{Root: root, Visibility: check.Private, Holder: "Zzq Holder"})
	if err == nil {
		t.Fatal("init wrote through a symlinked .github")
	}
	for _, rel := range []string{"SECURITY.md", "CODE_OF_CONDUCT.md", "LICENSE", "docs/INDEX.md"} {
		if _, err := os.Lstat(filepath.Join(root, rel)); err == nil {
			t.Errorf("%s written although the run was refused", rel)
		}
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Errorf("init wrote %v outside the repository", ents)
	}
}

// R5: a parent component that is a regular file fails validation before the
// first write lands — no half-written repository, no kept notes.
func TestInitFailureWritesNothing(t *testing.T) {
	root := writeRepo(t, baseRepo())
	if err := os.WriteFile(filepath.Join(root, ".github"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run(Options{Root: root, Visibility: check.Private, Holder: "Zzq Holder"})
	if err == nil {
		t.Fatal("init accepted a .github that is a regular file")
	}
	for _, rel := range []string{"SECURITY.md", "CODE_OF_CONDUCT.md", "LICENSE", "docs/INDEX.md"} {
		if _, err := os.Lstat(filepath.Join(root, rel)); err == nil {
			t.Errorf("%s written although the run failed", rel)
		}
	}
	if len(res.Lines) != 0 {
		t.Errorf("lines reported for a run that wrote nothing: %v", res.Lines)
	}
}

// R7: the host match is case-insensitive on every URL form, an ssh URL with a
// port still parses, and a non-GitHub scp-form remote names its problem.
func TestParseGitHubURLHostAndForms(t *testing.T) {
	for _, u := range []string{
		"https://GitHub.com/zzqowner/zzqrepo",
		"git@GitHub.com:zzqowner/zzqrepo",
		"ssh://git@GitHub.com/zzqowner/zzqrepo",
		"ssh://git@github.com:2222/zzqowner/zzqrepo",
	} {
		got, err := parseGitHubURL(u)
		if err != nil || got != "zzqowner/zzqrepo" {
			t.Errorf("%s: got %q err %v", u, got, err)
		}
	}
	if _, err := parseGitHubURL("git@gitlab.com:zzqowner/zzqrepo"); err == nil ||
		!strings.Contains(err.Error(), "not a GitHub remote") {
		t.Errorf("non-GitHub scp-form must name the problem: %v", err)
	}
}

// R8: "." and ".." are directory traversal, not an owner or a repository.
func TestRepoSlugRejectsDotSegments(t *testing.T) {
	for _, s := range []string{"./x", "../x", "x/.", "x/..", "./..", "../."} {
		if _, err := cleanSlug(s); err == nil {
			t.Errorf("cleanSlug(%q) accepted", s)
		}
	}
	for _, s := range []string{"zzqowner/zzqrepo", "o/.github", "o/x.github.io"} {
		if _, err := cleanSlug(s); err != nil {
			t.Errorf("cleanSlug(%q) rejected a real slug: %v", s, err)
		}
	}
	if _, err := Run(Options{Root: writeRepo(t, baseRepo()), Visibility: check.Public,
		Repo: "./x", License: "apache-2.0"}); err == nil {
		t.Error("--repo ./x accepted")
	}
}

// R3: a document added after the index gets a row appended; existing rows
// are untouched and the check is satisfied afterwards.
func TestUpdateIndexAppendsMissingRows(t *testing.T) {
	root := writeRepo(t, baseRepo())
	runInit(t, Options{Root: root, Visibility: check.Private, Holder: "Zzq Holder"})
	gitIn(t, root, "add", "-A")
	if err := os.WriteFile(filepath.Join(root, "docs", "extra.md"), []byte(filler("Extra", 3)), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, root, "add", "-A")
	before, err := os.ReadFile(filepath.Join(root, "docs", "INDEX.md"))
	if err != nil {
		t.Fatal(err)
	}
	// --dry-run reports and writes nothing.
	dry, err := UpdateIndex(IndexOptions{Root: root, DryRun: true})
	if err != nil || !hasLine(dry.Lines, "would index docs/extra.md") {
		t.Fatalf("dry run: %v %v", dry.Lines, err)
	}
	res, err := UpdateIndex(IndexOptions{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if !hasLine(res.Lines, "indexed docs/extra.md") {
		t.Fatalf("no indexed line in %v", res.Lines)
	}
	after, err := os.ReadFile(filepath.Join(root, "docs", "INDEX.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(after), string(before)) {
		t.Error("existing rows were rewritten or reordered")
	}
	if !strings.Contains(string(after), "](extra.md)") {
		t.Errorf("appended row missing:\n%s", after)
	}
	gitIn(t, root, "add", "-A")
	if fs := runCheck(t, root, check.Private); len(fs) != 0 {
		t.Fatalf("check after index: %v", fs)
	}
	res2, err := UpdateIndex(IndexOptions{Root: root})
	if err != nil || !hasLine(res2.Lines, "docs/INDEX.md is complete") {
		t.Errorf("second run should be a no-op: %v %v", res2.Lines, err)
	}
}

// R3: with no docs/INDEX.md the subcommand generates the whole index, like
// init does.
func TestUpdateIndexGeneratesWhenMissing(t *testing.T) {
	files := baseRepo()
	files["docs/guide.md"] = filler("Guide", 3)
	root := writeRepo(t, files)
	res, err := UpdateIndex(IndexOptions{Root: root})
	if err != nil || !hasLine(res.Lines, "created docs/INDEX.md") {
		t.Fatalf("%v %v", res.Lines, err)
	}
	idx, err := os.ReadFile(filepath.Join(root, "docs", "INDEX.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"](../README.md)", "](guide.md)"} {
		if !strings.Contains(string(idx), want) {
			t.Errorf("generated INDEX lacks link %q:\n%s", want, idx)
		}
	}
	root2 := writeRepo(t, baseRepo())
	res2, err := UpdateIndex(IndexOptions{Root: root2, DryRun: true})
	if err != nil || !hasLine(res2.Lines, "would create docs/INDEX.md") {
		t.Fatalf("dry run: %v %v", res2.Lines, err)
	}
	if _, err := os.Lstat(filepath.Join(root2, "docs", "INDEX.md")); err == nil {
		t.Error("dry-run wrote docs/INDEX.md")
	}
}

// R3: init's last word is the command that indexes the documents it could
// not write.
func TestInitSuggestsIndexForMissingDocs(t *testing.T) {
	root := writeRepo(t, map[string]string{"go.mod": "module zzq.example/x\n"})
	res := runInit(t, Options{Root: root, Visibility: check.Private, Holder: "Zzq"})
	for _, want := range []string{"run 'repo-standards index' after adding ", "README.md", "CLAUDE.md"} {
		if !strings.Contains(res.Hint, want) {
			t.Fatalf("hint %q lacks %q", res.Hint, want)
		}
	}
	if strings.Contains(res.Hint, ".gitignore") {
		t.Errorf(".gitignore is not an indexable document: %q", res.Hint)
	}
	// A skipped LICENSE is missing and indexable: the hint names it.
	res2 := runInit(t, Options{Root: writeRepo(t, baseRepo()), Visibility: check.Public, Repo: "o/n"})
	if res2.Hint != "run 'repo-standards index' after adding LICENSE" {
		t.Errorf("hint %q", res2.Hint)
	}
}

// The embedded issue forms must keep GitHub's documented shape: top-level
// name, description and body, and every body item carrying type, id,
// attributes and validations.
func TestIssueFormShapes(t *testing.T) {
	for name, doc := range map[string]string{
		"bug_report.yml":      bugReportForm,
		"feature_request.yml": featureRequestForm,
	} {
		checkIssueForm(t, name, doc)
	}
	if !strings.Contains(issueConfigPublic, "blank_issues_enabled: false") ||
		!strings.Contains(issueConfigPublic, "contact_links:") ||
		!strings.Contains(issueConfigPublic, "https://github.com/{{REPO}}/security/advisories/new") {
		t.Error("public config.yml lost its required keys")
	}
	if !strings.Contains(issueConfigPrivate, "blank_issues_enabled: false") || strings.Contains(issueConfigPrivate, "contact_links") {
		t.Error("private config.yml must hold only blank_issues_enabled")
	}
}

// checkIssueForm is a minimal YAML-subset validation: it scans the structure
// rather than parsing the documents, so no YAML dependency is needed.
func checkIssueForm(t *testing.T, name, doc string) {
	t.Helper()
	top := map[string]bool{}
	var item map[string]bool
	var itemType string
	flush := func() {
		if item == nil {
			return
		}
		for _, k := range []string{"id", "attributes", "validations"} {
			if !item[k] {
				t.Errorf("%s: body item of type %s lacks %s", name, itemType, k)
			}
		}
	}
	for _, l := range strings.Split(doc, "\n") {
		switch {
		case strings.HasPrefix(l, "  - type: "):
			flush()
			item, itemType = map[string]bool{}, strings.TrimSpace(strings.TrimPrefix(l, "  - type: "))
		case item != nil && strings.HasPrefix(l, "    "):
			key := strings.SplitN(strings.TrimSpace(l), ":", 2)[0]
			if key == "id" || key == "attributes" || key == "validations" {
				item[key] = true
			}
		case !strings.HasPrefix(l, " ") && strings.Contains(l, ":"):
			top[strings.SplitN(l, ":", 2)[0]] = true
		}
	}
	flush()
	for _, k := range []string{"name", "description", "body"} {
		if !top[k] {
			t.Errorf("%s lacks top-level %s", name, k)
		}
	}
}

package initfiles

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/anatolykoptev/repo-standards/internal/check"
)

var headingRE = regexp.MustCompile(`^#{1,6}[ \t]+(.+?)\s*$`)

const indexFile = "docs/INDEX.md"
const indexTableHead = "| Document | Description |\n|---|---|\n"

// indexMarkdown renders docs/INDEX.md: one table row per required index
// target, linked by the path relative to docs/ that the index check resolves.
// files is the repository file set (tracked files plus the ones this run
// created); written holds content this run produced, so a dry run renders the
// same index a real run would.
func indexMarkdown(root string, files []string, written map[string][]byte) string {
	var b strings.Builder
	b.WriteString("# Documentation index\n\n" + indexTableHead)
	for _, t := range check.IndexTargets(files) {
		desc := firstHeading(root, t.Path, written)
		if desc == "" {
			desc = t.Path
		}
		b.WriteString(indexRow(t, desc))
	}
	return b.String()
}

// indexRow renders one index table row: "[label](target) | description".
func indexRow(t check.IndexTarget, desc string) string {
	return fmt.Sprintf("| [%s](%s) | %s |\n", label(t.Path), relFromDocs(t.Path), cell(desc))
}

// IndexOptions configures UpdateIndex.
type IndexOptions struct {
	Root   string
	DryRun bool // report what would be appended, write nothing
}

// IndexResult is what repo-standards index did.
type IndexResult struct {
	// Lines narrate the run: "created docs/INDEX.md", "indexed X" or
	// "would index X", in target order.
	Lines []string
	// NotGit is set when root was not a git work tree.
	NotGit bool
}

// UpdateIndex appends a docs/INDEX.md row for every tracked document the
// index-link rule reports as unindexed; existing rows are never rewritten or
// reordered. When docs/INDEX.md is missing it is generated whole, exactly as
// init generates it.
func UpdateIndex(opts IndexOptions) (res IndexResult, err error) {
	files, notGit, err := check.RepoFiles(opts.Root)
	if err != nil {
		return IndexResult{}, err
	}
	res.NotGit = notGit
	resolvedRoot, err := filepath.EvalSymlinks(opts.Root)
	if err != nil {
		return IndexResult{}, err
	}
	p := filepath.Join(resolvedRoot, "docs", "INDEX.md")
	data, err := os.ReadFile(p)
	if err != nil {
		if !os.IsNotExist(err) {
			return IndexResult{}, err
		}
		// Missing: generate the index whole, like init does.
		if err := checkPath(resolvedRoot, indexFile); err != nil {
			return res, err
		}
		if opts.DryRun {
			res.Lines = append(res.Lines, "would create "+indexFile)
			return res, nil
		}
		created, err := writeNew(resolvedRoot, indexFile, []byte(indexMarkdown(resolvedRoot, files, nil)))
		if err != nil {
			return res, err
		}
		if created {
			res.Lines = append(res.Lines, "created "+indexFile)
		} else {
			res.Lines = append(res.Lines, "kept "+indexFile)
		}
		return res, nil
	}
	unindexed := check.UnindexedTargets(string(data), files)
	if len(unindexed) == 0 {
		res.Lines = append(res.Lines, indexFile+" is complete")
		return res, nil
	}
	if opts.DryRun {
		for _, t := range unindexed {
			res.Lines = append(res.Lines, "would index "+t.Path)
		}
		return res, nil
	}
	// Append mode only: a row lands after the last table row; when the file
	// does not end inside a table the appended block carries its own header.
	if err := checkPath(resolvedRoot, indexFile); err != nil {
		return res, err
	}
	var b strings.Builder
	if !strings.HasSuffix(string(data), "\n") {
		b.WriteString("\n")
	}
	trimmed := strings.TrimRight(string(data), "\n")
	lastLine := trimmed[strings.LastIndex(trimmed, "\n")+1:]
	if !strings.HasPrefix(lastLine, "|") {
		b.WriteString("\n" + indexTableHead)
	}
	for _, t := range unindexed {
		desc := firstHeading(resolvedRoot, t.Path, nil)
		if desc == "" {
			desc = t.Path
		}
		b.WriteString(indexRow(t, desc))
	}
	fh, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return res, err
	}
	if _, err := fh.WriteString(b.String()); err != nil {
		fh.Close()
		return res, err
	}
	if err := fh.Close(); err != nil {
		return res, err
	}
	for _, t := range unindexed {
		res.Lines = append(res.Lines, "indexed "+t.Path)
	}
	return res, nil
}

// label is the link text for a row: the path relative to the repository root,
// without its docs/ prefix or extension.
func label(p string) string {
	s := strings.TrimPrefix(p, "docs/")
	if ext := path.Ext(s); ext != "" {
		s = strings.TrimSuffix(s, ext)
	}
	return s
}

// relFromDocs is the link target for p resolved against docs/: a page under
// docs/ loses the prefix, everything else climbs one level.
func relFromDocs(p string) string {
	if rest, ok := strings.CutPrefix(p, "docs/"); ok {
		return rest
	}
	return "../" + p
}

// firstHeading returns the first Markdown heading of a file, from content
// this run wrote or from the work tree.
func firstHeading(root, rel string, written map[string][]byte) string {
	data, ok := written[rel]
	if !ok {
		var err error
		if data, err = os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			return ""
		}
	}
	for _, l := range strings.Split(string(data), "\n") {
		if m := headingRE.FindStringSubmatch(l); m != nil {
			return m[1]
		}
	}
	return ""
}

// cell escapes a table cell: a bare | would end the column.
func cell(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

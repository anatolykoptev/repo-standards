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

// indexMarkdown renders docs/INDEX.md: one table row per required index
// target, linked by the path relative to docs/ that the index check resolves.
// files is the repository file set (tracked files plus the ones this run
// created); written holds content this run produced, so a dry run renders the
// same index a real run would.
func indexMarkdown(root string, files []string, written map[string][]byte) string {
	var b strings.Builder
	b.WriteString("# Documentation index\n\n| Document | Description |\n|---|---|\n")
	for _, t := range check.IndexTargets(files) {
		desc := firstHeading(root, t.Path, written)
		if desc == "" {
			desc = t.Path
		}
		fmt.Fprintf(&b, "| [%s](%s) | %s |\n", label(t.Path), relFromDocs(t.Path), cell(desc))
	}
	return b.String()
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

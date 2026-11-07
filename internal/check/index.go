package check

import (
	"net/url"
	"path"
	"regexp"
	"strings"
)

const indexPath = "docs/INDEX.md"

var (
	inlineLinkRE = regexp.MustCompile(`\]\(\s*(<[^>]*>|[^)\s]*)`)
	refDefRE     = regexp.MustCompile(`(?m)^[ ]{0,3}\[[^\]]+\]:\s*(<[^>]+>|\S+)`)
	hrefRE       = regexp.MustCompile(`(?i)\bhref\s*=\s*["']([^"']+)["']`)
	codeSpanRE   = regexp.MustCompile("`+[^`]*`+")
	schemeRE     = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:`)
)

// stripCode removes fenced blocks, inline code spans and HTML comments: a path
// mentioned in code, or hidden in a comment nobody can see, is not a link.
// Every input line yields exactly one output line, so line numbers in the
// result are line numbers in the input.
//
// A comment may span lines. One that is never closed runs to the end of the
// document, as in CommonMark, so everything after it is hidden. A `<!--` inside
// a code span or fence is code, not a comment, and a fence marker inside a
// comment is comment text.
func stripCode(md string) string {
	var b strings.Builder
	fence := ""
	inComment := false
	for _, line := range strings.Split(md, "\n") {
		t := strings.TrimLeft(line, " ")
		switch {
		case fence != "":
			if strings.HasPrefix(t, fence) {
				fence = ""
			}
		case !inComment && (strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~")):
			fence = t[:3]
		default:
			if !inComment {
				line = codeSpanRE.ReplaceAllString(line, "")
			}
			line, inComment = stripComments(line, inComment)
			b.WriteString(line)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// stripComments removes the HTML comment text from one line. inComment says
// whether the line starts inside a comment; the result says whether it ends
// inside one.
func stripComments(line string, inComment bool) (string, bool) {
	var out strings.Builder
	for {
		if inComment {
			i := strings.Index(line, "-->")
			if i < 0 {
				return out.String(), true
			}
			line, inComment = line[i+3:], false
			continue
		}
		i := strings.Index(line, "<!--")
		if i < 0 {
			out.WriteString(line)
			return out.String(), false
		}
		out.WriteString(line[:i])
		line, inComment = line[i+4:], true
	}
}

// linkRef is one in-repo link: the repo-root-relative path it resolves to and
// the 1-based line it appears on.
type linkRef struct {
	path string
	line int
}

// linkRefs returns every in-repo link in md, resolved against baseDir (the
// directory of the document that holds it, relative to the repo root).
// Targets that leave the repository resolve to a path starting "../".
//
// The match is on the link TARGET, never on the file name. Searching INDEX.md
// for a bare file name as a substring (the first version of the check this
// replaces) lets one row satisfy every file sharing a base name, and lets
// prose count as a link: a document linked nowhere passed.
func linkRefs(md, baseDir string) []linkRef {
	md = stripCode(md)
	type rawLink struct {
		target string
		at     int
	}
	var raw []rawLink
	for _, re := range []*regexp.Regexp{inlineLinkRE, refDefRE, hrefRE} {
		for _, m := range re.FindAllStringSubmatchIndex(md, -1) {
			raw = append(raw, rawLink{md[m[2]:m[3]], m[2]})
		}
	}
	var out []linkRef
	for _, r := range raw {
		t := strings.TrimSuffix(strings.TrimPrefix(r.target, "<"), ">")
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") || schemeRE.MatchString(t) {
			continue
		}
		if i := strings.IndexAny(t, "#?"); i >= 0 {
			t = t[:i]
		}
		if u, err := url.PathUnescape(t); err == nil {
			t = u
		}
		if t == "" {
			continue
		}
		var p string
		if strings.HasPrefix(t, "/") {
			p = path.Clean(strings.TrimPrefix(t, "/"))
		} else {
			p = path.Clean(path.Join(baseDir, t))
		}
		out = append(out, linkRef{path: p, line: 1 + strings.Count(md[:r.at], "\n")})
	}
	return out
}

// linkTargets is the set of repo-root-relative paths linked from md, resolved
// against baseDir.
func linkTargets(md, baseDir string) map[string]bool {
	out := map[string]bool{}
	for _, l := range linkRefs(md, baseDir) {
		out[l.path] = true
	}
	return out
}

// trackedPaths returns every tracked file and every directory that is a prefix
// of one, so a link to a directory resolves. The root is ".".
func trackedPaths(files []string) map[string]bool {
	m := map[string]bool{".": true}
	for _, f := range files {
		m[f] = true
		for d := path.Dir(f); d != "."; d = path.Dir(d) {
			m[d] = true
		}
	}
	return m
}

// isNestedClaudeMD reports whether f is a CLAUDE.md below the root that the
// index must list. vendor/ and node_modules/ are third-party text. A file under
// docs/ is already required by the docs/ rule, so it is not counted twice.
func isNestedClaudeMD(f string) bool {
	return path.Base(f) == "CLAUDE.md" && f != "CLAUDE.md" && !isVendored(f) && !strings.HasPrefix(f, "docs/")
}

// IndexTarget is one path docs/INDEX.md must link, with the rule that
// requires it: a root document, a .md page under docs/ or a nested CLAUDE.md.
type IndexTarget struct {
	Path string
	Kind string // "root", "docs" or "claude"
}

// IndexTargets lists the link targets the index check requires, in display
// order: the root documents that are present, then every tracked .md under
// docs/ except INDEX.md itself and every nested CLAUDE.md, sorted by path.
// checkIndex verifies each is linked; init writes an INDEX row for each, so
// the generated index can never miss a target the check requires.
func IndexTargets(files []string) []IndexTarget {
	set := make(map[string]bool, len(files))
	for _, f := range files {
		set[f] = true
	}
	var out []IndexTarget
	for _, f := range rootDocs {
		if set[f] {
			out = append(out, IndexTarget{f, "root"})
		}
	}
	for _, f := range files {
		switch {
		case f == indexPath:
		case strings.HasPrefix(f, "docs/") && strings.EqualFold(path.Ext(f), ".md"):
			out = append(out, IndexTarget{f, "docs"})
		case isNestedClaudeMD(f):
			// Subsystem rules live in per-directory CLAUDE.md files; an agent
			// that starts from the index must learn they exist.
			out = append(out, IndexTarget{f, "claude"})
		}
	}
	return out
}

// checkIndex requires docs/INDEX.md to link every tracked .md under docs/,
// every root document and every nested CLAUDE.md, and every in-repo link in it
// to resolve to a tracked file or directory.
func checkIndex(files []string, content map[string][]byte) []Finding {
	data, ok := content[indexPath]
	if !ok {
		return nil // absence is already a missing-file finding
	}
	// A map lookup, not a shell pipeline: the shell version of this check
	// (`printf | grep -q` under pipefail) returned random results on Linux
	// because grep -q exits early and printf gets SIGPIPE.
	linked := linkTargets(string(data), path.Dir(indexPath))
	var out []Finding
	for _, t := range IndexTargets(files) {
		if linked[t.Path] {
			continue
		}
		msg := "not linked from " + indexPath
		switch t.Kind {
		case "root":
			msg = "root document " + msg
		case "claude":
			msg = "nested CLAUDE.md not linked from " + indexPath + " (every tracked CLAUDE.md must be indexed)"
		}
		out = append(out, Finding{Check: IndexLink, Path: t.Path, Msg: msg})
	}
	return out
}

// checkIndexDeadLinks reports every in-repo link in docs/INDEX.md whose target
// is neither a tracked file nor a directory holding one. The index is the
// agent entrypoint: a row for a moved file reads as true and leads nowhere.
// The #fragment is not validated. A target that climbs above the repository
// root is not a tracked file and no host resolves it, so it is dead too: a
// miscounted "../" is the likeliest typo.
func checkIndexDeadLinks(files []string, content map[string][]byte) []Finding {
	data, ok := content[indexPath]
	if !ok {
		return nil
	}
	live := trackedPaths(files)
	var out []Finding
	for _, l := range linkRefs(string(data), path.Dir(indexPath)) {
		if l.path == ".." || strings.HasPrefix(l.path, "../") {
			out = append(out, Finding{Check: IndexDeadLink, Path: indexPath, Line: l.line,
				Msg: "link target " + l.path + " leaves the repository"})
			continue
		}
		if live[l.path] {
			continue
		}
		out = append(out, Finding{Check: IndexDeadLink, Path: indexPath, Line: l.line,
			Msg: "link target " + l.path + " is not a tracked file or directory"})
	}
	return out
}

// checkClaudeIndex requires the root CLAUDE.md, which Claude Code always
// loads, to link docs/INDEX.md, so the chain CLAUDE.md -> INDEX -> every
// document is unbroken. A mention inside code does not count.
func checkClaudeIndex(content map[string][]byte) []Finding {
	data, ok := content["CLAUDE.md"]
	if !ok {
		return nil // absence is already a missing-file finding
	}
	if linkTargets(string(data), ".")[indexPath] {
		return nil
	}
	return []Finding{{Check: ClaudeIndex, Path: "CLAUDE.md", Msg: "root CLAUDE.md does not link " + indexPath}}
}

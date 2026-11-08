package check

import (
	"net/url"
	"path"
	"regexp"
	"strings"
)

const indexPath = "docs/INDEX.md"

var (
	// A reference definition's label may not start with ^: [^x]: is a
	// footnote definition, not a link.
	refDefRE = regexp.MustCompile(`(?m)^[ ]{0,3}\[[^\]^][^\]]*\]:\s*(<[^>]+>|\S+)`)
	hrefRE   = regexp.MustCompile(`(?i)\bhref\s*=\s*["']([^"']+)["']`)
	// importRE is Claude Code's import directive: an @path at a word start in
	// CLAUDE.md pulls the named file in, so it links the way a markdown link
	// does ("See @docs/INDEX.md", "- @docs/INDEX.md"). It is meaningful only
	// in the root CLAUDE.md; elsewhere @types/node is just text.
	importRE = regexp.MustCompile(`(?m)(?:^|[\s(])@(<[^>]+>|[^\s)]+)`)
	schemeRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:`)
)

// stripCode removes fenced blocks, inline code spans and HTML comments: a path
// mentioned in code, or hidden in a comment nobody can see, is not a link.
// Every input line yields exactly one output line, so line numbers in the
// result are line numbers in the input.
//
// A fence closes per CommonMark: same character as the opener, at least as
// long, and no info string; an opening backtick fence whose info string
// contains a backtick is not a fence at all. A comment may span lines. One
// opened at line-start position (an HTML block) runs to --> or the end of the
// document; one opened mid-line (an inline comment) opens only when a -->
// follows before the next blank line, since inline HTML cannot span one, so
// an unclosed inline <!-- stays visible text. A <!-- inside a code span or
// fence is code, not a comment, and a fence marker inside a comment is
// comment text.
func stripCode(md string) string {
	var b strings.Builder
	var fence byte   // 0 outside a fence, '`' or '~' inside
	var fenceLen int // the opener's run length
	inComment := false
	lines := strings.Split(md, "\n")
	nextCloser, nextBlank := lookahead(lines)
	for k, line := range lines {
		t := strings.TrimLeft(line, " ")
		switch {
		case fence != 0:
			if closesFence(t, fence, fenceLen) {
				fence = 0
			}
		case !inComment && opensFence(t):
			fence = t[0]
			fenceLen = runLen(t, t[0])
		default:
			var out string
			out, inComment = stripLine(line, inComment, nextCloser[k+1] < nextBlank[k+1])
			b.WriteString(out)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func runLen(s string, c byte) int {
	n := 0
	for n < len(s) && s[n] == c {
		n++
	}
	return n
}

// lookahead returns, for every line index k (and len(lines) as a sentinel),
// the index of the first line at or after k that holds a --> outside a fenced
// block, and the index of the first blank line at or after k; len(lines) when
// there is none. A --> inside a fence is code, never a comment closer, so a
// mid-line <!-- whose only later --> is fenced has no closer and stays text.
func lookahead(lines []string) (nextCloser, nextBlank []int) {
	n := len(lines)
	nextCloser, nextBlank = make([]int, n+1), make([]int, n+1)
	hasCloser := make([]bool, n)
	fence := byte(0)
	fenceLen := 0
	for k, line := range lines {
		t := strings.TrimLeft(line, " ")
		switch {
		case fence != 0:
			if closesFence(t, fence, fenceLen) {
				fence = 0
			}
		case opensFence(t):
			fence = t[0]
			fenceLen = runLen(t, t[0])
		default:
			hasCloser[k] = strings.Contains(line, "-->")
		}
	}
	nextCloser[n], nextBlank[n] = n, n
	for k := n - 1; k >= 0; k-- {
		nextCloser[k], nextBlank[k] = nextCloser[k+1], nextBlank[k+1]
		if hasCloser[k] {
			nextCloser[k] = k
		}
		if strings.TrimSpace(lines[k]) == "" {
			nextBlank[k] = k
		}
	}
	return nextCloser, nextBlank
}

// opensFence reports whether a trimmed line opens a code fence: a run of at
// least three backticks or tildes. The rest of the line is the info string;
// a backtick fence's info string cannot contain a backtick.
func opensFence(t string) bool {
	if len(t) < 3 || t[0] != '`' && t[0] != '~' {
		return false
	}
	n := runLen(t, t[0])
	if n < 3 {
		return false
	}
	return t[0] != '`' || strings.IndexByte(t[n:], '`') < 0
}

// closesFence reports whether a trimmed line closes a fence opened by a run
// of n of the character c: a run of c at least as long as n, followed by
// whitespace only. A closing fence carries no info string.
func closesFence(t string, c byte, n int) bool {
	if r := runLen(t, c); r >= n && strings.TrimSpace(t[r:]) == "" {
		return true
	}
	return false
}

// codeSpanLen returns the length of the code span that opens at the start of
// s (which begins with a backtick): the opening run, the text, and the next
// run of exactly the same length. 0 when no such run follows; the opening
// backticks are then literal text.
func codeSpanLen(s string) int {
	n := runLen(s, '`')
	for i := n; i < len(s); {
		if s[i] != '`' {
			i++
			continue
		}
		r := runLen(s[i:], '`')
		if r == n {
			return i + r
		}
		i += r
	}
	return 0
}

// stripLine drops code spans and comment text from one line. inComment says
// the line starts inside an unclosed comment and the result says whether it
// ends inside one. Spans and comments are scanned in one left-to-right pass
// so the leftmost opener wins: inside a comment backticks are text and a -->
// inside what would be a code span still closes the comment; inside a code
// span <!-- is text.
//
// laterCloser says a --> outside a fenced block follows on a later line,
// before the next blank line. A <!-- preceded only by up to three spaces
// (line-start position) opens a comment block that may run to the end of the
// document. One after text opens an inline comment only when a --> follows on
// this line or laterCloser holds; an unclosed inline <!-- is literal text, as
// CommonMark parses it.
func stripLine(line string, inComment, laterCloser bool) (string, bool) {
	var b strings.Builder
	i := 0
	for i < len(line) {
		if inComment {
			j := strings.Index(line[i:], "-->")
			if j < 0 {
				return b.String(), true
			}
			i += j + 3
			inComment = false
			continue
		}
		if strings.HasPrefix(line[i:], "<!--") {
			wsOnly := strings.TrimSpace(line[:i]) == ""
			switch {
			case wsOnly && i <= 3:
				inComment = true
			case !wsOnly && (strings.Contains(line[i+4:], "-->") || laterCloser):
				inComment = true
			default:
				b.WriteString(line[i : i+4])
			}
			i += 4
			continue
		}
		if line[i] == '`' {
			run := runLen(line[i:], '`')
			if m := codeSpanLen(line[i:]); m > 0 {
				i += m
			} else {
				b.WriteString(line[i : i+run])
				i += run
			}
			continue
		}
		b.WriteByte(line[i])
		i++
	}
	return b.String(), inComment
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
type rawLink struct {
	target string
	at     int
}

// maxParenDepth bounds paren nesting inside a link destination or title, as
// cmark does: deeper nesting is not a link. Together with the blank-line stop
// it keeps every scan short, so the whole pass is linear in the document.
const maxParenDepth = 32

// inlineLinks returns the target of every inline link [x](target ...) in md.
// CommonMark destination rules: a <...> destination ends at the first >, may
// not contain a line ending or an unescaped <; a bare one ends at whitespace
// or an unbalanced ) and may nest balanced () pairs; a backslash escapes the
// next character. An optional "...", '...' or (...) title may follow, then a
// ) is required — without it the construct is not a link. No part of a link
// crosses a blank line.
func inlineLinks(md string) []rawLink {
	// skipWS skips spaces, tabs and line endings; ok is false when it crossed
	// a blank line.
	skipWS := func(i int) (int, bool) {
		nl := 0
		for i < len(md) && (md[i] == ' ' || md[i] == '\t' || md[i] == '\n') {
			if md[i] == '\n' {
				if nl++; nl > 1 {
					return i, false
				}
			}
			i++
		}
		return i, true
	}
	var out []rawLink
	for i := 0; i+1 < len(md); i++ {
		if md[i] != ']' || md[i+1] != '(' {
			continue
		}
		j, ok := skipWS(i + 2)
		if !ok {
			continue
		}
		var start, end int
		if j < len(md) && md[j] == '<' {
			k := j + 1
		angle:
			for ; k < len(md); k++ {
				switch md[k] {
				case '\\':
					k++
				case '\n', '<':
					k = len(md)
					break angle
				case '>':
					break angle
				}
			}
			if k >= len(md) {
				continue
			}
			start, end = j, k+1
			j = end
		} else {
			start = j
			depth := 0
		dest:
			for j < len(md) {
				switch md[j] {
				case '\\':
					j++
				case '(':
					if depth++; depth > maxParenDepth {
						j = len(md)
						break dest
					}
				case ')':
					if depth == 0 {
						break dest
					}
					depth--
				case ' ', '\t', '\n':
					break dest
				}
				j++
			}
			if j >= len(md) {
				continue
			}
			end = j
		}
		if j, ok = skipWS(j); !ok {
			continue
		}
		if j < len(md) && md[j] != ')' {
			// Only a title may stand between the destination and the ).
			switch md[j] {
			case '"', '\'':
				q := md[j]
				for j++; j < len(md) && md[j] != q; j++ {
					if md[j] == '\\' {
						j++
					} else if md[j] == '\n' && blankAfter(md, j) {
						j = len(md)
					}
				}
				if j >= len(md) {
					continue
				}
				j++
			case '(':
				depth := 0
				for ; j < len(md); j++ {
					switch md[j] {
					case '\\':
						j++
					case '(':
						if depth++; depth > maxParenDepth {
							j = len(md)
						}
					case ')':
						depth--
					case '\n':
						if blankAfter(md, j) {
							j = len(md)
						}
					}
					if j >= len(md) || depth == 0 {
						break
					}
				}
				if j >= len(md) {
					continue
				}
				j++
			default:
				continue
			}
			if j, ok = skipWS(j); !ok {
				continue
			}
		}
		if j >= len(md) || md[j] != ')' {
			continue
		}
		out = append(out, rawLink{md[start:end], start})
	}
	return out
}

// blankAfter reports whether the line ending at md[i] (a '\n') is followed
// by a blank line: only spaces and tabs before the next line ending.
func blankAfter(md string, i int) bool {
	for i++; i < len(md); i++ {
		switch md[i] {
		case ' ', '\t':
		case '\n':
			return true
		default:
			return false
		}
	}
	return false
}

func linkRefs(md, baseDir string, imports bool) []linkRef {
	md = stripCode(md)
	raw := inlineLinks(md)
	for _, re := range []*regexp.Regexp{refDefRE, hrefRE} {
		for _, m := range re.FindAllStringSubmatchIndex(md, -1) {
			raw = append(raw, rawLink{md[m[2]:m[3]], m[2]})
		}
	}
	// A @path import is a link only when the token is path-shaped: an
	// @mention of prose carries no / or . and stays out of the link set.
	// Trailing sentence punctuation is not part of the path.
	if imports {
		for _, m := range importRE.FindAllStringSubmatchIndex(md, -1) {
			t := strings.TrimRight(md[m[2]:m[3]], ".,;:!?")
			if strings.ContainsAny(t, "/.") {
				raw = append(raw, rawLink{t, m[2]})
			}
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
// against baseDir. imports admits @path imports (root CLAUDE.md only).
func linkTargets(md, baseDir string, imports bool) map[string]bool {
	out := map[string]bool{}
	for _, l := range linkRefs(md, baseDir, imports) {
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
// index must list. vendor/, node_modules/, testdata/ and third_party/ hold
// third-party or fixture text. A file under docs/ is already required by the
// docs/ rule, so it is not counted twice.
func isNestedClaudeMD(f string) bool {
	return path.Base(f) == "CLAUDE.md" && f != "CLAUDE.md" && !skipForClaudeIndex(f) && !strings.HasPrefix(f, "docs/")
}

// skipForClaudeIndex reports whether a path is exempt from the nested-CLAUDE.md
// rule. It is wider than the personal-data scan's skip set: fixtures and
// third-party trees may carry a CLAUDE.md that is not ours to index, but their
// text can still leak personal data.
func skipForClaudeIndex(p string) bool {
	return isVendored(p) || hasSegment(p, "testdata") || hasSegment(p, "third_party")
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

// UnindexedTargets returns the index targets of files that the markdown of
// docs/INDEX.md does not link — the same set the index-link check reports.
// repo-standards index appends a row per result.
func UnindexedTargets(md string, files []string) []IndexTarget {
	linked := linkTargets(md, path.Dir(indexPath), false)
	var out []IndexTarget
	for _, t := range IndexTargets(files) {
		if !linked[t.Path] {
			out = append(out, t)
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
	// because grep -q exits on the first match and the writer received
	// SIGPIPE.
	var out []Finding
	for _, t := range UnindexedTargets(string(data), files) {
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
	for _, l := range linkRefs(string(data), path.Dir(indexPath), false) {
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
	if linkTargets(string(data), ".", true)[indexPath] {
		return nil
	}
	return []Finding{{Check: ClaudeIndex, Path: "CLAUDE.md", Msg: "root CLAUDE.md does not link " + indexPath}}
}

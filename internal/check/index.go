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

// stripCode removes fenced blocks and inline code spans: a path mentioned in
// code is not a link.
func stripCode(md string) string {
	var b strings.Builder
	fence := ""
	for _, line := range strings.Split(md, "\n") {
		t := strings.TrimLeft(line, " ")
		if fence == "" {
			if strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") {
				fence = t[:3]
				continue
			}
			b.WriteString(codeSpanRE.ReplaceAllString(line, ""))
			b.WriteByte('\n')
		} else if strings.HasPrefix(t, fence) {
			fence = ""
		}
	}
	return b.String()
}

// linkTargets returns the repo-root-relative path of every in-repo link in
// the markdown of docs/INDEX.md.
//
// The match is on the link TARGET, never on the file name. Searching INDEX.md
// for a bare file name as a substring (the first version of the check this
// replaces) lets one row satisfy every file sharing a base name, and lets
// prose count as a link: a document linked nowhere passed.
func linkTargets(md string) map[string]bool {
	md = stripCode(md)
	var raw []string
	for _, re := range []*regexp.Regexp{inlineLinkRE, refDefRE, hrefRE} {
		for _, m := range re.FindAllStringSubmatch(md, -1) {
			raw = append(raw, m[1])
		}
	}
	out := map[string]bool{}
	for _, t := range raw {
		t = strings.TrimSuffix(strings.TrimPrefix(t, "<"), ">")
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
			p = path.Clean(path.Join(path.Dir(indexPath), t))
		}
		out[p] = true
	}
	return out
}

// checkIndex requires docs/INDEX.md to link every tracked .md under docs/
// and every root document.
func checkIndex(files []string, set map[string]bool, content map[string][]byte, rootDocs []string) []Finding {
	data, ok := content[indexPath]
	if !ok {
		return nil // absence is already a missing-file finding
	}
	// A map lookup, not a shell pipeline: the shell version of this check
	// (`printf | grep -q` under pipefail) returned random results on Linux
	// because grep -q exits early and printf gets SIGPIPE.
	linked := linkTargets(string(data))
	var out []Finding
	for _, f := range files {
		if f == indexPath {
			continue
		}
		if strings.HasPrefix(f, "docs/") && strings.EqualFold(path.Ext(f), ".md") && !linked[f] {
			out = append(out, Finding{Check: IndexLink, Path: f, Msg: "not linked from " + indexPath})
		}
	}
	for _, f := range rootDocs {
		if set[f] && !linked[f] {
			out = append(out, Finding{Check: IndexLink, Path: f, Msg: "root document not linked from " + indexPath})
		}
	}
	return out
}

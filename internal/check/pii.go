package check

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/anatolykoptev/repo-standards/internal/denylist"
)

const (
	maxWindow   = 6 // longest token, in pieces, tried per run
	minTokenLen = denylist.MinTokenLen
	binaryProbe = 8192 // a NUL in this many leading bytes marks a file binary

	// suppressMarker is built from two halves so that this source line is not
	// itself a suppression.
	suppressMarker = "repo-standards:" + " ignore"
	minReasonLen   = 3
)

var (
	// A home path, not preceded by something that makes it part of a URL or a
	// longer path ("example.com/home/dashboard" is not a home directory).
	// Covers the Unix, file:// URL and WSL forms.
	unixHomeRE = regexp.MustCompile(`(?:^|[^A-Za-z0-9._~%/-]|file://)/(?:home|Users)/([A-Za-z0-9._-]+)`)
	wslHomeRE  = regexp.MustCompile(`(?i)/mnt/[a-z]/Users/([A-Za-z0-9._-]+)`)
	winHomeRE  = regexp.MustCompile(`(?i)[A-Z]:\\Users\\([A-Za-z0-9._-]+)`)
	// dashHomeRE: Claude Code's dash-encoded project paths — every '/' in a
	// directory becomes '-', so a home directory shows up as the segment
	// "-home-<name>-proj" (or "-Users-<name>-proj") inside /tmp/claude-1000/…
	// or .claude/projects/…. The dash before "home"/"Users" must not be
	// glued to a word ("x-home-<name>", "--set-home-dir"); "~/" stays out.
	dashHomeRE = regexp.MustCompile(`(?:^|[^A-Za-z0-9._-])-(?:home|Users)-([A-Za-z0-9._]+)`)

	// psLineRE: a ps aux row — USER PID %CPU %MEM VSZ RSS TTY STAT START
	// TIME COMMAND — with the numeric columns present.
	psLineRE = regexp.MustCompile(`^\S+\s+\d+\s+\d+(?:\.\d+)?\s+\d+(?:\.\d+)?\s+\d+\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S`)

	// ghRepoRE captures the repository name segment of a GitHub URL or
	// module/SSH path: github.com/<owner>/<name>.
	ghRepoRE    = regexp.MustCompile(`github\.com[/:][A-Za-z0-9_.-]+/([A-Za-z0-9_.-]+)`)
	pkgNameRE   = regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`)
	cargoNameRE = regexp.MustCompile(`name\s*=\s*"([^"]+)"`)
	// siteRelativeRE: the path is an attribute value or link target, a URL on
	// the site rather than a directory on a machine.
	siteRelativeRE = regexp.MustCompile(`(?i)\b(?:href|src|action|url)["']?\s*[=:(]\s*["']?$|\]\(\s*$`)

	// Generic names that appear in documentation, containers and CI, not people.
	placeholderUsers = toSet("user", "username", "you", "yourname", "your-name", "your_user",
		"me", "name", "example", "runner", "ubuntu", "node", "app", "vscode", "builder",
		"build", "foo", "bar", "test", "testuser", "jenkins", "appuser", "shared",
		"guest", "public", "default", "admin", "root", "ci", "docker", "dev", "worker",
		"nonroot", "postgres", "x", "git", "www-data", "nobody", "deploy")

	lockNames = toSet("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb",
		"npm-shrinkwrap.json", "go.sum", "cargo.lock", "poetry.lock", "uv.lock",
		"gemfile.lock", "composer.lock", "pipfile.lock", "flake.lock", "packages.lock.json")
)

func toSet(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}
	return m
}

// isVendored reports whether a path is third-party text: a vendor/ or
// node_modules/ directory anywhere in the path. The personal-data scan skips
// exactly this set, in the work tree and in --history alike.
func isVendored(p string) bool {
	return hasSegment(p, "vendor") || hasSegment(p, "node_modules")
}

// skipForPII reports whether a path is out of scope for the personal-data scan.
func skipForPII(p string) bool {
	if isVendored(p) {
		return true
	}
	base := strings.ToLower(path.Base(p))
	return lockNames[base] || strings.HasSuffix(base, ".lock") || strings.HasSuffix(base, ".lockb")
}

func isRunChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == '@'
}

func isSep(c byte) bool { return c == '_' || c == '-' || c == '.' || c == '@' }

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

// forEachCandidate calls fn with every lowercase token that could be on the
// denylist: each maximal run of [a-z0-9_.@-] and every contiguous sub-sequence
// of up to maxWindow of its pieces, joined by their original separators. So
// "ssh.host.example" yields host.example. fn returns true to stop.
func forEachCandidate(line string, fn func(tok string) bool) {
	n := len(line)
	for i := 0; i < n; {
		if !isRunChar(lower(line[i])) {
			i++
			continue
		}
		j := i
		for j < n && isRunChar(lower(line[j])) {
			j++
		}
		run := strings.ToLower(line[i:j])
		i = j
		run = strings.Trim(run, "_-.@")
		if len(run) < minTokenLen {
			continue
		}
		var starts, ends []int
		for k := 0; k < len(run); {
			for k < len(run) && isSep(run[k]) {
				k++
			}
			s := k
			for k < len(run) && !isSep(run[k]) {
				k++
			}
			if k > s {
				starts, ends = append(starts, s), append(ends, k)
			}
		}
		for a := range starts {
			for b := a; b < len(starts) && b-a < maxWindow; b++ {
				if tok := run[starts[a]:ends[b]]; len(tok) >= minTokenLen && fn(tok) {
					return
				}
			}
		}
	}
}

func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
func isLow(c byte) bool   { return c >= 'a' && c <= 'z' }
func isAlnum(c byte) bool { return isUpper(c) || isLow(c) || c >= '0' && c <= '9' }

// pieces splits a line into lowercase alphanumeric pieces, breaking at any
// non-alphanumeric byte and at CamelCase boundaries ("ZzqBadWord" -> zzq, bad,
// word; "HTTPServer" -> http, server).
func pieces(line string) []string {
	var out []string
	start := -1
	flush := func(end int) {
		if start >= 0 {
			out = append(out, strings.ToLower(line[start:end]))
			start = -1
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if !isAlnum(c) {
			flush(i)
			continue
		}
		if start < 0 {
			start = i
			continue
		}
		prev := line[i-1]
		switch {
		case isUpper(c) && (isLow(prev) || prev >= '0' && prev <= '9'):
			flush(i)
			start = i
		case isUpper(c) && isUpper(prev) && i+1 < len(line) && isLow(line[i+1]):
			flush(i)
			start = i
		}
	}
	flush(len(line))
	return out
}

// forEachWordWindow calls fn with the concatenation of every run of up to
// maxWindow consecutive pieces: the squashed forms a banned phrase can take
// when written with hyphens, underscores, spaces, CamelCase or no separator.
func forEachWordWindow(line string, fn func(squashed string) bool) {
	ps := pieces(line)
	for a := range ps {
		var b strings.Builder
		for k := a; k < len(ps) && k-a < maxWindow; k++ {
			b.WriteString(ps[k])
			if b.Len() >= minTokenLen && fn(b.String()) {
				return
			}
		}
	}
}

// Stats reports what a scan did not or could not look at.
type Stats struct {
	SkippedBinary int
	Suppressed    int
	// Suppressions lists where findings were suppressed: file, line and the
	// reason given, never the suppressed value.
	Suppressions []Suppression
}

// Suppression is one line whose findings an inline marker hid.
type Suppression struct {
	Path   string
	Line   int
	Reason string
}

type hit struct{ check, msg string }

// suppression parses an inline suppression marker. ok means the marker is
// present; reason is the text after it.
func suppression(line string) (ok bool, reason string) {
	i := strings.Index(line, suppressMarker)
	if i < 0 {
		return false, ""
	}
	r := strings.TrimSpace(line[i+len(suppressMarker):])
	r = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(r, "-->"), "*/"))
	return true, r
}

func homePathHit(line string) bool {
	for _, re := range []*regexp.Regexp{unixHomeRE, wslHomeRE, winHomeRE} {
		for _, loc := range re.FindAllStringSubmatchIndex(line, -1) {
			name := strings.ToLower(line[loc[2]:loc[3]])
			if placeholderUsers[name] {
				continue
			}
			if siteRelative(line, loc[0]) {
				continue
			}
			return true
		}
	}
	return false
}

// dashHomePathHit reports whether the line carries a dash-encoded home path.
// The same placeholder-name and site-relative exceptions apply: "-home-runner"
// is a CI account, and a path shown as a link target is not a machine layout.
func dashHomePathHit(line string) bool {
	for _, loc := range dashHomeRE.FindAllStringSubmatchIndex(line, -1) {
		name := strings.ToLower(line[loc[2]:loc[3]])
		if placeholderUsers[name] || siteRelative(line, loc[0]) {
			continue
		}
		return true
	}
	return false
}

// siteRelative reports whether the path match starting at idx is an attribute
// or link target.
func siteRelative(line string, idx int) bool {
	// idx may point at the char before the slash; move to the slash.
	for idx < len(line) && line[idx] != '/' {
		idx++
	}
	return siteRelativeRE.MatchString(line[:idx])
}

// publicRef reports whether a denylisted token that is also a public
// repository name is used here in a way that can only mean that repository:
// the name segment of github.com/<owner>/<name>, or the declared name of the
// repository's own go.mod, package.json or Cargo.toml. Everywhere else the
// token stays personal data.
func publicRef(line, filePath, tok string) bool {
	for _, m := range ghRepoRE.FindAllStringSubmatch(strings.ToLower(line), -1) {
		if strings.TrimSuffix(m[1], ".git") == tok {
			return true
		}
	}
	switch path.Base(filePath) {
	case "go.mod":
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "module" && lastSeg(f[1]) == tok {
			return true
		}
	case "package.json":
		if m := pkgNameRE.FindStringSubmatch(line); m != nil && lastSeg(m[1]) == tok {
			return true
		}
	case "Cargo.toml":
		if m := cargoNameRE.FindStringSubmatch(line); m != nil && lastSeg(m[1]) == tok {
			return true
		}
	}
	return false
}

func lastSeg(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// underPlansDir reports whether a tracked path sits below a directory named
// exactly "plans", at any depth. Plan files leak operator paths and deploy
// specifics and belong in a private location.
func underPlansDir(p string) bool {
	segs := strings.Split(p, "/")
	for _, s := range segs[:len(segs)-1] {
		if s == "plans" {
			return true
		}
	}
	return false
}

var plansHit = hit{PIIPlans, "tracked file inside a plans directory, category plans-dir"}

// scanLine applies every personal-data rule to one line of text. filePath is
// the file the line comes from (or is being scanned as, for names and symlink
// targets); it scopes the manifest-name suppression of public-name tokens.
func scanLine(line, filePath string, dl *denylist.List) []hit {
	var out []hit
	if homePathHit(line) || dashHomePathHit(line) {
		out = append(out, hit{PIIHomePath, "absolute home directory path"})
	}
	cats := map[string]bool{}
	forEachCandidate(line, func(tok string) bool {
		if cat, ok := dl.Lookup(tok); ok && cat != denylist.WordCategory {
			if dl.IsPublicName(tok) && publicRef(line, filePath, tok) {
				return false // a reference to the public repository itself
			}
			cats[cat] = true
		}
		return false
	})
	for _, cat := range sortedKeys(cats) {
		out = append(out, hit{PIIDenylist, "denylisted token, category " + cat})
	}
	banned := false
	forEachWordWindow(line, func(sq string) bool {
		banned = dl.LookupWord(sq)
		return banned
	})
	if banned {
		out = append(out, hit{PIIBannedWord, "banned word in a public repository"})
	}
	if ipLiteralHit(line) {
		out = append(out, hit{PIIIP, "globally routable IP literal, category public-ip"})
	}
	if psLineRE.MatchString(line) {
		out = append(out, hit{PIIPsDump, "process list line, category process-list"})
	}
	return out
}

// scanLines streams r line by line, with no limit on file or line size.
// line1Hits are synthetic hits attached to line 1 — today the plans
// directory rule, so its finding can be suppressed by a marker on line 1 and
// still fires for an empty file.
func scanLines(name, prefix string, r *bufio.Reader, dl *denylist.List, st *Stats, line1Hits []hit) []Finding {
	var out []Finding
	for ln := 1; ; ln++ {
		line, err := r.ReadString('\n')
		if line != "" || ln == 1 && len(line1Hits) > 0 {
			hits := append(line1Hits, scanLine(line, name, dl)...)
			if ok, reason := suppression(line); ok {
				if len(reason) < minReasonLen {
					out = append(out, Finding{Check: PIISuppression, Path: name, Line: ln,
						Msg: "suppression marker without a reason"})
				} else {
					st.Suppressed += len(hits)
					if len(hits) > 0 {
						st.Suppressions = append(st.Suppressions, Suppression{name, ln, reason})
					}
					hits = nil
				}
			}
			for _, h := range hits {
				out = append(out, Finding{Check: h.check, Path: name, Line: ln, Msg: prefix + h.msg})
			}
		}
		if err != nil {
			return out
		}
	}
}

// checkPII scans tracked files of a public repository: their names, symlink
// targets and contents. Findings carry the file, the line and the category
// only; a matched value is never reproduced. Binary files are not read but are
// counted in st.
func checkPII(root string, files []string, dl *denylist.List, st *Stats) ([]Finding, error) {
	var out []Finding
	for _, f := range files {
		if isVendored(f) {
			continue
		}
		plans := underPlansDir(f)
		if skipForPII(f) {
			// A lockfile's content is not scanned; its plans/ location is
			// still the exposure.
			if plans {
				out = append(out, plansFinding(f))
			}
			continue
		}
		// A published file name is published text.
		for _, h := range scanLine(f, f, dl) {
			if h.check == PIIHomePath && !dashHomePathHit(f) {
				continue // "home/x" as a directory name is not a home path
			}
			out = append(out, Finding{Check: h.check, Path: f, Msg: "file name: " + h.msg})
		}
		p := filepath.Join(root, filepath.FromSlash(f))
		fi, err := os.Lstat(p)
		if err != nil {
			if plans {
				out = append(out, plansFinding(f))
			}
			continue // a tracked file deleted from the work tree
		}
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			if plans {
				out = append(out, plansFinding(f))
			}
			target, err := os.Readlink(p)
			if err != nil {
				continue
			}
			for _, h := range scanLine(target, f, dl) {
				out = append(out, Finding{Check: h.check, Path: f, Msg: "symlink target: " + h.msg})
			}
		case fi.Mode().IsRegular():
			var extra []hit
			if plans {
				extra = []hit{plansHit}
			}
			fs, err := scanFile(p, f, dl, st, extra)
			if err != nil {
				return nil, fmt.Errorf("scan %s: %w", f, err)
			}
			out = append(out, fs...)
		}
	}
	return out, nil
}

func plansFinding(f string) Finding {
	return Finding{Check: PIIPlans, Path: f, Line: 1, Msg: plansHit.msg}
}

// scanFile scans a regular file's content. line1Hits ride along to
// scanLines; a binary file still yields them (there is no line 1 to carry a
// suppression marker, so they fire unconditionally).
func scanFile(p, name string, dl *denylist.List, st *Stats, line1Hits []hit) ([]Finding, error) {
	fh, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	r := bufio.NewReaderSize(fh, 64<<10)
	head, _ := r.Peek(binaryProbe)
	if bytes.IndexByte(head, 0) >= 0 {
		st.SkippedBinary++
		var out []Finding
		for _, h := range line1Hits {
			out = append(out, Finding{Check: h.check, Path: name, Line: 1, Msg: h.msg})
		}
		return out, nil
	}
	return scanLines(name, "", r, dl, st, line1Hits), nil
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

package check

import (
	"strings"
	"testing"
)

// idxWith appends rows to the good INDEX.
func idxWith(rows string) string { return goodFiles(Public)["docs/INDEX.md"] + rows }

func findingsOf(fs []Finding, id string) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Check == id {
			out = append(out, f)
		}
	}
	return out
}

func TestNestedClaudeMDMustBeIndexed(t *testing.T) {
	files := with(goodFiles(Public), map[string]string{
		"web/CLAUDE.md":                  prose("web", 3),
		"crates/CLAUDE.md":               prose("crates", 3),
		"internal/CLAUDE.md":             prose("internal", 3),
		"vendor/lib/CLAUDE.md":           prose("vendored", 3),
		"web/node_modules/pkg/CLAUDE.md": prose("npm", 3),
		"docs/INDEX.md":                  idxWith("- [Web](../web/CLAUDE.md)\n- [Internal](<../internal/./CLAUDE.md>)\n"),
		"notclaude/CLAUDE.md.bak":        "x",
		"sub/claude.md":                  prose("lower case is another file", 3),
	})
	got := ids(run(t, writeRepo(t, files), Public, nil))
	want := []string{IndexLink + " crates/CLAUDE.md"}
	if !equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	f := findingsOf(run(t, writeRepo(t, files), Public, nil), IndexLink)[0]
	if !strings.Contains(f.Msg, "nested CLAUDE.md") {
		t.Errorf("message does not name the rule: %q", f.Msg)
	}
}

func TestNestedClaudeMDLinkInCodeDoesNotCount(t *testing.T) {
	files := with(goodFiles(Public), map[string]string{
		"web/CLAUDE.md": prose("web", 3),
		"docs/INDEX.md": idxWith("```\n[Web](../web/CLAUDE.md)\n```\nprose mention of web/CLAUDE.md and `[x](../web/CLAUDE.md)`\n"),
	})
	got := ids(run(t, writeRepo(t, files), Public, nil))
	if want := []string{IndexLink + " web/CLAUDE.md"}; !equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestIndexDeadLinks(t *testing.T) {
	files := with(goodFiles(Public), map[string]string{
		"docs/live.md":      prose("live", 3),
		"docs/sub/inner.md": prose("inner", 3),
		"docs/two words.md": prose("two", 3),
		"docs/up.md":        prose("up", 3),
		"src/main.go":       "package main\n",
		"docs/INDEX.md": idxWith("" +
			"- [live file](live.md#frag)\n" + // line 11 onward are all live
			"- [live dir](sub/)\n" +
			"- [dir no slash](sub)\n" +
			"- [source dir](../src)\n" +
			"- [source file](../src/main.go)\n" +
			"- [encoded](two%20words.md)\n" +
			"- [dots](./sub/../up.md) [more](sub/./inner.md)\n" +
			"- [root](../)\n" +
			"- [external](https://example.com/gone.md) [mail](mailto:a@example.com)\n" +
			"- [dead file](gone.md)\n" +
			"- [dead dir](nowhere/)\n" +
			"- [dead encoded](no%20such%20file.md#x)\n" +
			"- [dead dots](./sub/../absent.md)\n" +
			"- [empty dir name is not a file](docs/live.md)\n" + // resolves to docs/docs/live.md
			"```\n[in fence](fenced-dead.md)\n```\n" +
			"- [after fence](after-fence-dead.md)\n"),
	})
	root := writeRepo(t, files)
	got := findingsOf(run(t, root, Public, nil), IndexDeadLink)
	idx := strings.Split(files["docs/INDEX.md"], "\n")
	lineOf := func(sub string) int {
		for i, l := range idx {
			if strings.Contains(l, sub) && !strings.HasPrefix(l, "[in fence") {
				return i + 1
			}
		}
		t.Fatalf("no line with %q", sub)
		return 0
	}
	want := map[int]string{
		lineOf("[dead file]"):            "docs/gone.md",
		lineOf("[dead dir]"):             "docs/nowhere",
		lineOf("[dead encoded]"):         "docs/no such file.md",
		lineOf("[dead dots]"):            "docs/absent.md",
		lineOf("[empty dir name is not"): "docs/docs/live.md",
		lineOf("[after fence]"):          "docs/after-fence-dead.md",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v\nwant lines %v", got, want)
	}
	for _, f := range got {
		tgt, ok := want[f.Line]
		if !ok || f.Path != "docs/INDEX.md" || !strings.Contains(f.Msg, tgt) {
			t.Errorf("unexpected finding %s (want target %q)", f, tgt)
		}
	}
}

func TestIndexDeadLinkNeedsTrackedTarget(t *testing.T) {
	files := with(goodFiles(Public), map[string]string{
		"docs/INDEX.md": idxWith("- [ghost](ghost.md)\n"),
	})
	root := writeRepo(t, files)
	// On disk but not tracked: still dead.
	gitIn(t, root, "rm", "-q", "--cached", "-r", "--ignore-unmatch", "docs/ghost.md")
	got := findingsOf(run(t, root, Public, nil), IndexDeadLink)
	if len(got) != 1 || got[0].Line != 10 {
		t.Fatalf("got %v", got)
	}
}

func TestClaudeMDMustLinkIndex(t *testing.T) {
	cases := []struct {
		name, body string
		ok         bool
	}{
		{"plain link", "[i](docs/INDEX.md)", true},
		{"dot slash", "[i](./docs/INDEX.md)", true},
		{"fragment", "[i](docs/INDEX.md#x)", true},
		{"root relative", "[i](/docs/INDEX.md)", true},
		{"reference definition", "[i]: docs/INDEX.md", true},
		{"dotdot", "[i](sub/../docs/INDEX.md)", true},
		{"no link", "docs/INDEX.md is the index", false},
		{"code span", "see `[i](docs/INDEX.md)`", false},
		{"fenced", "```\n[i](docs/INDEX.md)\n```", false},
		{"other doc", "[i](docs/CHECKS.md)", false},
		{"relative to docs is wrong", "[i](INDEX.md)", false},
		{"external", "[i](https://example.com/docs/INDEX.md)", false},
	}
	for _, c := range cases {
		files := with(goodFiles(Public), map[string]string{"CLAUDE.md": prose("Agent notes", 4) + "\n" + c.body + "\n"})
		got := findingsOf(run(t, writeRepo(t, files), Public, nil), ClaudeIndex)
		if c.ok && len(got) != 0 {
			t.Errorf("%s: want pass, got %v", c.name, got)
		}
		if !c.ok && (len(got) != 1 || got[0].Path != "CLAUDE.md") {
			t.Errorf("%s: want one finding, got %v", c.name, got)
		}
	}
}

func TestClaudeIndexSilentWhenClaudeMDMissing(t *testing.T) {
	got := ids(run(t, writeRepo(t, without(goodFiles(Public), "CLAUDE.md")), Public, nil))
	for _, g := range got {
		if strings.HasPrefix(g, ClaudeIndex) {
			t.Fatalf("missing CLAUDE.md is one missing-file finding, got %v", got)
		}
	}
}

func TestIndexDeadLinkLeavingRepo(t *testing.T) {
	for _, target := range []string{"../../README.md", "../..", "/../x.md", "%2e%2e/%2e%2e/x.md"} {
		files := with(goodFiles(Public), map[string]string{"docs/INDEX.md": idxWith("- [up](" + target + ")\n")})
		got := findingsOf(run(t, writeRepo(t, files), Public, nil), IndexDeadLink)
		if len(got) != 1 || got[0].Line != 10 || !strings.Contains(got[0].Msg, "leaves the repository") {
			t.Errorf("%s: got %v", target, got)
		}
	}
	// One level up from docs/ is the root: live.
	files := with(goodFiles(Public), map[string]string{"docs/INDEX.md": idxWith("- [root file](../README.md) [root](..)\n")})
	if got := findingsOf(run(t, writeRepo(t, files), Public, nil), IndexDeadLink); len(got) != 0 {
		t.Errorf("in-repo ../ must pass: %v", got)
	}
}

func TestHTMLCommentsAreNotLinks(t *testing.T) {
	claude := func(body string) []Finding {
		files := with(goodFiles(Public), map[string]string{"CLAUDE.md": prose("Agent notes", 4) + "\n" + body + "\n"})
		return findingsOf(run(t, writeRepo(t, files), Public, nil), ClaudeIndex)
	}
	cases := []struct {
		name, body string
		ok         bool
	}{
		{"single-line comment", "<!-- [i](docs/INDEX.md) -->", false},
		{"multi-line comment", "<!--\nnotes\n[i](docs/INDEX.md)\n-->", false},
		{"unclosed comment hides the rest", "<!-- open\n[i](docs/INDEX.md)", false},
		{"link after a comment on the same line", "<!-- x --> [i](docs/INDEX.md)", true},
		{"link after a multi-line comment close", "<!--\nx\n--> [i](docs/INDEX.md)", true},
		{"comment marker in a code span is code", "`<!--` [i](docs/INDEX.md)", true},
		{"comment marker in a fence is code", "```\n<!--\n```\n[i](docs/INDEX.md)", true},
		{"fence marker in a comment is text", "<!--\n```\n-->\n[i](docs/INDEX.md)", true},
	}
	for _, c := range cases {
		got := claude(c.body)
		if c.ok && len(got) != 0 {
			t.Errorf("%s: want pass, got %v", c.name, got)
		}
		if !c.ok && len(got) != 1 {
			t.Errorf("%s: want one finding, got %v", c.name, got)
		}
	}
}

func TestIndexRowInCommentDoesNotIndex(t *testing.T) {
	files := with(goodFiles(Public), map[string]string{
		"docs/hidden.md": prose("hidden", 3),
		"docs/INDEX.md":  idxWith("<!-- - [Hidden](hidden.md) -->\n"),
	})
	got := ids(run(t, writeRepo(t, files), Public, nil))
	if want := []string{IndexLink + " docs/hidden.md"}; !equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestLineNumbersSurviveMultiLineComment(t *testing.T) {
	// goodFiles INDEX is 9 lines; the comment spans lines 10-13.
	files := with(goodFiles(Public), map[string]string{
		"docs/INDEX.md": idxWith("<!--\nold\n[x](gone.md)\n--> [after](dead.md)\n- [next](dead2.md)\n"),
	})
	got := findingsOf(run(t, writeRepo(t, files), Public, nil), IndexDeadLink)
	if len(got) != 2 || got[0].Line != 13 || got[1].Line != 14 {
		t.Fatalf("want dead links on lines 13 and 14 only, got %v", got)
	}
}

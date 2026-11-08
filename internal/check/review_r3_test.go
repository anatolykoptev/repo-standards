package check

import (
	"strings"
	"testing"
	"time"
)

// J1: testdata/ and third_party/ are exempt from the nested-CLAUDE.md rule
// only; the personal-data scan still reads them.
func TestPIIScansTestdataAndThirdParty(t *testing.T) {
	res := piiFiles(t, Public, map[string]string{
		"testdata/capture.txt":   "see " + hm + "jdoe42/x\n",
		"third_party/x/a.txt":    "see " + hm + "jdoe42/x\n",
		"vendor/lib/a.txt":       "see " + hm + "jdoe42/x\n",
		"node_modules/m/a.txt":   "see " + hm + "jdoe42/x\n",
		"deep/vendor/b/note.txt": "see " + hm + "jdoe42/x\n",
	})
	var got []string
	for _, f := range res.Findings {
		got = append(got, f.Check+" "+f.Path)
	}
	want := []string{PIIHomePath + " testdata/capture.txt", PIIHomePath + " third_party/x/a.txt"}
	if !equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

// J2: the FSL text published at fsl.software titles the Apache variant
// "Apache 2.0 Future License"; the template says "ALv2".
func TestFSLTitles(t *testing.T) {
	for _, c := range []struct{ title, lic string }{
		{"Functional Source License, Version 1.1, MIT Future License", "FSL-1.1-MIT"},
		{"Functional Source License, Version 1.1, ALv2 Future License", "FSL-1.1-ALv2"},
		{"Functional Source License, Version 1.1, Apache 2.0 Future License", "FSL-1.1-ALv2"},
	} {
		kind, lic := classifyLicense("# " + c.title + "\n\nPermission is hereby granted, free of charge, to any person.\n")
		if kind != licSourceAvail || lic != c.lic {
			t.Errorf("%s: got (%v,%q) want (%v,%q)", c.title, kind, lic, licSourceAvail, c.lic)
		}
	}
}

// J3: a destination or title scan cannot cross a blank line or nest past 32
// parens, so pathological input stays linear.
func TestInlineLinksLinear(t *testing.T) {
	for _, c := range []struct{ name, unit string }{
		{"empty destinations", "]("},
		{"title parens", "](a ("},
		{"angle destinations", "](<"},
		{"quote titles", "](a \"x\\"},
		{"newline titles", "](a (\n"},
	} {
		md := strings.Repeat(c.unit, (1<<20)/len(c.unit))
		done := make(chan struct{})
		go func() { inlineLinks(md); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Errorf("%s: 1 MiB scan still running after 2s, want linear", c.name)
		}
	}
}

func TestInlineLinksBlankLineBounds(t *testing.T) {
	for _, c := range []struct {
		name, md string
		want     int
	}{
		{"plain", "[x](a.md)", 1},
		{"title after newline", "[x](a.md\n\"t\")", 1},
		{"blank line before title", "[x](a.md\n\n\"t\")", 0},
		{"blank line inside quote title", "[x](a.md \"t\n\nu\")", 0},
		{"blank line inside paren title", "[x](a.md (t\n\nu))", 0},
		{"blank line after open paren", "[x](\n\na.md)", 0},
		{"angle destination with newline", "[x](<a\nb.md>)", 0},
		{"nesting at the cap", "[x](a" + strings.Repeat("(", 32) + strings.Repeat(")", 32) + ")", 1},
		{"nesting past the cap", "[x](a" + strings.Repeat("(", 33) + strings.Repeat(")", 33) + ")", 0},
	} {
		if got := len(inlineLinks(c.md)); got != c.want {
			t.Errorf("%s: %d links, want %d", c.name, got, c.want)
		}
	}
}

// J4: an OSI header does not excuse a non-commercial rider, except in the
// GPL family whose canonical texts say "noncommercial".
func TestLicenseNonCommercialRider(t *testing.T) {
	rider := "\nThis software may be used provided the use is noncommercial only.\n"
	for _, c := range []struct {
		name, text string
		kind       licenseKind
		lic        string
	}{
		{"mit + rider", mitText + rider, licNonOSI, "non-commercial licence"},
		{"apache + rider", apacheHead + rider, licNonOSI, "non-commercial licence"},
		{"bsd + rider", "Redistribution and use in source and binary forms, with or without modification, are permitted." + rider, licNonOSI, "non-commercial licence"},
		{"mpl + rider", "Mozilla Public License Version 2.0\n" + rider, licNonOSI, "non-commercial licence"},
		{"agpl canonical", agpl30, licOSI, "AGPL"},
		{"gpl-2.0 canonical", gpl20, licOSI, "GPL"},
		{"mpl canonical", mpl20, licOSI, "MPL-2.0"},
		{"lgpl canonical", lgpl30, licOSI, "LGPL"},
	} {
		if kind, lic := classifyLicense(c.text); kind != c.kind || lic != c.lic {
			t.Errorf("%s: got (%v,%q) want (%v,%q)", c.name, kind, lic, c.kind, c.lic)
		}
	}
}

func claudeIndex(t *testing.T, body string) []Finding {
	t.Helper()
	files := with(goodFiles(Public), map[string]string{"CLAUDE.md": prose("Agent notes", 4) + "\n" + body + "\n"})
	return findingsOf(run(t, writeRepo(t, files), Public, nil), ClaudeIndex)
}

// J5: @path imports count in the root CLAUDE.md only, at any word start.
func TestImportsOnlyInRootClaudeMD(t *testing.T) {
	for _, c := range []struct {
		name, body string
		ok         bool
	}{
		{"line start", "@docs/INDEX.md", true},
		{"after a sentence", "See @docs/INDEX.md", true},
		{"list item", "- @docs/INDEX.md", true},
		{"trailing period", "See @docs/INDEX.md.", true},
		{"in parens", "(see @docs/INDEX.md)", true},
		{"in a code span", "See `@docs/INDEX.md`", false},
		{"mid-word is no import", "mail a@docs/INDEX.md", false},
		{"mention is no path", "ping @someone", false},
	} {
		got := claudeIndex(t, c.body)
		if c.ok && len(got) != 0 {
			t.Errorf("%s: want pass, got %v", c.name, got)
		}
		if !c.ok && len(got) != 1 {
			t.Errorf("%s: want one finding, got %v", c.name, got)
		}
	}

	// In INDEX an @token is text: @types/node is not a dead link and
	// @docs/a.md does not index docs/a.md.
	files := with(goodFiles(Public), map[string]string{
		"docs/a.md":     prose("a", 3),
		"docs/INDEX.md": idxWith("Uses @types/node and @docs/a.md\n"),
	})
	got := ids(run(t, writeRepo(t, files), Public, nil))
	if want := []string{IndexLink + " docs/a.md"}; !equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

// J6: an inline <!-- hides text only when its --> comes before the next blank
// line.
func TestInlineCommentCannotSpanBlankLine(t *testing.T) {
	for _, c := range []struct {
		name, body string
		ok         bool
	}{
		{"closer across a blank line", "x <!--\n\n[i](docs/INDEX.md)\n-->", true},
		{"closer before the blank line", "x <!--\n[i](docs/INDEX.md)\n-->\n\nplain", false},
		{"whitespace-only line is blank", "x <!--\n  \n[i](docs/INDEX.md)\n-->", true},
		{"block comment still runs on", "<!--\n\n[i](docs/INDEX.md)\n-->", false},
	} {
		got := claudeIndex(t, c.body)
		if c.ok && len(got) != 0 {
			t.Errorf("%s: want pass, got %v", c.name, got)
		}
		if !c.ok && len(got) != 1 {
			t.Errorf("%s: want one finding, got %v", c.name, got)
		}
	}
}

// A code span closes only on a backtick run of the same length.
func TestCodeSpanNeedsEqualRun(t *testing.T) {
	for _, c := range []struct {
		name, body string
		ok         bool
	}{
		{"unequal closer is no span", "`` [i](docs/INDEX.md) ` x", true},
		{"equal closer is a span", "`` x ` y `` [i](docs/INDEX.md)", true},
		{"link inside a span", "`` [i](docs/INDEX.md) ``", false},
		{"link inside a single span", "`[i](docs/INDEX.md)`", false},
	} {
		got := claudeIndex(t, c.body)
		if c.ok && len(got) != 0 {
			t.Errorf("%s: want pass, got %v", c.name, got)
		}
		if !c.ok && len(got) != 1 {
			t.Errorf("%s: want one finding, got %v", c.name, got)
		}
	}
}

// J7: a dual-licence layout satisfies the LICENSE requirement and every file
// must classify.
func TestDualLicenceLayout(t *testing.T) {
	pairs := [][2]string{
		{"LICENSE-MIT", "LICENSE-APACHE"},
		{"LICENSE-MIT", "LICENSE-APACHE-2.0"},
		{"LICENSE.MIT", "LICENSE.APACHE"},
	}
	for _, p := range pairs {
		mk := func(second string) map[string]string {
			files := without(goodFiles(Public), "LICENSE")
			files[p[0]] = mitText
			files[p[1]] = second
			files["docs/INDEX.md"] = idxWith("- [A](../" + p[0] + ")\n- [B](../" + p[1] + ")\n")
			files["docs/INDEX.md"] = strings.Replace(files["docs/INDEX.md"], "- [Licence](../LICENSE)\n", "", 1)
			return files
		}
		if fs := run(t, writeRepo(t, mk(apacheHead)), Public, nil); len(fs) != 0 {
			t.Errorf("%v: want clean, got %v", p, fs)
		}
		got := ids(run(t, writeRepo(t, mk("do what you want, this is long enough to pass the stub check\n")), Public, nil))
		if want := []string{License + " " + p[1]}; !equal(got, want) {
			t.Errorf("%v: got %v want %v", p, got, want)
		}
	}
	if fs := run(t, writeRepo(t, without(goodFiles(Public), "LICENSE")), Public, nil); len(findingsOf(fs, MissingFile)) == 0 {
		t.Errorf("no licence file must still be a missing-file finding")
	}
}

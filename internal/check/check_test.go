package check

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoodReposPass(t *testing.T) {
	for _, vis := range []Visibility{Public, Private} {
		root := writeRepo(t, goodFiles(vis))
		if fs := run(t, root, vis, nil); len(fs) != 0 {
			t.Errorf("%s: want clean, got %v", vis, fs)
		}
	}
}

func TestInvalidVisibility(t *testing.T) {
	if _, err := Run(Options{Root: t.TempDir(), Visibility: "internal"}); err == nil {
		t.Fatal("want error for unknown visibility")
	}
}

func TestRequiredMissingEach(t *testing.T) {
	for _, name := range []string{"README.md", "CLAUDE.md", "CHANGELOG.md", "LICENSE",
		"CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md", ".gitignore"} {
		for _, vis := range []Visibility{Public, Private} {
			root := writeRepo(t, without(goodFiles(vis), name))
			got := ids(run(t, root, vis, nil))
			// A missing root doc is a missing-file; INDEX.md still links it,
			// which is not a finding (dead links are out of scope).
			want := []string{MissingFile + " " + name}
			if !equal(got, want) {
				t.Errorf("%s without %s: got %v want %v", vis, name, got, want)
			}
		}
	}
}

func TestMissingIndexIsOneFinding(t *testing.T) {
	root := writeRepo(t, without(goodFiles(Public), "docs/INDEX.md"))
	got := ids(run(t, root, Public, nil))
	if want := []string{MissingFile + " docs/INDEX.md"}; !equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestLicenseSpellings(t *testing.T) {
	for _, name := range []string{"LICENSE.md", "LICENSE.txt"} {
		files := without(goodFiles(Public), "LICENSE")
		files[name] = apacheHead
		files["docs/INDEX.md"] = strings.Replace(files["docs/INDEX.md"], "../LICENSE", "../"+name, 1)
		if fs := run(t, writeRepo(t, files), Public, nil); len(fs) != 0 {
			t.Errorf("%s: %v", name, fs)
		}
	}
}

func TestStubs(t *testing.T) {
	cases := []struct {
		name, file, body, want string
	}{
		{"tiny readme", "README.md", "# Hi\n", StubFile + " README.md"},
		{"todo marker", "CONTRIBUTING.md", prose("Contributing", 4) + "TODO write this\n", StubFile + " CONTRIBUTING.md"},
		{"lorem", "SECURITY.md", prose("Security", 4) + "Lorem ipsum dolor sit amet\n", StubFile + " SECURITY.md"},
		{"template sentence", "README.md", prose("Readme", 6) + "Project description here\n", StubFile + " README.md"},
		{"covenant placeholder", "CODE_OF_CONDUCT.md", prose("Code of conduct", 5) + "Contact: [INSERT CONTACT METHOD]\n", StubFile + " CODE_OF_CONDUCT.md"},
		{"empty gitignore", ".gitignore", "# only a comment\n\n", StubFile + " .gitignore"},
		{"tiny changelog", "CHANGELOG.md", "#\n", StubFile + " CHANGELOG.md"},
	}
	for _, c := range cases {
		root := writeRepo(t, with(goodFiles(Public), map[string]string{c.file: c.body}))
		got := ids(run(t, root, Public, nil))
		if !equal(got, []string{c.want}) {
			t.Errorf("%s: got %v want [%s]", c.name, got, c.want)
		}
	}
}

func TestPlaceholderWordBoundary(t *testing.T) {
	// "TODOS" and "mastodon" are not markers.
	body := prose("Readme", 6) + "The TODOS endpoint and mastodon are fine. tbdx too.\n"
	root := writeRepo(t, with(goodFiles(Public), map[string]string{"README.md": body}))
	if fs := run(t, root, Public, nil); len(fs) != 0 {
		t.Fatalf("false positive: %v", fs)
	}
}

func TestIndexBasenameCollision(t *testing.T) {
	// Two README.md files; INDEX.md links only one. A basename or substring
	// match passes both, which is the defect this check exists to prevent.
	idx := goodFiles(Public)["docs/INDEX.md"] + "- [A](a/README.md)\n"
	files := with(goodFiles(Public), map[string]string{
		"docs/INDEX.md":       idx,
		"docs/a/README.md":    prose("A", 3),
		"docs/b/README.md":    prose("B", 3),
		"docs/INDEX-note.md":  prose("note", 3),
		"docs/mentioned.md":   prose("m", 3),
		"docs/in-code.md":     prose("c", 3),
		"docs/not-markdown.c": "x",
	})
	// Prose and code mentions must not count as links.
	files["docs/INDEX.md"] += "\nSee also docs/mentioned.md and README.md in prose, `docs/in-code.md` in code.\n\n```\n[x](in-code.md)\n```\n"
	got := ids(run(t, writeRepo(t, files), Public, nil))
	want := []string{IndexLink + " docs/INDEX-note.md", IndexLink + " docs/b/README.md", IndexLink + " docs/in-code.md", IndexLink + " docs/mentioned.md"}
	if !equal(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestIndexLinkForms(t *testing.T) {
	files := with(goodFiles(Public), map[string]string{
		"docs/one.md":           prose("1", 3),
		"docs/two words.md":     prose("2", 3),
		"docs/sub/three.md":     prose("3", 3),
		"docs/four.md":          prose("4", 3),
		"docs/five.md":          prose("5", 3),
		"docs/six.md":           prose("6", 3),
		"docs/seven.md":         prose("7", 3),
		"docs/eight.md":         prose("8", 3),
		"docs/nine/up.md":       prose("9", 3),
		"docs/ten.md":           prose("10", 3),
		"docs/UPPER.MD":         prose("11", 3),
		"docs/unlinked-last.md": prose("x", 3),
	})
	files["docs/INDEX.md"] += "" +
		"[a](./one.md#section) [b](two%20words.md) [c](sub/three.md \"title\")\n" +
		"[d](<four.md>) [e](/docs/five.md) [f](six.md?plain=1)\n" +
		"[g]: seven.md\n<a href=\"eight.md\">h</a> [i](nine/../nine/up.md) [j](ten.md)\n[k](UPPER.MD)\n" +
		"[ext](https://example.com/unlinked-last.md)\n"
	got := ids(run(t, writeRepo(t, files), Public, nil))
	want := []string{IndexLink + " docs/unlinked-last.md"}
	if !equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestIndexRootDocsMustBeLinked(t *testing.T) {
	files := with(goodFiles(Public), nil)
	files["docs/INDEX.md"] = "# Index\n\n- [Readme](../README.md)\n- [Licence](../LICENSE)\n" + strings.Repeat("filler\n", 10)
	got := ids(run(t, writeRepo(t, files), Public, nil))
	want := []string{IndexLink + " CHANGELOG.md", IndexLink + " CLAUDE.md", IndexLink + " CODE_OF_CONDUCT.md", IndexLink + " CONTRIBUTING.md", IndexLink + " SECURITY.md"}
	if !equal(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestLicenseMatrix(t *testing.T) {
	apache, err := os.ReadFile(filepath.Join("..", "..", "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, text string
		kind       licenseKind
		lic        string
	}{
		{"apache real text", string(apache), licOSI, "Apache-2.0"},
		{"mit", mitText, licOSI, "MIT"},
		{"bsd3", "BSD 3-Clause\n\nRedistribution and use in source and binary forms, with or without modification, are permitted provided that:\n3. Neither the name of the copyright holder nor the names of its contributors", licOSI, "BSD-3-Clause"},
		{"bsd2", "Redistribution and use in source and binary forms, with or without\nmodification, are permitted provided that the following conditions are met:", licOSI, "BSD-2-Clause"},
		{"mpl", "Mozilla Public License Version 2.0\n==================================\n", licOSI, "MPL-2.0"},
		{"gpl3", "                    GNU GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007\n", licOSI, "GPL"},
		{"gpl2", "GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991\n", licOSI, "GPL"},
		{"agpl", "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007\n" + strings.Repeat("x ", 400) + "GNU General Public License", licOSI, "AGPL"},
		{"lgpl", "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3\n", licOSI, "LGPL"},
		{"isc", "ISC License\nPermission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted", licOSI, "ISC"},
		{"unlicense", "This is free and unencumbered software released into the public domain.", licOSI, "Unlicense"},
		{"commons clause over apache", "\"Commons Clause\" License Condition v1.0\n\n" + apacheHead, licNonOSI, "Commons Clause"},
		{"bsl", "Business Source License 1.1\n", licNonOSI, "BSL"},
		{"proprietary", propText, licProprietary, "proprietary notice"},
		{"proprietary range", "Copyright (c) 2024-2026 Some Holder. All rights reserved.", licProprietary, "proprietary notice"},
		{"proprietary unicode ©", "Copyright © 2026 Some Holder. All rights reserved.", licProprietary, "proprietary notice"},
		{"copyright only", "Copyright (c) 2026 Some Holder\n", licUnknown, ""},
		{"gibberish", "do what you want", licUnknown, ""},
	}
	for _, c := range cases {
		kind, lic := classifyLicense(c.text)
		if kind != c.kind || lic != c.lic {
			t.Errorf("%s: got (%v,%q) want (%v,%q)", c.name, kind, lic, c.kind, c.lic)
		}
	}
}

func TestLicenseVsVisibility(t *testing.T) {
	cases := []struct {
		vis  Visibility
		text string
		bad  bool
	}{
		{Public, apacheHead, false},
		{Public, mitText, false},
		{Public, propText, true},
		{Public, "Business Source License 1.1, a restricted licence text", true},
		{Public, "do what you want with this, no licence text at all", true},
		{Private, propText, false},
		{Private, apacheHead, true},
		{Private, mitText, true},
		{Private, "Business Source License 1.1, a restricted licence text", true},
		{Private, "do what you want with this, no licence text at all", true},
	}
	for _, c := range cases {
		root := writeRepo(t, with(goodFiles(c.vis), map[string]string{"LICENSE": c.text}))
		got := ids(run(t, root, c.vis, nil))
		var want []string
		if c.bad {
			want = []string{License + " LICENSE"}
		}
		if !equal(got, want) {
			t.Errorf("%s %.20q: got %v want %v", c.vis, c.text, got, want)
		}
	}
}

func TestOnlyTrackedFilesCount(t *testing.T) {
	files := without(goodFiles(Public), "SECURITY.md")
	root := writeRepo(t, files)
	// Present on disk but never `git add`ed.
	if err := os.WriteFile(filepath.Join(root, "SECURITY.md"), []byte(prose("Security", 4)), 0o644); err != nil {
		t.Fatal(err)
	}
	got := ids(run(t, root, Public, nil))
	if want := []string{MissingFile + " SECURITY.md"}; !equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestNonGitDirectoryWalks(t *testing.T) {
	root := t.TempDir()
	for name, body := range without(goodFiles(Public), "SECURITY.md") {
		p := filepath.Join(root, filepath.FromSlash(name))
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := ids(run(t, root, Public, nil))
	if want := []string{MissingFile + " SECURITY.md"}; !equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestTrackedSymlinkIsNotFollowed(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte(strings.Repeat("padding line\n", 30)), 0o644); err != nil {
		t.Fatal(err)
	}
	root := writeRepo(t, without(goodFiles(Public), "SECURITY.md"))
	if err := os.Symlink(outside, filepath.Join(root, "SECURITY.md")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	gitIn(t, root, "add", "-A")
	got := ids(run(t, root, Public, nil))
	if want := []string{StubFile + " SECURITY.md"}; !equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

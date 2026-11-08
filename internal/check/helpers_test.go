package check

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anatolykoptev/repo-standards/internal/denylist"
)

const (
	apacheHead  = "Apache License\nVersion 2.0, January 2004\nhttp://www.apache.org/licenses/\n\nTERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION\n"
	mitText     = "MIT License\n\nCopyright (c) 2026 Someone\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the \"Software\"), to deal\nin the Software without restriction.\n"
	propText    = "Copyright (c) 2026 Some Holder. All rights reserved.\n"
	polyNoncomm = "# PolyForm Noncommercial License 1.0.0\n\n<https://polyformproject.org/licenses/noncommercial/1.0.0>\n" +
		"\nThe licensor grants you a copyright license for the software.\n"
	// fslMIT deliberately carries the embedded MIT grant: the FSL must be
	// recognised before the OSI phrases can claim it.
	fslMIT = "# Functional Source License, Version 1.1, MIT Future License\n" +
		"\nPermission is hereby granted, free of charge, to any person obtaining a copy\n" +
		"of this software and associated documentation files (the \"Software\"), to deal\n" +
		"in the Software without restriction.\n"
	bsl11    = "Business Source License 1.1\n\nThe Licensor hereby grants you the right to copy, modify, create derivative works, redistribute, and make non-production use of the software.\n"
	ssplText = "Server Side Public License\nVersion 1, October 16, 2018\n\nEveryone is permitted to copy and distribute verbatim copies of this license document.\n"
)

func prose(title string, lines int) string {
	return "# " + title + "\n\n" + strings.Repeat("This sentence documents real behaviour of the project.\n", lines)
}

// goodFiles is a repository that passes every check at the given visibility.
func goodFiles(vis Visibility) map[string]string {
	lic := apacheHead
	if vis == Private {
		lic = propText
	}
	return map[string]string{
		"README.md":                             prose("Readme", 6),
		"CLAUDE.md":                             prose("Agent notes", 4) + "\nAll docs: [index](docs/INDEX.md).\n",
		"CHANGELOG.md":                          "# Changelog\n\nNothing released yet.\n",
		"LICENSE":                               lic,
		"CONTRIBUTING.md":                       prose("Contributing", 4),
		"SECURITY.md":                           prose("Security", 4),
		"CODE_OF_CONDUCT.md":                    prose("Code of conduct", 5),
		".gitignore":                            "bin/\n",
		".github/pull_request_template.md":      prose("Pull request", 1),
		".github/ISSUE_TEMPLATE/bug_report.yml": "name: Bug report\ndescription: report a bug\nbody: []\n",
		".github/ISSUE_TEMPLATE/config.yml":     "blank_issues_enabled: false\n",
		"docs/INDEX.md": "# Index\n\n" +
			"- [Readme](../README.md)\n- [Agent notes](../CLAUDE.md)\n- [Changelog](../CHANGELOG.md)\n" +
			"- [Licence](../LICENSE)\n- [Contributing](../CONTRIBUTING.md)\n- [Security](../SECURITY.md)\n" +
			"- [Conduct](../CODE_OF_CONDUCT.md)\n",
	}
}

func without(m map[string]string, keys ...string) map[string]string {
	c := with(m, nil)
	for _, k := range keys {
		delete(c, k)
	}
	return c
}

func with(m, extra map[string]string) map[string]string {
	c := map[string]string{}
	for k, v := range m {
		c[k] = v
	}
	for k, v := range extra {
		c[k] = v
	}
	return c
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

// ids renders findings as "check path" pairs, the form the tests assert on.
func ids(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Check+" "+f.Path)
	}
	return out
}

// run uses a default list for public repos when none is given: an empty list
// is refused, so tests that do not care about tokens still need one.
func run(t *testing.T, root string, vis Visibility, dl *denylist.List) []Finding {
	t.Helper()
	return runFull(t, root, vis, dl).Findings
}

func runFull(t *testing.T, root string, vis Visibility, dl *denylist.List) Result {
	t.Helper()
	if dl == nil {
		dl = testList(t, "host:zzqdefaulthost\n")
	}
	res, err := Run(Options{Root: root, Visibility: vis, Denylist: dl})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// testList builds a denylist from plaintext with a fixed salt. The tokens are
// invented words, so they cannot collide with the shipped list.
func testList(t *testing.T, plain string) *denylist.List {
	t.Helper()
	data, _, err := denylist.Generate(strings.NewReader(plain), []byte("0123456789abcdef"), nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := denylist.Parse(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	return l
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

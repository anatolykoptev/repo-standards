package check

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func piiFiles(t *testing.T, vis Visibility, extra map[string]string) Result {
	t.Helper()
	root := writeRepo(t, with(goodFiles(vis), extra))
	return runFull(t, root, vis, testList(t, plainList))
}

func TestPIIStreamsLargeFiles(t *testing.T) {
	// Larger than the old 2 MiB cap, alias on the last line.
	big := strings.Repeat("lorem filler line of ordinary text\n", 80000) + "zzqalias\n"
	res := piiFiles(t, Public, map[string]string{"logs/big.txt": big})
	if len(res.Findings) != 1 || res.Findings[0].Check != PIIDenylist || res.Findings[0].Path != "logs/big.txt" {
		t.Fatalf("got %v", res.Findings)
	}
	// One very long line, too.
	long := strings.Repeat("a", 3<<20) + " zzqalias\n"
	if res := piiFiles(t, Public, map[string]string{"logs/long.txt": long}); len(res.Findings) != 1 {
		t.Fatalf("long line: %v", res.Findings)
	}
}

func TestPIIBinaryCountedNotSilent(t *testing.T) {
	res := piiFiles(t, Public, map[string]string{
		"data/a.bin": "\x00\x01zzqalias\n",
		"data/b.bin": "\x00\x00",
	})
	if len(res.Findings) != 0 || res.Stats.SkippedBinary != 2 {
		t.Fatalf("findings %v skipped %d", res.Findings, res.Stats.SkippedBinary)
	}
	// A NUL after the probe window does not make a file binary.
	late := strings.Repeat("x", binaryProbe+10) + "\x00zzqalias\n"
	if res := piiFiles(t, Public, map[string]string{"data/late.txt": late}); res.Stats.SkippedBinary != 0 || len(res.Findings) != 1 {
		t.Fatalf("late NUL: %v %d", res.Findings, res.Stats.SkippedBinary)
	}
}

func TestPIIFileNames(t *testing.T) {
	for _, name := range []string{"notes-zzqalias.txt", "zzqalias/readme-extra.txt", "dir/zzqbanned_thing.md"} {
		res := piiFiles(t, Public, map[string]string{name: "harmless content\n"})
		var got []string
		for _, f := range res.Findings {
			if strings.HasPrefix(f.Check, "pii-") && f.Path == name && strings.HasPrefix(f.Msg, "file name: ") {
				got = append(got, f.Check)
			}
		}
		if len(got) != 1 {
			t.Errorf("%s: %v", name, res.Findings)
		}
	}
	// A binary file whose PATH matches is still a finding.
	res := piiFiles(t, Public, map[string]string{"img/zzqalias.png": "\x00\x01"})
	if len(res.Findings) != 1 || res.Stats.SkippedBinary != 1 {
		t.Fatalf("binary path: %v", res.Findings)
	}
}

func TestPIISymlinkNameAndTarget(t *testing.T) {
	root := writeRepo(t, goodFiles(Public))
	if err := os.Symlink("harmless", filepath.Join(root, "link-zzqalias")); err != nil {
		t.Skip(err)
	}
	if err := os.Symlink(hm+"jdoe42/x", filepath.Join(root, "abs-link")); err != nil {
		t.Skip(err)
	}
	gitIn(t, root, "add", "-A")
	got := run(t, root, Public, testList(t, plainList))
	want := map[string]bool{"link-zzqalias": false, "abs-link": false}
	for _, f := range got {
		if _, ok := want[f.Path]; ok {
			want[f.Path] = true
		}
	}
	if !want["link-zzqalias"] || !want["abs-link"] || len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}

func TestPIIGitlinkPath(t *testing.T) {
	root := writeRepo(t, goodFiles(Public))
	gitIn(t, root, "update-index", "--add", "--cacheinfo", "160000,"+strings.Repeat("a", 40)+",vendored-zzqalias")
	got := run(t, root, Public, testList(t, plainList))
	if len(got) != 1 || got[0].Path != "vendored-zzqalias" {
		t.Fatalf("got %v", got)
	}
}

func TestBannedWordVariants(t *testing.T) {
	for _, line := range []string{
		"zzqbanned-thing", "zzqbanned_thing", "zzqbanned thing", "ZzqBannedThing",
		"zzqbannedthing", "ZZQBANNED-THING", "the zzqBanned.Thing api", "ZZQBANNEDTHING", "MyZzqBannedThingKit", "HTTPZzqBannedThing",
	} {
		res := piiFiles(t, Public, map[string]string{"src/a.txt": line + "\n"})
		if len(res.Findings) != 1 || res.Findings[0].Check != PIIBannedWord {
			t.Errorf("%q: %v", line, res.Findings)
		}
	}
	for _, line := range []string{"zzqbanned things", "zzqbannedthinger", "zzqbanned", "xzzqbannedthing"} {
		if res := piiFiles(t, Public, map[string]string{"src/a.txt": line + "\n"}); len(res.Findings) != 0 {
			t.Errorf("%q false positive: %v", line, res.Findings)
		}
	}
}

func TestHomePathForms(t *testing.T) {
	hit := []string{
		"file://" + hm + "jdoe42/x", "file://" + um + "jdoe42/x",
		"/mnt/c/" + "Users/jdoe42/Desktop", "see " + hm + "jdoe42/.ssh",
	}
	for _, l := range hit {
		if res := piiFiles(t, Public, map[string]string{"src/a.txt": l + "\n"}); len(res.Findings) != 1 || res.Findings[0].Check != PIIHomePath {
			t.Errorf("%q: %v", l, res.Findings)
		}
	}
	// Words that merely end in an attribute-like suffix must not suppress.
	for _, l := range []string{
		"into: " + um + "jdoe42/out", "symlink: " + hm + "jdoe42/x", "copy to: " + hm + "jdoe42/x",
		"curl=" + hm + "jdoe42/x", "photo: " + um + "jdoe42/x", "action_url: " + hm + "jdoe42/x",
	} {
		if res := piiFiles(t, Public, map[string]string{"src/a.txt": l + "\n"}); len(res.Findings) != 1 || res.Findings[0].Check != PIIHomePath {
			t.Errorf("%q must still be a finding: %v", l, res.Findings)
		}
	}
	miss := []string{
		hm + "postgres/data", hm + "runner/work", um + "x/y", hm + "ubuntu",
		`<a href="` + hm + `privacy-policy">x</a>`, "[policy](" + hm + "privacy-policy)",
		`src='` + um + `assets/logo.png'`, "url(" + hm + "banner.png)",
	}
	for _, l := range miss {
		if res := piiFiles(t, Public, map[string]string{"src/a.txt": l + "\n"}); len(res.Findings) != 0 {
			t.Errorf("%q false positive: %v", l, res.Findings)
		}
	}
}

func TestSuppression(t *testing.T) {
	m := suppressMarker
	res := piiFiles(t, Public, map[string]string{"src/a.txt": "zzqalias " + m + " documented example host\n" +
		"zzqalias // " + m + "\n" + "zzqalias plain\n"})
	var checks []string
	for _, f := range res.Findings {
		checks = append(checks, f.Check+":"+itoa(f.Line))
	}
	// line 1 suppressed (counted), line 2 marker lacks a reason (finding + the alias stays reported? marker is rejected, so both), line 3 plain.
	want := []string{PIIDenylist + ":2", PIISuppression + ":2", PIIDenylist + ":3"}
	if len(res.Stats.Suppressions) != 1 || res.Stats.Suppressions[0] != (Suppression{"src/a.txt", 1, "documented example host"}) {
		t.Fatalf("suppression list: %v", res.Stats.Suppressions)
	}
	if !equal(checks, want) || res.Stats.Suppressed != 1 {
		t.Fatalf("got %v suppressed %d", checks, res.Stats.Suppressed)
	}
}

func itoa(n int) string { return strings.TrimSpace(strings.Repeat(" ", 0) + string(rune('0'+n))) }

func TestResolveVisibility(t *testing.T) {
	cases := []struct {
		declared, detected string
		want               Visibility
		err                bool
	}{
		{"", "", Public, false},
		{"private", "", Private, false},
		{"public", "", Public, false},
		{"", "private", Private, false},
		{"", "public", Public, false},
		{"public", "private", Private, false}, // stricter declaration is accepted; the environment wins
		{"private", "private", Private, false},
		{"private", "public", "", true}, // less strict than reality
		{"internal", "", "", true},
		{"", "weird", "", true},
	}
	for _, c := range cases {
		got, err := ResolveVisibility(c.declared, c.detected)
		if (err != nil) != c.err || got != c.want {
			t.Errorf("%q/%q: got %q %v", c.declared, c.detected, got, err)
		}
	}
}

func TestGitFailureInGitWorkTreeIsAnError(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil { // not a valid repository
		t.Fatal(err)
	}
	if _, err := Run(Options{Root: root, Visibility: Private}); err == nil {
		t.Fatal("a broken .git fell back to a directory walk")
	}
}

func TestNonGitSetsNotGit(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "README.md"), []byte("x"), 0o644)
	res, err := Run(Options{Root: root, Visibility: Private})
	if err != nil || !res.NotGit {
		t.Fatalf("%v %v", res.NotGit, err)
	}
}

func TestHistoryFindsDeletedValue(t *testing.T) {
	root := writeRepo(t, goodFiles(Public))
	commit := func(msg string) {
		gitIn(t, root, "-c", "user.name=T", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", msg)
	}
	commit("initial")
	if err := os.WriteFile(filepath.Join(root, "src.txt"), []byte("see zzqalias here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, root, "add", "-A")
	commit("add")
	gitIn(t, root, "rm", "-q", "src.txt")
	commit("remove zzqbanned-thing")
	dl := testList(t, plainList)
	if got := run(t, root, Public, dl); len(got) != 0 {
		t.Fatalf("work tree should be clean: %v", got)
	}
	res, err := RunHistory(Options{Root: root, Visibility: Public, Denylist: dl})
	if err != nil {
		t.Fatal(err)
	}
	var cats []string
	for _, f := range res.Findings {
		cats = append(cats, f.Check)
		if strings.Contains(f.String(), "zzq") {
			t.Fatalf("leaks value: %s", f)
		}
	}
	// The alias appears in the added line and in the removed line; the banned
	// phrase in the commit message.
	if !equal(cats, []string{PIIDenylist, PIIDenylist, PIIBannedWord}) && !equal(cats, []string{PIIDenylist, PIIBannedWord, PIIDenylist}) && !equal(cats, []string{PIIBannedWord, PIIDenylist, PIIDenylist}) {
		t.Fatalf("got %v", cats)
	}
	if _, err := RunHistory(Options{Root: root, Visibility: Private}); err == nil {
		t.Fatal("history for private accepted")
	}
}

func TestHistoryRefusesShallowClone(t *testing.T) {
	src := writeRepo(t, goodFiles(Public))
	gitIn(t, src, "-c", "user.name=T", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "one")
	if err := os.WriteFile(filepath.Join(src, "more.txt"), []byte("more\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, src, "add", "-A")
	gitIn(t, src, "-c", "user.name=T", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "two")
	shallow := filepath.Join(t.TempDir(), "s")
	gitIn(t, filepath.Dir(shallow), "clone", "-q", "--depth", "1", "file://"+src, shallow)
	_, err := RunHistory(Options{Root: shallow, Visibility: Public, Denylist: testList(t, plainList)})
	if err == nil || !strings.Contains(err.Error(), "shallow") {
		t.Fatalf("shallow clone scanned: %v", err)
	}
	if _, err := RunHistory(Options{Root: src, Visibility: Public, Denylist: testList(t, plainList)}); err != nil {
		t.Fatalf("full clone refused: %v", err)
	}
}

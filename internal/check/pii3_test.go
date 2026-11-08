package check

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anatolykoptev/repo-standards/internal/denylist"
)

// Global literals the tests feed to the scanner are built from pieces so this
// file does not trip the tool's own pii-ip, pii-home-path and pii-ps-dump
// rules. Addresses marked safe below are documentation ranges or otherwise
// excluded and may stay literal.
var (
	globV4 = strings.Join([]string{"77", "88", "8", "1"}, ".")
	globV6 = "2a00:1450:4001:" + ":9"
	dashH  = "-ho" + "me-"
	dashU  = "-Us" + "ers-"
)

func piiCheck(res Result, id string) []Finding {
	var out []Finding
	for _, f := range res.Findings {
		if f.Check == id {
			out = append(out, f)
		}
	}
	return out
}

func TestPIIIPFlagsPublicAddresses(t *testing.T) {
	for i, line := range []string{
		"upstream = " + globV4,
		"listen on " + globV4 + ":8080/tcp",
		"peer [" + globV6 + "] and mapped ::ffff:" + globV4,
	} {
		fs := piiRepo(t, Public, "src/net.txt", "intro\n"+line+"\n")
		if len(fs) != 1 || fs[0].Check != PIIIP || fs[0].Line != 2 {
			t.Fatalf("case %d: got %v", i, fs)
		}
		if !strings.Contains(fs[0].Msg, "public-ip") {
			t.Fatalf("case %d: no category in %q", i, fs[0].Msg)
		}
		if strings.Contains(fs[0].String(), globV4) || strings.Contains(fs[0].String(), globV6) {
			t.Fatalf("case %d: finding leaks the value: %s", i, fs[0])
		}
	}
}

func TestPIIIPExclusions(t *testing.T) {
	lines := []string{
		"versions v1.2.3 and 1.2.3.4-beta and OID 1.3.6.1.4.1",
		"docs 192.0.2.7 198.51.100.7 203.0.113.7 2001:db8::7",
		"private 10.1.2.3 172.16.5.5 192.168.1.7 fc00::1 fd12::9",
		"loop 127.0.0.1 ::1 link 169.254.1.1 fe80::9",
		"cgnat 100.64.1.1 multi 224.0.0.1 ff02::1 unspec 0.0.0.0 ::",
		"bcast 255.255.255.255 mapped ::ffff:10.0.0.1",
		"resolvers 1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 149.112.112.112 208.67.222.222 208.67.220.220",
		"resolvers6 2606:4700:4700::1111 2606:4700:4700::1001 2001:4860:4860::8888 2001:4860:4860::8844 2620:fe::fe 2620:fe::9 2620:119:35::35 2620:119:53::53",
		"not literals 999.1.1.1 1.2.3 1.2.3.4.5 a1.2.3.4 x1.2.3.4",
		"mac aa:bb:cc:dd:ee:ff time 10:23:45 stamp 2024",
	}
	fs := piiRepo(t, Public, "src/notes.txt", strings.Join(lines, "\n")+"\n")
	for _, f := range fs {
		if f.Check == PIIIP {
			t.Errorf("false positive: %v", f)
		}
	}
}

func TestPIIIPInFileName(t *testing.T) {
	res := piiFiles(t, Public, map[string]string{"logs/" + globV4 + ".txt": "x\n"})
	got := piiCheck(res, PIIIP)
	if len(got) != 1 || got[0].Path != "logs/"+globV4+".txt" || !strings.HasPrefix(got[0].Msg, "file name: ") {
		t.Fatalf("got %v", res.Findings)
	}
}

func TestPIIIPInHistory(t *testing.T) {
	root := writeRepo(t, goodFiles(Public))
	commit := func(msg string) {
		gitIn(t, root, "-c", "user.name=T", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", msg)
	}
	commit("initial")
	if err := os.WriteFile(filepath.Join(root, "net.txt"), []byte("dial "+globV4+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, root, "add", "-A")
	commit("add")
	gitIn(t, root, "rm", "-q", "net.txt")
	commit("remove")
	dl := testList(t, plainList)
	if got := run(t, root, Public, dl); len(got) != 0 {
		t.Fatalf("work tree should be clean: %v", got)
	}
	res, err := RunHistory(Options{Root: root, Visibility: Public, Denylist: dl})
	if err != nil {
		t.Fatal(err)
	}
	if got := piiCheck(res, PIIIP); len(got) == 0 {
		t.Fatalf("history scan missed the IP: %v", res.Findings)
	}
}

func TestPIIPlansDir(t *testing.T) {
	res := piiFiles(t, Public, map[string]string{
		"docs/plans/deploy.md":   "# plan\n",
		"plans/root.md":          "# plan\n",
		"a/b/plans/deep/x.txt":   "x\n",
		"planning/not-a-dir.txt": "x\n",
		"docs/my-plans/x.md":     "x\n",
	})
	var got []string
	for _, f := range res.Findings {
		if strings.HasPrefix(f.Check, "pii-") {
			got = append(got, f.Check+" "+f.Path)
			if f.Check == PIIPlans && f.Line != 1 {
				t.Errorf("plans finding not at line 1: %v", f)
			}
			if f.Check == PIIPlans && !strings.Contains(f.Msg, "plans-dir") {
				t.Errorf("no category in %q", f.Msg)
			}
		}
	}
	want := []string{PIIPlans + " a/b/plans/deep/x.txt", PIIPlans + " docs/plans/deploy.md", PIIPlans + " plans/root.md"}
	if !equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// A file named "plans" is not under a plans directory.
	if res := piiFiles(t, Public, map[string]string{"docs/plans": "x\n"}); len(piiCheck(res, PIIPlans)) != 0 {
		t.Errorf("file named plans flagged: %v", res.Findings)
	}
	// Private repositories are not scanned.
	if res := piiFiles(t, Private, map[string]string{"plans/x.md": "x\n"}); len(res.Findings) != 0 {
		t.Errorf("private plans flagged: %v", res.Findings)
	}
	// A suppression marker on line 1 suppresses the plans finding.
	res2 := piiFiles(t, Public, map[string]string{
		"docs/plans/kept.md": "# kept " + suppressMarker + " archived mirror of a private plan\n",
	})
	for _, f := range res2.Findings {
		if f.Check == PIIPlans {
			t.Errorf("plans finding not suppressed: %v", f)
		}
	}
}

func TestPIIDashEncodedHomePaths(t *testing.T) {
	for _, l := range []string{
		"logs in /tmp/claude-1000/" + dashH + "jdoe42/out",
		"under .claude/projects/" + dashU + "jdoe42-proj",
		"v=" + dashH + "jdoe42",
		"quoted \"" + dashU + "jdoe42-x\"",
	} {
		fs := piiRepo(t, Public, "src/a.txt", l+"\n")
		if len(fs) != 1 || fs[0].Check != PIIHomePath || strings.Contains(fs[0].String(), "jdoe42") {
			t.Errorf("%q: got %v", l, fs)
		}
	}
	for _, l := range []string{
		"glued x" + dashH + "jdoe42 mid-token",
		"glued x" + dashU + "jdoe42 mid-token",
		"to " + dashU + "runner-x", // "runner" is a CI placeholder name
		"~/deploy/x and ~/projects",
		"flag --set" + dashH + "dir ok",
		"trailing " + dashH,
	} {
		fs := piiRepo(t, Public, "src/a.txt", l+"\n")
		for _, f := range fs {
			if strings.HasPrefix(f.Check, "pii-") {
				t.Errorf("%q false positive: %v", l, f)
			}
		}
	}
	// A checked-in Claude Code projects directory names a home path.
	res := piiFiles(t, Public, map[string]string{"snap/" + dashH + "jdoe42/cfg.txt": "x\n"})
	if got := piiCheck(res, PIIHomePath); len(got) != 1 {
		t.Fatalf("dash-encoded path in a file name: %v", res.Findings)
	}
}

func TestPIIProcessList(t *testing.T) {
	dump := strings.Join([]string{
		"root      1234 " + " 0.0  0.1 1234567 89012 ?        Ss   10:23   0:01 /usr/bin/sshd -D",
		"alice    23456 " + " 1.5  2.3 2345678 45678 pts/0    R+   Nov07   1:23:45 vim note.md",
	}, "\n")
	fs := piiRepo(t, Public, "src/dump.txt", dump+"\n")
	if len(fs) != 2 || fs[0].Check != PIIPsDump || fs[1].Check != PIIPsDump || fs[0].Line != 1 || fs[1].Line != 2 {
		t.Fatalf("got %v", fs)
	}
	if !strings.Contains(fs[0].Msg, "process-list") {
		t.Fatalf("no category in %q", fs[0].Msg)
	}
	if strings.Contains(fs[0].String(), "1234567") || strings.Contains(fs[0].String(), "sshd") {
		t.Fatalf("finding leaks the value: %s", fs[0])
	}
	// The ps header alone is not a process list; neither are near-misses.
	negs := []string{
		"USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND",
		"user 1234 0.0 0.1 123 456 pts/0 Ss 10:23",
		"a 1 2 3 4 5 6 7 8 9",
		"name pid %cpu %mem vsz rss tty stat start time cmd",
		"ps aux | grep ssh",
		"0.0 0.1 1234567 89012 ? Ss 10:23 0:01 cmd x",
	}
	for _, l := range negs {
		for _, f := range piiRepo(t, Public, "src/n.txt", l+"\n") {
			if f.Check == PIIPsDump {
				t.Errorf("%q flagged: %v", l, f)
			}
		}
	}
}

// testListPublic builds a denylist like testList but records public
// repository names (denylist.Generate's third argument).
func testListPublic(t *testing.T, plain string, public map[string]bool) *denylist.List {
	t.Helper()
	data, _, err := denylist.Generate(strings.NewReader(plain), []byte("0123456789abcdef"), public)
	if err != nil {
		t.Fatal(err)
	}
	l, err := denylist.Parse(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestDenylistPublicNameContext(t *testing.T) {
	// zqpubapi is denylisted AND names a public repository: it is reported
	// everywhere except a reference that can only mean the repository itself.
	dl := testListPublic(t, "host:zqpubapi\n", map[string]bool{"zqpubapi": true})

	clean := runFull(t, writeRepo(t, with(goodFiles(Public), map[string]string{
		"go.mod":           "module github.com/zqown/zqpubapi\n",
		"web/package.json": "{\"name\": \"zqpubapi\"}\n",
		"cli/Cargo.toml":   "[package]\nname = \"zqpubapi\"\n",
		"notes/link.txt":   "the source lives at github.com/zqown/zqpubapi.git\n",
	})), Public, dl)
	for _, f := range clean.Findings {
		if f.Check == PIIDenylist {
			t.Errorf("self-reference flagged: %v", f)
		}
	}

	// Anywhere else the token is still a finding: prose, a file name, and a
	// go.mod line that is not the module declaration.
	res := runFull(t, writeRepo(t, with(goodFiles(Public), map[string]string{
		"notes.txt":              "nightly backups go to the zqpubapi host\n",
		"docs/zqpubapi-notes.md": "# notes\n\n",
		"go.mod":                 "module example.com/zqother\nrequire zqpubapi v0.0.0\n",
	})), Public, dl)
	got := piiCheck(res, PIIDenylist)
	if len(got) != 3 {
		t.Fatalf("out-of-context uses must be flagged: %v", res.Findings)
	}
}

func TestMissingFileIgnoredByGitignore(t *testing.T) {
	for _, vis := range []Visibility{Public, Private} {
		files := without(goodFiles(vis), "SECURITY.md")
		files[".gitignore"] = "bin/\nSECURITY.md\n"
		root := writeRepo(t, files)
		// On disk but ignored, so it is never tracked.
		if err := os.WriteFile(filepath.Join(root, "SECURITY.md"), []byte(prose("Security", 4)), 0o644); err != nil {
			t.Fatal(err)
		}
		fs := run(t, root, vis, nil)
		var missing *Finding
		for i := range fs {
			if fs[i].Check == MissingFile && fs[i].Path == "SECURITY.md" {
				missing = &fs[i]
			}
		}
		if missing == nil {
			t.Fatalf("%s: no missing-file finding: %v", vis, fs)
		}
		if !strings.Contains(missing.Msg, "exists but is ignored by .gitignore (line 2 of .gitignore)") {
			t.Fatalf("%s: %q", vis, missing.Msg)
		}
	}
}

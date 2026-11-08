package check

import (
	"strings"
	"testing"

	"github.com/anatolykoptev/repo-standards/internal/denylist"
)

// Review round 4 (PR #12), driven by the fleet diff. Address literals below
// are IANA special-purpose ranges, placeholders or context-suppressed forms
// that the rule must NOT flag, so they may stay literal in this file. Real
// public literals are built from pieces (globV4, globV6) as in pii3_test.go.

// L1: the plans finding belongs to line 1, not to every line of the file.
func TestPIIPlansOncePerFile(t *testing.T) {
	res := piiFiles(t, Public, map[string]string{
		"docs/plans/run.md": "one\ntwo\nthree\n",
	})
	got := piiCheck(res, PIIPlans)
	if len(got) != 1 || got[0].Line != 1 || got[0].Path != "docs/plans/run.md" {
		t.Fatalf("got %v", got)
	}
}

// L7: a lockfile under plans/ is still a plans file — its name is published.
func TestPIIPlansLockfile(t *testing.T) {
	res := piiFiles(t, Public, map[string]string{
		"app/plans/go.sum": "mod v1.0.0 h1:abc=\n",
	})
	got := piiCheck(res, PIIPlans)
	if len(got) != 1 || got[0].Path != "app/plans/go.sum" {
		t.Fatalf("got %v", res.Findings)
	}
}

// L2: real address shapes stay flagged — one positive per shape.
func TestPIIIPPrecisionPositives(t *testing.T) {
	for i, line := range []string{
		"upstream = " + globV4,               // bare public IPv4
		"listen " + globV4 + ":8080/tcp",     // ip:port
		"dial [" + globV6 + "]:443",          // [v6]:port
		"mapped " + "::ffff:" + globV4,       // IPv4-mapped public
		"upstream = " + globV4 + " # pinned", // still a host, not a blob
	} {
		fs := piiRepo(t, Public, "src/net.txt", line+"\n")
		if len(fs) != 1 || fs[0].Check != PIIIP {
			t.Fatalf("case %d: got %v", i, fs)
		}
	}
}

// L2: the fleet false-positive classes — one negative per class a–g.
func TestPIIIPPrecisionNegatives(t *testing.T) {
	lines := []string{
		// (a) IANA special-purpose ranges that still report as global unicast.
		"iana 0.9.9.9 192.0.0.9 192.88.99.2 198.18.9.9 198.19.9.9 240.9.9.9",
		"iana6 64:ff9b::9999 64:ff9b:1::9 2002::9 2001::9 2001:20::9 100::9 ::808:808",
		// (b) version strings and user-agent tokens.
		"agent Chrome/139.0.0.0 Version/17.0.0.1",
		"vers v=51.1.2.3 since 51.1.2.3 ver 51.1.2.3 version=51.1.2.3 @since 51.1.2.3",
		// (c) longer dotted numbers and section references.
		"oid 1.3.6.1.4.1 and ref §4.1.1.1",
		// (d) CIDR notation names a range, not a host.
		"cidr 51.0.0.0/8 77.88.8.0/24",
		// (e) placeholder octet patterns.
		"fill 2.2.2.2 99.99.99.99 seq 5.6.7.8",
		// (f) slice syntax, not IPv6.
		"slice a[::2] b[::53]",
		// (g) one number inside a space-separated run of numbers.
		`svg d="0 1 2 3 9.4.6.7 8 9 0 1 2"`,
	}
	fs := piiRepo(t, Public, "src/notes.txt", strings.Join(lines, "\n")+"\n")
	for _, f := range fs {
		if f.Check == PIIIP {
			t.Errorf("false positive: %v", f)
		}
	}
}

// L7: the Unmap step is load-bearing — a mapped public address flags, a
// mapped private one does not.
func TestPIIIPMappedForms(t *testing.T) {
	fs := piiRepo(t, Public, "src/m.txt", "peer ::ffff:"+globV4+"\n")
	if len(fs) != 1 || fs[0].Check != PIIIP {
		t.Fatalf("mapped public: %v", fs)
	}
	for _, l := range []string{
		"peer ::ffff:10.0.0.1",
		"peer ::ffff:192.168.1.9",
		"peer ::ffff:172.16.9.9",
		"peer ::ffff:127.0.0.9",
		// These unwrap only through Unmap: a resolver, a doc range, CGNAT and
		// a placeholder in mapped form.
		"peer ::ffff:8.8.8.8",
		"peer ::ffff:192.0.2.9",
		"peer ::ffff:100.64.9.9",
		"peer ::ffff:2.2.2.2",
	} {
		for _, f := range piiRepo(t, Public, "src/m.txt", l+"\n") {
			if f.Check == PIIIP {
				t.Errorf("%q flagged: %v", l, f)
			}
		}
	}
}

// L3: the generator records the go-less and first-segment forms of a public
// name, so a derived token in the repository-name position is suppressed too.
func TestPIIPublicNameDerivedForms(t *testing.T) {
	dl := testListPublic(t, "host:zzqpub\n", denylist.PublicNames([]string{"zzqpub-chat"}))
	res := runFull(t, writeRepo(t, with(goodFiles(Public), map[string]string{
		"notes/link.txt": "source github.com/o/zzqpub-chat\n",
	})), Public, dl)
	if got := piiCheck(res, PIIDenylist); len(got) != 0 {
		t.Fatalf("derived name in repo position flagged: %v", res.Findings)
	}
	// The same token outside a self-reference is still personal data.
	res = runFull(t, writeRepo(t, with(goodFiles(Public), map[string]string{
		"notes.txt": "ssh zzqpub now\n",
	})), Public, dl)
	if got := piiCheck(res, PIIDenylist); len(got) != 1 {
		t.Fatalf("out-of-context derived token must flag: %v", res.Findings)
	}
}

// L4: suppression covers the matched span only — the same token elsewhere on
// the line still reports.
func TestPIIPublicNameSpanOnly(t *testing.T) {
	dl := testListPublic(t, "host:zzqrepo\n", denylist.PublicNames([]string{"zzqrepo"}))
	res := runFull(t, writeRepo(t, with(goodFiles(Public), map[string]string{
		"src/a.txt": "ssh zzqrepo # see github.com/someone/zzqrepo\n",
	})), Public, dl)
	if got := piiCheck(res, PIIDenylist); len(got) != 1 || got[0].Line != 1 {
		t.Fatalf("non-reference occurrence must flag: %v", res.Findings)
	}
	// A lone self-reference stays clean.
	res = runFull(t, writeRepo(t, with(goodFiles(Public), map[string]string{
		"src/a.txt": "see github.com/someone/zzqrepo\n",
	})), Public, dl)
	if got := piiCheck(res, PIIDenylist); len(got) != 0 {
		t.Fatalf("self-reference flagged: %v", res.Findings)
	}
}

// L4: manifest name positions are anchored — "hostname" is not a Cargo
// package name, and a nested package.json "name" is not the repo's own.
func TestPIIPublicNameManifestAnchoring(t *testing.T) {
	dl := testListPublic(t, "host:zzqrepo\n", denylist.PublicNames([]string{"zzqrepo"}))
	res := runFull(t, writeRepo(t, with(goodFiles(Public), map[string]string{
		"cli/Cargo.toml":   "[package]\nhostname = \"zzqrepo\"\n",
		"web/package.json": "{\"deps\": {\"name\": \"zzqrepo\"}}\n",
	})), Public, dl)
	if got := piiCheck(res, PIIDenylist); len(got) != 2 {
		t.Fatalf("anchored non-name fields must flag: %v", res.Findings)
	}
	// The real package name positions still suppress.
	res = runFull(t, writeRepo(t, with(goodFiles(Public), map[string]string{
		"cli/Cargo.toml":   "[package]\nname = \"zzqrepo\"\n",
		"web/package.json": "{\"name\": \"zzqrepo\"}\n",
	})), Public, dl)
	if got := piiCheck(res, PIIDenylist); len(got) != 0 {
		t.Fatalf("package name suppressed: %v", res.Findings)
	}
}

// L5: large-file skips third-party trees like the personal-data scan does.
func TestLargeFileVendored(t *testing.T) {
	big := strings.Repeat("x", 11<<20)
	res := runFull(t, writeRepo(t, with(goodFiles(Public), map[string]string{
		"vendor/mod/big.go":         big,
		"web/node_modules/p/big.js": big,
		"data/big.bin":              big,
	})), Public, nil)
	got := piiCheck(res, LargeFile)
	if len(got) != 1 || got[0].Path != "data/big.bin" {
		t.Fatalf("got %v", res.Findings)
	}
}

// L6: a process-list row in test sources and fixtures is synthetic.
func TestPIIProcessListSkipsTestSources(t *testing.T) {
	row := "alice    23456 " + " 1.5  2.3 2345678 45678 pts/0    R+   Nov07   1:23:45 vim note.md\n"
	for _, name := range []string{
		"pkg/x_test.go", "web/foo.test.js", "mod/x_test.py", "mod/test_x.py",
		"testdata/dump.txt", "fixtures/dump.txt",
	} {
		res := piiFiles(t, Public, map[string]string{name: row})
		for _, f := range res.Findings {
			if f.Check == PIIPsDump {
				t.Errorf("%s: synthetic row flagged: %v", name, f)
			}
		}
	}
	// The same row in a real file is still a dump.
	res := piiFiles(t, Public, map[string]string{"src/dump.txt": row})
	if got := piiCheck(res, PIIPsDump); len(got) != 1 {
		t.Fatalf("real dump must flag: %v", res.Findings)
	}
}

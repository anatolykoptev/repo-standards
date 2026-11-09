package check

import (
	"strings"
	"testing"
)

// A denylisted token that spells a recorded public domain — its leftmost
// label in DNS order, or followed by the domain's tail in reverse-DNS order
// as in a package id — is not personal data in that context. The invented
// domain is zzqhost.example; zzqhost is a denylisted ssh alias, zzqnode a
// denylisted host.
var domainList = "ssh-alias:zzqhost\nhost:zzqnode\npublic-domain:zzqhost.example\n"

func domainRepo(t *testing.T, line string) Result {
	t.Helper()
	root := writeRepo(t, with(goodFiles(Public), map[string]string{"src/a.txt": "intro\n" + line + "\n"}))
	return runFull(t, root, Public, testList(t, domainList))
}

func TestDenylistPublicDomainSuppressed(t *testing.T) {
	for _, line := range []string{
		"see https://zzqweb.zzqhost.example/x", // a host under the domain
		"zzqhost.example",                      // the domain itself
		"mail user@zzqhost.example please",     // mail at the public domain
		"docs at zzqhost.example/path?q=1",
		"example.zzqhost.app.MainActivity", // a package id
		"example.zzqhost",                  // reverse-DNS at run end
		"deep.example.zzqhost.x",           // deeper reversed prefix
	} {
		res := domainRepo(t, line)
		for _, f := range res.Findings {
			if f.Check == PIIDenylist {
				t.Errorf("%q: public-domain context flagged: %v", line, f)
			}
		}
		if res.Stats.Suppressed != 0 {
			t.Errorf("%q: a domain suppression is not a marker suppression", line)
		}
	}
}

func TestDenylistPublicDomainStillReported(t *testing.T) {
	for _, line := range []string{
		"ssh zzqhost",                           // bare
		"zzqhost-tunnel",                        // not a domain
		"zzqhost.internal",                      // not the recorded domain
		"other.zzqhost.app",                     // a different reversed tail
		"see zzqhost.example, then ssh zzqhost", // the bare use still reports
		"a zzqhost.example b zzqhost.internal",  // only the domain use is suppressed
	} {
		res := domainRepo(t, line)
		got := piiCheck(res, PIIDenylist)
		if len(got) != 1 {
			t.Errorf("%q: got %v", line, res.Findings)
			continue
		}
		if strings.Contains(got[0].String(), "zzq") {
			t.Errorf("%q: finding leaks the value: %s", line, got[0])
		}
	}
}

// A second denylisted label inside the same name is still reported: the
// domain suppression anchors at the occurrence, it does not clear the run.
func TestDenylistPublicDomainLeftmostLabel(t *testing.T) {
	res := domainRepo(t, "zzqnode.zzqhost.example")
	got := piiCheck(res, PIIDenylist)
	if len(got) != 1 || !strings.Contains(got[0].Msg, "category host") {
		t.Fatalf("the other label must report: %v", res.Findings)
	}
}

// The domain context does not travel across lines.
func TestDenylistPublicDomainPerLine(t *testing.T) {
	root := writeRepo(t, with(goodFiles(Public), map[string]string{
		"src/a.txt": "zzqhost.example\nzzqhost\n",
	}))
	res := runFull(t, root, Public, testList(t, domainList))
	got := piiCheck(res, PIIDenylist)
	if len(got) != 1 || got[0].Line != 2 {
		t.Fatalf("the bare use on line 2 must report: %v", res.Findings)
	}
}

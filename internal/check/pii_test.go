package check

import (
	"strings"
	"testing"

	"github.com/anatolykoptev/repo-standards/internal/denylist"
)

// The denylisted tokens below are invented words.
// Built from pieces so this file does not trip the tool's own home-path scan.
const (
	hm = "/ho" + "me/"
	um = "/Us" + "ers/"
)

const plainList = "host:zzqhost.example\nssh-alias:zzqalias\nword:zzqbanned-thing\nemail:zzq@zzqmail.example\nhome-user:zzquser\n"

func piiRepo(t *testing.T, vis Visibility, name, body string) []Finding {
	t.Helper()
	root := writeRepo(t, with(goodFiles(vis), map[string]string{name: body}))
	return run(t, root, vis, testList(t, plainList))
}

func TestPIIDenylistForms(t *testing.T) {
	cases := []struct {
		name, line, check string
	}{
		{"bare", "connect to zzqalias now", PIIDenylist},
		{"upper case", "ZZQALIAS", PIIDenylist},
		{"url host", "see https://zzqhost.example/path?q=1", PIIDenylist},
		{"subdomain", "ssh build.zzqhost.example", PIIDenylist},
		{"email", "mail zzq@zzqmail.example please", PIIDenylist},
		{"email domain only", "contact someone@zzqhost.example", PIIDenylist},
		{"banned word inside hyphenated", "a web-zzqbanned-thing-kit", PIIBannedWord},
		{"banned word plain", "zzqbanned-thing.", PIIBannedWord},
		{"underscore joined", "ssh_zzqalias_cfg", PIIDenylist},
		{"in quotes", `host = "zzqalias"`, PIIDenylist},
	}
	for _, c := range cases {
		fs := piiRepo(t, Public, "src/app.txt", "line one\n"+c.line+"\n")
		if len(fs) != 1 || fs[0].Check != c.check || fs[0].Path != "src/app.txt" || fs[0].Line != 2 {
			t.Errorf("%s: got %v", c.name, fs)
			continue
		}
		for _, secret := range []string{"zzq"} {
			if strings.Contains(fs[0].String(), secret) {
				t.Errorf("%s: finding leaks the matched value: %s", c.name, fs[0])
			}
		}
	}
}

func TestPIINegatives(t *testing.T) {
	lines := []string{
		"zzqaliasx and xzzqalias are other words",
		"zzqhost is not the whole host",
		"banned zzqbanned alone is not the phrase",
		"/home/user/project and /home/runner/work and /home/node/app",
		"https://example.com/home/dashboard and a/home/jdoe42/x relative",
		"~/projects and $HOME/x",
		"C:\\Users\\Public\\Documents",
	}
	fs := piiRepo(t, Public, "docs/notes.md", strings.Join(lines, "\n")+"\n")
	// docs/notes.md is not in INDEX.md, which is a different finding.
	for _, f := range fs {
		if strings.HasPrefix(f.Check, "pii-") {
			t.Errorf("false positive: %v", f)
		}
	}
}

func TestPIIHomePaths(t *testing.T) {
	for _, line := range []string{
		"cd " + hm + "jdoe42/work",
		"open " + um + "jdoe42/Developer/x",
		`"path": "` + hm + `jdoe42"`,
		`C:\` + "Users" + `\jdoe42\AppData`,
		"(" + um + "jdoe42/x)",
	} {
		fs := piiRepo(t, Public, "src/a.txt", line+"\n")
		if len(fs) != 1 || fs[0].Check != PIIHomePath || strings.Contains(fs[0].String(), "jdoe42") {
			t.Errorf("%q: got %v", line, fs)
		}
	}
}

func TestPIIExclusions(t *testing.T) {
	leak := "zzqalias at " + hm + "jdoe42/x\n"
	for _, name := range []string{"vendor/pkg/a.go", "web/node_modules/x/index.js", "package-lock.json",
		"deep/Cargo.lock", "go.sum", "yarn.lock", "thing.lock"} {
		if fs := piiRepo(t, Public, name, leak); len(fs) != 0 {
			t.Errorf("%s should be skipped: %v", name, fs)
		}
	}
	if fs := piiRepo(t, Public, "blob.bin", "\x00\x01zzqalias\n"); len(fs) != 0 {
		t.Errorf("binary file scanned: %v", fs)
	}
	if fs := piiRepo(t, Public, "src/vendored.txt", leak); len(fs) != 2 {
		t.Errorf("a name merely containing 'vendor' must be scanned: %v", fs)
	}
}

func TestPIIOnlyForPublic(t *testing.T) {
	if fs := piiRepo(t, Private, "src/a.txt", "zzqalias "+hm+"jdoe42/x zzqbanned-thing\n"); len(fs) != 0 {
		t.Fatalf("private repos are not scanned: %v", fs)
	}
}

func TestPIIOneFindingPerCategoryPerLine(t *testing.T) {
	fs := piiRepo(t, Public, "src/a.txt", "zzqalias zzqalias build.zzqalias\n")
	if len(fs) != 1 {
		t.Fatalf("got %v", fs)
	}
}

func TestPIIInDocsAndRootFiles(t *testing.T) {
	// The scan covers the required documents themselves.
	fs := piiRepo(t, Public, "README.md", prose("Readme", 6)+"Deploy to zzqhost.example\n")
	if len(fs) != 1 || fs[0].Check != PIIDenylist || fs[0].Path != "README.md" {
		t.Fatalf("got %v", fs)
	}
}

func TestEmptyDenylistIsRefusedForPublic(t *testing.T) {
	root := writeRepo(t, goodFiles(Public))
	for _, l := range []*denylist.List{nil, testList(t, "")} {
		if _, err := Run(Options{Root: root, Visibility: Public, Denylist: l}); err == nil {
			t.Fatal("public scan ran with an empty denylist")
		}
	}
	if _, err := Run(Options{Root: writeRepo(t, goodFiles(Private)), Visibility: Private}); err != nil {
		t.Fatalf("private needs no denylist: %v", err)
	}
}

package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func do(args ...string) (code int, out, errOut string) {
	var o, e bytes.Buffer
	code = run(args, &o, &e)
	return code, o.String(), e.String()
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"bogus"}, {"check", "--visibility", "internal", t.TempDir()}, {"check", "a", "b"},
		{"init", "--visibility", "internal", t.TempDir()}, {"init", "--license", "bogus", t.TempDir()},
		{"init", "--year", "20x6", t.TempDir()}, {"init", "a", "b"}, {"index", "a", "b"}} {
		if code, _, _ := do(args...); code != exitUsage {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func TestInitRun(t *testing.T) {
	dir := t.TempDir()
	code, out, e := do("init", "--visibility", "private", "--holder", "Zzq Holder", dir)
	if code != exitOK || !strings.Contains(out, "created SECURITY.md") || !strings.Contains(out, "[missing-file]") {
		t.Fatalf("%d\n%s\n%s", code, out, e)
	}
	if _, err := os.Stat(filepath.Join(dir, "SECURITY.md")); err != nil {
		t.Fatal("SECURITY.md not written")
	}
	// The visibility rule is the same as check's: private cannot be declared
	// for a repo detected as public.
	if code, _, e := do("init", "--visibility", "private", "--detected", "public", dir); code != exitUsage || !strings.Contains(e, "less strict") {
		t.Fatalf("init visibility rule: %d %q", code, e)
	}
	// --dry-run reports and writes nothing.
	dir2 := t.TempDir()
	code, out, _ = do("init", "--visibility", "private", "--holder", "Zzq", "--dry-run", dir2)
	if code != exitOK || !strings.Contains(out, "would create SECURITY.md") {
		t.Fatalf("%d %q", code, out)
	}
	if ents, _ := os.ReadDir(dir2); len(ents) != 0 {
		t.Fatalf("dry-run wrote %v", ents)
	}
	// A public repo without --repo or a GitHub origin fails before writing.
	dir3 := t.TempDir()
	if code, _, e := do("init", "--visibility", "public", "--holder", "Zzq", "--license", "mit", dir3); code != exitUsage || !strings.Contains(e, "--repo") {
		t.Fatalf("public init without repo: %d %q", code, e)
	}
	if ents, _ := os.ReadDir(dir3); len(ents) != 0 {
		t.Fatalf("failed init wrote %v", ents)
	}
}

func TestIndexRun(t *testing.T) {
	dir := t.TempDir()
	code, out, e := do("index", dir)
	if code != exitOK || !strings.Contains(out, "created docs/INDEX.md") {
		t.Fatalf("%d\n%s\n%s", code, out, e)
	}
	if _, err := os.Stat(filepath.Join(dir, "docs", "INDEX.md")); err != nil {
		t.Fatal("docs/INDEX.md not written")
	}
	// A second run finds nothing to index.
	code, out, _ = do("index", dir)
	if code != exitOK || !strings.Contains(out, "is complete") {
		t.Fatalf("%d %q", code, out)
	}
	// A tracked-but-unlinked document gets a row.
	if err := os.WriteFile(filepath.Join(dir, "docs", "extra.md"), []byte("# Extra\n\nSome words here.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ = do("index", "--dry-run", dir)
	if code != exitOK || !strings.Contains(out, "would index docs/extra.md") {
		t.Fatalf("dry-run: %d %q", code, out)
	}
	if code, out, _ := do("index", dir); code != exitOK || !strings.Contains(out, "indexed docs/extra.md") {
		t.Fatalf("%d %q", code, out)
	}
	idx, _ := os.ReadFile(filepath.Join(dir, "docs", "INDEX.md"))
	if !strings.Contains(string(idx), "](extra.md)") {
		t.Fatalf("no row appended:\n%s", idx)
	}
}

func TestCheckExitCodes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := do("check", "--visibility", "private", dir)
	if code != exitViolation || !strings.Contains(out, "[missing-file]") {
		t.Fatalf("code %d out %q", code, out)
	}
	// Self-check: this repository must pass its own public rules.
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	if code, out, _ := do("check", "--visibility", "public", root); code != exitOK {
		t.Fatalf("self-check failed (%d):\n%s", code, out)
	}
}

func TestGenRefusesReadablePlaintextAndNeverEchoes(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "deny.txt")
	out := filepath.Join(dir, "out.hashes")
	if err := os.WriteFile(in, []byte("host:zzqhost\nbad line zzqsecret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := do("denylist-gen", "--in", in, "--out", out); code != exitUsage || !strings.Contains(errOut, "chmod 600") {
		t.Fatalf("world-readable list accepted: %d %q", code, errOut)
	}
	if err := os.Chmod(in, 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, errOut := do("denylist-gen", "--in", in, "--out", out)
	if code != exitUsage || strings.Contains(stdout+errOut, "zzqsecret") {
		t.Fatalf("malformed list: %d %q %q", code, stdout, errOut)
	}
	if err := os.WriteFile(in, []byte("host:zzqhost\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, so, _ := do("denylist-gen", "--in", in, "--out", out); code != exitOK || !strings.Contains(so, "(1 tokens)") {
		t.Fatalf("%d %q", code, so)
	}
	first, _ := os.ReadFile(out)
	// Regeneration keeps the salt, so the file does not churn.
	if code, _, _ := do("denylist-gen", "--in", in, "--out", out); code != exitOK {
		t.Fatal(code)
	}
	if second, _ := os.ReadFile(out); !bytes.Equal(first, second) {
		t.Fatal("regeneration changed the file")
	}
}

func TestCustomDenylistFlag(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "d.txt")
	hashes := filepath.Join(dir, "d.hashes")
	_ = os.WriteFile(in, []byte("word:zzqbanned\n"), 0o600)
	if code, _, e := do("denylist-gen", "--in", in, "--out", hashes); code != exitOK {
		t.Fatal(e)
	}
	if code, _, _ := do("check", "--denylist", filepath.Join(dir, "missing"), dir); code != exitUsage {
		t.Fatal(code)
	}
}

func TestGenDropsPublicRepoNames(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "d.txt")
	names := filepath.Join(dir, "names.txt")
	out := filepath.Join(dir, "d.hashes")
	_ = os.WriteFile(in, []byte("host:zzqpub\nhost:zzqpriv\n"), 0o600)
	_ = os.WriteFile(names, []byte("zzqpub-chat\nother\n"), 0o644)
	code, so, e := do("denylist-gen", "--in", in, "--out", out, "--public-repos", names)
	if code != exitOK || !strings.Contains(so, "(1 tokens); dropped 1") || strings.Contains(so+e, "zzqpub") {
		t.Fatalf("%d %q %q", code, so, e)
	}
	if code, _, _ := do("denylist-gen", "--in", in, "--out", out, "--public-repos", names, "--public-owner", "x"); code != exitUsage {
		t.Fatal("both sources accepted")
	}
}

func TestPanicExitsThree(t *testing.T) {
	old := runFn
	defer func() { runFn = old }()
	runFn = func([]string, io.Writer, io.Writer) int { panic("boom") }
	var o, e bytes.Buffer
	if code := guarded(nil, &o, &e); code != exitPanic || !strings.Contains(e.String(), "internal error") {
		t.Fatalf("%d %q", code, e.String())
	}
}

func TestEmptyDenylistFileIsError(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.hashes")
	_ = os.WriteFile(empty, []byte("# nothing\n"), 0o644)
	if code, _, e := do("check", "--denylist", empty, dir); code != exitUsage || !strings.Contains(e, "no entries") {
		t.Fatalf("%d %q", code, e)
	}
}

func TestDetectedOverridesAndRefusesLaxDeclaration(t *testing.T) {
	dir := t.TempDir()
	if code, _, e := do("check", "--visibility", "private", "--detected", "public", dir); code != exitUsage || !strings.Contains(e, "less strict") {
		t.Fatalf("%d %q", code, e)
	}
}

func TestHistoryFlagAndSummary(t *testing.T) {
	root, _ := filepath.Abs(filepath.Join("..", ".."))
	if code, _, e := do("check", "--visibility", "private", "--history", root); code != exitUsage {
		t.Fatalf("history on private: %d %q", code, e)
	}
	_, _, e := do("check", "--visibility", "public", root)
	if !strings.Contains(e, "skipped ") || !strings.Contains(e, " binary files") {
		t.Fatalf("summary missing: %q", e)
	}
}

// The action is the only way callers run this tool. It must build from its own
// checkout (so the pinned ref is the version that runs), take no second version
// string, and neutralise a caller's go.work.
func TestActionBuildsFromItself(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	a := string(b)
	for _, want := range []string{"using: composite", "github.action_path", "GOWORK: 'off'",
		"github.event.repository.private", "--detected", `cd "$ACTION_PATH" && go build`} {
		if !strings.Contains(a, want) {
			t.Errorf("action.yml lacks %q", want)
		}
	}
	for _, bad := range []string{"tool-ref", "repository: anatolykoptev/repo-standards", "workflow_call"} {
		if strings.Contains(a, bad) {
			t.Errorf("action.yml must not contain %q", bad)
		}
	}
	ents, _ := os.ReadDir(filepath.Join("..", "..", ".github", "workflows"))
	for _, e := range ents {
		w, _ := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", e.Name()))
		if strings.Contains(string(w), "workflow_call") {
			t.Errorf("%s: a reusable workflow would reintroduce a second version string", e.Name())
		}
	}
}

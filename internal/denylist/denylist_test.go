package denylist

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

var salt = []byte("0123456789abcdef")

func gen(t *testing.T, plain string, s []byte) *List {
	t.Helper()
	data, _, err := Generate(strings.NewReader(plain), s, nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := Parse(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestRoundTripAndCategory(t *testing.T) {
	l := gen(t, "# c\nhost:zzqhost.example\nword:zzq-word\n", salt)
	if c, ok := l.Lookup("zzqhost.example"); !ok || c != "host" {
		t.Fatalf("got %q %v", c, ok)
	}
	if !l.LookupWord("zzqword") || l.LookupWord("zzq") {
		t.Fatal("word entries match in squashed form only")
	}
	if _, ok := l.Lookup("zzqhost"); ok {
		t.Fatal("prefix must not match")
	}
	if l.Len() != 2 {
		t.Fatal(l.Len())
	}
}

// Independent oracle: compute the digest by hand rather than via hash().
func TestHashFormatMatchesSpec(t *testing.T) {
	data, _, err := Generate(strings.NewReader("host:zzqhost\n"), salt, nil)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append(append([]byte{}, salt...), "zzqhost"...))
	if !strings.Contains(string(data), "host "+hex.EncodeToString(sum[:])+"\n") {
		t.Fatalf("hash line missing:\n%s", data)
	}
	if strings.Contains(string(data), "zzqhost") {
		t.Fatal("plaintext token present in output")
	}
}

func TestSaltChangesHashes(t *testing.T) {
	l := gen(t, "host:zzqhost\n", []byte("fedcba9876543210"))
	l2 := gen(t, "host:zzqhost\n", salt)
	d1, _, _ := Generate(strings.NewReader("host:zzqhost\n"), []byte("fedcba9876543210"), nil)
	d2, _, _ := Generate(strings.NewReader("host:zzqhost\n"), salt, nil)
	if string(d1) == string(d2) {
		t.Fatal("different salts produced identical output")
	}
	if _, ok := l.Lookup("zzqhost"); !ok {
		t.Fatal()
	}
	_ = l2
}

func TestGenerateRejectsBadInput(t *testing.T) {
	for _, in := range []string{"host:UPPER", "host:ab", "nocolon", "bogus:zzqhost", "host:has space", "host:a/b"} {
		if _, _, err := Generate(strings.NewReader(in+"\n"), salt, nil); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestErrorsDoNotEchoTokens(t *testing.T) {
	_, _, err := Generate(strings.NewReader("host:ZZQSECRET\n"), salt, nil)
	if err == nil || strings.Contains(strings.ToLower(err.Error()), "zzqsecret") {
		t.Fatalf("err = %v", err)
	}
}

func TestRandomSaltWhenNil(t *testing.T) {
	a, _, _ := Generate(strings.NewReader("host:zzqhost\n"), nil, nil)
	b, _, _ := Generate(strings.NewReader("host:zzqhost\n"), nil, nil)
	if string(a) == string(b) {
		t.Fatal("salts repeated")
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"host\n", "salt zz\n", "salt 00112233445566778899\nbogus " + strings.Repeat("a", 64) + "\n",
		"host " + strings.Repeat("a", 64) + "\n", "salt 00112233445566778899\nhost abc\n"} {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestEmbeddedMeetsMinimum(t *testing.T) {
	l, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if l.Len() < MinEmbeddedEntries {
		t.Fatalf("embedded list has %d entries", l.Len())
	}
}

func TestNilListLooksUpNothing(t *testing.T) {
	var l *List
	if _, ok := l.Lookup("anything"); ok {
		t.Fatal()
	}
}

func TestPublicNamesRecorded(t *testing.T) {
	pub := PublicNames([]string{"zzqproduct", "Go-Zzqlib", "zzqfam-chat", "zz-x", "go-zzqext-kit"})
	plain := "host:zzqproduct\nssh-alias:zzqlib\nhost:zzqfam\nhost:zzqfam-chat\nhost:zzqext-kit\nhost:zzqprivate\nword:zzqproduct\n"
	data, n, err := Generate(strings.NewReader(plain), salt, pub)
	if err != nil {
		t.Fatal(err)
	}
	// zzqproduct, go-zzqlib, zzqlib, zzqfam-chat, zzqfam, zz-x, go-zzqext-kit,
	// zzqext-kit, zzqext; "zz" is too short.
	if n != 9 || len(pub) != 9 {
		t.Fatalf("recorded %d, set %v", n, pub)
	}
	l, err := Parse(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	// Public repository names stay denylisted — they are only suppressed
	// contextually, at scan time.
	for _, tok := range []string{"zzqproduct", "zzqlib", "zzqfam", "zzqfam-chat", "zzqext-kit", "zzqprivate"} {
		if _, ok := l.Lookup(tok); !ok {
			t.Errorf("token %q was dropped", tok)
		}
	}
	for _, tok := range []string{"zzqproduct", "go-zzqlib", "zzqlib", "zzqfam-chat", "zzqfam", "zz-x", "go-zzqext-kit", "zzqext-kit", "zzqext"} {
		if !l.IsPublicName(tok) {
			t.Errorf("%q not recorded as a public name", tok)
		}
	}
	if l.IsPublicName("zzqprivate") {
		t.Error("private token recorded as public")
	}
	if l.IsPublicName("zz") {
		t.Error("short segment recorded")
	}
	if !l.LookupWord("zzqproduct") {
		t.Error("word entry lost")
	}
}

func TestPublicDomainRecords(t *testing.T) {
	plain := "ssh-alias:zzqhost\npublic-domain:zzqhost.example\npublic-domain:zzqhost.example\npublic-domain:deep.zzqhost.example\n"
	data, _, err := Generate(strings.NewReader(plain), salt, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The domains are hashed like every other record: the plaintext never
	// reaches the output.
	for _, s := range []string{"zzqhost.example", "deep", "zzqhost"} {
		if strings.Contains(string(data), s) {
			t.Fatalf("plaintext present in output:\n%s", data)
		}
	}
	if !strings.Contains(string(data), PublicDomainCategory+" ") {
		t.Fatalf("no public-domain record written:\n%s", data)
	}
	l, err := Parse(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if !l.IsPublicDomain("zzqhost.example") || !l.IsPublicDomain("deep.zzqhost.example") {
		t.Fatal("recorded domains not read back")
	}
	for _, d := range []string{"zzqhost.internal", "other.zzqhost.example", "zzqhost"} {
		if l.IsPublicDomain(d) {
			t.Errorf("unrecorded domain %q matches", d)
		}
	}
	// A public domain is context, not a denylist entry: it must not count
	// toward the minimum and must not match by itself.
	if _, ok := l.Lookup("zzqhost.example"); ok {
		t.Fatal("public-domain became a denylist entry")
	}
	if l.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", l.Len())
	}
}

func TestPublicDomainRejectsBadInput(t *testing.T) {
	for _, in := range []string{
		"public-domain:zzqhost",          // one label
		"public-domain:",                 // empty
		"public-domain:zzqhost..example", // empty label
		"public-domain:.zzqhost.example", // leading dot
		"public-domain:zzqhost.example.", // trailing dot
		"public-domain:Zzqhost.example",  // uppercase
		"public-domain:zzq_host.example", // character outside [a-z0-9.-]
		"public-domain:zzqhost.ex_ample",
	} {
		_, _, err := Generate(strings.NewReader(in+"\n"), salt, nil)
		if err == nil {
			t.Errorf("%q accepted", in)
			continue
		}
		if v := in[len("public-domain:"):]; v != "" && strings.Contains(err.Error(), v) {
			t.Errorf("%q: error echoes the value: %v", in, err)
		}
	}
}

func TestMinimumRejectsStrippedList(t *testing.T) {
	if err := checkMinimum(gen(t, "host:zzqhost\n", salt)); err == nil {
		t.Fatal("a one-entry list passed the minimum")
	}
	if err := checkMinimum(gen(t, "", salt)); err == nil {
		t.Fatal("an empty list passed the minimum")
	}
}

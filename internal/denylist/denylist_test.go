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

func TestPublicNamesExcluded(t *testing.T) {
	ex := PublicNames([]string{"zzqproduct", "Go-Zzqlib", "zzqfam-chat", "zz-x", "go-zzqext-kit"})
	plain := "host:zzqproduct\nssh-alias:zzqlib\nhost:zzqfam\nhost:zzqfam-chat\nhost:zzqext-kit\nhost:zzqprivate\nword:zzqproduct\n"
	data, n, err := Generate(strings.NewReader(plain), salt, ex)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("excluded %d, want 5", n)
	}
	l, _ := Parse(strings.NewReader(string(data)))
	for _, tok := range []string{"zzqlib", "zzqfam", "zzqfam-chat", "zzqext-kit"} {
		if _, ok := l.Lookup(tok); ok {
			t.Errorf("public name %q still on the list", tok)
		}
	}
	if _, ok := l.Lookup("zzqprivate"); !ok {
		t.Error("private token was dropped")
	}
	// Banned words are never excluded, even when a repo carries the name.
	if !l.LookupWord("zzqproduct") {
		t.Error("word entry lost")
	}
	// zzqproduct, go-zzqlib, zzqlib, zzqfam-chat, zzqfam, zz-x, go-zzqext-kit,
	// zzqext-kit, zzqext; "zz" is too short.
	if len(ex) != 9 {
		t.Fatalf("set size %d: %v", len(ex), ex)
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

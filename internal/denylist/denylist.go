// Package denylist holds a list of forbidden tokens as salted SHA-256 hashes,
// so a public repository can ship the list without disclosing it.
//
// Hash file format (text, one record per line):
//
//	# comment
//	salt <hex>
//	<category> <sha256-hex>
//
// where sha256-hex = SHA-256(salt || token) and token is lowercase.
//
// Limit, stated plainly: a salted hash hides a token from someone reading the
// file, not from someone who can guess it. A short, dictionary-like token can
// be recovered by brute force. The list stops casual disclosure and
// copy-paste, nothing more.
package denylist

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

//go:embed denylist.hashes
var embedded []byte

// MinTokenLen is the shortest token a list may hold. Shorter tokens would
// match inside ordinary words and are trivially brute-forced.
const MinTokenLen = 3

// WordCategory marks entries that are banned words rather than identifiers.
const WordCategory = "word"

// Categories a plaintext list may use.
var categories = map[string]bool{
	"host": true, "ssh-alias": true, "home-user": true,
	"account": true, "email": true, "domain": true, WordCategory: true,
}

var tokenRE = regexp.MustCompile(`^[a-z0-9_.@-]+$`)

// List is a parsed hash file.
type List struct {
	salt    []byte
	entries map[[sha256.Size]byte]string
}

// MinEmbeddedEntries is the fewest tokens the compiled-in list may hold. A list
// that lost its hashes would make every public repo pass the scan silently.
const MinEmbeddedEntries = 20

// Embedded returns the list compiled into the binary and refuses one that is
// suspiciously small.
func Embedded() (*List, error) {
	l, err := Parse(bytes.NewReader(embedded))
	if err != nil {
		return nil, err
	}
	if err := checkMinimum(l); err != nil {
		return nil, err
	}
	return l, nil
}

func checkMinimum(l *List) error {
	if l.Len() < MinEmbeddedEntries {
		return fmt.Errorf("denylist: embedded list holds %d entries, need at least %d", l.Len(), MinEmbeddedEntries)
	}
	return nil
}

// Squash lowercases s and drops everything but ASCII letters and digits. Word
// entries are stored and matched in this form, so "foo-bar", "foo_bar",
// "foo bar", "FooBar" and "foobar" are one entry.
func Squash(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + 32)
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteByte(c)
		}
	}
	return b.String()
}

// LookupWord reports whether a squashed string is a banned word.
func (l *List) LookupWord(squashed string) bool {
	c, ok := l.Lookup(squashed)
	return ok && c == WordCategory
}

// Len reports how many tokens the list holds.
func (l *List) Len() int { return len(l.entries) }

// Salt returns the list's salt.
func (l *List) Salt() []byte { return l.salt }

func hash(salt []byte, token string) [sha256.Size]byte {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(token))
	var out [sha256.Size]byte
	h.Sum(out[:0])
	return out
}

// Lookup reports the category of a lowercase token, if it is on the list.
func (l *List) Lookup(token string) (category string, ok bool) {
	if l == nil || len(l.entries) == 0 {
		return "", false
	}
	category, ok = l.entries[hash(l.salt, token)]
	return category, ok
}

// Parse reads a hash file.
func Parse(r io.Reader) (*List, error) {
	l := &List{entries: map[[sha256.Size]byte]string{}}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 {
			return nil, fmt.Errorf("denylist: line %d: want 2 fields, got %d", n, len(f))
		}
		if f[0] == "salt" {
			s, err := hex.DecodeString(f[1])
			if err != nil || len(s) < 8 {
				return nil, fmt.Errorf("denylist: line %d: bad salt", n)
			}
			l.salt = s
			continue
		}
		sum, err := hex.DecodeString(f[1])
		if err != nil || len(sum) != sha256.Size {
			return nil, fmt.Errorf("denylist: line %d: bad hash", n)
		}
		if !categories[f[0]] {
			return nil, fmt.Errorf("denylist: line %d: unknown category %q", n, f[0])
		}
		var k [sha256.Size]byte
		copy(k[:], sum)
		l.entries[k] = f[0]
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(l.entries) > 0 && l.salt == nil {
		return nil, fmt.Errorf("denylist: hashes without a salt line")
	}
	return l, nil
}

// PublicNames expands the names of public repositories into the set of tokens
// that are public by construction: the name itself, the name without a "go-"
// prefix, and its first hyphen-separated segment (the product family:
// "oxpulse" for "oxpulse-chat"). A denylist token in this set names something
// already published, so it is not personal data. Names are lowercased; segments
// shorter than MinTokenLen are ignored.
func PublicNames(repoNames []string) map[string]bool {
	set := map[string]bool{}
	add := func(t string) {
		if len(t) >= MinTokenLen {
			set[t] = true
		}
	}
	for _, n := range repoNames {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		add(n)
		add(strings.TrimPrefix(n, "go-"))
		first, _, _ := strings.Cut(strings.TrimPrefix(n, "go-"), "-")
		add(first)
	}
	return set
}

// Generate turns a plaintext list ("category:token" per line, '#' comments)
// into a hash file. A non-nil salt is reused so regeneration produces a
// minimal diff; nil draws a fresh random salt. Tokens (outside the "word"
// category) that are in exclude are dropped; the number dropped is returned,
// never the tokens.
func Generate(plain io.Reader, salt []byte, exclude map[string]bool) (data []byte, excluded int, err error) {
	if salt == nil {
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, 0, err
		}
	}
	type rec struct{ cat, sum string }
	seen := map[string]bool{}
	var recs []rec
	sc := bufio.NewScanner(plain)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cat, tok, ok := strings.Cut(line, ":")
		if !ok {
			return nil, 0, fmt.Errorf("plaintext line %d: want category:token", n)
		}
		cat, tok = strings.TrimSpace(cat), strings.TrimSpace(tok)
		if !categories[cat] {
			return nil, 0, fmt.Errorf("plaintext line %d: unknown category %q", n, cat)
		}
		// Reject rather than silently normalise: a token that cannot match
		// would otherwise look like protection and protect nothing.
		if !tokenRE.MatchString(tok) || len(tok) < MinTokenLen {
			return nil, 0, fmt.Errorf("plaintext line %d: token must be lowercase [a-z0-9_.@-], >= %d chars", n, MinTokenLen)
		}
		if cat != WordCategory && exclude[tok] {
			excluded++
			continue
		}
		hashed := tok
		if cat == WordCategory {
			hashed = Squash(tok)
			if len(hashed) < MinTokenLen {
				return nil, 0, fmt.Errorf("plaintext line %d: word needs >= %d letters or digits", n, MinTokenLen)
			}
		}
		sum := hash(salt, hashed)
		key := hex.EncodeToString(sum[:])
		if seen[key] {
			continue
		}
		seen[key] = true
		recs = append(recs, rec{cat, key})
	}
	if err := sc.Err(); err != nil {
		return nil, 0, err
	}
	sort.Slice(recs, func(i, j int) bool {
		if recs[i].cat != recs[j].cat {
			return recs[i].cat < recs[j].cat
		}
		return recs[i].sum < recs[j].sum
	})
	var b bytes.Buffer
	b.WriteString("# Salted SHA-256 hashes of forbidden tokens. Generated by `repo-standards denylist-gen`; do not edit.\n")
	fmt.Fprintf(&b, "salt %s\n", hex.EncodeToString(salt))
	for _, r := range recs {
		fmt.Fprintf(&b, "%s %s\n", r.cat, r.sum)
	}
	return b.Bytes(), excluded, nil
}

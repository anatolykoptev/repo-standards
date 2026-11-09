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

// PublicNameCategory marks a hash-file record that is not a denylist entry:
// the token names a public repository. The scanner keeps matching the token
// wherever it is a real denylist entry, but suppresses the match when the
// token can only mean the repository itself (a github.com/<owner>/<name>
// segment, or the repo's own name in go.mod/package.json/Cargo.toml).
const PublicNameCategory = "public-name"

// PublicDomainCategory marks a hash-file record that is not a denylist
// entry: the hashed value is a public domain name, recorded from a
// "public-domain:<domain>" plaintext line. A denylisted token that is also
// a label of that domain stays on the list, but the scanner suppresses it
// where it can only spell the domain (the leftmost label in DNS order, or
// followed by the domain's tail in reverse-DNS order as in a Java package
// id).
const PublicDomainCategory = "public-domain"

// Categories a plaintext list may use.
var categories = map[string]bool{
	"host": true, "ssh-alias": true, "home-user": true,
	"account": true, "email": true, "domain": true, WordCategory: true,
}

var tokenRE = regexp.MustCompile(`^[a-z0-9_.@-]+$`)

// List is a parsed hash file.
type List struct {
	salt []byte
	// entries maps a token hash to its category; banned words live in words
	// instead so a token can be denylisted and banned at once, and public
	// names and public domains live in their own maps (they are context,
	// not denylist entries).
	entries map[[sha256.Size]byte]string
	words   map[[sha256.Size]byte]bool
	public  map[[sha256.Size]byte]bool
	domains map[[sha256.Size]byte]bool
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
	if l == nil {
		return false
	}
	return l.words[hash(l.salt, squashed)]
}

// Len reports how many tokens the list holds: denylist entries and banned
// words, not public-name records.
func (l *List) Len() int { return len(l.entries) + len(l.words) }

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

// IsPublicName reports whether the lowercase token names a public repository
// recorded at generation time. The scanner suppresses such a token only in
// repository-self references, so a hash file without public-name records
// behaves exactly like an older one.
func (l *List) IsPublicName(token string) bool {
	if l == nil || len(l.public) == 0 {
		return false
	}
	return l.public[hash(l.salt, token)]
}

// IsPublicDomain reports whether the lowercase domain is recorded as a
// public domain. The scanner suppresses a denylisted token only where it
// spells that domain, so a hash file without public-domain records behaves
// exactly like an older one.
func (l *List) IsPublicDomain(domain string) bool {
	if l == nil || len(l.domains) == 0 {
		return false
	}
	return l.domains[hash(l.salt, domain)]
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
		var k [sha256.Size]byte
		copy(k[:], sum)
		switch {
		case f[0] == PublicNameCategory:
			if l.public == nil {
				l.public = map[[sha256.Size]byte]bool{}
			}
			l.public[k] = true
		case f[0] == PublicDomainCategory:
			if l.domains == nil {
				l.domains = map[[sha256.Size]byte]bool{}
			}
			l.domains[k] = true
		case f[0] == WordCategory:
			if l.words == nil {
				l.words = map[[sha256.Size]byte]bool{}
			}
			l.words[k] = true
		case categories[f[0]]:
			l.entries[k] = f[0]
		default:
			return nil, fmt.Errorf("denylist: line %d: unknown category %q", n, f[0])
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if l.Len()+len(l.public)+len(l.domains) > 0 && l.salt == nil {
		return nil, fmt.Errorf("denylist: hashes without a salt line")
	}
	return l, nil
}

// NameForms expands one repository name into the token forms the public-name
// records cover: the name itself, the name without a "go-" prefix, and the
// first hyphen-separated segment of that stripped form (the product family:
// "oxpulse" for "oxpulse-chat"). The name is lowercased; empty input yields
// nil. The scanner compares against the same forms, so this is the single
// source of the derivation.
func NameForms(n string) []string {
	n = strings.ToLower(strings.TrimSpace(n))
	if n == "" {
		return nil
	}
	un := strings.TrimPrefix(n, "go-")
	first, _, _ := strings.Cut(un, "-")
	forms := []string{n}
	if un != n && un != "" {
		forms = append(forms, un)
	}
	if first != un && first != "" {
		forms = append(forms, first)
	}
	return forms
}

// PublicNames expands the names of public repositories into the set of tokens
// that are public by construction (see NameForms). Tokens in this set stay on
// the denylist — they are also recorded as public-name records so the scanner
// can suppress them only where they can mean nothing but the repository
// itself. Segments shorter than MinTokenLen are ignored.
func PublicNames(repoNames []string) map[string]bool {
	set := map[string]bool{}
	for _, n := range repoNames {
		for _, f := range NameForms(n) {
			if len(f) >= MinTokenLen {
				set[f] = true
			}
		}
	}
	return set
}

// validPublicDomain reports whether s has the only form the scanner can
// produce as a public-domain candidate: at least two non-empty labels of
// lowercase letters, digits and hyphens, joined by single dots.
func validPublicDomain(s string) bool {
	if !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Generate turns a plaintext list ("category:token" per line, '#' comments)
// into a hash file. A non-nil salt is reused so regeneration produces a
// minimal diff; nil draws a fresh random salt. Every token in public (the
// PublicNames set) is recorded as a public-name record — it is NOT removed
// from the list: the scanner keeps matching it everywhere except a reference
// that can only mean the repository itself. The number of records written is
// returned, never the names.
func Generate(plain io.Reader, salt []byte, public map[string]bool) (data []byte, publicRecords int, err error) {
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
		if cat == PublicDomainCategory {
			// Reject rather than silently normalise, for the same reason
			// as tokens: a domain the scanner cannot produce would look
			// like protection and protect nothing.
			if !validPublicDomain(tok) {
				return nil, 0, fmt.Errorf("plaintext line %d: public-domain wants >= 2 lowercase [a-z0-9-] labels joined by dots", n)
			}
			sum := hash(salt, tok)
			key := hex.EncodeToString(sum[:])
			if !seen[cat+" "+key] {
				seen[cat+" "+key] = true
				recs = append(recs, rec{cat, key})
			}
			continue
		}
		if !categories[cat] {
			return nil, 0, fmt.Errorf("plaintext line %d: unknown category %q", n, cat)
		}
		// Reject rather than silently normalise: a token that cannot match
		// would otherwise look like protection and protect nothing.
		if !tokenRE.MatchString(tok) || len(tok) < MinTokenLen {
			return nil, 0, fmt.Errorf("plaintext line %d: token must be lowercase [a-z0-9_.@-], >= %d chars", n, MinTokenLen)
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
		// One record per (category, token): the same token can be a denylist
		// entry and a banned word at once.
		if seen[cat+" "+key] {
			continue
		}
		seen[cat+" "+key] = true
		recs = append(recs, rec{cat, key})
	}
	if err := sc.Err(); err != nil {
		return nil, 0, err
	}
	// Public names are appended as their own record kind. A name that cannot
	// take part in a scan (not a token form) is skipped — the same tokens the
	// scanner could never produce.
	pubSeen := map[string]bool{}
	for tok := range public {
		if !tokenRE.MatchString(tok) || len(tok) < MinTokenLen {
			continue
		}
		sum := hash(salt, tok)
		key := hex.EncodeToString(sum[:])
		if pubSeen[key] {
			continue
		}
		pubSeen[key] = true
		recs = append(recs, rec{PublicNameCategory, key})
	}
	publicRecords = len(pubSeen)
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
	return b.Bytes(), publicRecords, nil
}

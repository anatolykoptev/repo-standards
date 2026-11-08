# Denylist

## Files

| File | Where | Content |
|---|---|---|
| plaintext list | outside the repository, `<config dir>/repo-standards/denylist.txt`, mode 0600 | `category:token`, one per line, `#` comments |
| hash list | `internal/denylist/denylist.hashes`, compiled into the binary | salt, one `category hash` line per token, and one `public-name hash` line per public repository name |

`<config dir>` is `$XDG_CONFIG_HOME`, or `~/.config` when that is unset.

Categories: `host`, `ssh-alias`, `home-user`, `account`, `email`, `domain`,
`word`. A `word` entry reports as `pii-banned-word`, every other category as
`pii-denylist`.

Tokens are lowercase, use only `a-z 0-9 _ . @ -`, and are at least three
characters long. Anything else is rejected with a line number (the message never
echoes the token) rather than normalised, because a token that can never match
would look like protection and protect nothing.

## Regenerate

```sh
go run ./cmd/repo-standards denylist-gen
```

Options: `--in FILE` for the plaintext list, `--out FILE` for the hash list,
and one of `--public-repos FILE` (public repository names, one per line) or
`--public-owner NAME` (listed with the gh CLI). Each public name, its form
without a `go-` prefix, and its first hyphen-separated segment is written to
the hash list as a `public-name` record; the command prints how many, never
which. Banned words are never recorded as public names. The
command refuses a plaintext list that group or others can read. It reuses the
salt already in the output file, so regenerating an unchanged list leaves no
diff. Commit the new hash list, never the plaintext.

A denylist token equal to a public repository name **stays on the list** — a
host name or SSH alias that collides with a repo name is still personal data.
The `public-name` records only let the scanner suppress the match where the
token can mean nothing but the repository itself: as the name segment of
`github.com/<owner>/<name>` in a URL or module path, or as the declared name
in the repository's own `go.mod`, `package.json` or `Cargo.toml`. Anywhere
else the token is reported.

## What a salted hash protects

Each entry is SHA-256 of the salt followed by the token. The salt is in the file
and is the same for every entry, so one pass over candidate strings tests all
entries at once.

This stops anyone reading the list in the repository, and stops a search of the
repository or its history for a plain name. It does **not** stop enumeration:
SHA-256 runs at tens of millions of guesses per second per CPU core, so every
token of seven characters or fewer over `[a-z0-9]` is recoverable in minutes on
a laptop, and eight characters in hours; a GPU is about two orders of magnitude
faster. Long, unguessable tokens hold up; short aliases do not. Treat the list
as a guard against accidents and casual reading, not a vault.

Word entries (`word` category) are stored squashed, lowercase letters and digits
only, and matched against runs of up to six pieces of a line split at every
non-alphanumeric character and at CamelCase boundaries. So `foo-bar`,
`foo_bar`, `foo bar`, `FooBar` and `foobar` are one entry. The match is at
piece boundaries: the squashed phrase inside a longer word is not a hit.

## What is deliberately not on the list

An e-mail address that is already in the public commit history of every
published repository (the commit identity) is not personal data in the sense of
this scan, and listing it only produces a finding on every `git log` of every
repository. Do not add the commit identity. Names of public repositories are
not denylist entries either — but when such a name is a real token on the
list, it stays on the list and only its in-context uses are suppressed (see
above).

## Guards against an empty list

The compiled-in list must hold at least `MinEmbeddedEntries` tokens, or every
command refuses to run. `--denylist` pointing at a file with no entries is an
error, and a public scan with an empty list is refused. Regenerating from an
empty plaintext file therefore breaks the build instead of shipping a scanner
that matches nothing.

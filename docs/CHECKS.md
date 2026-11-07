# Checks

Every check runs on the set of tracked files (`git ls-files`). A file that is
ignored or untracked does not count, for or against.

## Required documents

The same list applies to public and private repositories.

| File | Minimum content (bytes, trimmed) |
|---|---|
| README.md | 200 |
| CLAUDE.md | 100 |
| CHANGELOG.md | 30 |
| LICENSE, LICENSE.md or LICENSE.txt | 40 |
| CONTRIBUTING.md | 100 |
| SECURITY.md | 100 |
| CODE_OF_CONDUCT.md | 150 |
| .gitignore | at least one non-comment pattern |
| docs/INDEX.md | 60 |

A missing file is `missing-file`. A file below its minimum, a file that is not a
regular file (a symlink is not followed), or a file with a template placeholder
is `stub-file`. Placeholders are: a TODO or TBD marker as a whole word, the
classic filler paragraph, an unfilled bracketed template field such as the
contact field of the Contributor Covenant, and sentences such as "project
description here". Licence texts and .gitignore skip the placeholder scan.

## docs/INDEX.md

Links are matched by **target**, resolved relative to `docs/`, never by file
name. Two earlier failures shaped this:

- A substring search for the base file name let one row satisfy every file with
  that name (several `README.md` files), and let a mention in prose count as a
  link. A document linked from nowhere passed.
- A shell pipeline that fed `grep -q` under `pipefail` returned random results
  on Linux, because `grep -q` exits on the first match and the writer received
  SIGPIPE. This implementation uses a set lookup.

Recognised forms: inline links, reference definitions, `href` attributes,
`./` and `../` segments, `#fragment` and `?query` suffixes, percent-encoding,
angle-bracket targets, link titles, and root-relative `/docs/x.md`. External
URLs are ignored. Fenced code blocks, inline code spans and HTML comments
(`<!-- ... -->`, also across lines) are removed first, so a path in code or in a
comment is not a link. A comment that is never closed hides the rest of the
document, as in CommonMark. A `<!--` inside code is code, and a fence marker
inside a comment is comment text.

Required targets: every tracked `.md` under `docs/` other than INDEX.md, plus the
root documents (README.md, CLAUDE.md, CHANGELOG.md, CONTRIBUTING.md,
SECURITY.md, CODE_OF_CONDUCT.md and the licence file), plus every tracked
`CLAUDE.md` at any depth (`web/CLAUDE.md`, `crates/CLAUDE.md`, ...). Per-directory
CLAUDE.md files hold subsystem rules, and an agent that starts from the index
must learn they exist. Files under `vendor/` or `node_modules/` are exempt, the
same set the personal-data scan skips. These findings are `index-link`.

### Dead links: `index-dead-link`

Every in-repo link in INDEX.md must resolve, exactly as above, to a tracked file
or to a directory that is a prefix of a tracked file (`../src/` is fine). A row
for a moved or deleted file reads as true and sends the agent to nothing. The
finding carries the INDEX line number. The `#fragment` is not validated. A link
that climbs above the repository root (`../../x` from docs/, `/../x`,
`%2e%2e/%2e%2e/x`) is not a tracked file and no host resolves it, so it is dead
too, reported as "leaves the repository". A miscounted `../` is the likeliest typo.

## CLAUDE.md: `claude-index`

The root CLAUDE.md must link `docs/INDEX.md`, resolved from the repository root
with the same parser (`./docs/INDEX.md`, `docs/INDEX.md#x` and `/docs/INDEX.md`
pass). A mention in a code span or fenced block does not count. This closes the
chain CLAUDE.md, INDEX, every document for an agent that starts at CLAUDE.md,
which Claude Code always loads. A missing CLAUDE.md is only a `missing-file`.

## Licence

The text is recognised by signature phrases; the family is read from the header
because licence titles also appear inside other licences as cross-references.

- Public: Apache-2.0, MIT, BSD-2/3-Clause, MPL-2.0, ISC, the GPL family
  (GPL, LGPL, AGPL), EPL and the Unlicense pass. A source-available licence
  (Commons Clause, BSL, PolyForm, Elastic, SSPL, FSL, non-commercial terms), a
  proprietary notice or unrecognised text is a finding.
- Private: only a proprietary notice passes,
  `Copyright (c) <year or range> <holder>. All rights reserved.` An OSI licence
  in a private repository is a finding.

## Personal data (public repositories only)

Scanned: the **name** of every tracked file, the target of every tracked
symlink (the scan never follows it), and the **content** of every tracked
regular file, of any size, streamed line by line. Gitlink (submodule) paths are
names too. Excluded: anything under a `vendor/` or `node_modules/` directory and
lockfiles.

Binary files (a NUL byte in the first 8 KiB) are not read, but they are counted:
the run ends with `skipped N binary files`. Their names are still scanned.

- `pii-home-path`: `/home/<name>` or `/Users/<name>` at the start of a path (not
  inside a URL or a longer path), `file:///home/<name>`, WSL `/mnt/c/Users/<name>`
  and `C:\Users\<name>`. Generic and service names (`user`, `runner`, `ubuntu`,
  `node`, `postgres`, `x`, ...) pass, and so does a path that is the value of an
  `href`, `src`, `action`, `url(` or a markdown link target (a site URL). File
  names are not tested for this rule.
- `pii-denylist`: every maximal run of letters, digits and `_ - . @` is
  lowercased, and the run plus each contiguous sub-sequence of up to six of its
  pieces is hashed and looked up. A host inside a URL and a domain inside an
  e-mail address are found; a word that merely contains a token is not.
- `pii-banned-word`: see [DENYLIST.md](DENYLIST.md) for the separator and
  CamelCase variants.
- `pii-suppression`: a suppression marker without a reason.

Findings carry the file, the line and the category only.

### Suppressing a line

A line containing `repo-standards: ignore <reason>` (anywhere on the line, for
example in a comment) is not reported; the marker must be followed by a reason of
at least three characters, otherwise it is itself a finding and suppresses
nothing. The run reports how many findings were suppressed.

### History

`check --history` runs the same rules over `git log -p --all --format=fuller`.
It exists because a value committed and later deleted is invisible to a work-tree
scan but not to anyone who clones.

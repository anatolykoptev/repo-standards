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
| LICENSE, LICENSE.md, LICENSE.txt, or a dual-licence layout (LICENSE-MIT, LICENSE-APACHE, LICENSE-APACHE-2.0, LICENSE.MIT, LICENSE.APACHE) | 40 |
| CONTRIBUTING.md | 100 |
| SECURITY.md | 100 |
| CODE_OF_CONDUCT.md | 150 |
| .gitignore | at least one non-comment pattern |
| docs/INDEX.md | 60 |
| .github/pull_request_template.md, .github/PULL_REQUEST_TEMPLATE.md, pull_request_template.md, PULL_REQUEST_TEMPLATE.md, docs/pull_request_template.md or docs/PULL_REQUEST_TEMPLATE.md, or a `.md` file directly inside .github/PULL_REQUEST_TEMPLATE/ | 30 |
| a `.yml`, `.yaml` or `.md` issue template other than config.yml directly inside .github/ISSUE_TEMPLATE/, or a legacy ISSUE_TEMPLATE.md, .github/ISSUE_TEMPLATE.md or docs/ISSUE_TEMPLATE.md | 30 |

The issue-template directory is satisfied by a file directly inside it; a
config.yml or config.yaml is the chooser configuration, not a template, and
files in subdirectories do not count. The pull-request directory follows the
same shape: only `.md` files directly inside `.github/PULL_REQUEST_TEMPLATE/`
count.

A missing file is `missing-file`. A file below its minimum, a file that is not a
regular file (a symlink is not followed), or a file with a template placeholder
is `stub-file`. Placeholders are: a TODO or TBD marker as a whole word, the
classic filler paragraph, an unfilled bracketed template field such as the
contact field of the Contributor Covenant, and sentences such as "project
description here". Licence texts, .gitignore and issue templates skip the
placeholder scan (an issue template is itself fill-in scaffolding).

## docs/INDEX.md

Links are matched by **target**, resolved relative to `docs/`, never by file
name. Two earlier failures shaped this:

- A substring search for the base file name let one row satisfy every file with
  that name (several `README.md` files), and let a mention in prose count as a
  link. A document linked from nowhere passed.
- A shell pipeline that fed `grep -q` under `pipefail` returned random results
  on Linux, because `grep -q` exits on the first match and the writer received
  SIGPIPE. This implementation uses a set lookup.

Recognised forms: inline links (bare or angle-bracket targets with balanced
parentheses, optional titles), reference definitions, `href` attributes,
Claude Code `@path` imports (an `@` at a word start in the root CLAUDE.md only, for
the `claude-index` check; elsewhere `@types/node` is text), `./` and `../` segments, `#fragment` and
`?query` suffixes, percent-encoding, and root-relative `/docs/x.md`. External
URLs are ignored, and a footnote definition (`[^x]: ...`) is not a link.
Fenced code blocks, inline code spans and HTML comments are removed first, so
a path in code or in a comment is not a link: a fence closes only on the same
character in a run at least as long as the opener with no info string, a
comment runs from `<!--` to `-->` even across lines, and spans and comments
are scanned left to right so the leftmost opener wins. A `<!--` at line-start
position that is never closed hides the rest of the document, as in
CommonMark; a `<!--` after text is an inline comment only when its `-->` comes
before the next blank line, otherwise it stays visible text. A code span closes
only on a backtick run of the same length. A link destination or title never
crosses a blank line and nests parentheses at most 32 deep, so the scan is
linear in the document size.

Required targets: every tracked `.md` under `docs/` other than INDEX.md, plus the
root documents (README.md, CLAUDE.md, CHANGELOG.md, CONTRIBUTING.md,
SECURITY.md, CODE_OF_CONDUCT.md and the licence file), plus every tracked
`CLAUDE.md` at any depth (`web/CLAUDE.md`, `crates/CLAUDE.md`, ...). Per-directory
CLAUDE.md files hold subsystem rules, and an agent that starts from the index
must learn they exist. Files under `vendor/`, `node_modules/`, `testdata/` or
`third_party/` are exempt from this rule (wider than the personal-data scan, which
skips only `vendor/` and `node_modules/`). These findings are `index-link`.

`repo-standards index` repairs them: it appends one row per unindexed
document to docs/INDEX.md, or generates the whole index when the file is
missing. Existing rows are never rewritten or reordered; `--dry-run` reports
what would be appended.

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
pass). Claude Code's import form `@docs/INDEX.md` counts too: an import pulls
the file in, so the chain is complete. A mention in a code span or fenced
block does not count. This closes the
chain CLAUDE.md, INDEX, every document for an agent that starts at CLAUDE.md,
which Claude Code always loads. A missing CLAUDE.md is only a `missing-file`.

## Licence

The text is recognised by signature phrases; the family is read from the header
because licence titles also appear inside other licences as cross-references.
The owner decides the licence; the check requires a recognised one.

- Public and private accept the same set: an OSI-approved licence
  (Apache-2.0, MIT, BSD-2/3-Clause, MPL-2.0, ISC, the GPL family — GPL, LGPL,
  AGPL — EPL or the Unlicense), a recognised source-available licence —
  PolyForm (Noncommercial, Small Business, Shield, Internal Use, Free Trial,
  Perimeter or Strict), the Functional Source License (FSL-1.1-MIT or
  FSL-1.1-ALv2, whose title may read "Apache 2.0 Future License") or the Business Source License 1.1 — or a proprietary notice,
  `Copyright (c) <year or range> <holder>. All rights reserved.` A private
  repository may carry the licence it will be published under.
- A non-commercial rider ("provided the use is noncommercial only") on an
  MIT, Apache, BSD or MPL text makes it non-OSI; the GPL family is exempt
  because its canonical texts contain the word.
- A dual-licence layout satisfies the LICENSE requirement; every licence file
  present is classified and each one must pass.
- Still a finding at either visibility: a missing LICENSE, unrecognised text,
  or a restricted licence outside the recognised set (Commons Clause, an
  unlisted PolyForm variant, another BSL version, Elastic, SSPL, Sustainable
  Use or other non-commercial terms).

Each source-available licence is matched by a distinctive phrase from its
canonical text; the sources are recorded in `internal/check/license.go`. The
match runs before the OSI phrases because the FSL embeds an MIT or Apache
grant.

## Personal data (public repositories only)

Scanned: the **name** of every tracked file, the target of every tracked
symlink (the scan never follows it), and the **content** of every tracked
regular file, of any size, streamed line by line. Gitlink (submodule) paths are
names too. Excluded: anything under a `vendor/` or `node_modules/` directory and
lockfiles. `testdata/` and `third_party/` are scanned.

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

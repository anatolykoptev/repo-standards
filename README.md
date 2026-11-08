# repo-standards

A dependency-free command that checks a repository against a fixed set of
standard project documents and, for public repositories, scans tracked files
for personal data. It prints one line per finding and exits 1 if there is any.

Every repository, private or public, must carry the same documents. That is the
project-maturity bar this tool enforces.

## What it checks

| Check id | Rule |
|---|---|
| `missing-file` | README.md, CLAUDE.md, CHANGELOG.md, LICENSE (or LICENSE.md / LICENSE.txt), CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md, .gitignore, docs/INDEX.md, a pull-request template and at least one issue template under .github/ exist as tracked files |
| `stub-file` | Each is above a minimum size and carries no template placeholder |
| `index-link` | docs/INDEX.md links, by link target, every tracked `.md` under `docs/`, every root document and every nested `CLAUDE.md` (outside `vendor/`, `node_modules/`, `testdata/` and `third_party/`) |
| `index-dead-link` | An in-repo link in docs/INDEX.md points at nothing: not a tracked file, not a directory holding one |
| `claude-index` | The root CLAUDE.md links docs/INDEX.md — a `[text](docs/INDEX.md)` link or an `@docs/INDEX.md` import — so an agent that starts at CLAUDE.md reaches every document |
| `license` | An OSI-approved licence, a recognised source-available licence (PolyForm, FSL-1.1, BSL-1.1) or a proprietary notice, `Copyright (c) <year> <holder>. All rights reserved.` — the same set at either visibility |
| `pii-denylist` | Public only: a token from the hashed denylist appears in a tracked file |
| `pii-home-path` | Public only: an absolute home directory path appears in a tracked file |
| `pii-banned-word` | Public only: a word banned in public repositories appears in a tracked file |

Details, thresholds and the matching rules are in [docs/CHECKS.md](docs/CHECKS.md).

Personal-data findings print `file:line` and a category, never the matched value.

## Run it

```sh
go run github.com/anatolykoptev/repo-standards/cmd/repo-standards@latest check --visibility public .
```

`--visibility` is `public` or `private`; `--detected` is the visibility the
environment reports and wins over it (a less strict `--visibility` is an error).
With neither the rule set is `public`, the strictest. The path defaults to the current directory. Only files tracked by git
are examined; outside a git work tree every file is.

`check --history` scans the text of `git log -p --all` instead of the work tree:
commit metadata, messages and every added or removed line, so a value committed
and later deleted is still found.

Exit codes: 0 clean, 1 findings, 2 usage or I/O error, 3 internal error.
The run ends with `skipped N binary files, suppressed M finding(s)` on stderr.

## Scaffold the documents

`init` writes the boilerplate the check requires — the code of conduct, the
security policy, the licence, the issue and pull-request templates and
docs/INDEX.md — where each is missing, and never touches a file that exists.
It then lists the required documents that remain for a human: README.md,
CLAUDE.md, CONTRIBUTING.md, CHANGELOG.md and .gitignore are never written,
because they must come from the project's real code and history.

```sh
repo-standards init --visibility public --license apache-2.0 --repo OWNER/NAME .
```

The visibility flags are the same as `check`'s. A public repository takes
`--license apache-2.0` or `--license mit` (choosing a licence is the owner's
decision; without one LICENSE is skipped, not guessed) and resolves
OWNER/NAME for the security-advisory links from `--repo` or the origin
remote. A private repository takes `--holder` for the proprietary LICENCE.
`--dry-run` reports what would be created and writes nothing.

A repository that already has issue templates — a file under
`.github/ISSUE_TEMPLATE/` or a legacy `ISSUE_TEMPLATE.md` — keeps them:
init never replaces the issue intake. The accepted spellings for every
generated file are the check's own list, so init never reports `kept` for a
file the check would reject.

`repo-standards index` maintains the generated index afterwards: it appends
a docs/INDEX.md row for every tracked document the `index-link` rule reports
as unindexed, without rewriting or reordering existing rows. Run it after
adding the documents init leaves for a human — init says so itself.

```sh
repo-standards index .
```

## Use it in CI

The check is a composite action. Add it as a step in your own job, so you choose
the runner: a hosted ARM runner for a public repository, a self-hosted one for a
private repository. The repository is public so that any repository can use it.
Pin a release tag, never a branch; the action builds the tool from the very
checkout the tag names, so the version that runs is the version you pinned.

```yaml
# .github/workflows/repo-standards.yml
name: repo-standards
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  standards:
    runs-on: ubuntu-24.04-arm   # a private repository: its self-hosted runner label
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
      - uses: anatolykoptev/repo-standards@v0.1.0
```

Visibility is read from the event (`github.event.repository.private`), so a
repository that changes visibility is checked by the right rules without an edit.
The optional input `visibility` overrides it, and an override that is less strict
than the real visibility fails the run. Set `history: true` (with
`fetch-depth: 0` on checkout) to also scan the text of `git log -p --all`.

The action needs Go to be installable on the runner (`actions/setup-go`). It sets
`GOWORK=off`, so a `go.work` in the caller does not interfere.

## The denylist

The personal-data scan compares tokens from the files with a list of forbidden
tokens (hostnames, SSH aliases, user names, account names, e-mail addresses and
banned words). The list ships only as salted SHA-256 hashes in
`internal/denylist/denylist.hashes`, so the public repository does not disclose
it. The plaintext lives outside the repository, in a file readable only by its
owner, and `repo-standards denylist-gen` regenerates the hashes from it. See
[docs/DENYLIST.md](docs/DENYLIST.md), including what a salted hash does and does
not protect.

## Develop

```sh
go vet ./... && go test ./...
```

Standard library only; no dependencies to install. The repository must pass its
own check: `go run ./cmd/repo-standards check --visibility public .`.

## Licence

Apache-2.0, see [LICENSE](LICENSE).

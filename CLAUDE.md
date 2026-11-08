# repo-standards: notes for agents

Standard-library-only Go command. Layout: `cmd/repo-standards` (flags, exit
codes), `internal/check` (one file per check), `internal/denylist` (hash
list), `internal/initfiles` (the `init` scaffold: embedded templates and the
docs/INDEX.md generator).

Commands: `go vet ./... && go test ./...`, then
`go run ./cmd/repo-standards check --visibility public .`. The repository must
pass its own check, and `cmd/repo-standards` has a test that enforces it, so new
docs must be `git add`ed before the tests can pass.

Rules that are easy to break:

- This repository is public. No hostnames, operator paths, account names, tokens
  or personal data in any tracked file, tests and fixtures included. Test
  fixtures are built at run time from invented words.
- Never print a matched personal-data value, in output, errors or tests.
- The plaintext denylist is never committed. Only `denylist.hashes` is.
- The commit identity is public and is not on the denylist. Before the first
  push of a repository run `check --history`.
- Index links are matched by target, not by file name.
- Add a dependency only with a written reason; the tool is meant to run
  anywhere with a bare Go toolchain.
- Commits use Conventional Commits; release-please builds the changelog.

Every document is indexed in [docs/INDEX.md](docs/INDEX.md).

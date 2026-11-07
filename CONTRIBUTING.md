# Contributing

Open an issue before a large change. For a small one, send a pull request.

1. Keep a change to one concern and under about 200 lines where you can.
2. Run `go vet ./... && go test ./...` and
   `go run ./cmd/repo-standards check --visibility public .` before pushing.
3. A new rule needs a test that fails when the rule is removed.
4. Use Conventional Commits (`feat:`, `fix:`, `docs:`); release-please reads them.
5. Do not add a dependency without saying why the standard library is not enough.

Never put hostnames, local paths, account names or other personal data in a
commit, an issue or a test fixture.

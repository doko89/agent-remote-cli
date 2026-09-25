# Repository Guidelines

## Project Structure & Module Organization

This is a Go CLI (`agent-remote`) that wraps SSH and WinRM behind a uniform interface, built with Clean Architecture.

- `main.go` — composition root; the only file importing all infrastructure packages.
- `internal/domain/` — core entities, errors, and pure business types.
- `internal/usecase/` — application logic; depends on interfaces (ports), not concrete clients.
- `internal/adapter/cli/` — command parsing and flag handling.
- `internal/adapter/presenter/` — output formatting (JSON, raw text).
- `internal/infrastructure/` — protocol clients (`sshclient`, `winrmclient`), config store, and secret resolution.
- `bin/` — local build output.
- `PRD.md` — product requirements; `README.md` — usage documentation.

Tests live beside source files as `*_test.go`.

## Build, Test, and Development Commands

```sh
go build -o agent-remote .   # compile the CLI binary
go test ./...                # run all tests
go vet ./...                 # static analysis (must be clean)
gofmt -l .                   # list files needing formatting (empty = clean)
```

No Makefile is configured; run commands directly.

## Coding Style & Naming Conventions

- Format with `gofmt` (tabs, standard Go style). CI enforces it.
- Use standard Go naming: exported `PascalCase`, unexported `camelCase`.
- Keep `main.go` as the sole wiring point; use cases never import concrete infrastructure types.
- Errors follow the domain error pattern (`domain.Fail` with a code constant).
- Avoid `interface{}` as an escape hatch; use typed parameters and generics where appropriate.

## Testing Guidelines

- Use Go's standard `testing` package. No external test framework is configured.
- Name test functions `Test<Subject>_<Behavior>` (e.g., `TestCp_RecursiveSSH`).
- Cover empty input, boundary values, error paths, and concurrency.
- Run `go test ./...` before every commit. All tests must pass.

## Commit & Pull Request Guidelines

Commit messages follow Conventional Commits style observed in history:

```
feat: remote cp ([host:]path, recursive, SSH SFTP + WinRM chunked)
fix: resolve SonarQube complexity and param-count issues
ci: release workflow for linux amd64/arm64 + windows (tar.gz)
```

Pull requests should include a clear description and motivation, reference linked issues, pass `gofmt` / `go vet` / `go test` locally, and stay focused on one concern.

## Security & Configuration Tips

- Never hardcode secrets or passwords. Secrets resolve via OS keyring, env var references, or stdin at runtime.
- Config files are written with `0600` permissions and never contain secret values.
- Use `--password-stdin` or `--auth-ref VAR` patterns; never pass secrets as CLI flags.

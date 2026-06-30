# Contributing

Issues and merge requests welcome. Major changes should be discussed in an issue first.

## Setup

```bash
git clone https://github.com/verophi/verophi.git
cd verophi
mise install
make build
make test
```

## Before submitting

```bash
make test
make lint
make build
```

All three must pass.

## Tests

New `.go` files need a `_test.go` (except `cmd/`, `version/`, `logging/`). Coverage target is 80%+.

## Commits

Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`.

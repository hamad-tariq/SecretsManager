# Contributing

Thanks for considering a contribution! Bug reports, docs fixes, tests, reviews of the cryptography and new features are all welcome.

> [!IMPORTANT]
> Security problems go through [SECURITY.md](SECURITY.md), **not** public issues or pull requests.

## Ways to help

- **Try it and report what breaks:** `scripts/try-local.sh` starts a local 3-node cluster in about a minute.
- **Review the security-critical code:** `internal/barrier`, `internal/crypto`, `internal/pki`, `internal/api` (authentication and policy checks). Fresh eyes are the most valuable contribution right now.
- **Improve the docs:** if something confused you, it will confuse others.
- **Pick an issue** labelled `good first issue` or `help wanted`.
- **Propose features:** open an issue first to discuss the design. The project deliberately stays small, so a "no" is about scope, not about your idea.

## Development setup

You need:

- Go (the exact version in `go.mod`), and
- Python 3.11+ for the SDK and Sentinel tests.

Linux, macOS or Windows (Git Bash or WSL for the shell scripts).

```sh
sh scripts/check.sh           # gofmt, vet, staticcheck, gosec, govulncheck, Go and Python tests
RACE=1 sh scripts/check.sh    # the same with the race detector (needs a C compiler)
```

Dev tools (staticcheck, gosec, govulncheck) are pinned in `tools/go.mod`, separate from the product's dependencies. Run one with `go tool -modfile=tools/go.mod <name>`.

Tests against real databases are skipped unless you point them at one:

```sh
SM_TEST_POSTGRES='postgres://admin:pw@localhost:5432/app' go test ./internal/rotation/ ./internal/lease/
SM_TEST_MYSQL='admin:pw@tcp(localhost:3306)/' go test ./internal/rotation/ ./internal/lease/
```

### Documentation site

The docs at https://hamad-tariq.github.io/SecretsManager/ are built from `docs/` with MkDocs Material and published by `.github/workflows/docs.yml`:

```sh
pip install -r requirements-docs.txt
mkdocs serve                  # http://127.0.0.1:8000 with live reload
mkdocs build --strict         # what CI runs: broken links and anchors fail the build
```

## Project layout

| Path | What |
|---|---|
| `cmd/smd` | the server node |
| `cmd/smctl` | operator CLI |
| `cmd/sm-agent` | sidecar / init container that logs in, renews certificates and writes secrets to files |
| `internal/` | everything else: `barrier` (encryption, seal/unseal), `crypto` (AEAD, Shamir), `pki`, `cluster` (Raft), `api`, `kv`, `policy`, `audit`, `rotation`, `lease`, `snapshot`, `metrics`, `agent`, `secret` |
| `sdk/python` | Python client (standard library only) |
| `sentinel/` | anomaly alerts from the audit log (standard library only) |
| `docs/` | the documentation site (MkDocs): guides, reference, threat model, runbooks, production checklist |
| `IMPLEMENTATION_PLAN.md` | design, iteration history and review findings |

## Rules for code

- **Hold sensitive bytes in `secret.Secret`** (`internal/secret`). It prints `[REDACTED]` in fmt, slog and JSON. Call `Reveal()` only where the value must go over the wire or into crypto.
- **Randomness comes from `crypto/rand` only.** gosec fails the build on `math/rand`.
- **No new third-party services.** The product must run with nothing outside your own infrastructure. New libraries must be open source, license-compatible with Apache-2.0, and justified in the pull request.
- **Every change that touches security leaves a test behind** that fails without the change.
- **Update `docs/threat-model.md`** when you add an attack surface.
- Keep it small: a few clear lines beat an abstraction. Match the style of the code around your change.

## Pull requests

1. Fork, and branch from `main`.
2. Make the change with tests; run `sh scripts/check.sh`.
3. Describe **what** changed and **why**, and link the issue.
4. One logical change per pull request makes review faster.

CI runs the same `scripts/check.sh`. A maintainer reviews every pull request; security-sensitive ones may take longer.

## Licensing of contributions

This project is licensed under [Apache-2.0](LICENSE). Under section 5 of that license, anything you intentionally submit for inclusion is licensed under Apache-2.0 too, with no additional terms. By opening a pull request you confirm that:

- you wrote the contribution, or have the right to submit it under Apache-2.0;
- if your employer has rights to your work, they allow the contribution;
- it contains no code copied from sources with incompatible licenses.

The exception is `internal/crypto/shamir/shamir.go`, which is MPL-2.0 (see [NOTICE](NOTICE)). Changes to that file are contributed under MPL-2.0.

## Code of conduct

Everyone taking part agrees to the [Code of Conduct](CODE_OF_CONDUCT.md).

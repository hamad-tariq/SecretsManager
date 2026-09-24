# Contributing

Contributions of every kind are welcome. The most valuable right now:

- **Review the security-critical code**: `internal/barrier`, `internal/crypto`, `internal/pki`, and `internal/api` (authentication and policy checks).
- **Try it and report what breaks**, starting from the [quick start](../getting-started/quickstart.md).
- **Improve these docs**. Every page has an edit button (:material-file-edit-outline:) that opens it on GitHub.
- **Add tests**, especially fuzzing and failure injection.

!!! important "Security issues"
    Report vulnerabilities privately, never in public issues or pull requests. See the [security policy](security.md).

## Development setup

```bash
git clone https://github.com/hamad-tariq/SecretsManager.git
cd SecretsManager
sh scripts/check.sh           # gofmt, vet, staticcheck, gosec, govulncheck, Go + Python tests
RACE=1 sh scripts/check.sh    # with the race detector (needs a C compiler)
```

To work on these docs:

```bash
pip install -r requirements-docs.txt
mkdocs serve                  # http://127.0.0.1:8000, live reload
mkdocs build --strict         # what CI runs: fails on broken links
```

## Ground rules

- **No third-party services.** The product must run with nothing outside your own infrastructure. New libraries must be open source, compatible with Apache-2.0, and justified.
- **Security changes come with a test** that fails without the change.
- **Sensitive bytes go in `secret.Secret`**, which never prints itself; randomness comes from `crypto/rand` only.
- **Keep it small.** A few clear lines beat an abstraction.

The full guide, including the project layout, pull request process and how contributions are licensed, is in [CONTRIBUTING.md](https://github.com/hamad-tariq/SecretsManager/blob/main/CONTRIBUTING.md). Everyone taking part follows the [Code of Conduct](https://github.com/hamad-tariq/SecretsManager/blob/main/CODE_OF_CONDUCT.md).

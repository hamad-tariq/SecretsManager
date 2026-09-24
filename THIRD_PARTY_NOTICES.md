# Third-party notices

The `smd`, `smctl` and `sm-agent` binaries are built from this repository plus the Go modules below, used unmodified at the versions pinned in `go.sum`. Each module's full license text is in its source, at the link given.

The Python SDK (`sdk/python`) and Sentinel (`sentinel/`) use only the Python standard library.

Development tools pinned in `tools/go.mod` (staticcheck, gosec, govulncheck) are used only to check the code. They are not part of any binary and are not listed here.

## Modules compiled into the binaries

| Module | Version | License | Source |
|---|---|---|---|
| filippo.io/age | v1.3.2 | BSD-3-Clause | https://github.com/FiloSottile/age |
| filippo.io/edwards25519 | v1.2.0 | BSD-3-Clause | https://github.com/FiloSottile/edwards25519 |
| filippo.io/hpke | v0.4.0 | BSD-3-Clause | https://github.com/FiloSottile/hpke |
| github.com/awnumar/memcall | v0.4.0 | Apache-2.0 | https://github.com/awnumar/memcall |
| github.com/awnumar/memguard | v0.23.0 | Apache-2.0 | https://github.com/awnumar/memguard |
| github.com/boltdb/bolt | v1.3.1 | MIT | https://github.com/boltdb/bolt |
| github.com/fatih/color | v1.19.0 | MIT | https://github.com/fatih/color |
| github.com/go-sql-driver/mysql | v1.10.1 | **MPL-2.0** | https://github.com/go-sql-driver/mysql |
| github.com/hashicorp/go-hclog | v1.6.3 | MIT | https://github.com/hashicorp/go-hclog |
| github.com/hashicorp/go-immutable-radix | v1.3.1 | **MPL-2.0** | https://github.com/hashicorp/go-immutable-radix |
| github.com/hashicorp/go-metrics | v0.7.0 | MIT | https://github.com/hashicorp/go-metrics |
| github.com/hashicorp/go-msgpack/v2 | v2.1.5 | MIT | https://github.com/hashicorp/go-msgpack |
| github.com/hashicorp/golang-lru | v1.0.2 | **MPL-2.0** | https://github.com/hashicorp/golang-lru |
| github.com/hashicorp/raft | v1.8.0 | **MPL-2.0** | https://github.com/hashicorp/raft |
| github.com/hashicorp/raft-boltdb/v2 | v2.4.2 | **MPL-2.0** | https://github.com/hashicorp/raft-boltdb |
| github.com/jackc/pgpassfile | v1.0.0 | MIT | https://github.com/jackc/pgpassfile |
| github.com/jackc/pgservicefile | v0.0.0-20240606120523-5a60cdf6a761 | MIT | https://github.com/jackc/pgservicefile |
| github.com/jackc/pgx/v5 | v5.11.0 | MIT | https://github.com/jackc/pgx |
| github.com/mattn/go-colorable | v0.1.15 | MIT | https://github.com/mattn/go-colorable |
| github.com/mattn/go-isatty | v0.0.24 | MIT | https://github.com/mattn/go-isatty |
| go.etcd.io/bbolt | v1.4.1 | MIT | https://github.com/etcd-io/bbolt |
| golang.org/x/crypto | v0.57.0 | BSD-3-Clause | https://go.googlesource.com/crypto |
| golang.org/x/sys | v0.48.0 | BSD-3-Clause | https://go.googlesource.com/sys |
| golang.org/x/term | v0.46.0 | BSD-3-Clause | https://go.googlesource.com/term |
| golang.org/x/text | v0.42.0 | BSD-3-Clause | https://go.googlesource.com/text |
| golang.org/x/time | v0.16.0 | BSD-3-Clause | https://go.googlesource.com/time |

The Go standard library and runtime (BSD-3-Clause, https://go.dev/LICENSE) are also compiled in.

## What the MPL-2.0 modules require

Those modules are used as they are, and never modified. MPL-2.0 is file-level copyleft. Anyone distributing binaries that contain them must tell recipients where to get the source of those MPL-2.0 files; the links above do that. Anyone who changes an MPL-2.0 file must publish that change under MPL-2.0. Your own code built alongside them is not affected.

`internal/crypto/shamir/shamir.go` in this repository is also MPL-2.0; see `NOTICE`.

## Regenerating this list

After changing dependencies:

```sh
go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}}{{end}}{{end}}' ./cmd/... | sort -u
```

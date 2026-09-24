# Configuration

There are no configuration files. Every component is configured with command-line flags, and the clients also accept environment variables.

## smd

| Flag | Default | Description |
|---|---|---|
| `-id` | *(required)* | Node ID; must match the certificate (`spiffe://sm/node/<id>`) |
| `-data` | *(required)* | Data directory (Raft state, snapshots, `audit.log`) |
| `-api-addr` | *(required)* | HTTPS API `host:port` |
| `-raft-addr` | *(required)* | Raft `host:port` |
| `-rpc-addr` | *(required)* | Cluster RPC `host:port` |
| `-cert` | *(required)* | Node certificate PEM (leaf, then intermediates) |
| `-key` | *(required)* | Node private key PEM |
| `-ca` | *(required)* | Root CA PEM |
| `-bootstrap` | `false` | Form a new cluster (first node, first start) |
| `-join` | | RPC address of an existing member (new node, first start) |
| `-audit-forward` | | Syslog-over-TLS collector `host:port` |
| `-audit-forward-ca` | value of `-ca` | CA for the collector's certificate |
| `-audit-forward-max-lag` | `67108864` | Bytes waiting to be forwarded before requests fail |
| `-max-cert-lineage` | `720h` | How long service certificates can keep renewing after the last full login |
| `-rotation-check` | `10s` | Leader's interval for due rotations and expired leases |
| `-version` | | Print the version and exit |

## smctl

| Flag | Environment | Description |
|---|---|---|
| `-addr` | `SM_ADDR` | Node API addresses, comma-separated |
| `-cert` | `SM_CERT` | Admin certificate PEM |
| `-key` | `SM_KEY` | Admin private key PEM |
| `-ca` | `SM_CA` | Root CA PEM |
| `-version` | | Print the version and exit |

Command flags are listed in [smctl (CLI)](../components/smctl.md).

## sm-agent

| Flag | Environment | Default | Description |
|---|---|---|---|
| `-addr` | `SM_ADDR` | | Node API addresses, comma-separated |
| `-ca` | `SM_CA` | | Root CA PEM |
| `-out` | | `/run/secrets/sm` | Output directory (use tmpfs) |
| `-auth` | | `kubernetes` | `token` or `kubernetes` |
| `-token-file` | | | Enrollment token file |
| `-jwt-file` | | `/var/run/secrets/sm/token` | Projected service-account token |
| `-secret` | | | `kvpath=file`, repeatable |
| `-db` | | | `role=file`, repeatable |
| `-refresh` | | `5m` | Secret re-fetch interval |
| `-once` | | `false` | Log in, write files, exit |
| `-version` | | | Print the version and exit |

## Python SDK

`Client(addrs, cert, key, ca, *, ttl=300.0, max_stale=3600.0, timeout=10.0, background=True)`. The SDK reads no environment variables itself. A common convention (used in the Kubernetes example) is:

```python
Client.from_agent_dir(os.environ["SM_ADDR"].split(","), os.environ["SM_AGENT_DIR"])
```

## Sentinel

Command-line options: `watch|replay FILE… [--config FILE] [--alerts FILE] [--state FILE] [--webhook URL] [--webhook-format alertmanager|text|json] [--webhook-ca FILE] [--quiet]`.

The JSON config keys are listed in [Sentinel](../components/sentinel.md#configuration).

## Build-time settings

| Setting | Where | Description |
|---|---|---|
| `main.version` | `-ldflags "-X main.version=v0.1.0"` | Version printed by `-version` (set by `scripts/release.sh`; `dev` otherwise) |
| `GOTOOLCHAIN=local` | `scripts/release.sh` | Refuse to download a different Go toolchain |
| `RACE=1` | `scripts/check.sh` | Run the tests with the race detector |
| `SM_TEST_POSTGRES`, `SM_TEST_MYSQL` | `go test` | Admin connection strings for the real-database tests |
| `PYTHON` | `scripts/check.sh` | Python interpreter for the SDK and Sentinel tests |
| `GOVULNDB` | `scripts/check.sh` | Point govulncheck at a local mirror for offline CI |

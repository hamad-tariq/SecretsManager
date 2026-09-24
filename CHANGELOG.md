# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/). Until 1.0, minor versions may contain breaking changes; they are called out under **Changed**.

## [Unreleased]

## [0.1.0] - first public release

First open-source release. Experimental: not independently audited (see [SECURITY.md](SECURITY.md)).

### Added

- **Server (`smd`):** 3-node Raft cluster with leader election and request forwarding; mTLS (TLS 1.3) on every connection, Raft included.
- **Encryption at rest:** every stored value is encrypted by the barrier (XChaCha20-Poly1305, authenticated against its storage path, so values cannot be swapped between paths), with keyring rotation.
- **Shamir unseal:** init splits the unseal key into N shares with threshold M (default 5 of 3); shares can be encrypted to each holder's `age` key. Also seal-now, rekey (new shares), and encryption-key rotation.
- **Identities from certificates:** an internal CA (offline root, intermediate in the cluster); service certificates last 24 h and renew automatically.
- **Policies:** path-glob rules, deny by default, explicit deny wins, `create` separate from `update`.
- **Versioned key/value secrets:** `current`, `previous` and `pending` labels, a 7-day soft-delete recovery window, and check-and-set writes.
- **Logins:** single-use enrollment tokens, and Kubernetes service-account login (TokenReview).
- **`sm-agent`:** init container or sidecar that logs in, renews its certificate, and keeps secrets and database credentials in files.
- **Python SDK (`smclient`):** caching, refresh, and serving the last good value when the cluster is unreachable.
- **Rotation engine:** scheduled rotation in four steps with zero downtime (two alternating database users). Plugins: random value, PostgreSQL, MySQL, and an HTTP hook to your own service.
- **Dynamic database credentials:** a PostgreSQL or MySQL user per requester, with leases (TTL, renew, revoke, revoke by prefix).
- **Audit log:** hash-chained and tamper-evident, fail-closed, forwarded over TLS syslog, and checked offline with `smctl audit verify`.
- **Operations:** encrypted snapshots with restore, Prometheus metrics, health endpoints, cluster membership commands, runbooks and a disaster-recovery drill test.
- **Sentinel:** rule-based alerts from the audit log, for stolen certificates, bulk reads, probing, rate spikes, off-hours admin use, and audit-log tampering or gaps.
- **Revocation list** (certificates, identities, whole renewal lineages); root-admin handover by share holders; a limit on how long renewal can continue without a fresh login.
- **Reproducible, signed release builds** (`scripts/release.sh`).
- Local try-out script (`scripts/try-local.sh`), threat model, production checklist.

[Unreleased]: https://github.com/hamad-tariq/SecretsManager/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hamad-tariq/SecretsManager/releases/tag/v0.1.0

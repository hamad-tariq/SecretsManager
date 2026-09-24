# Defaults and limits

## Keys and shares

| Setting | Value |
|---|---|
| Shares (N), threshold (M) | default 5 and 3; `2 ≤ M ≤ N ≤ 255` |
| Unseal progress timeout | 10 minutes of inactivity |
| Encryption | XChaCha20-Poly1305, 256-bit keys, random 24-byte nonces |
| Certificate keys | ECDSA P-256 |
| TLS | 1.3 only |

## Certificate lifetimes

| Certificate | Default | Maximum |
|---|---|---|
| Root CA (`pki root-init`) | 10 years | |
| Intermediate CA (`pki intermediate`) | 1 year | |
| Issued with `pki issue` | **24 h, all kinds** (pass `-ttl`) | nodes 1 year, admins 30 days, services 72 h |
| Service certificates from the cluster | 24 h | |
| Service renewal | at 2/3 of lifetime (~16 h) | refused 30 days after the last full login (`-max-cert-lineage`) |
| Enrollment token | 15 minutes | 1 hour, single use |

## Secrets

| Setting | Value |
|---|---|
| Versions kept per secret | 10 (labelled versions are never trimmed) |
| Soft-delete recovery window | 7 days |
| Path segment characters | `A–Z a–z 0–9 . _ -` |
| Identity and policy names | 1–63 of `a-z 0-9 -` |
| Request body | 1 MiB (snapshot restore: 64 MiB) |

## API

| Setting | Value |
|---|---|
| Rate limit | 50 requests/s per identity (per IP when unauthenticated), burst 100 |
| Server timeouts | read header 10 s, read 30 s, write 30 s, idle 2 min |

## Rotation and leases

| Setting | Value |
|---|---|
| Check interval (leader) | 10 s (`-rotation-check`) |
| Minimum rotation interval | 1 minute |
| Retry backoff | 1 min, doubling, up to 1 h |
| `random` plugin length | 32 (16–1024), format `alnum` |
| SQL plugin password length | 32 |
| Lease `default_ttl` / `max_ttl` | 1 h / 24 h; `1m ≤ default ≤ max ≤ 720h` |
| Agent lease renewal | at 2/3 of the lease |
| Dynamic user name | `v_<role, 10 chars>_<12 hex>`, at most 25 chars |

## Audit

| Setting | Value |
|---|---|
| Forwarding lag before requests fail | 64 MiB (`-audit-forward-max-lag`) |
| Serials on the revocation list | kept until the certificate's expiry (default 366 days if unknown) |
| Lineages on the revocation list | kept until login + `-max-cert-lineage` + 366 days |

## Clients

| Setting | Value |
|---|---|
| `sm-agent -refresh` | 5 minutes |
| SDK cache `ttl` | 300 s |
| SDK `max_stale` (serve cached values while all nodes are down) | 3600 s |
| SDK request timeout | 10 s |

## Sentinel

| Setting | Default |
|---|---|
| Learning period | 7 days |
| `bulk_read` | 5 new paths in 10 minutes |
| `denial_burst` | 10 denials in 5 minutes |
| `rate_spike` | 3 × p99 of 14 days, at least 50 requests |
| `cert_multiple_hosts` window | 1 hour |
| Alert deduplication | 1 hour |

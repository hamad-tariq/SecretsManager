# HTTP API

All endpoints are served by every node over **HTTPS (TLS 1.3 only)** under `/v1/`. Followers forward to the leader, so any node answers any request.

## Conventions

**Authentication** is by TLS client certificate. Each endpoint has one of four modes:

| Mode | Meaning |
|---|---|
| **none** | No certificate needed. |
| **cert** | Any valid, non-revoked certificate. The endpoint does its own checks (e.g. only the lease's owner). |
| **policy** | A certificate whose identity's policies grant the listed **capability** on the listed **policy path** (or the root admin). |
| **admin** | Any admin certificate (`spiffe://sm/admin/...`), whatever its policies. |

**Bodies** are JSON. Unknown fields are rejected (`400`), and the limit is 1 MiB (64 MiB for snapshot restore).

**Errors** return a JSON body `{"error": "…"}` with one of these statuses:

| Status | Meaning |
|---|---|
| `400` | Malformed request, invalid path or name, unknown field |
| `401` | No client certificate where one is required; certificate revoked; login failed |
| `403` | Policy doesn't allow it (the same answer whether or not the path exists); admin certificate required |
| `404` | Not found |
| `409` | Conflict: check-and-set mismatch, already initialised, not deleted, lease expired |
| `429` | Rate limit (50 requests/s per identity, burst 100; per IP when unauthenticated); also health on a standby |
| `500` | Internal error, **including audit log failures** (fail closed) |
| `502` | A database operation failed (details only in the server log) |
| `503` | Node sealed; too many concurrent updates (retry) |

Every request except health and metrics is recorded in the audit log under its **operation** name, shown below as `op`.

---

## Secrets (KV)

### Read

`GET /v1/kv/{path}`: **policy** `read` on `kv/{path}` · op `kv.read`

| Query | Meaning |
|---|---|
| *(none)* | the `current` version |
| `version=N` | a specific version |
| `label=current\|previous\|pending` | the version a label points at |
| `metadata` | versions, labels and timestamps, no value (works on soft-deleted secrets) |
| `list` | every path under `{path}` (use `GET /v1/kv/?list` for all); **policy** `list` on `kv/{path}` (or `kv`) |

```json title="200 (read)"
{"path": "prod/orders/db", "value": "s3cret", "version": 2, "created": "2026-09-24T11:50:11.8517945Z"}
```

```json title="200 (?metadata)"
{"versions": [{"version": 1, "created": "…"}, {"version": 2, "created": "…"}],
 "latest": 2, "labels": {"current": 2, "previous": 1}, "created": "…", "updated": "…"}
```

```json title="200 (?list)"
{"keys": ["prod/orders/api-key", "prod/orders/db"]}
```

### Write

`PUT /v1/kv/{path}`: **policy** `create` if the path doesn't exist, `update` if it does (soft-deleted counts as existing) · op `kv.write`

```json title="request"
{"value": "s3cret", "cas": 2}
```

`cas` is optional: absent means no check, `0` means it must not exist, and `N` means the latest version must be `N` (otherwise `409`).

```json title="200"
{"version": 3}
```

### Delete, destroy, undelete

| Request | Auth | op |
|---|---|---|
| `DELETE /v1/kv/{path}`: soft delete (7-day recovery) | **policy** `delete` on `kv/{path}` | `kv.delete` |
| `DELETE /v1/kv/{path}?destroy`: delete permanently | **policy** `delete` on `kv/{path}` | `kv.delete` |
| `POST /v1/kv/{path}?op=undelete` | **policy** `update` on `kv/{path}` | `kv.undelete` |

---

## Authentication and certificates

### Log in with an enrollment token

`POST /v1/auth/enroll`: **none** · op `auth.enroll`

```json title="request"
{"token": "smt_…", "csr": "<base64 DER certificate signing request>"}
```

```json title="200"
{"identity": "spiffe://sm/svc/orders-api", "certificate": "-----BEGIN CERTIFICATE-----\n…(leaf, then intermediate)", "not_after": "2026-09-25T09:59:50Z"}
```

The token is consumed atomically: of concurrent uses, exactly one succeeds. The CSR's signature is checked (proof of key possession); everything else in it is ignored.

### Log in with Kubernetes

`POST /v1/auth/kubernetes`: **none** · op `auth.kubernetes`

```json title="request"
{"jwt": "<projected service-account token>", "csr": "<base64 DER CSR>"}
```

Same response as enrollment. Fails with `401` if the TokenReview doesn't authenticate the token, the audience doesn't match, or the service account isn't mapped.

### Renew

`POST /v1/auth/renew`: **cert** (a service certificate) · op `auth.renew`

```json title="request"
{"csr": "<base64 DER CSR for a new key>"}
```

Same response. The new certificate carries the presented certificate's login time. Refused with `403` when that login is older than `-max-cert-lineage`.

### Create an enrollment token

`POST /v1/sys/enroll-tokens`: **cert**, plus `create` on `sys/enroll-tokens/{service}` · op `sys.enroll.create`

```json title="request"
{"service": "orders-api", "ttl": "15m"}
```

```json title="200"
{"token": "smt_…", "service": "orders-api", "expires": "2026-09-24T10:14:50Z"}
```

`ttl` defaults to 15 minutes, with a maximum of 1 hour.

### Upload the intermediate CA

`PUT /v1/sys/pki/intermediate`: **policy** `update` on `sys/pki/intermediate` · op `sys.pki.intermediate`

```json title="request"
{"cert_pem": "-----BEGIN CERTIFICATE-----…", "key_pem": "-----BEGIN PRIVATE KEY-----…"}
```

```json title="200"
{"subject": "…", "not_after": "2027-09-24T09:56:40Z"}
```

### Configure Kubernetes login

`PUT /v1/sys/auth/kubernetes`: **policy** `update` on `sys/auth/kubernetes` · op `sys.auth.kubernetes`

```json title="request"
{
  "host": "https://k8s-api.internal:6443",
  "ca_pem": "-----BEGIN CERTIFICATE-----…",
  "reviewer_token": "eyJ…",
  "audience": "sm",
  "roles": {"shop/orders": "orders-api"}
}
```

---

## Policies and bindings

| Request | Auth (policy path, capability) | op |
|---|---|---|
| `GET /v1/sys/policies` | `sys/policies`, `list` | `sys.policy.list` |
| `GET /v1/sys/policies/{name}` | `sys/policies/{name}`, `read` | `sys.policy.read` |
| `PUT /v1/sys/policies/{name}` | `sys/policies/{name}`, `update` | `sys.policy.write` |
| `DELETE /v1/sys/policies/{name}` | `sys/policies/{name}`, `delete` | `sys.policy.delete` |
| `GET /v1/sys/bindings/{kind}/{name}` | `sys/bindings/{kind}/{name}`, `read` | `sys.binding.read` |
| `PUT /v1/sys/bindings/{kind}/{name}` | `sys/bindings/{kind}/{name}`, `update` | `sys.binding.write` |
| `DELETE /v1/sys/bindings/{kind}/{name}` | `sys/bindings/{kind}/{name}`, `delete` | `sys.binding.delete` |

The policy body is the policy JSON itself (see [Policy language](policy-language.md)), and its `name` must match the URL. A binding body is `{"policies": ["orders", "shared"]}`. `{kind}` is `svc`, `admin` or `node`.

`GET /v1/sys/policies` returns `{"policies": ["orders", …]}`.

---

## Rotation

| Request | Auth (policy path, capability) | op |
|---|---|---|
| `GET /v1/sys/rotation/{path}` | `sys/rotation/{path}`, `read` | `sys.rotation.read` |
| `PUT /v1/sys/rotation/{path}` | `sys/rotation/{path}`, `update` (+ `read` on `kv/{admin}` for SQL plugins) | `sys.rotation.write` |
| `DELETE /v1/sys/rotation/{path}` | `sys/rotation/{path}`, `delete` | `sys.rotation.delete` |
| `POST /v1/sys/rotation/{path}?op=rotate` | `sys/rotation/{path}`, `update` | `sys.rotation.trigger` |

```json title="PUT request"
{"interval": "720h", "plugin": "postgres", "params": {"admin": "db/admin", "users": "app_a,app_b"}}
```

```json title="GET 200"
{"interval": "720h", "plugin": "postgres", "params": {…},
 "step": "test", "pending_version": 7, "last_rotated": "…", "next_due": "…",
 "attempts": 2, "next_attempt": "…", "last_error": "test: …"}
```

`step`, `pending_version`, `attempts`, `next_attempt` and `last_error` appear only while a rotation is in progress or failing. See [Rotate secrets](../guides/rotation.md) for plugins and parameters.

---

## Dynamic database credentials and leases

| Request | Auth | op |
|---|---|---|
| `GET /v1/sys/db-roles/{name}` | **policy** `read` on `sys/db-roles/{name}` | `sys.dbrole.read` |
| `PUT /v1/sys/db-roles/{name}` | **policy** `update` on `sys/db-roles/{name}`, + `read` on `kv/{admin}` | `sys.dbrole.write` |
| `DELETE /v1/sys/db-roles/{name}` | **policy** `delete` on `sys/db-roles/{name}` | `sys.dbrole.delete` |
| `POST /v1/db/creds/{name}` | **policy** `read` on `db/creds/{name}` | `db.creds` |
| `POST /v1/leases/renew` | **cert**, and must be the lease's owner | `lease.renew` |
| `POST /v1/leases/revoke` | **cert**, and must be the lease's owner | `lease.revoke` |
| `GET /v1/sys/leases/{prefix}` | **policy** `list` on `sys/leases/{prefix}` (or `sys/leases`) | `sys.lease.list` |
| `POST /v1/sys/leases/revoke-prefix/{prefix}` | **policy** `update` on `sys/leases/{prefix}` | `sys.lease.revoke-prefix` |

```json title="PUT /v1/sys/db-roles/orders-rw"
{"plugin": "postgres", "admin": "db/orders-admin", "grants": ["GRANT app_rw TO {{name}}"],
 "default_ttl": "1h", "max_ttl": "24h"}
```

```json title="POST /v1/db/creds/orders-rw → 200"
{"lease_id": "db/orders-rw/7867be7fdbfea795", "username": "v_orders_rw_ff578dab55b2", "password": "…",
 "expires": "2026-09-24T13:00:00Z", "max_expires": "2026-09-25T12:00:00Z"}
```

The request body is optional: `{"ttl": "30m"}`.

```json title="POST /v1/leases/renew"
{"lease_id": "db/orders-rw/7867be7fdbfea795", "increment": "1h"}
```

Returns the lease record. `increment` is optional (the default is the lease's TTL), and the result never goes past `max_expires`. `revoke` takes `{"lease_id": "…"}`.

`GET /v1/sys/leases/{prefix}` returns `{"leases": [ {lease record}, … ]}`. Prefixes match whole path segments, or one exact lease ID. `revoke-prefix` returns `{"revoked": N}`, or `502` with how many were revoked when some drops failed; those are retried.

---

## Revocation and root admin

| Request | Auth | op |
|---|---|---|
| `GET /v1/sys/revocations` | **policy** `read` on `sys/revocations` | `sys.revocation.list` |
| `POST /v1/sys/revocations` | **policy** `update` on `sys/revocations` | `sys.revocation.add` |
| `DELETE /v1/sys/revocations?serial=…\|identity=…\|lineage=…` | **policy** `delete` on `sys/revocations` | `sys.revocation.remove` |
| `GET /v1/sys/root-admin` | **policy** `read` on `sys/root-admin` | `sys.root-admin.read` |
| `POST /v1/sys/root-admin` | **admin**, plus M current shares in the body | `sys.root-admin.set` |

```json title="POST /v1/sys/revocations: one of"
{"serial": "1f3a9c…", "reason": "INC-123", "until": "2026-09-25T09:59:50Z"}
{"identity": "svc/orders-api", "reason": "INC-124"}
{"identity": "svc/orders-api", "login": "2026-09-20T08:00:00Z", "serial": "1f3a9c…", "reason": "INC-123"}
```

The third form revokes a **lineage** (identity plus login time), optionally with a serial. `smctl cert revoke -cert` sends it.

```json title="POST /v1/sys/root-admin"
{"identity": "admin/bob", "shares": ["…", "…", "…"]}
```

Returns `{"root_admin": "spiffe://sm/admin/bob"}`. Wrong shares give `403`.

---

## Seal lifecycle

| Request | Auth | op |
|---|---|---|
| `GET /v1/sys/health` | **none**, works sealed, not audited | `sys.health` |
| `POST /v1/sys/init` | **admin**, works sealed | `sys.init` |
| `POST /v1/sys/unseal` | **admin**, works sealed | `sys.unseal` |
| `POST /v1/sys/seal` | **policy** `update` on `sys/seal` | `sys.seal` |
| `POST /v1/sys/rotate` | **policy** `update` on `sys/rotate` | `sys.rotate` |
| `POST /v1/sys/rekey` | **policy** `update` on `sys/rekey`, plus M current shares | `sys.rekey` |

```json title="POST /v1/sys/init"
{"shares": 5, "threshold": 3, "recipients": ["age1…", "…"]}
```
→ `{"shares": ["…", …]}`. `recipients` is optional (one per share). The caller becomes root admin. `409` if already initialised.

```json title="POST /v1/sys/unseal"
{"share": "…"}
```
→ the seal status `{"initialized", "sealed", "shares", "threshold", "progress"}`.

```json title="POST /v1/sys/rekey"
{"shares": ["current share", "…"], "new_shares": 5, "threshold": 3, "recipients": ["age1…"]}
```
→ `{"shares": [...]}`, plus `"warning"` if the outcome of the storage write couldn't be confirmed (keep both old and new shares).

`POST /v1/sys/rotate` → `{"term": 2}`. `POST /v1/sys/seal` → `{"sealed": true}`.

`GET /v1/sys/health` returns `200` for the leader (or any unsealed node with `?standbyok`), `429` for a standby, `503` if sealed and `501` if not initialised:

```json
{"initialized": true, "sealed": false, "shares": 3, "threshold": 2, "progress": 0, "leader": true, "standby": false}
```

---

## Cluster, snapshots, metrics

| Request | Auth | op |
|---|---|---|
| `GET /v1/sys/cluster` | **policy** `read` on `sys/cluster` | `sys.cluster.read` |
| `DELETE /v1/sys/cluster/members/{id}` | **policy** `update` on `sys/cluster` | `sys.cluster.remove` |
| `POST /v1/sys/cluster/step-down` | **policy** `update` on `sys/cluster` | `sys.cluster.step-down` |
| `GET /v1/sys/snapshot` | **policy** `read` on `sys/snapshot` | `sys.snapshot.save` |
| `POST /v1/sys/snapshot/restore` | **admin**, works sealed, only on an empty cluster | `sys.snapshot.restore` |
| `GET /v1/sys/metrics` | **policy** `read` on `sys/metrics`, not audited | `sys.metrics` |

```json title="GET /v1/sys/cluster"
{"leader": "node-2", "voters": ["node-1", "node-2", "node-3"],
 "members": {"node-1": "10.0.0.1:8202", "node-2": "10.0.0.2:8202", "node-3": "10.0.0.3:8202"}}
```

`DELETE …/members/{id}` → `{"removed": "node-3"}` (the ID is banned for good). `step-down` → `{"leader": "node-1"}`.

`GET /v1/sys/snapshot` returns the snapshot file (JSON: `format`, `created`, `keys`, `sha256`, and `data`, the encrypted key/value pairs). `POST /v1/sys/snapshot/restore` takes that file as the body and returns `{"restored_keys", "snapshot_created", "status"}`, or `409` if the cluster isn't empty.

`GET /v1/sys/metrics` returns Prometheus text format; see [Metrics](metrics.md).

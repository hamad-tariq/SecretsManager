# Dynamic database credentials

Instead of every instance of an app sharing one database password, each instance asks for **its own database user**, valid for a short time. When the lease ends (it expires, is revoked, or the pod goes away and stops renewing), the user's sessions are killed and the user is dropped.

**Why bother:**

- A leaked credential expires on its own, usually within the hour.
- Every database session can be traced to one pod, through the lease and the audit log.
- Revoking a compromised app takes one command and ends its sessions immediately.

Supported databases: **PostgreSQL** and **MySQL**.

```mermaid
sequenceDiagram
    participant Pod as Pod (sm-agent -db)
    participant SM as Secrets cluster
    participant DB as PostgreSQL
    Pod->>SM: POST /v1/db/creds/orders-rw
    SM->>SM: write lease db/orders-rw/7867be7f… (before the user exists)
    SM->>DB: CREATE ROLE "v_orders_rw_ff578d…" LOGIN PASSWORD '<SCRAM>' VALID UNTIL max_expires; GRANT …
    SM-->>Pod: username, password, lease_id, expires, max_expires
    loop at 2/3 of the lease
        Pod->>SM: POST /v1/leases/renew
    end
    Note over SM,DB: lease expires (or is revoked)
    SM->>DB: NOLOGIN, terminate sessions, REASSIGN/DROP OWNED, DROP ROLE
    SM->>SM: delete lease (only after the user is gone)
```

The lease is written **before** the user is created and deleted only **after** the user is dropped, so a crash at any point can't leave an orphaned user behind.

## 1. Store the admin connection string

The admin user creates and drops users. On PostgreSQL it needs `CREATEROLE` plus the right to grant what your roles grant.

```bash
printf 'postgres://sm_admin:…@db.internal:5432/app?sslmode=verify-full' | smctl kv put db/orders-admin
```

## 2. Define a role

```json title="orders-rw.json"
{
  "plugin": "postgres",
  "admin": "db/orders-admin",
  "grants": [
    "GRANT app_rw TO {{name}}"
  ],
  "default_ttl": "1h",
  "max_ttl": "24h"
}
```

```bash
smctl db write-role orders-rw orders-rw.json
```

| Field | Meaning |
|---|---|
| `plugin` | `postgres` or `mysql` |
| `admin` | kv path of the admin connection string (you need `read` on it to write the role) |
| `grants` | SQL statements run right after the user is created. `{{name}}` becomes the quoted user: `"v_…"` on PostgreSQL, `'v_…'@'host'` on MySQL. On PostgreSQL they run in the same transaction as `CREATE ROLE`. |
| `host` | MySQL only: the account host (default `%`) |
| `default_ttl` | Lease length when the caller doesn't ask (default `1h`) |
| `max_ttl` | Hard limit including renewals (default `24h`) |

TTLs must satisfy `1m ≤ default_ttl ≤ max_ttl ≤ 720h`.

!!! warning "Grants are SQL run as the admin"
    Whoever may write `sys/db-roles/...` can run any SQL the admin user can. Grant it like the admin credential itself.

=== "MySQL example"

    ```json
    {
      "plugin": "mysql",
      "admin": "db/mysql-admin",
      "host": "10.42.%",
      "grants": ["GRANT SELECT, INSERT, UPDATE ON shop.* TO {{name}}"],
      "default_ttl": "30m",
      "max_ttl": "12h"
    }
    ```

## 3. Allow the service to get credentials

```json
{ "name": "orders-db", "rules": [
    { "path": "db/creds/orders-rw", "capabilities": ["read"] } ] }
```

```bash
smctl policy write orders-db orders-db.json
smctl identity bind svc/orders-api orders,orders-db
```

## 4. Get credentials

=== "sm-agent (recommended)"

    Run the agent as a **sidecar** or service (not `-once` alone, since the lease must be renewed):

    ```bash
    sm-agent … -db orders-rw=db.json
    ```

    It writes `db.json`, renews the lease at 2/3 of its lifetime, and gets a **new user** once the lease can't be extended past `max_ttl`. The old user keeps working until its own expiry, so the app has time to reconnect with the new file.

    ```python
    from smclient import DBCredentials
    creds = DBCredentials.from_file("/run/secrets/sm/db.json")
    conn = psycopg.connect(host="db.internal", dbname="app",
                           user=creds.username, password=creds.password.reveal())
    ```

=== "Python SDK"

    ```python
    creds = sm.db_creds("orders-rw", ttl="30m")
    ...
    sm.renew_lease(creds.lease_id)          # extend by the lease's TTL, never past max_expires
    sm.revoke_lease(creds.lease_id)         # on shutdown: drop the user now
    ```

=== "CLI (a person, a one-off job)"

    ```bash
    smctl db creds -ttl 15m orders-rw
    ```

=== "HTTP"

    ```bash
    curl --cert tls.crt --key tls.key --cacert ca.crt -X POST \
         -d '{"ttl":"30m"}' https://sm-1.internal:8200/v1/db/creds/orders-rw
    ```

The response:

```json
{
  "lease_id": "db/orders-rw/7867be7fdbfea795",
  "username": "v_orders_rw_ff578dab55b2",
  "password": "…",
  "expires": "2026-09-24T13:00:00Z",
  "max_expires": "2026-09-25T12:00:00Z"
}
```

User names are `v_<first 10 characters of the role>_<12 hex characters>`, at most 25 characters, so they're recognisable in the database as issued by the secrets cluster.

## 5. Revoke

```bash
smctl lease list db/orders-rw                  # who holds what
smctl lease revoke-prefix db/orders-rw         # every user of this role, now
smctl lease revoke-prefix db/orders-rw/7867be7fdbfea795   # just one
```

`revoke-prefix` is **synchronous**. When it returns `200`, the users are dropped and their sessions killed. Prefixes match whole segments: `db/orders` does not match `db/orders-rw`. If the database can't be reached, the command reports how many were revoked, and the rest are marked expired and retried by the leader.

Leases are also dropped automatically when they expire. The leader checks every `-rotation-check` (10 s).

## How users are dropped

=== "PostgreSQL"

    1. `ALTER ROLE … NOLOGIN` (no new sessions)
    2. `pg_terminate_backend` for every session of the user
    3. `REASSIGN OWNED BY … TO CURRENT_USER`, then `DROP OWNED BY …`
    4. `DROP ROLE …`

    Users are also created with `VALID UNTIL <max_expires>`, so PostgreSQL itself stops them at the max TTL even if the secrets cluster is unreachable.

=== "MySQL"

    1. `DROP USER IF EXISTS …` (no new logins)
    2. `KILL` every remaining session of the user

    MySQL users have **no expiry of their own**. If the secrets cluster can't reach MySQL, an expired user keeps working until a drop succeeds.

## Permissions summary

| Action | Needs |
|---|---|
| Get credentials for role `x` | `read` on `db/creds/x` |
| Renew or revoke a lease | Being the identity that got it |
| Write a role | `update` on `sys/db-roles/x`, plus `read` on its `admin` kv path |
| Read or delete a role | `read` / `delete` on `sys/db-roles/x` |
| List leases | `list` on `sys/leases/<prefix>` |
| Revoke by prefix | `update` on `sys/leases/<prefix>` |

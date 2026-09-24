# smctl (CLI)

`smctl` is the operator CLI. It talks to the HTTPS API with an **admin certificate**, and also runs the offline PKI commands and audit verification, which need no cluster.

```text
smctl [-addr host:port[,host:port...]] [-cert admin.pem -key admin.key -ca root.pem] <group> <command> [flags] [args]
```

## Connection

| Flag | Environment variable | Meaning |
|---|---|---|
| `-addr` | `SM_ADDR` | Node API addresses, comma-separated. Commands go to the first that answers; per-node commands (`operator status`, `operator unseal`, `operator seal -all`) go to every address. |
| `-cert` | `SM_CERT` | Admin certificate PEM |
| `-key` | `SM_KEY` | Its private key |
| `-ca` | `SM_CA` | Root CA PEM |
| `-version` | | Print the version and exit |

```bash
export SM_ADDR=sm-1:8200,sm-2:8200,sm-3:8200
export SM_CERT=~/.sm/alice.pem SM_KEY=~/.sm/alice.key SM_CA=~/.sm/root.pem
```

!!! tip "Secrets are never arguments"
    Values and shares are read from **stdin**, or from a **no-echo prompt** on a terminal, never from command-line arguments, which end up in shell history and process listings.

Output is JSON on stdout, and messages and errors go to stderr. Exit codes: `0` success, `1` error, `2` usage error.

---

## operator: cluster lifecycle

| Command | Description |
|---|---|
| `operator status` | Health of **every** node in `SM_ADDR`: initialised, sealed, unseal progress, leader. |
| `operator init [-shares 5] [-threshold 3] [-recipient age1…]…` | Initialise a new cluster. The caller becomes root admin. Prints the shares **once**. With `-recipient` (one per share) each share is `age`-encrypted to its holder. |
| `operator unseal` | Submit one share (from stdin or a prompt) to **every** node. |
| `operator seal [-all]` | Seal one node (the first that answers), or every node with `-all`. |
| `operator rotate` | Add a new encryption-key term. |
| `operator rekey [-shares 5] [-threshold 3] [-current-threshold M] [-recipient age1…]…` | Replace the shares. Prompts for M current shares (M read from the cluster unless `-current-threshold` is given). |
| `operator root-admin -identity admin/NAME [-current-threshold M]` | Hand root admin to another admin. Prompts for M current shares. |
| `operator members` | Leader, voters and member addresses. |
| `operator remove-node <node-id>` | Remove a dead node for good (its ID is banned). |
| `operator step-down` | Hand leadership to another node, e.g. before upgrading the leader. |

```console
$ smctl operator status
{
  "127.0.0.1:8210": { "initialized": true, "leader": true,  "progress": 0, "sealed": false, "shares": 3, "standby": false, "threshold": 2 },
  "127.0.0.1:8220": { "initialized": true, "leader": false, "progress": 0, "sealed": false, "shares": 3, "standby": true,  "threshold": 2 },
  "127.0.0.1:8230": { "initialized": true, "leader": false, "progress": 0, "sealed": false, "shares": 3, "standby": true,  "threshold": 2 }
}
```

## kv: secrets

| Command | Description |
|---|---|
| `kv put [-cas N] <path>` | Write a new version. The value comes from stdin exactly, or a no-echo prompt. `-cas 0`: only if it doesn't exist; `-cas N`: only if the latest version is N. |
| `kv get [-reveal] [-version N \| -label L] <path>` | Read. Without `-reveal` the value is hidden; with it, **only the raw value** is printed (ready for `> file`). |
| `kv list [prefix]` | Every path under the prefix. |
| `kv history <path>` | Versions, labels, timestamps, deletion state. Never values. |
| `kv delete <path>` | Soft delete (recoverable for 7 days). |
| `kv undelete <path>` | Undo a soft delete. |
| `kv destroy <path>` | Delete permanently, all versions. |

```bash
printf 'postgres://app:pw@db:5432/app' | smctl kv put prod/orders/db
smctl kv put prod/tls/key < server.key
smctl kv get -reveal prod/tls/key > server.key
```

## policy and identity: access control

| Command | Description |
|---|---|
| `policy write <name> <file.json>` | Create or replace a policy. The name must match the file's `name`. |
| `policy read <name>` | Show a policy. |
| `policy list` | List policy names. |
| `policy delete <name>` | Delete a policy. |
| `identity bind <kind>/<name> <policy>[,<policy>…]` | Set the identity's policies (replaces the previous list). |
| `identity show <kind>/<name>` | Show the identity's policies. |
| `identity unbind <kind>/<name>` | Remove all of the identity's policies. |

```bash
smctl policy write orders orders.json
smctl identity bind svc/orders-api orders,shared-config
```

## pki: certificate authority

The first three run **offline** (no cluster needed) and write `name.pem` and `name.key` (mode 0600) into `-out`.

| Command | Description |
|---|---|
| `pki root-init -out DIR [-ttl 87600h]` | Create the root CA (`root.pem`, `root.key`). Keep `root.key` offline. |
| `pki intermediate -ca-cert root.pem -ca-key root.key -out DIR [-ttl 8760h]` | Create the intermediate CA (`intermediate.pem`, `intermediate.key`). |
| `pki issue -ca-cert inter.pem -ca-key inter.key -kind svc\|admin\|node -name N [-host H]… [-ttl D] -out DIR` | Issue a certificate. `-host` (repeatable) for node certificates. **Default TTL is 24 h for every kind**: pass `-ttl 8760h` for nodes and `-ttl 720h` for admins. |
| `pki upload -cert intermediate.pem -key intermediate.key` | Give the cluster the intermediate, so it can issue service certificates. |

## enroll and auth: onboarding services

| Command | Description |
|---|---|
| `enroll token -service NAME [-ttl 15m]` | A single-use enrollment token for `sm-agent -auth token` (maximum TTL 1 h). |
| `auth kubernetes -host https://k8s:6443 -ca-file ca.crt -reviewer-token-file f [-audience sm] -role ns/sa=service…` | Configure Kubernetes login. `-role` is repeatable and maps a namespace/service account to a service name. |

## rotation: scheduled rotation

| Command | Description |
|---|---|
| `rotation set -interval 720h -plugin random\|postgres\|mysql\|http [-param k=v]… <path>` | Configure rotation for a secret. The first rotation runs at the next check. |
| `rotation get <path>` | Settings and progress (`step`, `last_rotated`, `next_due`, `attempts`, `last_error`). |
| `rotation now <path>` | Rotate at the next check, clearing any backoff. |
| `rotation delete <path>` | Stop rotating (the secret is kept). |

```console
$ smctl rotation set -interval 720h -plugin random -param length=40 -param format=base64 prod/orders/api-key
$ smctl rotation get prod/orders/api-key
{
  "interval": "720h",
  "last_rotated": "2026-09-24T11:50:19.4847106Z",
  "next_due": "2026-10-24T11:50:19.4847106Z",
  "params": { "format": "base64", "length": "40" },
  "plugin": "random"
}
```

## db and lease: dynamic database credentials

| Command | Description |
|---|---|
| `db write-role <name> <role.json>` | Create or replace a role (`plugin`, `admin`, `grants`, `host`, `default_ttl`, `max_ttl`). |
| `db read-role <name>` | Show a role. |
| `db delete-role <name>` | Delete a role. Existing leases run their course. |
| `db creds [-ttl 30m] <role>` | Create a database user now and print its credentials (for testing, or for a person). |
| `lease list [prefix]` | Active leases, e.g. `db/orders-rw`. |
| `lease revoke-prefix <prefix>` | Drop the users and kill their sessions **now**. A full lease ID revokes one lease. |

## cert: revocation

| Command | Description |
|---|---|
| `cert revoke -cert FILE.pem [-reason TEXT]` | Revoke a certificate **and every renewal from the same login**. |
| `cert revoke -serial HEX [-reason TEXT]` | Revoke one certificate by serial (renewals not included). |
| `cert revoke -identity kind/name [-reason TEXT]` | Revoke every certificate of an identity. |
| `cert unrevoke -serial HEX \| -identity kind/name \| -lineage KEY` | Reinstate. `KEY` is as listed under `lineages`. |
| `cert revocations` | Show the revocation list. |

## snapshot: backups

| Command | Description |
|---|---|
| `snapshot save -out FILE` | Save an encrypted snapshot (mode 0600). Prints its SHA-256. |
| `snapshot verify FILE` | Check a snapshot's checksum **offline**. |
| `snapshot restore FILE` | Load a snapshot into a **new, empty** cluster, which then needs unsealing with the shares that were current when it was taken. |

```console
$ smctl snapshot save -out sm-2026-09-24.json
saved 11 keys to sm-2026-09-24.json (sha256 64871a46d841061efedddf910b1376b0191091ba82810032f9ba7f6f779c83fd)
$ smctl snapshot verify sm-2026-09-24.json
ok: 11 keys, taken 2026-09-24T11:50:14Z, sha256 64871a46d841061efedddf910b1376b0191091ba82810032f9ba7f6f779c83fd
```

## audit: offline verification

| Command | Description |
|---|---|
| `audit verify [-head SEQ:HASH] <audit.log>` | Check the hash chain and exact encoding of a log. `-head` (the collector's last record) also catches truncation. |

```console
$ smctl audit verify /var/lib/smd/audit.log
ok: 77 records, head ae9dde023a49c561235a1f0c63f95b35dc8ca91ac49ba8a2959241e4d41df071
```

Run `smctl` with no arguments, or `smctl -h`, for the built-in list of every command and its usage.

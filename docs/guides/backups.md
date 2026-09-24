# Backups and restore

A **snapshot** is every stored key and value exactly as the cluster holds them: barrier ciphertext plus the sealed keyring, with a SHA-256 checksum. Nothing in it is readable without the unseal shares that were current when it was taken.

## Taking snapshots

```console
$ smctl snapshot save -out sm-2026-09-24.json
saved 11 keys to sm-2026-09-24.json (sha256 64871a46d841061efedddf910b1376b0191091ba82810032f9ba7f6f779c83fd)
$ smctl snapshot verify sm-2026-09-24.json
ok: 11 keys, taken 2026-09-24T11:50:14Z, sha256 64871a46d841061efedddf910b1376b0191091ba82810032f9ba7f6f779c83fd
```

Needs `read` on `sys/snapshot`. Give a dedicated backup identity only that:

```json
{ "name": "backup", "rules": [ { "path": "sys/snapshot", "capabilities": ["read"] } ] }
```

### A daily job

```bash title="/usr/local/bin/sm-backup"
#!/bin/sh
set -eu
f=/backup/sm/sm-$(date +%F).json
smctl snapshot save -out "$f"
smctl snapshot verify "$f" | tee -a /backup/sm/checksums.log   # keep the checksums separately
```

- **Frequency.** Take snapshots at least daily, and **right after every rekey**: a snapshot needs the shares that were current when it was taken.
- **Storage.** Keep copies on storage the secrets nodes **can't write to**, ideally write-once. The checksum catches corruption, not a deliberate edit by someone holding the file, so record checksums somewhere else.
- **Retention.** Keep enough history that you can recover from a bad change noticed late.

## Restoring

Restore goes into a **new, empty cluster**, never over a running one:

```mermaid
flowchart LR
    A["Start fresh nodes<br/>(empty -data, -bootstrap / -join)"] --> B["smctl snapshot restore FILE<br/>(admin certificate, before init)"]
    B --> C["Unseal with the shares that were<br/>current when the snapshot was taken"]
    C --> D["Verify, then point clients at it"]
```

```console
$ smctl snapshot restore sm-2026-09-24.json
{
  "restored_keys": 11,
  "snapshot_created": "2026-09-24T11:50:14Z",
  "status": { "initialized": true, "sealed": true, … }
}
```

Then unseal as usual. The full procedure, with checks, is in the [Restore from backup](../runbooks/restore-from-backup.md) runbook.

!!! warning "Restore only into a cluster you control"
    `snapshot restore` works with **any** admin certificate, but only on a cluster that has no data at all: the same trust as `init`. Don't expose a freshly started, empty cluster to untrusted admins.

## Practise

A backup you've never restored is a hope, not a backup. The repository's DR drill test (`cmd/smd/dr_test.go`) does it end to end: it builds a cluster, snapshots it, destroys it, restores into a new cluster, unseals, and checks every secret. Do the same by hand in a lab every quarter, using the [runbook](../runbooks/restore-from-backup.md).

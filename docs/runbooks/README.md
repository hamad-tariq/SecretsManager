# Runbooks

For whoever is on call for the secrets cluster. Each runbook is a checklist: follow it in order, and write down what you did in the incident log.

| Situation | Runbook |
|---|---|
| Nodes restarted and are sealed | [unseal-after-restart.md](unseal-after-restart.md) |
| One node is dead or must be replaced | [lost-node.md](lost-node.md) |
| A majority of nodes is gone (no leader) | [lost-quorum.md](lost-quorum.md) |
| Rebuilding from a backup | [restore-from-backup.md](restore-from-backup.md) |
| A service's certificate or key leaked | [compromised-service-cert.md](compromised-service-cert.md) |
| A share holder leaves or a share may have leaked | [compromised-share-holder.md](compromised-share-holder.md) |
| Upgrading `smd` | [rolling-upgrade.md](rolling-upgrade.md) |

## Everyday setup

All commands are `smctl` with an admin certificate:

```sh
export SM_ADDR=sm-1:8200,sm-2:8200,sm-3:8200 SM_CERT=alice.pem SM_KEY=alice.key SM_CA=root.pem
```

## Root admin

The root admin has access regardless of policies and can't be revoked while it is root. To move root to another admin, for example when the root admin leaves or their certificate may be stolen, a threshold of share holders runs, on one machine, with any admin certificate:

```sh
smctl operator root-admin -identity admin/bob   # prompts for M current shares
smctl cert revoke -identity admin/alice         # now possible
```

The shares pass through that one machine, as with rekey, so use a trusted one. `GET /v1/sys/root-admin` (or the audit log, op `sys.root-admin.set`) shows who is root now.

## Backups

Take a snapshot at least daily and after every rekey, and keep copies on storage the secrets nodes can't write to:

```sh
smctl snapshot save -out sm-$(date +%F).json
smctl snapshot verify sm-$(date +%F).json
```

A snapshot is only useful together with the shares that were current when it was taken. After a rekey, older snapshots need the old shares. Keep the two in step, or keep the old shares until those snapshots expire.

## Monitoring

Scrape `GET /v1/sys/metrics` on every node, using a service certificate (e.g. `svc/prometheus`) bound to a policy with `read` on `sys/metrics`. Alert on:

| Metric | Alert when | Means |
|---|---|---|
| `sm_sealed` | 1 for more than 5 min | A node restarted: [unseal-after-restart.md](unseal-after-restart.md) |
| `sm_leader` | sum over nodes is 0 for more than 1 min | No leader: [lost-quorum.md](lost-quorum.md) |
| `sm_leader_changes` | rises more than 3 times in 10 min | Flapping: network or overloaded nodes |
| `sm_audit_forward_lag_bytes` | above 1 MiB | The audit collector is down; requests start failing at `-audit-forward-max-lag` (64 MiB by default) |
| `sm_requests_total{code="500"}` | any increase | Includes audit write failures (fail closed) |
| `sm_requests_total{code="403"}` | sudden spike | Someone probing, or a policy change broke a service |
| `sm_rotation_failures_total` | any increase | `smctl rotation get <path>` shows `last_error` |
| `sm_node_cert_expiry_seconds`, `sm_cert_expiry_seconds` | below 14 days | Renew node certificates, or upload a new intermediate |
| `sm_leases` | growing steadily | Services requesting credentials without reusing them |

Sentinel alerts ([Sentinel](../components/sentinel.md)) point to these runbooks:

| Alert | First move |
|---|---|
| `cert_multiple_hosts`, `new_source` on a service | [compromised-service-cert.md](compromised-service-cert.md) |
| `bulk_read`, `rate_spike`, `denial_burst` | Look up the identity and addresses in the audit log; if it isn't a deploy or a misconfigured client, treat it as [compromised-service-cert.md](compromised-service-cert.md) |
| `admin_off_hours`, `new_source` on an admin | Call the admin. If it wasn't them, `smctl cert revoke -identity admin/<name>` and rotate what they touched. If it's the **root admin**, hand root to another admin first (see [Root admin](#root-admin) below), then revoke |
| `audit_gap`, unexpected `audit_restart` | Someone edited or wiped a node's log. Treat that node's host as compromised; the collector's copy is the record |

For load balancers: `GET /v1/sys/health?standbyok` returns 200 on any unsealed node (standbys forward to the leader), 503 when sealed and 501 when not initialised. Without `?standbyok`, standbys return 429.

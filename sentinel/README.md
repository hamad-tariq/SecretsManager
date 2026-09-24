# Sentinel

Raises alerts about suspicious use of the secrets manager, from a copy of its audit log. It only alerts: it never blocks a request, changes the cluster or talks to it. Python 3.11+, standard library only.

## Where it runs

On the audit collector host (or anywhere that can read the collector's files), as its own user with **read-only** access to the audit files and no route to the secrets cluster. It never sees secret values: the audit log holds only HMAC fingerprints of them.

```
smd nodes --(-audit-forward, TLS syslog)--> collector (rsyslog/syslog-ng) --> /var/log/sm/*.log --> sentinel (read-only)
```

With rsyslog, write one file per node, for example `/var/log/sm/audit-%HOSTNAME%.log`. A single shared file works too, because the syslog HOSTNAME field tells the nodes apart.

Have the collector accept syslog only from clients presenting the nodes' certificates. Sentinel trusts the HOSTNAME field to tell nodes apart, and anyone who can send to the collector can inject lines. Injected or edited lines fail their hash and raise `audit_forged`, and they can't hide real records, but they are still noise.

## Running

```sh
python -m sentinel watch --config sentinel.json --state /var/lib/sentinel/state.json \
    --alerts /var/log/sentinel_alerts.log \
    --webhook https://alertmanager.internal:9093/api/v2/alerts --webhook-format alertmanager \
    /var/log/sm/audit-node-1.log /var/log/sm/audit-node-2.log /var/log/sm/audit-node-3.log
```

- `--state` keeps what Sentinel has learned (known paths and addresses per identity, hourly volumes, where each node's chain ended) across restarts. Without it, every restart begins a new learning period.
- `--webhook-format`: `alertmanager` for Alertmanager's `/api/v2/alerts`; `text` for Mattermost, Rocket.Chat or other Slack-compatible incoming webhooks; `json` for anything else. `--webhook-ca` sets the CA for a self-hosted webhook's certificate. If the webhook is down, alerts still go to the alerts log.
- `replay` runs the same rules over recorded logs and exits, printing a summary. Use it to tune the config against your own history before going live:

  ```sh
  python -m sentinel replay --config sentinel.json /var/log/sm/audit-*.log > alerts.jsonl
  ```

## Rules

| Rule | Severity | Fires when |
|---|---|---|
| `audit_forged` | critical | A record's hash doesn't match its contents: it was edited, or written by something other than the node's logger. The record is otherwise ignored. |
| `audit_gap` | critical | A node's audit chain doesn't link up: lines were deleted. Re-sent lines are ignored. |
| `audit_restart` | high | A node's chain starts over from its first record. Expected after rebuilding a node or restoring the cluster; otherwise someone wiped a log. |
| `cert_multiple_hosts` | high | One service or node certificate is used from two addresses within an hour: the certificate and key were copied. |
| `new_source` | high | An identity makes its first request from an address outside `trusted_networks`. |
| `bulk_read` | high | An identity reads `bulk_new_paths` never-read paths within 10 minutes. |
| `denial_burst` | high | `denials` denied requests from one identity (or one address, if unauthenticated) within 5 minutes. |
| `rate_spike` | high | An identity's requests this hour exceed `spike_factor` × its p99 hourly count over the last 14 days (and at least `spike_min`). |
| `new_path` | medium | A service reads a path it has never read. Admins browse, so this rule doesn't apply to them. |
| `admin_off_hours` | medium | Any admin request outside `admin_windows`. |
| `governance` | info | Init, unseal, seal, rekey, snapshot save/restore, intermediate upload, node removal. |

`new_path` and `new_source` stay quiet for an identity's first `learn_days`, while its normal pattern is learned. The same alert fires at most once an hour. Every alert carries the evidence behind it: path, addresses, counts and thresholds.

Settings are in `sentinel.example.json`; unknown keys are rejected so a typo can't silently switch a rule off. Put the pod network and the VPN range in `trusted_networks`, or every pod restart and laptop reconnect raises `new_source`.

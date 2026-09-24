# Sentinel

Sentinel reads a **copy** of the audit stream and raises alerts about misuse and tampering. It's a small Python program (3.11+, standard library only) that:

- **never talks to the cluster**: it has no credentials and no route to it;
- **never sees secret values**: the audit log holds only HMAC fingerprints;
- **only alerts**: it never blocks anything.

```text
smd nodes ──(-audit-forward, TLS syslog)──▶ collector (rsyslog / syslog-ng) ──▶ /var/log/sm/*.log ──▶ sentinel (read-only)
```

## Rules

| Rule | Severity | Fires when |
|---|---|---|
| `audit_forged` | critical | A record's hash doesn't match its contents: edited, or injected by something other than the node's logger. The record is otherwise ignored. |
| `audit_gap` | critical | A node's chain doesn't link up: lines were deleted. Re-sent duplicates are ignored. |
| `audit_restart` | high | A node's chain starts over. Expected after rebuilding a node or restoring the cluster; otherwise someone wiped a log. |
| `cert_multiple_hosts` | high | One service or node certificate is used from two addresses within an hour: the certificate and key were copied. |
| `new_source` | high | An identity's first request from an address outside `trusted_networks`. |
| `bulk_read` | high | An identity reads `bulk_new_paths` never-read paths within 10 minutes. |
| `denial_burst` | high | `denials` denied requests from one identity (or one address, if unauthenticated) within 5 minutes. |
| `rate_spike` | high | This hour's requests exceed `spike_factor` × the identity's p99 hourly count over 14 days (and at least `spike_min`). |
| `new_path` | medium | A service reads a path it has never read. Not applied to admins, who browse. |
| `admin_off_hours` | medium | Any admin request outside `admin_windows`. |
| `governance` | info | Init, unseal, seal, rekey, snapshot save/restore, intermediate upload, node removal. |

`new_path` and `new_source` stay quiet for an identity's first `learn_days`, while its normal pattern is learned. The same alert repeats at most once an hour. Rules run in **event time**, so replaying recorded logs gives exactly the alerts a live run would have.

## Running

=== "watch (live)"

    ```bash
    python -m sentinel watch --config sentinel.json --state /var/lib/sentinel/state.json \
        --alerts /var/log/sentinel_alerts.log \
        --webhook https://alertmanager.internal:9093/api/v2/alerts --webhook-format alertmanager \
        /var/log/sm/audit-node-1.log /var/log/sm/audit-node-2.log /var/log/sm/audit-node-3.log
    ```

    Follows the files like `tail -F`, handling partial lines, rotation and truncation. `--state` keeps what was learned across restarts; without it, every restart begins a new learning period.

=== "replay (history)"

    ```bash
    python -m sentinel replay --config sentinel.json /var/log/sm/audit-*.log > alerts.jsonl
    ```

    Runs the rules over recorded logs and prints a summary on stderr. Use it to tune the config against your own history before going live:

    ```json
    {"summary": {"alerts": {"governance": 2}, "duplicates": 0, "malformed": 0, "records": 16}}
    ```

| Option | Description |
|---|---|
| `--config FILE` | JSON settings (below). Unknown keys are rejected. |
| `--alerts FILE` | Append alerts as JSON lines. Default in watch mode: `sentinel_alerts.log`. |
| `--state FILE` | Persist learned baselines. |
| `--webhook URL` | Also POST each alert to this URL. |
| `--webhook-format` | `alertmanager` (Alertmanager `/api/v2/alerts`), `text` (Mattermost, Rocket.Chat, Slack-compatible) or `json`. |
| `--webhook-ca FILE` | CA for a self-hosted webhook's certificate. |
| `--quiet` | Don't print alerts to stdout. |

Files can be the collector's syslog files (the syslog HOSTNAME tells nodes apart) or plain `audit.log` files (the file name is used as the host). `-` reads stdin.

## Configuration

```json title="sentinel.json"
{
  "trusted_networks": ["10.42.0.0/16", "10.8.0.0/24"],
  "learn_days": 7,
  "admin_windows": [{"days": [0, 1, 2, 3, 4], "start_hour": 8, "end_hour": 19}],
  "admin_utc_offset_hours": 5,
  "spike_factor": 3,
  "spike_min": 50,
  "bulk_new_paths": 5,
  "denials": 10
}
```

| Key | Default | Meaning |
|---|---|---|
| `trusted_networks` | `[]` | CIDRs where new addresses are normal. Put the pod network and VPN range here. |
| `learn_days` | `7` | Quiet period per identity for `new_path` and `new_source`. |
| `admin_windows` | Mon–Fri 08–18 | When admin activity is expected. `days`: 0 = Monday. |
| `admin_utc_offset_hours` | `0` | Time zone for `admin_windows`. |
| `spike_factor`, `spike_min` | `3`, `50` | `rate_spike` thresholds. |
| `spike_min_history_hours` | `24` | History needed before `rate_spike` can fire. |
| `history_hours` | `336` (14 days) | Window for the p99 baseline. |
| `bulk_new_paths`, `bulk_window_s` | `5`, `600` | `bulk_read` thresholds. |
| `denials`, `denial_window_s` | `10`, `300` | `denial_burst` thresholds. |
| `serial_window_s` | `3600` | Window for `cert_multiple_hosts`. |
| `governance_ops` | init, unseal, seal, rekey, snapshots, intermediate upload, node removal | Operations reported as `governance`. |
| `dedup_s` | `3600` | Same alert at most once per this many seconds. |

## Alert format

```json
{"evidence": {"host": "node-1", "op": "sys.unseal", "result": "ok", "source_ip": "10.0.0.5"}, "identity": "spiffe://sm/admin/alice", "rule": "governance", "severity": "info", "summary": "sys.unseal (ok)", "time": "2026-09-24T09:56:55.725440Z"}
```

Every alert carries its **evidence**: paths, addresses, counts, thresholds. A down webhook never loses an alert, because the alerts log still has it.

!!! warning "Protect the collector"
    Have the collector accept syslog **only from the nodes' certificates**. Sentinel trusts the HOSTNAME field to tell nodes apart. Injected lines fail their hash (`audit_forged`) and can't hide real records, but they are still noise.

What each alert means, and what to do about it, is in the [runbooks](../runbooks/README.md). Setting up the collector is covered in [Audit forwarding and alerts](../guides/audit-forwarding.md).

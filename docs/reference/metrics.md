# Metrics

`GET /v1/sys/metrics` returns the Prometheus text format. It needs `read` on `sys/metrics` and isn't audited. Each node reports for itself; scrape all of them.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sm_sealed` | gauge | | `1` if this node is sealed |
| `sm_leader` | gauge | | `1` if this node is the Raft leader |
| `sm_leader_changes` | gauge | | Leadership changes seen by this node since it started |
| `sm_requests_total` | counter | `op`, `code` | API requests by operation and HTTP status |
| `sm_request_duration_seconds_sum` | counter | `op` | Total time spent serving requests |
| `sm_request_duration_seconds_count` | counter | `op` | Requests timed (divide `_sum` by it for the average) |
| `sm_cert_expiry_seconds` | gauge | `cert="intermediate"` | Seconds until the cluster's intermediate CA expires (after that, no service certificates can be issued). Absent while sealed. |
| `sm_node_cert_expiry_seconds` | gauge | `cert="node"`, `cert="root"` | Seconds until this node's certificate and the root CA expire |
| `sm_audit_forward_lag_bytes` | gauge | | Audit log bytes not yet forwarded (only with `-audit-forward`) |
| `sm_leases` | gauge | | Active database credential leases (reported by the leader) |
| `sm_rotations_total` | counter | `path` | Completed rotations |
| `sm_rotation_failures_total` | counter | `path`, `step` | Failed rotation steps |

Sample output (a follower):

```text
# HELP sm_leader 1 if this node is the Raft leader.
# TYPE sm_leader gauge
sm_leader 0
# HELP sm_node_cert_expiry_seconds Seconds until this node's certificates expire.
# TYPE sm_node_cert_expiry_seconds gauge
sm_node_cert_expiry_seconds{cert="node"} 3.15291829e+07
sm_node_cert_expiry_seconds{cert="root"} 3.153531828887253e+08
# HELP sm_requests_total API requests by operation and status.
# TYPE sm_requests_total counter
sm_requests_total{op="kv.read",code="200"} 13
sm_requests_total{op="kv.write",code="200"} 3
# HELP sm_sealed 1 if this node is sealed.
# TYPE sm_sealed gauge
sm_sealed 0
```

Example alert rules are in [Monitoring](../guides/monitoring.md#3-alert-rules).

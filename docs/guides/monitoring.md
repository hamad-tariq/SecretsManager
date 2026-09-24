# Monitoring

Each node exposes **Prometheus metrics** at `GET /v1/sys/metrics` (with a certificate allowed `read` on `sys/metrics`), and a **health endpoint** at `GET /v1/sys/health` (no certificate needed).

## 1. An identity for Prometheus

```bash
cat > prometheus.json <<'EOF'
{ "name": "prometheus", "rules": [ { "path": "sys/metrics", "capabilities": ["read"] } ] }
EOF
smctl policy write prometheus prometheus.json
smctl identity bind svc/prometheus prometheus
smctl enroll token -service prometheus
```

Run `sm-agent` next to Prometheus with that token and no `-secret` flags. It then just keeps `tls.crt` and `tls.key` renewed in its output directory:

```bash
sm-agent -auth token -token-file prometheus.token -out /run/prometheus-sm \
         -addr sm-1.internal:8200,sm-2.internal:8200,sm-3.internal:8200 -ca /etc/sm/root.pem
```

## 2. Scrape configuration

```yaml title="prometheus.yml"
scrape_configs:
  - job_name: secrets-manager
    scheme: https
    metrics_path: /v1/sys/metrics
    tls_config:
      ca_file: /etc/sm/root.pem
      cert_file: /run/prometheus-sm/tls.crt
      key_file: /run/prometheus-sm/tls.key
    static_configs:
      - targets: ["sm-1.internal:8200", "sm-2.internal:8200", "sm-3.internal:8200"]
```

Scrape **every node**, not a load balancer: each node reports its own sealed, leader and certificate state. Scrapes aren't audited.

## 3. Alert rules

```yaml title="secrets-manager.rules.yml"
groups:
  - name: secrets-manager
    rules:
      - alert: SecretsNodeSealed
        expr: sm_sealed == 1
        for: 5m
        annotations: { summary: "{{ $labels.instance }} is sealed: share holders must unseal it" }

      - alert: SecretsNoLeader
        expr: sum(sm_leader) < 1
        for: 1m
        annotations: { summary: "No Raft leader: the cluster can't serve requests (lost quorum?)" }

      - alert: SecretsNodeDown
        expr: up{job="secrets-manager"} == 0
        for: 5m

      - alert: SecretsAuditForwardingBehind
        expr: sm_audit_forward_lag_bytes > 16 * 1024 * 1024
        for: 10m
        annotations: { summary: "Audit forwarding is behind; requests fail at 64 MiB" }

      - alert: SecretsNodeCertExpiring
        expr: sm_node_cert_expiry_seconds{cert="node"} < 14 * 86400
        annotations: { summary: "Node certificate expires in under 14 days" }

      - alert: SecretsIntermediateExpiring
        expr: sm_cert_expiry_seconds{cert="intermediate"} < 30 * 86400
        annotations: { summary: "Intermediate CA expires in under 30 days: services will stop getting certificates" }

      - alert: SecretsRotationFailing
        expr: increase(sm_rotation_failures_total[1h]) > 0
        annotations: { summary: "Rotation of {{ $labels.path }} failing at step {{ $labels.step }} (see smctl rotation get)" }

      - alert: SecretsServerErrors
        expr: sum(rate(sm_requests_total{code=~"5.."}[5m])) > 0.1
        for: 10m

      - alert: SecretsFrequentLeaderChanges
        expr: increase(sm_leader_changes[1h]) > 3
        annotations: { summary: "Leadership is flapping: check the network between nodes" }
```

All metrics are described in the [metrics reference](../reference/metrics.md).

## Health checks

| Use | Endpoint | Healthy |
|---|---|---|
| Load balancer (any node can serve) | `GET /v1/sys/health?standbyok` | `200` |
| "Is this node the leader?" | `GET /v1/sys/health` | `200` leader, `429` follower |
| Liveness (process up) | `GET /v1/sys/health?standbyok` | any response; `503` just means sealed |

!!! tip "Don't restart sealed nodes"
    A sealed node returns `503`. Restarting it doesn't help, and it will still be sealed. Make sure orchestration liveness probes don't treat `503` as dead.

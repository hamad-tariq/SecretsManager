# smd (server)

`smd` runs one node: Raft storage, the encryption barrier, the HTTPS API, and, on the leader, scheduled rotations and lease expiry.

## Synopsis

```bash
smd -id node-1 -data /var/lib/smd \
    -api-addr 10.0.0.1:8200 -raft-addr 10.0.0.1:8201 -rpc-addr 10.0.0.1:8202 \
    -cert /etc/smd/node-1.pem -key /etc/smd/node-1.key -ca /etc/smd/root.pem \
    -audit-forward collector.internal:6514 \
    -bootstrap
```

`-bootstrap` is for the first node's first start only. Other nodes use `-join 10.0.0.1:8202` on their first start instead. `-audit-forward` is optional but strongly recommended.

## Flags

| Flag | Default | Description |
|---|---|---|
| `-id` | *(required)* | Node ID. Must match the certificate's identity `spiffe://sm/node/<id>`. |
| `-data` | *(required)* | Data directory: Raft log, snapshots, state (`raft.db`, `snapshots/`) and the local audit log (`audit.log`). Created with mode 0700. |
| `-api-addr` | *(required)* | `host:port` for the HTTPS API. |
| `-raft-addr` | *(required)* | `host:port` for Raft traffic between nodes. |
| `-rpc-addr` | *(required)* | `host:port` for cluster RPC: joining, and followers forwarding requests to the leader. |
| `-cert` | *(required)* | Node certificate PEM (the leaf, optionally followed by the intermediate). |
| `-key` | *(required)* | Node private key PEM. |
| `-ca` | *(required)* | Root CA certificate PEM. The only trust anchor; the system trust store is never used. |
| `-bootstrap` | `false` | Form a new cluster. Use it on the first node, once. |
| `-join` | | RPC address of any existing member, on a new node's first start. |
| `-audit-forward` | | `host:port` of a syslog-over-TLS collector. Without it, `smd` logs a warning at startup. |
| `-audit-forward-ca` | the `-ca` file | CA that signed the collector's certificate. |
| `-audit-forward-max-lag` | `67108864` (64 MiB) | Bytes of audit log not yet forwarded, beyond which requests fail. |
| `-max-cert-lineage` | `720h` (30 days) | How long a service certificate can keep renewing after its last full login. |
| `-rotation-check` | `10s` | How often the leader looks for due rotations and expired leases. |
| `-version` | | Print the version and exit. |

## Startup sequence

1. Load the node certificate and the root CA; start the Raft and RPC listeners (node certificates only).
2. Bootstrap or join if asked; otherwise rejoin from the data directory.
3. Open the audit log, and start forwarding if configured.
4. Start the HTTPS API, **sealed**.
5. Wait for share holders to unseal.

The API serves `sys/health`, `sys/init`, `sys/unseal` and snapshot restore while sealed; everything else gets `503`.

## Logs

Structured logs go to **stderr** in `key=value` form (Go `slog` text):

```text
time=2026-09-24T14:56:50.648+05:00 level=WARN msg="audit log is not forwarded off this node (-audit-forward); a compromised node could rewrite its own log"
time=2026-09-24T14:56:50.649+05:00 level=INFO msg="node started" version=dev id=node-1 api=127.0.0.1:8210 raft=127.0.0.1:8212 rpc=127.0.0.1:8211
```

Secret values never appear in logs. Types that hold secrets print `[REDACTED]`, and database errors are scrubbed of connection strings.

## Health endpoint

`GET /v1/sys/health` needs no certificate. Use it for load balancers and liveness checks.

| Status | Meaning |
|---|---|
| `200` | Unsealed **leader**, or any unsealed node with `?standbyok` |
| `429` | Unsealed **standby** (follower). Use `?standbyok` if your balancer should send traffic to followers too; they forward to the leader. |
| `503` | Sealed |
| `501` | Not initialised |

```json
{"initialized":true,"sealed":false,"shares":3,"threshold":2,"progress":0,"leader":false,"standby":true}
```

`progress` is how many unseal shares a sealed node has received so far.

## TLS

- The API accepts **TLS 1.3 only**. Client certificates are verified against `-ca` when presented; routes that need one reject requests without.
- Every client certificate must chain to the root CA, and its identity is its single `spiffe://sm/...` URI.
- The node certificate must include every host name or IP clients use to reach this node.

## Running under systemd

```ini title="/etc/systemd/system/smd.service"
[Unit]
Description=Secrets Manager node
After=network-online.target
Wants=network-online.target

[Service]
User=smd
Group=smd
ExecStart=/usr/local/bin/smd -id node-1 -data /var/lib/smd \
  -api-addr 10.0.0.1:8200 -raft-addr 10.0.0.1:8201 -rpc-addr 10.0.0.1:8202 \
  -cert /etc/smd/node-1.pem -key /etc/smd/node-1.key -ca /etc/smd/root.pem \
  -audit-forward collector.internal:6514
Restart=on-failure
RestartSec=5
# Keys are kept in locked memory; core dumps would contain them.
LimitMEMLOCK=infinity
LimitCORE=0
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/smd

[Install]
WantedBy=multi-user.target
```

Remember that after every restart the node is sealed. See [Unseal after a restart](../runbooks/unseal-after-restart.md). For a full walkthrough, see [Deploy a production cluster](../guides/deploy-cluster.md).

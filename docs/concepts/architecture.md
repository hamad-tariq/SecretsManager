# Architecture

## Components

| Component | Language | Runs where | Role |
|---|---|---|---|
| `smd` | Go | 3 servers (Linux) | The server node: Raft storage, the encryption barrier, the HTTPS API, rotation and lease expiry. |
| `smctl` | Go | Operator laptops, the offline CA machine | CLI for everything an operator does: PKI, init/unseal, secrets, policies, operations. |
| `sm-agent` | Go | Next to each application | Logs in, keeps the service certificate renewed, writes secrets and database credentials to files. |
| `smclient` | Python | Inside Python applications | SDK: mTLS client with caching, background refresh and serving the last value on errors. |
| Sentinel | Python | Next to the audit collector | Reads the audit stream and raises alerts. Never talks to the cluster. |

## Runtime topology

```mermaid
flowchart TB
    subgraph clients["Clients"]
        APP["Applications<br/>(sm-agent / smclient / HTTPS)"]
        OPS["Operators<br/>(smctl, admin certificates)"]
    end

    subgraph cluster["Secrets cluster"]
        direction LR
        subgraph n1["smd node-1 (leader)"]
            API1["API :8200"]
            RPC1["RPC :8202"]
            RAFT1["Raft :8201"]
            DISK1[("bbolt<br/>ciphertext only")]
        end
        subgraph n2["smd node-2"]
            API2["API"]
            RPC2["RPC"]
            RAFT2["Raft"]
            DISK2[("bbolt")]
        end
        subgraph n3["smd node-3"]
            API3["API"]
            RPC3["RPC"]
            RAFT3["Raft"]
            DISK3[("bbolt")]
        end
        RAFT1 <--> RAFT2
        RAFT1 <--> RAFT3
        RPC2 -. "forward reads and writes" .-> RPC1
        RPC3 -. "forward" .-> RPC1
    end

    APP -->|mTLS| API1 & API2 & API3
    OPS -->|mTLS| API1
    n1 & n2 & n3 -->|"audit (syslog/TLS)"| COL["Audit collector"] --> SEN["Sentinel"]
```

Each node listens on three ports. The numbers are only conventions; you choose them with flags.

| Port (example) | Flag | Who connects | Accepts |
|---|---|---|---|
| 8200 | `-api-addr` | applications, operators, load balancers | any certificate from the CA (TLS 1.3); `sys/health` and the login endpoints work without one |
| 8201 | `-raft-addr` | other nodes | node certificates of current members only |
| 8202 | `-rpc-addr` | other nodes (join, forwarding) | node certificates only; join is refused for removed node IDs |

## Layers inside a node

```mermaid
flowchart TB
    A["HTTPS API<br/>(internal/api)"] --> P["Policy engine<br/>(internal/policy)"]
    A --> AU["Audit log<br/>(internal/audit)"]
    A --> KV["Versioned KV<br/>(internal/kv)"]
    A --> ROT["Rotation engine<br/>(internal/rotation)"]
    A --> LE["Leases<br/>(internal/lease)"]
    A --> PKI["CA and identities<br/>(internal/pki)"]
    KV & ROT & LE --> B["Barrier: encrypt/decrypt every value<br/>(internal/barrier)"]
    B --> C["Raft replication<br/>(internal/cluster)"]
    C --> S[("bbolt on local disk")]
```

- Everything **above** the barrier sees plaintext; everything **below** it (Raft, disks, snapshots) sees only ciphertext.
- The barrier works only while the node is **unsealed**. A sealed node holds no keys, so it can replicate data but can't read any of it.

## The request pipeline

Every API request passes the same checks, in this order. The first failure ends the request.

```mermaid
flowchart LR
    R([Request]) --> I{"Client<br/>certificate?"}
    I -- "missing (route needs one)" --> E401[401]
    I --> RL{"Rate limit<br/>50/s per identity"}
    RL -- exceeded --> E429[429]
    RL --> S{"Node<br/>sealed?"}
    S -- yes --> E503[503]
    S --> RV{"Certificate, lineage<br/>or identity revoked?"}
    RV -- yes --> E401b["401 certificate revoked"]
    RV --> PO{"Policy allows<br/>path + capability?"}
    PO -- no --> E403[403]
    PO --> A1["Audit: request record"]
    A1 -- "write fails" --> E500[500]
    A1 --> H[Handler]
    H --> A2["Audit: outcome record<br/>(values as HMACs)"]
    A2 -- "write fails" --> E500b["500, no data"]
    A2 --> OK([Response])
```

Things that follow from this order:

- **Policy is checked before existence.** A caller without access gets `403` whether or not the path exists, so secret names can't be probed.
- **Fail closed on audit.** If the log can't be written, the caller gets `500` and never the data. The same happens when audit forwarding falls too far behind (`-audit-forward-max-lag`).
- **Revocation beats policy.** A revoked certificate is refused even if it belongs to the root admin.

## Reading a secret, end to end

```mermaid
sequenceDiagram
    participant App as App (svc/orders-api)
    participant F as Follower node
    participant L as Leader node
    App->>F: GET /v1/kv/prod/orders/db (mTLS)
    F->>F: identity from certificate, rate limit, sealed?, revoked?, policy
    F->>F: audit "request"
    F->>L: consistent read (cluster RPC, mTLS)
    L->>L: confirm still leader, read ciphertext
    L-->>F: ciphertext
    F->>F: barrier decrypt (keyring term from the envelope)
    F->>F: audit "ok" + HMAC of the value
    F-->>App: {"path", "value", "version", "created"}
```

Reads are **linearizable**: the leader answers only after confirming it's still the leader, so a client never sees a value older than one it already wrote.

## Source layout

| Path | What |
|---|---|
| `cmd/smd`, `cmd/smctl`, `cmd/sm-agent` | the three binaries |
| `internal/crypto/aead` | XChaCha20-Poly1305 envelope |
| `internal/crypto/shamir` | Shamir secret sharing over GF(2⁸) |
| `internal/barrier` | key hierarchy, encryption of every value, seal/unseal/rekey |
| `internal/cluster` | Raft (hashicorp/raft + bbolt), join, forwarding, membership |
| `internal/storage` | the key/value interface every layer uses |
| `internal/api` | HTTPS server and request pipeline |
| `internal/policy` | policy parsing and evaluation |
| `internal/pki` | CA, certificates, identities |
| `internal/kv` | versioned secrets |
| `internal/rotation` | scheduled rotation and plugins |
| `internal/lease` | dynamic database users |
| `internal/audit` | hash-chained log, verification, forwarding |
| `internal/snapshot` | backup file format |
| `internal/metrics` | Prometheus text output |
| `internal/agent` | the logic behind `sm-agent` |
| `internal/secret` | a value type that refuses to print itself |
| `sdk/python` | `smclient` |
| `sentinel` | Sentinel |

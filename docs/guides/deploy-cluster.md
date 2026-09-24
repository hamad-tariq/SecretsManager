# Deploy a production cluster

This guide builds a three-node cluster the way it's meant to run: root CA offline, shares encrypted to their holders, audit forwarded off-host, nodes under systemd.

!!! warning "Read first"
    Secrets Manager hasn't been independently audited. Read the [threat model](../threat-model.md) and work through the [production checklist](../production-checklist.md) before storing anything valuable.

## What you need

| Item | Example |
|---|---|
| 3 Linux hosts in different failure domains | `sm-1.internal` (10.0.0.1), `sm-2.internal` (10.0.0.2), `sm-3.internal` (10.0.0.3) |
| An offline machine for the CA | an air-gapped laptop, or one never networked |
| Share holders | 5 people, each with an [`age`](https://age-encryption.org) key pair |
| At least one admin | alice, who will run `init` and become root admin |
| An audit collector host | `collector.internal` (see [Audit forwarding](audit-forwarding.md)) |
| Binaries | `smd` and `smctl` for Linux, built as in [Installation](../getting-started/installation.md) |

Plan the network:

| Port | From | To | Purpose |
|---|---|---|---|
| 8200/tcp | apps, operators, load balancer | every node | HTTPS API |
| 8201/tcp | the other nodes only | every node | Raft |
| 8202/tcp | the other nodes only | every node | cluster RPC |
| 6514/tcp | every node | collector | audit forwarding |

Firewall 8201 and 8202 so only the nodes reach them. They accept only node certificates anyway, but defence in depth is cheap.

## 1. Create the CA (offline machine)

```bash
smctl pki root-init -out ca/
smctl pki intermediate -ca-cert ca/root.pem -ca-key ca/root.key -out ca/
```

Node certificates must name every host clients use, and need `-ttl` (the default is 24 h):

```bash
for i in 1 2 3; do
  smctl pki issue -ca-cert ca/intermediate.pem -ca-key ca/intermediate.key \
        -kind node -name node-$i -host sm-$i.internal -host 10.0.0.$i -ttl 8760h -out certs/
done
smctl pki issue -ca-cert ca/intermediate.pem -ca-key ca/intermediate.key -kind admin -name alice -ttl 720h -out certs/
```

Copy to each node **only** its own `node-N.pem` and `node-N.key`, plus `root.pem`. Give alice `alice.pem`, `alice.key` and `root.pem`. `root.key` never leaves the offline machine; keep a second copy offline in another place.

## 2. Install on each node

```bash
sudo useradd --system --home /var/lib/smd --shell /usr/sbin/nologin smd
sudo install -m 0755 smd /usr/local/bin/smd
sudo install -d -o smd -g smd -m 0700 /var/lib/smd /etc/smd
sudo install -o smd -g smd -m 0600 node-1.pem node-1.key root.pem /etc/smd/
```

Disable swap, or encrypt it. Values and keys pass through memory, and only the keys are in locked pages.

## 3. systemd unit

```ini title="/etc/systemd/system/smd.service (node-1)"
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
  -audit-forward collector.internal:6514 -audit-forward-ca /etc/smd/collector-ca.pem
Restart=on-failure
RestartSec=5
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

## 4. Form the cluster

On **node-1 only**, the first start carries `-bootstrap`. Start it once by hand, or add the flag to the unit and remove it afterwards:

```bash
sudo -u smd /usr/local/bin/smd -id node-1 -bootstrap -data /var/lib/smd … # same flags as the unit
```

Then start node-2 and node-3 with `-join 10.0.0.1:8202` on their first start. From then on, `systemctl enable --now smd` on all three; nodes rejoin from their data directories.

!!! danger "Remove `-bootstrap` after the first start"
    `-bootstrap` does nothing on a node that already has data. But if node-1's data directory were ever wiped, a leftover `-bootstrap` would form a **second, separate cluster**. Remove it once the cluster exists; a rebuilt node-1 must `-join` instead (under a new ID; see [Lost node](../runbooks/lost-node.md)). Leaving `-join` in a unit is harmless.

Check from alice's machine:

```bash
export SM_ADDR=sm-1.internal:8200,sm-2.internal:8200,sm-3.internal:8200
export SM_CA=root.pem SM_CERT=alice.pem SM_KEY=alice.key
smctl operator members       # three voters and a leader
smctl operator status        # initialized: false, sealed: true on all three
```

## 5. Initialise with encrypted shares

Collect one `age` public key from each share holder (`age-keygen -o key.txt` prints it). Then:

```bash
smctl operator init -shares 5 -threshold 3 \
  -recipient age1holder1… -recipient age1holder2… -recipient age1holder3… \
  -recipient age1holder4… -recipient age1holder5… > init.json
```

Share *i* is encrypted to recipient *i*. Send each holder their share, then **delete `init.json`**. alice is now the root admin.

## 6. Unseal

Three holders each run, on their own machine, with any admin certificate:

```bash
age -d -i key.txt share.age | smctl operator unseal
```

```bash
smctl operator status        # sealed: false on all three
```

## 7. Finish the setup

```bash
smctl pki upload -cert ca/intermediate.pem -key ca/intermediate.key   # from the offline machine's copy
smctl snapshot save -out sm-$(date +%F).json && smctl snapshot verify sm-$(date +%F).json
```

Then:

- write policies and bind identities (see [Policies](../concepts/policies.md));
- issue per-person admin certificates, with policies narrower than root;
- consider [handing root](key-ceremonies.md#hand-root-admin-to-someone-else) to a break-glass admin whose key stays offline;
- set up [monitoring](monitoring.md), [backups](backups.md) and [Sentinel](audit-forwarding.md);
- rehearse the [runbooks](../runbooks/README.md), especially [Unseal after a restart](../runbooks/unseal-after-restart.md).

## Load balancing

Clients (`sm-agent`, `smclient`, `smctl`) accept several addresses and fail over themselves, so no load balancer is needed. If you use one, pass TLS through (don't terminate it; client certificates must reach the nodes) and health-check `GET /v1/sys/health?standbyok`, which returns `200` on any unsealed node.

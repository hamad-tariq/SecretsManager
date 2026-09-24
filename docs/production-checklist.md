# Production rollout checklist

For the team taking the secrets manager to production. Work through it in order, and tick each item only once someone has checked it. The runbooks in [runbooks/](runbooks/README.md) cover what to do when things go wrong afterwards.

## 1. Release

- [ ] Build from a tagged commit with `scripts/release.sh VERSION <signing-key>` on a clean machine, with the Go version pinned in `go.mod`.
- [ ] A second person rebuilds the same tag independently and gets an identical `SHA256SUMS` (the build is reproducible).
- [ ] `SHA256SUMS.sig` verifies against the release key in your `allowed_signers` (`ssh-keygen -Y verify`, see the script header). Hosts install only verified binaries.
- [ ] Container images are built from the verified binaries or `deploy/docker/Dockerfile` with a base image pinned by digest in your own registry. If you sign images (e.g. `cosign sign --key` with a key you hold), verify them at admission.
- [ ] `scripts/check.sh` passed on the release commit, including the race detector (`RACE=1`) and the Python tests.

## 2. PKI

- [ ] Root CA created with `smctl pki root-init` on an offline machine; its key never touches a networked host. A backup copy of the root key is stored offline, in a different location.
- [ ] Intermediate created offline and uploaded (`smctl pki upload`); the offline copy is protected like the root.
- [ ] Node certificates carry exactly the hosts clients use (DNS names or IPs).
- [ ] Admin certificates are issued per person, never shared, with a TTL of 30 days or less. Reissuing admin certificates is a calendar item.
- [ ] `smd -max-cert-lineage` chosen (default 30 days: services must log in fully again at least that often).

## 3. Cluster

- [ ] 3 nodes (or 5) in separate failure domains; Raft and RPC ports reachable only between nodes.
- [ ] Swap disabled or encrypted on nodes (key material and values in memory).
- [ ] Clocks synchronised (NTP): certificate validity, lease expiry, the audit log and Sentinel all depend on time.
- [ ] Load balancer health check uses `GET /v1/sys/health?standbyok`.
- [ ] `operator init` run by the intended root admin **before** any other admin can reach the cluster.

## 4. Shares

- [ ] Split into N ≥ 5 shares with threshold M ≥ 3, each encrypted to its holder's age key (`operator init -recipient ...`).
- [ ] Every holder has confirmed they can decrypt their share, and stores it offline, separately from the others.
- [ ] Holders know the unseal runbook and who to call; at least M holders can be reached at any time.
- [ ] A test seal and unseal has been done with the real holders.

## 5. Audit and alerting

- [ ] Every `smd` runs with `-audit-forward` to a collector with write-once storage, which the nodes can't alter.
- [ ] `sm_audit_forward_lag_bytes` alerts before it reaches `-audit-forward-max-lag` (requests fail past it).
- [ ] Sentinel runs next to the collector, read-only, with `--state` and a webhook to your alerting. `trusted_networks` and `admin_windows` are set for your networks and hours.
- [ ] **After two weeks of real traffic:** `sentinel replay` over those logs, false positives reviewed, thresholds tuned. (Sentinel's false-positive rate has only been measured on synthetic traffic.)
- [ ] Metrics scraped with a dedicated `svc/prometheus` identity limited to `sys/metrics`, and the alerts in [runbooks/README.md](runbooks/README.md) are wired up.

## 6. Backups and recovery

- [ ] `smctl snapshot save` scheduled daily; each file verified (`snapshot verify`) and its checksum recorded; copies on storage the nodes can't write to.
- [ ] A restore drill has been run on separate hosts with the real share holders ([runbooks/restore-from-backup.md](runbooks/restore-from-backup.md)), and it's on the calendar again (at least yearly, and after every rekey).

## 7. Access

- [ ] Policies are least-privilege: each service reads only its own paths; `sys/*` is granted to named admins only.
- [ ] `sys/revocations`, `sys/db-roles/*` and `sys/rotation/*` (which can point hooks and run SQL as the database admin) are granted like the root admin.
- [ ] Who revokes a certificate (`smctl cert revoke`) in an incident is decided in advance, and they have a certificate with that right.
- [ ] Rotation is configured for every static credential that supports it; database users use two alternating accounts.
- [ ] Every runbook has been rehearsed at least once.

## 8. Before going live, the remaining risks

Accepted and documented in [threat-model.md](threat-model.md) (Known gaps). Read them with whoever signs off, in particular:

- Values in process memory can be swapped or copied by the garbage collector (so: no swap).
- Snapshot checksums detect corruption, not a deliberate rollback of the file (so: write-once storage).
- No external penetration test yet. The 1.0 review was internal (see the plan, iteration 13).

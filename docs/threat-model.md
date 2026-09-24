# Threat model

Version 2, 2026-09-24 (1.0 security review, iteration 13). Update this file in any iteration that adds an attack surface (see the release gate in IMPLEMENTATION_PLAN.md §7.3).

## Assets

| Asset | Where it lives | Impact if exposed |
|---|---|---|
| Unseal key | Nowhere: rebuilt from shares during unseal/rekey, then wiped | Decrypts the stored root key |
| Root key | RAM (locked) of unsealed nodes; stored only encrypted by the unseal key | Every secret, past and present |
| Shamir shares | With share holders (offline), never on the cluster | M shares = the unseal key |
| Keyring (data encryption keys) | Raft storage, encrypted by the root key; RAM (locked) on unsealed nodes | Every secret |
| Secret values | Raft storage (encrypted); client memory; agent tmpfs files | That secret's target system |
| Root CA private key | Offline machine or hardware token | Attacker can mint any identity |
| Intermediate CA key | Raft storage, behind the barrier (uploaded with `smctl pki upload`) | Attacker can mint service identities until it's rotated |
| Enrollment tokens | Only a SHA-256 hash in storage; the token itself with the operator until used | One service certificate, once, within ≤ 1 h |
| Kubernetes reviewer token | Raft storage, behind the barrier | Can create TokenReviews in the Kubernetes cluster (not read secrets there) |
| Agent output (certificate, key, secret files) | Pod tmpfs volume, mode 0600, shared UID | That service's secrets and identity until certificate expiry |
| Database admin connection strings (rotation) | kv secrets referenced by rotation settings | Full control of those database users |
| Dynamic database credentials | Returned once to the requester (agent file on tmpfs); only a lease record (no password) in storage | That role's grants until the lease expires (≤ max TTL, enforced by PostgreSQL's VALID UNTIL too) |
| Pending rotation values | kv, labelled `pending` until the test passes | Readable by anyone with read on that secret, as `current` is |
| Service / admin / node certificates | Pods, operator machines, nodes | That identity's policy scope until expiry: services ≤ 72 h, admins ≤ 30 days, nodes ≤ 1 year |
| Audit log | Nodes + remote append-only host | Loss of forensics; tampering hides an attack |

## Trust boundaries

1. **Client → cluster**: mTLS, TLS 1.3. The client identity comes only from a certificate issued by our CA.
2. **Node ↔ node**: mTLS with node certificates for Raft and request forwarding.
3. **Cluster → disk**: everything above the storage layer is encrypted by the barrier. Disks, snapshots and backups are untrusted.
4. **Operator → cluster**: admin certificates; init, unseal, rekey and policy changes all go to the audit log. `sys/init` needs an admin certificate and makes that identity the root admin. `sys/unseal` needs an admin certificate too (any admin, even one with no bindings), so anonymous callers can't jam an unseal with junk shares; the shares are still the real credential. `sys/health` needs no certificate. Every certificate is checked against the revocation list (`sys/revocations`) before anything else.
5. **Cluster → Kubernetes API**: TokenReview calls only; the cluster trusts your K8s API server's answer about which service account a token belongs to.
6. **Audit stream → Sentinel**: one-way. Sentinel has no credentials for the cluster's write API.

## Assumptions

- Hosts run a supported, patched OS; swap is disabled or encrypted on secrets nodes.
- Fewer than M share holders collude.
- The offline root CA machine is never networked.
- Clock skew between nodes and clients is under 1 minute (certificate validity checks).

## Threats and mitigations

| Threat | Mitigation | Iteration |
|---|---|---|
| Stolen disk, snapshot or backup | Barrier encryption; root key stored only wrapped by the unseal key; restore needs M shares | 5, 11 |
| One node compromised while unsealed | Root key and keyring in locked memory; short-lived certs; seal-now; audit copy on another host | 1, 5, 11 |
| Stolen service certificate | 24 h TTL; least-privilege policies; source-IP alerts; revoke the certificate and all its renewals (`smctl cert revoke -cert`) or the whole identity; renewals stop 30 days after the last full login | 3, 6, 12, 13 |
| Stolen admin or root-admin certificate | Revocation list checked on every request; share holders hand root to another admin (`smctl operator root-admin`, needs M shares), after which the old root can be revoked | 13 |
| Removed node trying to come back | Its ID is banned cluster-wide on removal (Raft, RPC and join all refuse it); a replacement joins under a new ID | 13 |
| Someone who may configure rotation or DB roles reading other secrets through them | The `admin` path needs read permission on that secret; driver errors are scrubbed of connection strings before they're logged or stored | 13 |
| Insider holding one share | Threshold M ≥ 3; shares encrypted per holder; seal/unseal/rekey audited | 5 |
| Audit log tampering | Hash chain; `smctl audit verify` also requires the logger's exact encoding and, with `-head`, the collector's last record (catches truncation); the forwarder stops if the local log was cut back; Sentinel checks every record's hash | 2, 11, 13 |
| Network attacker | TLS 1.3 + mutual auth everywhere, including Raft | 3, 4, 6 |
| Brute force / path enumeration | Per-identity rate limits; LIST is its own capability; uniform 403 responses | 6 |
| Secrets leaking via logs, errors or debug output | `secret.Secret` type redacts itself in fmt, slog and JSON; canary-grep tests | 0, 13 |
| Weak randomness | `crypto/rand` only; gosec G404 fails CI on `math/rand` | 0 |
| Supply-chain compromise | Minimal, pinned dependencies; dev tools isolated in `tools/go.mod`; govulncheck in CI | 0 |
| Lost quorum or data | 3 nodes across failure domains; encrypted snapshots; DR drill | 4, 11 |
| Too many shares lost | N = 5, M = 3 tolerates losing 2; rekey when a holder leaves | 5 |

## Known gaps (accepted for now)

- `secret.Secret` bytes and ordinary secret values live on the normal Go heap and can be copied by the GC or swapped. Only the root key, keyring and pending shares are in locked memory (`memguard`). Shares also pass through the API as Go strings, which can't be wiped. Run nodes with swap disabled or encrypted.
- Storage key names (secret paths) are stored in plaintext. Don't put secrets in paths.
- Shamir `Combine` can't tell wrong shares from right ones; the barrier detects it by failing to decrypt the wrapped root key (AEAD tag), and reveals nothing about which share was wrong.
- Locked memory is a small per-process quota. The barrier keeps it at a constant 2–3 buffers; don't add per-secret locked buffers.
- Any node may forward writes (put, delete, remove-node) to the leader, so a compromised node can alter or remove data cluster-wide. That's inherent: a node holds the data anyway. Adding a node, though, requires that node's own certificate.
- `raft-boltdb/v2` compiles in the unmaintained `boltdb/bolt` for its one-off v1→v2 migration helper, which we never call. Revisit if an advisory lands against it.
- The intermediate CA key now lives behind the barrier so the cluster can issue service certificates. Keep the offline copy used to create it as protected as the root key.
- The leader sends new values to HTTP rotation hooks. A hook is trusted with exactly the secret it rotates. It must prove the configured SPIFFE identity with a certificate that isn't revoked, and redirects are never followed. Anyone who can change rotation settings (`sys/rotation/...` update) can point a hook at another service identity, so grant that like write access to the secret.
- Role grant statements are SQL run as the database admin. Whoever may write `sys/db-roles/...` (and, since 1.0, must also be able to read the admin credential) can run any SQL that admin can.
- A MySQL user issued dynamically has no expiry of its own; if the secrets cluster can't reach MySQL, an expired user keeps working until a drop succeeds. PostgreSQL users stop at their max TTL regardless (VALID UNTIL).
- A snapshot's checksum catches corruption, not a deliberate edit: someone with the file can drop keys or mix in values from an older snapshot and recompute the checksum. They can't forge or swap values, since every value is authenticated against its path, and they can't read anything without the shares. Keep snapshots on write-once storage and record each checksum when it's saved.
- Audit forwarding is plain syslog with no acknowledgements. A collector that dies without closing the connection can lose the lines in flight; the node's local file still has them. Use an acknowledging receiver (e.g. RELP) if that gap matters.
- Metrics scrapes aren't audited (they'd flood the log); they expose counts and states, never values or paths of secrets.
- `snapshot restore` works for any admin certificate, but only on a cluster with no data at all, the same trust as `init`. Don't expose a freshly started, empty cluster to untrusted admins.
- Sentinel sees what the audit log sees, no more. It can't catch a stolen credential used exactly like its owner uses it (same paths, same trusted network, normal volume), and its rules learn for 7 days, during which a newly created identity isn't compared with anything. An attacker who knows the thresholds can stay under them. It alerts; it never blocks.
- Sentinel's `trusted_networks` are a blind spot by design: a new address inside them isn't reported. Keep them to the pod network and VPN range.
- Rotation with a single database user (not two alternating users) breaks clients between `set` and their next refresh. Use two users for anything that can't tolerate that.
- A renewed certificate keeps its lineage's login time, and renewal is refused 30 days after it (`smd -max-cert-lineage`); the service must log in again (enrollment token or Kubernetes). Within those 30 days a stolen certificate can be renewed by the thief. `smctl cert revoke -cert FILE` covers that: it revokes the lineage, every certificate renewed from that login, including renewals already made. Revoking by `-serial` alone does not: it misses renewals.
- Anyone who can create TokenReview-valid tokens for a mapped service account in your Kubernetes cluster can get that service's identity. Keep the `roles` mapping narrow and Kubernetes RBAC tight.
- The revocation list is enforced by the API, not by TLS. The cluster's own Raft and RPC traffic doesn't consult it: take a compromised node out with `smctl operator remove-node`, which bans its ID. Uploading a new intermediate doesn't invalidate anything, since nodes trust whatever chains to the root CA. Replacing the root CA is still the only way to kill every outstanding certificate at once.
- The root admin can't be revoked while it is root. Share holders first hand root to another admin (M shares), then revoke the old one. Until then, protect the root admin's key like a share.
- The revocation list is one record, read on every request, like policies. Tens of thousands of entries would slow every request; revoke identities rather than thousands of serials. Serials drop off when their certificate expires, lineages a year after they can last renew.
- Whoever first reaches `sys/init` with an admin certificate becomes root admin. Initialise a new cluster before exposing it to other admins.
- Policy lookups read storage on every request (no cache), so removing access takes effect immediately, at some latency cost.
- govulncheck queries vuln.go.dev. Mirror the vulnerability DB locally for fully offline CI.
- Whoever can write to the audit collector can inject lines. Sentinel rejects any line whose hash doesn't match (`audit_forged`) and a broken link doesn't move its idea of the chain tip, so injected lines raise alerts but can't hide the real records. It can't stop the noise: have the collector accept syslog only from the nodes' certificates.
- There has been no external penetration test. The 1.0 review was internal (iteration 13 in the plan): 17 confirmed findings, all fixed and covered by tests.

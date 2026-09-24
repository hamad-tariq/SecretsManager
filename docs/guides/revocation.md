# Revoke access

There are four levers, from gentlest to strongest:

| Lever | Command | Takes effect | Effect |
|---|---|---|---|
| Remove permissions | `smctl identity unbind svc/x` | next request | The identity still authenticates but can do nothing. |
| Revoke a certificate lineage | `smctl cert revoke -cert leaked.pem` | next request | That certificate **and every renewal from the same login** are refused. The service can log in again (new lineage). |
| Revoke an identity | `smctl cert revoke -identity svc/x` | next request | Every certificate for that name is refused, and no new ones are issued. |
| Remove a node | `smctl operator remove-node node-3` | immediately | The node ID is banned from the cluster for good. |

## Revoking a leaked certificate

```bash
smctl cert revoke -cert leaked.pem -reason "INC-123: laptop stolen"
```

`-cert` sends the serial, the identity and the certificate's **login time**. A renewal keeps the login time of the enrollment or Kubernetes login it descends from, so this covers:

- the leaked certificate itself;
- renewals the thief already made from it;
- renewals anyone makes in future from the same login.

The legitimate service is usually in the same lineage, so it stops too and has to log in again (a new enrollment token, or a fresh Kubernetes login, which the agent does by itself). That starts a new lineage, which the revocation doesn't cover.

!!! warning "Don't use `-serial` for a stolen certificate"
    `-serial` revokes that one certificate. If the thief renewed it before you acted, the renewed copy has a different serial and keeps working. Use `-cert` (you need the certificate file), or `-identity`.

## Revoking an identity

When you don't know which certificate leaked, or an identity must never be trusted again:

```bash
smctl cert revoke -identity svc/orders-api -reason "INC-124: host compromised"
```

Every certificate for `svc/orders-api` is refused, and enrollment and Kubernetes login refuse to issue new ones. To restore the service, move it to a **new name** (`svc/orders-api-v2`) with its own binding. Unrevoking the old name would let stolen copies back in.

The root admin can't be revoked while it is root: [hand root to someone else](key-ceremonies.md#hand-root-admin-to-someone-else) first.

## The revocation list

```console
$ smctl cert revocations
{
  "identities": {
    "spiffe://sm/svc/orders-api": { "at": "2026-09-24T12:10:00Z", "by": "spiffe://sm/admin/alice", "reason": "INC-124: host compromised" }
  },
  "lineages": {
    "spiffe://sm/svc/billing-api@2026-09-20T08:00:00Z": { "at": "…", "by": "…", "reason": "INC-123", "until": "…" }
  },
  "serials": {
    "1f3a9c…": { "at": "…", "by": "…", "reason": "INC-123", "until": "2026-09-25T09:59:50Z" }
  }
}
```

- **Serials** drop off the list when their certificate would have expired anyway.
- **Lineages** drop off about a year after the lineage can last renew.
- **Identities** stay until removed.

Undo a mistake:

```bash
smctl cert unrevoke -serial 1f3a9c…
smctl cert unrevoke -identity svc/orders-api
smctl cert unrevoke -lineage "spiffe://sm/svc/billing-api@2026-09-20T08:00:00Z"
```

## Permissions

| Action | Needs |
|---|---|
| Revoke | `update` on `sys/revocations` |
| Unrevoke | `delete` on `sys/revocations` |
| List | `read` on `sys/revocations` |

Grant revoke rights in advance to whoever handles incidents, so it doesn't wait on the root admin.

## What revocation doesn't cover

- **Node-to-node traffic.** Raft and cluster RPC don't consult the list. Use `remove-node`, which bans the node ID.
- **Secrets already read.** Revocation stops future access. Rotate whatever the identity could read; see [Compromised service certificate](../runbooks/compromised-service-cert.md).
- **Database users already issued.** Revoke their leases: `smctl lease revoke-prefix db/<role>`.

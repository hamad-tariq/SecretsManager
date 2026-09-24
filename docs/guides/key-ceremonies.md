# Shares, rekey and root admin

Three procedures involve the **share holders**. Write down who holds a share, and rehearse these before you need them.

## Choosing N and M

| Setting | Default | Trade-off |
|---|---|---|
| **N** (shares) | 5 | More holders means more resilience to people being unavailable, and more people to trust |
| **M** (threshold) | 3 | Higher is safer against collusion, but harder to gather at 3 a.m. |

Rules of thumb:

- **M ≥ 3.** Two colluding people shouldn't be enough.
- **N − M ≥ 2.** You can lose two holders and still unseal.
- **Different people, different locations, different employers where possible.**
- A holder can hold at most **one** share.

## Distributing shares safely

Encrypt each share to its holder's [`age`](https://age-encryption.org) key at `init` (or `rekey`), so the operator running the command never sees them:

```bash
# each holder, once:
age-keygen -o ~/.sm-share-key.txt        # prints "Public key: age1…"; send that to the operator

# the operator:
smctl operator init -shares 5 -threshold 3 \
  -recipient age1alice… -recipient age1bob… -recipient age1carol… \
  -recipient age1dave… -recipient age1erin… > shares.json
```

Share *i* is encrypted to recipient *i*. Send each holder their (encrypted) share, then delete `shares.json`. Holders unseal with:

```bash
age -d -i ~/.sm-share-key.txt my-share.age | smctl operator unseal
```

## Rekey: when a holder leaves, or a share may be exposed

Rekey issues **new shares** (optionally with a new N and M) and invalidates the old ones. Data isn't re-encrypted, and unsealed nodes keep running.

```bash
smctl operator rekey -shares 5 -threshold 3 \
  -recipient age1… -recipient age1… -recipient age1… -recipient age1… -recipient age1…
# prompts for M *current* shares; the current holders enter them in turn (on one machine)
```

1. Gather M current holders (the departing holder doesn't need to take part).
2. Run the rekey with the **new** holders' `age` keys.
3. Distribute the new shares; confirm each holder can decrypt theirs.
4. **Take a new snapshot immediately.** Older snapshots need the **old** shares; keep a record of which shares open which backups.
5. Test: seal one node and unseal it with new shares.

!!! warning "The shares pass through one machine"
    During `rekey` (and `root-admin`), M current shares are typed into a single `smctl` process. Use a trusted, clean machine.

!!! danger "If rekey prints a warning"
    If rekey can't confirm the outcome of its storage write, it still prints the new shares **with a warning**. Keep **both** the old and the new shares until an unseal confirms which set works.

See also the [Compromised share holder](../runbooks/compromised-share-holder.md) runbook.

## Hand root admin to someone else

The admin who ran `init` is **root**: unrestricted access, regardless of policies. Share holders can move root to another admin:

```bash
smctl operator root-admin -identity admin/bob       # prompts for M current shares
smctl cert revoke -identity admin/alice             # now possible, if needed
```

```console
$ curl … https://sm-1.internal:8200/v1/sys/root-admin
{"root_admin":"spiffe://sm/admin/bob"}
```

- The authority is the **shares**, not a certificate. A stolen root certificate can neither keep root nor take it back.
- The new root must be an admin identity that isn't revoked.
- It's audited as `sys.root-admin.set`.

A good pattern is a **break-glass root**: hand root to an admin identity (e.g. `admin/breakglass`) whose certificate and key stay offline with the share holders. Day-to-day admins then get narrower policies.

## Rotating the encryption key

Independently of shares, add a new keyring term periodically (e.g. yearly) or after a suspected exposure of a node's memory:

```console
$ smctl operator rotate
{ "term": 2 }
```

New writes use the new term. Existing values stay readable and are re-encrypted with the new term the next time they're written.

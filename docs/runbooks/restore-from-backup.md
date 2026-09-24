# Restore from backup

For rebuilding the whole cluster: all nodes destroyed, lost quorum with data gone, or moving to new hosts. This procedure is exercised end to end by `TestDisasterRecovery` in `cmd/smd`.

You need:
- the snapshot file, and its checksum from when it was saved;
- share holders for the shares that were current **when the snapshot was taken** (a threshold of them);
- an admin certificate that chains to the root CA, plus node certificates for the new hosts.

Steps:

1. Check the file before anything else:

   ```sh
   smctl snapshot verify backup.json      # "ok: N keys, taken <time>, sha256 <hash>"
   ```

   Compare the sha256 with the one recorded when it was saved. A mismatch means the file changed: don't use it.
2. Start 3 new nodes with **empty** data directories, as for a new cluster (`-bootstrap` on the first, `-join` on the others). Don't run `operator init`.
3. Restore (any admin certificate can do this, and only while the cluster has no data):

   ```sh
   smctl snapshot restore backup.json
   smctl operator status                  # every node: initialized true, sealed true
   ```

4. Unseal with the snapshot's shares ([unseal-after-restart.md](unseal-after-restart.md)).
5. Verify:
   - `smctl kv get -reveal <a few known paths>`, and `kv history` on one of them;
   - a service can still read its secrets (its binding and policies came back with the data);
   - `smctl rotation get <path>` for rotated secrets;
   - the off-host audit copy of the old cluster verifies: export each node's lines from the collector and run `smctl audit verify <file>`.
6. Take a fresh snapshot of the rebuilt cluster.

What comes back: secrets with their history, policies, bindings, the root admin, the keyring (including every past rotation term), the intermediate CA, rotation settings and progress, database roles and leases, and enrollment tokens that were still unused. What doesn't: each node's local audit file (the off-host copy is the record) and anything written after the snapshot.

# Rolling upgrade of `smd`

Upgrading one node at a time keeps the cluster serving throughout. Each restarted node must be unsealed, so line up share holders beforehand (or upgrade during a window when they're available).

1. **Snapshot first:** `smctl snapshot save -out pre-upgrade.json && smctl snapshot verify pre-upgrade.json`.
2. Find the leader: `smctl operator members`.
3. **Upgrade the followers first**, one at a time. For each:
   1. Stop `smd` (SIGTERM: it finishes in-flight requests and wipes its keys).
   2. Replace the binary and start it with the same flags and `-data` directory.
   3. Unseal it ([unseal-after-restart.md](unseal-after-restart.md)).
   4. Wait until `smctl operator status` shows it unsealed and `sm_leader` still sums to 1 before the next node.
4. **Then the leader:** hand leadership over first, so no election happens while the leader is down.

   ```sh
   smctl operator step-down
   smctl operator members          # confirm the leader changed
   ```

   Then upgrade that node as in step 3.
5. Check: every node unsealed, one leader, a test `kv get` works, and no rise in `sm_requests_total{code="500"}`.

If an upgraded node fails to start or join, stop and roll that node back to the previous binary. Don't continue with the others. If the data directory itself is damaged, treat it as a lost node ([lost-node.md](lost-node.md)).

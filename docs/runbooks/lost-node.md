# Lost node

**Symptoms:** a node doesn't answer; the other two still have a leader (`sm_leader` sums to 1) and serve requests.

With 3 nodes, the cluster tolerates 1 lost node. It can't tolerate a second one until the first is replaced or removed, so act the same day.

1. Confirm what's left: `smctl -addr <a healthy node> operator members`. The dead node is still listed in `voters`.
2. If the node will come back soon (reboot, network blip): start `smd` again with the same `-data` directory and unseal it ([unseal-after-restart.md](unseal-after-restart.md)). It catches up from the leader by itself. You're done.
3. If it won't come back (disk gone, host retired), remove it so quorum is counted over the remaining nodes:

   ```sh
   smctl operator remove-node node-3
   smctl operator members          # node-3 is gone from voters and members
   ```

4. Replace it: issue a node certificate for the new host (`smctl pki issue -kind node -name node-4 -host <ip/dns> ...` on the offline CA machine), start `smd` with an empty `-data` directory and `-join <any member's rpc-addr>`, then unseal it. It receives all data through Raft.
5. Check `operator members` shows 3 voters, and that `sm_leader` sums to 1.

Use a new node ID (for example `node-4`) for a replacement unless the old node's data directory is truly gone. A second node with the same ID and different state confuses Raft.

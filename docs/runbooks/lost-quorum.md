# Lost quorum

**Symptoms:** no node is leader (`sm_leader` sums to 0); reads and writes time out with "no leader available"; `operator status` shows errors.

With 3 nodes, losing 2 means no majority: the survivor can't accept writes or serve consistent reads. That's deliberate, because a lone node might be the one cut off.

1. **Try to bring the lost nodes back first.** Restart them with their existing `-data` directories. As soon as 2 of 3 are up, they elect a leader. Then unseal them ([unseal-after-restart.md](unseal-after-restart.md)). Nothing is lost in this case.
2. If they can't come back (data gone), rebuild from the latest snapshot: [restore-from-backup.md](restore-from-backup.md). **Writes since that snapshot are lost.** Afterwards:
   - Every secret written or rotated after the snapshot must be written again. For rotated database passwords, run `smctl rotation now <path>` so the database and the store agree again.
   - Database users issued after the snapshot have no lease in the restored cluster. They still expire in PostgreSQL through `VALID UNTIL`; in MySQL, drop leftover `v_%` users by hand.
3. There is no "force a single survivor to become leader" command. It's the kind of emergency action that loses acknowledged writes silently, so we rebuild from a snapshot instead.

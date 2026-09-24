# Share holder leaves, or a share may have leaked

**Trigger:** a share holder leaves the company or changes role; a share (or the age key protecting it) may have been exposed.

One share alone reveals nothing, but it brings an attacker one step closer to the threshold. Rekeying makes every old share useless.

1. Gather current share holders to the threshold (e.g. 3 of 5). The departing holder doesn't need to take part.
2. Decide the new holders and their age public keys.
3. Rekey:

   ```sh
   # current shares one per line on stdin (each holder pastes theirs), new split as flags
   smctl operator rekey -shares 5 -threshold 3 -recipient age1... -recipient age1... ...
   ```

   The output has the new shares, each encrypted to its holder's age key. Hand each to its holder and have them confirm they can decrypt it. The data isn't re-encrypted, and the cluster stays unsealed throughout.
4. If the output carries a warning that the result is uncertain, **keep both the old and the new shares** until `smctl operator seal` on a test cluster, or a planned restart, shows which set works.
5. **Take a new snapshot.** Older snapshots still open with the *old* shares, so either destroy those snapshots or keep old shares under the same protection until the snapshots expire. If the departing holder could have kept a copy of an old snapshot, that snapshot plus old shares is still a risk; an `operator rotate` doesn't help there, because old snapshots carry the old keyring.
6. Record the rekey (time, participants) in the incident log. The audit log has a `sys.rekey` entry.

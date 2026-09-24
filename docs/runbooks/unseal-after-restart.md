# Unseal after a restart

**Symptoms:** `sm_sealed` is 1; services get 503 from that node; `smctl operator status` shows `"sealed": true`.

A node forgets its keys whenever it stops. That is by design: it can't serve anything until share holders unseal it again.

1. Check why it restarted (host reboot, crash, OOM) before unsealing. A restart you can't explain is a reason to look at the host first.
2. Check the rest of the cluster: `smctl operator status`. If most nodes are sealed and none is leader, all of them need unsealing. Do this runbook for all of them at once: `operator unseal` sends each share to every address in `SM_ADDR`.
3. Contact share holders until you reach the threshold (for example 3 of 5). Each holder needs an admin certificate (`SM_CERT`/`SM_KEY`). It can be one with no bindings, which can unseal and do nothing else. Each holder runs, on their own machine:

   ```sh
   smctl operator unseal        # prompts for the share without echoing it
   ```

   Shares encrypted to a holder's age key are decrypted first: `age -d -i key.txt share.age | smctl operator unseal`.
4. After the last share: `smctl operator status` shows `"sealed": false` on every node, and `sm_sealed` returns to 0.
5. If `unseal` says the share is invalid, stop. Don't let holders try shares at random. Unseal progress resets after 10 minutes of inactivity. Confirm each holder has the current share (after a rekey, old shares no longer work).

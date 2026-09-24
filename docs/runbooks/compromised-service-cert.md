# Compromised service certificate

**Trigger:** a service's `tls.key` (or the agent's output directory) may have been copied; a host running a service was breached; alerts show a service identity used from an unexpected IP.

A service certificate works for up to 24 hours and can renew itself, so waiting for it to expire doesn't help. Cut access first, then clean up.

1. **Cut access now.** Both options take effect on the next request.
   - If you have the leaked certificate file, revoke it and every certificate renewed from the same login, including renewals the thief already made:

     ```sh
     smctl cert revoke -cert leaked.pem -reason "INC-123"
     ```

     The service's own copy is usually from the same login, so it stops too and must log in again (step 5). Don't use `-serial` here: it misses renewals.
   - If you don't know which certificate leaked, revoke the whole identity:

     ```sh
     smctl cert revoke -identity svc/orders-api -reason "INC-123"
     ```

   `smctl cert revocations` lists what is revoked. Also remove the binding (`smctl identity unbind svc/orders-api`) if you want the name to have no access even after it's reinstated.
2. **Revoke its database users:** `smctl lease revoke-prefix db/<its role>`. This kills their sessions and drops the users.
3. **Rotate what it could read.** For each path in its policies: `smctl rotation now <path>` if rotation is configured, otherwise write a new value with `smctl kv put`. Treat every secret it could read as leaked.
4. **Find out what was done:** search the audit log (the off-host copy) for the identity (`spiffe://sm/svc/orders-api`) and the certificate serial, and look for unexpected source IPs.
5. **Restore the service** from a clean host with a new enrollment token or Kubernetes login. A new login starts a new lineage, which the revocation in step 1 doesn't cover. Bind the policies again if you removed them.
   - If you revoked by `-cert`: nothing else to do.
   - If you revoked the identity: don't unrevoke it, because that would let the thief's copy back in. Move the service to a new name (`svc/orders-api-v2`) and leave the old name revoked. Stolen copies stop renewing at most 30 days after their login, and the revocation entry can go after that plus 72 hours.

   Uploading a new intermediate does **not** invalidate certificates already issued, because the nodes trust anything that chains to the root CA. Only replacing the root CA does, and that means re-issuing every certificate, so keep it for a CA compromise.

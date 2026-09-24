# Concepts

These pages explain how Secrets Manager works and why it's built that way. You don't need them to follow the tutorials, but you do need them to run it safely.

<div class="grid cards" markdown>

-   :material-sitemap: __[Architecture](architecture.md)__

    The components, the ports, and the path every request takes.

-   :material-lock-outline: __[Encryption and sealing](encryption-and-sealing.md)__

    The key hierarchy, the barrier, Shamir shares, init, unseal, seal, rekey and key rotation.

-   :material-card-account-details-outline: __[Identities and PKI](identities.md)__

    Certificates as identities, the CA hierarchy, enrollment, Kubernetes login, renewal and revocation.

-   :material-shield-key-outline: __[Policies](policies.md)__

    Deny-by-default access control: capabilities, path patterns, bindings, and the root admin.

-   :material-history: __[Secrets and versions](secrets.md)__

    Versioned key/value secrets, labels, check-and-set, soft delete.

-   :material-server-network: __[Clustering](clustering.md)__

    Three nodes with Raft: quorum, leaders, forwarding, membership.

-   :material-file-document-check-outline: __[Audit log](audit.md)__

    The hash chain, value fingerprints, failing closed, and off-host forwarding.

</div>

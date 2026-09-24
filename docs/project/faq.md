# FAQ

??? question "Is it ready for production?"
    Not yet. The code is complete for its scope and well tested: about 130 Go test functions, 34 Python tests, a disaster-recovery drill, and real-database rotation tests. An internal security review found 17 issues, all fixed. But it has had **no independent audit or penetration test**. Use it for learning, labs and non-critical systems.

??? question "What happens when a node restarts?"
    It comes back **sealed** and serves nothing until M share holders unseal it. The other nodes keep serving meanwhile. There's no auto-unseal, by design: the unseal key never touches disk. See [Unseal after a restart](../runbooks/unseal-after-restart.md).

??? question "What if we lose the unseal shares?"
    With fewer than M shares, **nobody can ever decrypt the data**, including the author. There's no backdoor. Keep shares with different people and rekey when someone leaves ([Shares, rekey and root admin](../guides/key-ceremonies.md)).

??? question "Can a single admin read every secret?"
    Only the **root admin** can, and root can be handed to a break-glass identity by the share holders. Other admins can do exactly what their policies allow. Every access, by anyone, is in the tamper-evident audit log.

??? question "Why certificates instead of tokens or passwords?"
    A private key never leaves the machine it was generated on, a certificate expires by itself, and an identity is bound to it cryptographically. There's nothing reusable to paste into a chat or leak in a log. `sm-agent` handles the renewals.

??? question "Does it need Kubernetes?"
    No. Kubernetes login is optional; VMs, Docker hosts and bare metal use enrollment tokens. See [Onboard a service](../guides/onboard-service.md).

??? question "Which languages can use it?"
    Any. `sm-agent` writes secrets to files, and the API is plain HTTPS with a client certificate. There's a Python SDK, and Go and Node.js examples in [Other languages](../guides/other-languages.md).

??? question "Which databases can it rotate or issue users for?"
    PostgreSQL and MySQL. Anything else can be rotated through the HTTP hook plugin, which calls a small service you write ([Rotate secrets](../guides/rotation.md#http-hook-protocol)).

??? question "Does it phone home or need internet access?"
    No. It contacts only what you configure: your other nodes, your Kubernetes API, your databases, your rotation hooks and your audit collector. There's no telemetry. (The development checks' `govulncheck` queries the public Go vulnerability database; mirror it for offline CI.)

??? question "How does it compare to HashiCorp Vault or OpenBao?"
    Those are mature, widely deployed and far broader: many secret engines, auth methods and plugins, plus a UI. Secrets Manager is deliberately small: key/value secrets, certificate identities, rotation, dynamic database users, audit and built-in alerts, with no external dependencies, in a codebase you can read in a day. If you need a proven product today, use one of those.

??? question "Why is there no web UI?"
    A UI adds a large attack surface and wasn't needed to prove the core. It may come later if there's demand.

??? question "Does it run on Windows or macOS?"
    For development and trying it out, yes. Production release builds target Linux (amd64 and arm64).

??? question "How do applications notice a rotated secret?"
    `sm-agent` rewrites the file within its refresh interval (5 minutes by default), and the Python SDK's `on_rotate` callback fires on the next background refresh. With two alternating database users, the previous credential keeps working until the next rotation, so there's no rush.

??? question "Why is it called Secrets Manager? Is it related to AWS Secrets Manager?"
    It's a descriptive name. The project is independent and not affiliated with AWS, HashiCorp or any other vendor.

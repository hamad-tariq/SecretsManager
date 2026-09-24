# Getting started

This section takes you from nothing to an application reading its secrets from a running cluster, in three steps:

1. **[Installation](installation.md)**: build the binaries, or get the Python SDK and Sentinel.
2. **[Quick start](quickstart.md)**: start a 3-node cluster on your machine with one script, then store, read, version and delete secrets.
3. **[Your first application](first-app.md)**: give an application its own identity and a policy, and have it read a secret in three different ways.

After that, the [concepts](../concepts/index.md) explain what happened under the hood, and the [how-to guides](../guides/index.md) cover real deployments.

## The vocabulary in one minute

| Term | Meaning |
|---|---|
| **Node** | One `smd` server process. A cluster is three of them, kept in sync with Raft. |
| **Sealed / unsealed** | A sealed node holds only ciphertext and can't serve anything. Unsealing rebuilds its master key from key *shares*. |
| **Share** | One piece of the unseal key. `init` creates N of them, and any M (the *threshold*) unseal a node. |
| **Barrier** | The encryption layer every stored byte passes through. |
| **Identity** | Who a caller is, taken from its certificate: `spiffe://sm/svc/<name>`, `spiffe://sm/admin/<name>` or `spiffe://sm/node/<name>`. |
| **Policy** | A named set of rules granting capabilities on path patterns. |
| **Binding** | The link from an identity to its policies. |
| **Root admin** | The admin identity with unrestricted access: whoever ran `init`, until share holders hand it to someone else. |
| **Enrollment token** | A single-use, short-lived token a new service exchanges for its first certificate. |
| **Lease** | The lifetime of a dynamic database user. It's renewed while in use and dropped when it ends. |

## What you need

| For | You need |
|---|---|
| Building the binaries | [Go](https://go.dev/dl/) at the version in `go.mod` (1.27) |
| The local quick start | Go, Python 3.10+, `curl`, and a Bash shell (Git Bash or WSL on Windows) |
| The Python SDK | Python 3.10+, nothing else (standard library only) |
| Sentinel | Python 3.11+, nothing else (standard library only) |
| A production cluster | Three Linux hosts (amd64 or arm64), and an offline machine for the root CA |

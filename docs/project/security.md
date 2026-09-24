# Security policy

!!! warning "Status"
    Secrets Manager has **not** had an external security audit or penetration test. Its only review so far was internal (17 findings, all fixed).

## Reporting a vulnerability

**Please don't open a public issue, discussion or pull request.** Report privately, by either:

- **GitHub private vulnerability reporting:** the repository's [Security tab → Report a vulnerability](https://github.com/hamad-tariq/SecretsManager/security/advisories/new), or
- **email:** [hammadt451@gmail.com](mailto:hammadt451@gmail.com), with `[SECURITY] Secrets Manager` in the subject.

Include the affected component and version, what an attacker needs and gains, and steps to reproduce.

| Step | Target |
|---|---|
| Acknowledgement | within 5 days |
| First assessment | within 14 days |
| Fix for high or critical issues | as fast as possible, usually within 90 days |
| Disclosure | coordinated with you, after a fix is released |

Fixes are published as GitHub Security Advisories and credited to the reporter. Good-faith research on clusters you run yourself is welcome, and no action will be taken against you for it.

## What's in scope

Everything in the repository. Weaknesses that require M colluding share holders, or the offline root CA key, are outside the threat model. The [threat model](../threat-model.md) lists the accepted gaps; showing that one is worse than described is in scope.

The full policy is in [SECURITY.md](https://github.com/hamad-tariq/SecretsManager/blob/main/SECURITY.md).

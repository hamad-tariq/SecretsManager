# Security policy

Secrets Manager is security software. Reports of weaknesses are very welcome, and they are handled privately and credited.

## Status

> [!WARNING]
> This project has **not** had an external security audit or penetration test. Its only review so far was internal (17 findings, all fixed; see `IMPLEMENTATION_PLAN.md`, iteration 13). Don't rely on it to protect production secrets until it has been independently reviewed.

## Supported versions

Only the latest release gets security fixes while the project is below 1.0.

| Version | Supported |
|---|---|
| latest 0.x | ✅ |
| older | ❌ |

## Reporting a vulnerability

**Please don't open a public issue, discussion or pull request for a security problem.** It would reveal the flaw before a fix exists.

Report it privately, by either:

- **GitHub private vulnerability reporting:** the repository's **Security** tab → **Report a vulnerability** (once it's enabled), or
- **email:** **hammadt451@gmail.com**, with `[SECURITY] Secrets Manager` in the subject.

Include what you can:

- the affected component (`smd`, `smctl`, `sm-agent`, Python SDK, Sentinel) and version or commit;
- what an attacker needs (network position, credentials, share holders…) and what they gain;
- steps or a proof of concept to reproduce it;
- any fix you'd suggest.

## What happens next

This is a one-maintainer project, so timings are best effort:

| Step | Target |
|---|---|
| Acknowledgement | within 5 days |
| First assessment (is it valid, how severe) | within 14 days |
| Fix or mitigation for high/critical issues | as fast as possible, usually within 90 days |
| Public disclosure | coordinated with you after a fix is released, or at 90 days if agreed |

Fixed vulnerabilities are published as GitHub Security Advisories (with a CVE where appropriate) and credited to the reporter unless you prefer otherwise.

## Scope

In scope: everything in this repository. That includes the cryptography (barrier, keyring, Shamir sharing), authentication and policy checks, the internal PKI, the Raft cluster protocol, the audit log's tamper evidence, the agent, the SDK, Sentinel, and the release scripts.

Out of scope:

- weaknesses that need M share holders to collude, or the offline root CA key, which are outside the threat model;
- problems only in the local try-out script (`scripts/try-local.sh`), which puts every key on one disk on purpose;
- denial of service needing an admin certificate;
- issues in third-party dependencies, which should go to their maintainers. Tell us too if it affects this project.

The threat model, with its list of accepted gaps, is in [docs/threat-model.md](docs/threat-model.md). A report showing that an "accepted" gap is worse than described is in scope.

## Safe harbour

If you act in good faith, respect this policy, test only against clusters you run yourself, and give reasonable time to fix before disclosing, you will not face any action from the maintainer for your research.

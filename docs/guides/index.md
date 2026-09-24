# How-to guides

Task-focused walkthroughs. Each assumes you've done the [quick start](../getting-started/quickstart.md), or have a cluster and an admin certificate.

| Setting up | |
|---|---|
| [Deploy a production cluster](deploy-cluster.md) | Three Linux hosts, an offline CA, systemd, init with encrypted shares |
| [Audit forwarding and alerts](audit-forwarding.md) | An rsyslog collector and Sentinel |
| [Monitoring](monitoring.md) | Prometheus scraping, health checks, alert rules |
| [Build and verify releases](releases.md) | Reproducible, signed builds |

| Connecting applications | |
|---|---|
| [Onboard a service (VM or Docker)](onboard-service.md) | Enrollment tokens and `sm-agent` as a service or sidecar container |
| [Kubernetes](kubernetes.md) | Service-account login, an init container plus sidecar, tmpfs files |
| [Other languages](other-languages.md) | Go, Node.js and plain HTTPS clients |

| Managing secrets | |
|---|---|
| [Rotate secrets](rotation.md) | Random values, PostgreSQL/MySQL passwords, HTTP hooks |
| [Dynamic database credentials](dynamic-credentials.md) | A database user per app instance, with leases |

| Operating | |
|---|---|
| [Backups and restore](backups.md) | Snapshots, verification, restore drills |
| [Shares, rekey and root admin](key-ceremonies.md) | Key ceremonies and handovers |
| [Revoke access](revocation.md) | Certificates, identities, lineages |

For incidents (a lost node, lost quorum, a leaked certificate), go straight to the [runbooks](../runbooks/README.md).

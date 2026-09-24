# sm-agent

`sm-agent` runs next to an application and turns the cluster into **files**. Any application in any language can then read secrets without code changes.

It:

1. **logs in**: it generates a key pair and exchanges an enrollment token or a Kubernetes service-account token for a 24 h service certificate;
2. **syncs**: it fetches each configured secret and writes it to a file, atomically, only when the version changed;
3. **renews**: at 2/3 of the certificate's lifetime it gets a fresh one. Under Kubernetes auth it falls back to a new login if renewal is refused (expired, or past the lineage limit);
4. **manages database credentials** (optional): it gets a per-instance database user for each configured role, renews the lease at 2/3 of its lifetime, and fetches new credentials once the lease can't be extended any more.

## Synopsis

```bash
sm-agent -addr sm-1:8200,sm-2:8200,sm-3:8200 -ca /etc/sm/ca.crt -out /run/secrets/sm \
         -auth kubernetes \
         -secret prod/orders/api-key=api-key \
         -db orders-rw=db.json \
         [-once]
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `-addr` | `$SM_ADDR` | Node API addresses, comma-separated. The agent tries them in order. |
| `-ca` | `$SM_CA` | Root CA PEM, used to verify the cluster. It's also copied to `ca.crt` in `-out`. |
| `-out` | `/run/secrets/sm` | Output directory, created with mode 0700. **Put it on tmpfs.** |
| `-auth` | `kubernetes` | `token` or `kubernetes`. |
| `-token-file` | | Enrollment token file (with `-auth token`). Surrounding whitespace is ignored. |
| `-jwt-file` | `/var/run/secrets/sm/token` | Projected service-account token (with `-auth kubernetes`). Re-read on every login, because the kubelet rotates it. |
| `-secret` | | `kvpath=filename`, repeatable. |
| `-db` | | `role=filename`, repeatable. Dynamic database credentials as JSON. |
| `-refresh` | `5m` | How often secrets are re-fetched. |
| `-once` | `false` | Log in, write the files and exit. For init containers. |
| `-version` | | Print the version and exit. |

## Files it writes

| File | Contents |
|---|---|
| `tls.crt` | Service certificate followed by the intermediate |
| `tls.key` | The private key, generated here and never sent anywhere |
| `ca.crt` | The root CA |
| `<name>` for each `-secret` | The secret's current value, as raw bytes |
| `<name>` for each `-db` | `{"username", "password", "lease_id", "expires", "max_expires"}` |

Every file is written to a temporary file and renamed into place (mode **0600**), so an application never reads a half-written file.

```json title="db.json (from -db orders-rw=db.json)"
{
  "username": "v_orders_rw_ff578dab55b2",
  "password": "…",
  "lease_id": "db/orders-rw/7867be7fdbfea795",
  "expires": "2026-09-24T13:00:00Z",
  "max_expires": "2026-09-25T12:00:00Z"
}
```

## Modes

=== "Sidecar / service (default)"

    Runs until `SIGTERM` or `SIGINT`. It checks every minute (or every `-refresh`, if shorter) whether the certificate needs renewing or leases need extending, and re-fetches secrets every `-refresh`.

    ```bash
    sm-agent -auth token -token-file /etc/sm/token -out /run/secrets/sm -secret prod/orders/db=db-password
    ```

=== "Init container (`-once`)"

    Logs in, writes everything, exits `0`. Pair it with a sidecar in the same pod so the certificate and secrets stay fresh.

    !!! warning
        Don't use `-db` with `-once` alone. Nobody would renew the lease, and the database user is dropped when it expires.

## Picking up changes in your application

When a rotation produces a new version, the agent rewrites the file within `-refresh`. Your application can:

- read the file on each use (simplest; the file is in memory);
- watch the file for changes (inotify, `fsnotify`, or Python `watchdog`);
- use the [Python SDK](python-sdk.md)'s `on_rotate` callback instead of files.

For database credentials, a new file means a new user; the old one keeps working until its own lease expires, so reconnect at your convenience.

## Logs

JSON on stderr, one object per line:

```json
{"time":"2026-09-24T14:59:50.92565+05:00","level":"INFO","msg":"certificate installed","path":"/v1/auth/enroll","not_after":"2026-09-25T09:59:50Z"}
{"time":"2026-09-24T14:59:50.9739941+05:00","level":"INFO","msg":"secret updated","path":"demo/db-password","file":"db-password","version":1}
```

## Running as a systemd service (VMs)

```ini title="/etc/systemd/system/sm-agent-orders.service"
[Unit]
Description=sm-agent for orders-api
After=network-online.target

[Service]
User=orders
ExecStart=/usr/local/bin/sm-agent -addr sm-1:8200,sm-2:8200,sm-3:8200 \
  -ca /etc/sm/root.pem -auth token -token-file /etc/sm/orders.token \
  -out /run/orders-secrets -secret prod/orders/db=db-password
# /run is tmpfs: the secrets never touch the disk.
RuntimeDirectory=orders-secrets
RuntimeDirectoryMode=0700
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

The enrollment token is only needed for the **first** login. After that the agent renews with its certificate, so you can delete the token file. If the agent is down long enough for the certificate to expire (24 h), create a new token.

See [Onboard a service](../guides/onboard-service.md) and [Kubernetes](../guides/kubernetes.md) for complete walkthroughs.

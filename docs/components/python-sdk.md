# Python SDK (`smclient`)

A single-file client with no dependencies beyond the standard library (Python 3.10+). It talks mTLS to the API, caches values, refreshes them in the background, and keeps serving the last known value for a while if every node is unreachable.

```bash
pip install ./sdk/python
# or: pip install "git+https://github.com/hamad-tariq/SecretsManager.git#subdirectory=sdk/python"
```

## Quick example

```python
from smclient import Client

sm = Client.from_agent_dir(["sm-1:8200", "sm-2:8200", "sm-3:8200"], "/run/secrets/sm")

db_password = sm.get("prod/orders/db")         # SecretStr
connect(password=db_password.reveal())

# React to rotations:
sm.on_rotate("prod/orders/db", lambda s: pool.reconnect(s.reveal()))
```

## Creating a client

```python
Client(addrs, cert, key, ca, *, ttl=300.0, max_stale=3600.0, timeout=10.0, background=True)
Client.from_agent_dir(addrs, path, **kw)   # uses path/tls.crt, path/tls.key, path/ca.crt
```

| Parameter | Default | Meaning |
|---|---|---|
| `addrs` | *(required)* | Node addresses `"host:port"`, tried in order. |
| `cert`, `key`, `ca` | *(required)* | PEM file paths: the service certificate (may include the intermediate), its key, the root CA. |
| `ttl` | `300` s | How long a cached value is used before it's fetched again. |
| `max_stale` | `3600` s | While **every** node is unreachable, cached values up to this age are still served (with a warning in the log). |
| `timeout` | `10` s | Per-request timeout. |
| `background` | `True` | Refresh cached secrets in a daemon thread every `ttl × 2/3`, so reads rarely wait. |

`from_agent_dir` is the usual choice: `sm-agent` keeps the certificate in that directory renewed, and the client **reloads it automatically** when the file changes.

The client is a context manager, and `close()` stops the background thread:

```python
with Client.from_agent_dir(addrs, "/run/secrets/sm") as sm:
    ...
```

## Reading secrets

```python
secret = sm.get("prod/orders/db")                    # current version, cached
old    = sm.get("prod/orders/db", label="previous")  # bypasses the cache
v3     = sm.get("prod/orders/db", version=3)         # bypasses the cache
print(secret.version)                                # 4
print(secret)                                        # SecretStr('**********')
password = secret.reveal()                           # the actual string
```

### `SecretStr`

A value that refuses to leak by accident:

- `str()`, `repr()` and logging print `SecretStr('**********')`;
- pickling raises `TypeError`;
- `.reveal()` returns the value, and `.version` the version number;
- instances compare equal when their values match.

## Rotation callbacks

```python
def reconnect(new: "SecretStr") -> None:
    pool.reconnect(password=new.reveal())

sm.on_rotate("prod/orders/db", reconnect)
```

When a background refresh sees a **new version**, each callback registered for that path is called with the new `SecretStr`. A callback that raises is logged and doesn't stop refreshing.

## Dynamic database credentials

Let `sm-agent -db role=file` manage the lease and read the file:

```python
from smclient import DBCredentials

creds = DBCredentials.from_file("/run/secrets/sm/db.json")
conn = psycopg.connect(host="db", user=creds.username, password=creds.password.reveal())
```

Or manage the lease yourself:

```python
creds = sm.db_creds("orders-rw", ttl="30m")   # a brand-new database user
# creds.username, creds.password (SecretStr), creds.lease_id, creds.expires, creds.max_expires
sm.renew_lease(creds.lease_id, increment="30m")   # never past max_expires
sm.revoke_lease(creds.lease_id)                   # drop the user now, e.g. on shutdown
```

Only the identity that got a lease can renew or revoke it.

## Errors

| Exception | When |
|---|---|
| `NotFound` | `404`: the path or lease doesn't exist |
| `PermissionDenied` | `401` or `403`: no certificate, revoked, or the policy doesn't allow it |
| `Unavailable` | No node could answer, and there's no cached value young enough to serve |
| `SecretsError` | Base class; any other error (`.status` holds the HTTP status) |

```python
from smclient import NotFound, PermissionDenied, Unavailable

try:
    key = sm.get("prod/orders/api-key")
except PermissionDenied:
    log.error("orders-api isn't allowed to read its API key: check its policy")
    raise
```

A node that answers `429` (rate limited) or `503` (sealed or busy) is skipped and the next address is tried.

## Logging

The SDK logs to the `smclient` logger, for example when serving a stale value or when a background refresh fails:

```python
import logging
logging.getLogger("smclient").setLevel(logging.INFO)
```

## Using it without the agent

Any certificate the cluster issued works, for example one from `smctl pki issue -kind svc` for a batch job:

```python
sm = Client(["sm-1:8200"], cert="job.pem", key="job.key", ca="root.pem", background=False)
```

Without the agent, nothing renews the certificate. Use this only for short-lived processes.

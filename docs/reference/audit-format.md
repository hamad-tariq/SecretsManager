# Audit record format

Each node writes `audit.log` in its data directory: one JSON object per line, append-only, mode 0600.

```json
{"seq":81,"time":"2026-09-24T11:50:24.7633959Z","request_id":"dfb1ef574df64574","identity":"spiffe://sm/admin/alice","op":"kv.read","path":"kv/prod/orders/api-key","result":"ok","source_ip":"127.0.0.1","cert_serial":"14835837262f13fab7bd1500ee815a6d","prev":"5aa9a9dcf39c7a09b27414a15e40c2b86e728e8da9f9827d347116a520a9732a","hash":"3ed2f611d8faf496c88e30db8998210786bbcf4cab8d038c279c5608f5ea187f"}
```

## Fields

Fields appear in this order. Empty optional fields are omitted.

| Field | Always | Description |
|---|:---:|---|
| `seq` | ✔ | Sequence number, starting at 1 for each node's log |
| `time` | ✔ | UTC, RFC 3339 with nanoseconds |
| `request_id` | | Random ID shared by a request's `request` and outcome records |
| `identity` | | Caller's identity (`spiffe://sm/…`); absent for unauthenticated calls; `k8s:ns/sa` during a Kubernetes login |
| `op` | ✔ | Operation name (see the [HTTP API](http-api.md)), or an internal operation such as rotation steps and lease expiry |
| `path` | | Policy path the request concerned |
| `result` | ✔ | `request`, then `ok`, `denied:<status>` (401, 403, 429) or `error:<status>` |
| `source_ip` | | Client address |
| `cert_serial` | | Client certificate serial, lowercase hex |
| `hmacs` | | For operations involving a secret value (KV reads and writes, dynamic credentials): `{"<field>": HMAC-SHA256(audit key, value)}` in hex. Never the value. |
| `prev` | ✔ | The previous record's `hash` (64 zeros for the first record) |
| `hash` | ✔ | This record's hash (below). Always the last field. |

## Hash computation

```text
hash = hex( SHA-256( bytes(prev) ‖ canonical_json(record without "hash") ) )
```

- `bytes(prev)` is the previous hash decoded from hex, 32 bytes.
- `canonical_json` is the compact JSON encoding the logger writes, with fields in the order above. In practice it's the line itself with the trailing `,"hash":"…"}` replaced by `}`.
- `smctl audit verify` recomputes every hash **and** requires each line to be byte-identical to the canonical encoding.

A verifier in a few lines of Python:

```python
import hashlib, json, re

HASHED = re.compile(r'(\{.*),"hash":"([0-9a-f]{64})"\}')
prev = "0" * 64
for n, line in enumerate(open("audit.log", encoding="utf-8"), 1):
    m = HASHED.fullmatch(line.strip())
    rec = json.loads(line)
    body, h = m.group(1) + "}", m.group(2)
    assert rec["prev"] == prev, f"line {n}: chain broken"
    assert hashlib.sha256(bytes.fromhex(prev) + body.encode()).hexdigest() == h, f"line {n}: modified"
    prev = h
print("ok, head", prev)
```

## Forwarded form

Forwarded records are wrapped in RFC 5424 syslog, with the node ID as HOSTNAME:

```text
<110>1 2026-09-24T11:50:24.763Z node-1 smd - - - {"seq":81,…}
```

Priority `110` is facility 13 (log audit), severity 6 (informational).

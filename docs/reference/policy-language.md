# Policy language

## Structure

```json
{
  "name": "orders",
  "rules": [
    { "path": "kv/prod/orders/*", "capabilities": ["read", "list"] },
    { "path": "kv/prod/orders/root-password", "deny": true }
  ]
}
```

| Field | Type | Rules |
|---|---|---|
| `name` | string | Required. 1–63 of `a-z 0-9 -`. Must match the URL when written. |
| `rules` | array | Required, at least one rule. |
| `rules[].path` | string | Required. A path pattern (below). |
| `rules[].capabilities` | array of strings | A non-empty list of capabilities. Set either this or `deny`. |
| `rules[].deny` | boolean | `true` to deny every capability on matching paths. |

Unknown fields anywhere are **rejected**, as are trailing data after the object, unknown capabilities, and rules with both or neither of `capabilities` and `deny`.

## Path patterns

A pattern is segments separated by `/`:

| Segment | Matches |
|---|---|
| literal (`A–Z a–z 0–9 . _ -`) | exactly that segment, case-sensitively |
| `+` | exactly one segment, whatever it is (any position) |
| `*` | one or more remaining segments (**last segment only**) |

Wildcards must be whole segments (`orders-*` is invalid), and `.`, `..` and empty segments are invalid.

| Pattern | `kv/prod/orders` | `kv/prod/orders/db` | `kv/prod/orders/a/b` | `kv/prod/billing/db` |
|---|:---:|:---:|:---:|:---:|
| `kv/prod/orders/db` | | ✔ | | |
| `kv/prod/orders/*` | | ✔ | ✔ | |
| `kv/prod/+/db` | | ✔ | | ✔ |
| `kv/prod/*` | ✔ | ✔ | ✔ | ✔ |
| `kv/*` | ✔ | ✔ | ✔ | ✔ |

## Capabilities

`read`, `list`, `create`, `update`, `delete`, `rotate`. See [Policies](../concepts/policies.md#capabilities) for what each allows; `rotate` is reserved.

## Evaluation

For a request by identity *I* for capability *C* on policy path *P*:

1. If *I* is the root admin: **allow**.
2. Load every policy bound to *I* (missing policies are skipped).
3. If any rule in any of them matches *P* and has `"deny": true`: **deny**.
4. If any rule matches *P* and lists *C*: **allow**.
5. Otherwise: **deny**.

There is no rule ordering and no "most specific wins".

## Policy paths by area

| Area | Policy path |
|---|---|
| Secret | `kv/<secret path>` |
| Listing all secrets | `kv` |
| Dynamic credentials | `db/creds/<role>` |
| Everything administrative | `sys/...` (see the [HTTP API](http-api.md) for each endpoint) |

# Quick start

Start a real 3-node cluster on `127.0.0.1` with one script. It creates a CA and certificates, starts the nodes, initialises and unseals the cluster, and stores a first secret. It takes about two minutes, most of it compiling.

!!! danger "For trying it out only"
    The script puts the root CA key, every certificate and all unseal shares in one folder (`try/`) on one disk. That's convenient for a demo, and exactly what a real deployment must never do. `try/` is in `.gitignore`.

## 1. Start the cluster

**You need:** Go (the version in `go.mod`), Python 3.10+, `curl`, and a Bash shell. On Windows, use Git Bash (it comes with Git for Windows) or WSL.

```bash
git clone https://github.com/hamad-tariq/SecretsManager.git
cd SecretsManager
scripts/try-local.sh
```

What it does, step by step:

| Step | What happens | Where it ends up |
|---|---|---|
| build | compiles `smd`, `smctl`, `sm-agent` | `try/bin/` |
| certificates | a root CA, an intermediate CA, three node certificates (1 year) and an admin certificate for **alice** (30 days) | `try/ca/`, `try/certs/` |
| start | node-1 forms the cluster (`-bootstrap`), then node-2 and node-3 join it | `try/data/node-N/`, `try/logs/` |
| init | alice runs `operator init -shares 3 -threshold 2` and becomes **root admin** | shares in `try/init.json` |
| unseal | two of the three shares are sent to every node | |
| first secret | `demo/db-password` = `hunter2` | |

The nodes listen on these ports:

| Node | API (HTTPS) | Cluster RPC | Raft |
|---|---|---|---|
| node-1 | `127.0.0.1:8210` | `8211` | `8212` |
| node-2 | `127.0.0.1:8220` | `8221` | `8222` |
| node-3 | `127.0.0.1:8230` | `8231` | `8232` |

## 2. Point the CLI at it

`smctl` reads its connection settings from environment variables:

=== "Bash / Git Bash / macOS / Linux"

    ```bash
    export PATH="$PWD/try/bin:$PATH"
    export SM_ADDR=127.0.0.1:8210,127.0.0.1:8220,127.0.0.1:8230
    export SM_CA=try/ca/root.pem SM_CERT=try/certs/alice.pem SM_KEY=try/certs/alice.key
    ```

=== "Windows PowerShell"

    ```powershell
    $env:PATH    = "$PWD\try\bin;$env:PATH"
    $env:SM_ADDR = "127.0.0.1:8210,127.0.0.1:8220,127.0.0.1:8230"
    $env:SM_CA   = "try\ca\root.pem"
    $env:SM_CERT = "try\certs\alice.pem"
    $env:SM_KEY  = "try\certs\alice.key"
    ```

```console
$ smctl operator members
{
  "leader": "node-2",
  "members": {
    "node-1": "127.0.0.1:8211",
    "node-2": "127.0.0.1:8221",
    "node-3": "127.0.0.1:8231"
  },
  "voters": ["node-1", "node-2", "node-3"]
}
```

## 3. Work with secrets

Values are never taken from command-line arguments (they'd end up in your shell history). `kv put` reads the value from a no-echo prompt, or from stdin when piped:

```console
$ printf 's3cret-v1' | smctl kv put prod/orders/db
{
  "version": 1
}
$ printf 's3cret-v2' | smctl kv put prod/orders/db
```

Reading hides the value unless you ask for it:

```console
$ smctl kv get prod/orders/db
{
  "created": "2026-09-24T11:50:11.8517945Z",
  "path": "prod/orders/db",
  "value": "(hidden; use -reveal)",
  "version": 2
}
$ smctl kv get -reveal prod/orders/db
s3cret-v2
$ smctl kv get -reveal -label previous prod/orders/db
s3cret-v1
```

Every write is a new version. `history` shows versions and labels, never values:

```console
$ smctl kv history prod/orders/db
{
  "created": "2026-09-24T11:50:11.3210429Z",
  "labels": { "current": 2, "previous": 1 },
  "latest": 2,
  "updated": "2026-09-24T11:50:11.8517945Z",
  "versions": [
    { "created": "2026-09-24T11:50:11.3210429Z", "version": 1 },
    { "created": "2026-09-24T11:50:11.8517945Z", "version": 2 }
  ]
}
```

List, delete (recoverable for 7 days), undelete, and destroy (gone for good):

```bash
smctl kv list prod
smctl kv delete prod/orders/db
smctl kv undelete prod/orders/db
smctl kv destroy prod/orders/db
```

## 4. Watch it survive failures

=== "A node dies"

    ```bash
    kill $(cat try/node-2.pid)      # stop one node (use the leader from `operator members`)
    smctl operator members          # another node became leader within seconds
    smctl kv get -reveal demo/db-password   # still served: 2 of 3 is a majority

    # Bring everything back (restarted nodes come up sealed; the script unseals them):
    scripts/try-local.sh stop && scripts/try-local.sh start
    ```

=== "Everything restarts"

    ```bash
    scripts/try-local.sh stop       # all nodes stop; data stays in try/
    scripts/try-local.sh start      # nodes come back SEALED, then the script unseals them
    smctl kv get -reveal demo/db-password
    ```

    In a real deployment, unsealing means reaching share holders. See [Unseal after a restart](../runbooks/unseal-after-restart.md).

=== "Seal on purpose"

    ```bash
    smctl operator seal -all        # every node forgets its keys immediately
    smctl kv get demo/db-password   # fails: 503, sealed

    # Unseal: two share holders each submit their share (here both come from try/init.json)
    python -c "import json; print(json.load(open('try/init.json'))['shares'][0])" | smctl operator unseal
    python -c "import json; print(json.load(open('try/init.json'))['shares'][1])" | smctl operator unseal
    smctl kv get -reveal demo/db-password
    ```

## 5. Look at the audit log

Every request above was written to each node's hash-chained audit log:

```console
$ smctl audit verify try/data/node-1/audit.log
ok: 77 records, head ae9dde023a49c561235a1f0c63f95b35dc8ca91ac49ba8a2959241e4d41df071
$ tail -1 try/data/node-1/audit.log
{"seq":77,"time":"2026-09-24T11:50:14.1201147Z","request_id":"c277d5bad2212af7","identity":"spiffe://sm/admin/alice","op":"sys.snapshot.save","path":"sys/snapshot","result":"ok","source_ip":"127.0.0.1","cert_serial":"14835837262f13fab7bd1500ee815a6d","prev":"39c34eb9…","hash":"ae9dde02…"}
```

Edit any character of any line and `audit verify` fails. Run Sentinel over the same log:

```bash
cd sentinel && python -m sentinel replay ../try/data/node-1/audit.log
```

## Stop or remove it

```bash
scripts/try-local.sh stop     # stop the nodes, keep the data
scripts/try-local.sh start    # start again (and unseal)
scripts/try-local.sh clean    # stop and delete try/ entirely
```

## Next

[Your first application :material-arrow-right:](first-app.md){ .md-button .md-button--primary }

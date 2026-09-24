# Other languages

The API is **plain HTTPS with a client certificate** and JSON bodies, so any language works. The easiest setup is to run [`sm-agent`](../components/sm-agent.md) next to the application and either:

- read the **secret files** it writes, which needs no client code at all; or
- use the **certificate files** it keeps renewed (`tls.crt`, `tls.key`, `ca.crt`) to call the API directly, as below.

Both examples below were run against a live cluster. Each reads `$SM_AGENT_DIR` (for example `/run/secrets/sm`) and prints the secret's version.

!!! important "Reload the certificate"
    `sm-agent` replaces the certificate about every 16 hours. Load `tls.crt` and `tls.key` **per connection** (as both examples do), or reload them when the files change, or the app will fail once the old certificate expires.

## Go

```go title="main.go"
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

type secret struct {
	Path    string `json:"path"`
	Value   string `json:"value"`
	Version int    `json:"version"`
}

func main() {
	dir := os.Getenv("SM_AGENT_DIR") // e.g. /run/secrets/sm, written by sm-agent
	caPEM, err := os.ReadFile(dir + "/ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    roots,
			// Re-read on every handshake, so certificates renewed by sm-agent are picked up.
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				c, err := tls.LoadX509KeyPair(dir+"/tls.crt", dir+"/tls.key")
				return &c, err
			},
		}},
	}

	resp, err := client.Get("https://127.0.0.1:8210/v1/kv/app/api-key")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("secrets manager: %s", resp.Status)
	}
	var s secret
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("version %d, %d bytes\n", s.Version, len(s.Value))
}
```

```console
$ SM_AGENT_DIR=/run/secrets/sm go run .
version 1, 5 bytes
```

## Node.js

```js title="secret.mjs"
import https from "node:https";
import fs from "node:fs";

const dir = process.env.SM_AGENT_DIR; // e.g. /run/secrets/sm, written by sm-agent

function getSecret(path) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: "127.0.0.1",
        port: 8210,
        path: `/v1/kv/${path}`,
        method: "GET",
        // Read the files on each call: sm-agent renews the certificate in place.
        cert: fs.readFileSync(`${dir}/tls.crt`),
        key: fs.readFileSync(`${dir}/tls.key`),
        ca: fs.readFileSync(`${dir}/ca.crt`),
        minVersion: "TLSv1.3",
        agent: false,
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () =>
          res.statusCode === 200
            ? resolve(JSON.parse(body))
            : reject(new Error(`secrets manager: ${res.statusCode} ${body}`)),
        );
      },
    );
    req.on("error", reject);
    req.end();
  });
}

const secret = await getSecret("app/api-key");
console.log(`version ${secret.version}, ${secret.value.length} bytes`);
```

```console
$ SM_AGENT_DIR=/run/secrets/sm node secret.mjs
version 1, 5 bytes
```

## Shell (curl)

```bash
curl --fail --silent --cert "$SM_AGENT_DIR/tls.crt" --key "$SM_AGENT_DIR/tls.key" \
     --cacert "$SM_AGENT_DIR/ca.crt" https://sm-1.internal:8200/v1/kv/app/api-key \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["value"])'
```

This works with curl built on OpenSSL (Linux, macOS). Windows' built-in `curl` uses Schannel, which can't load PEM client certificates.

## Other languages

Any HTTP client that can present a PEM client certificate and trust a custom CA will do:

- **Java / Kotlin:** convert to PKCS#12 for a `KeyStore` (`openssl pkcs12 -export -in tls.crt -inkey tls.key -out client.p12`), put `ca.crt` in a trust store, and reload when the files change.
- **.NET:** `X509Certificate2.CreateFromPemFile(tlsCrt, tlsKey)` for the client certificate, plus a custom validation callback that checks the chain against `ca.crt` only.
- **Rust:** `reqwest` with `Identity::from_pem` and `Certificate::from_pem`.

## What to call

| Need | Request |
|---|---|
| Read a secret | `GET /v1/kv/<path>` → `{"path", "value", "version", "created"}` |
| A specific version or label | `GET /v1/kv/<path>?version=3` or `?label=previous` |
| A database user | `POST /v1/db/creds/<role>` with optional `{"ttl": "30m"}` |
| Renew or revoke that user | `POST /v1/leases/renew` / `POST /v1/leases/revoke` with `{"lease_id": "…"}` |

Also:

- **Retries.** Try the next node on connection errors, `429` or `503`.
- **Other errors.** Don't retry on `401`, `403` or `404`.
- **Status codes.** Errors come back as `{"error": "…"}` with a meaningful status. See the [HTTP API reference](../reference/http-api.md).

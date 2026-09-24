# Onboard a service (VM or Docker)

For applications outside Kubernetes. The service proves who it is **once**, with a single-use enrollment token; after that, `sm-agent` renews its certificate by itself.

## 1. Admin: identity, policy, token

```bash
cat > billing.json <<'EOF'
{ "name": "billing", "rules": [
    { "path": "kv/prod/billing/*", "capabilities": ["read"] } ] }
EOF
smctl policy write billing billing.json
smctl identity bind svc/billing-api billing

smctl enroll token -service billing-api -ttl 30m
```

```json
{
  "expires": "2026-09-24T10:44:50Z",
  "service": "billing-api",
  "token": "smt_…"
}
```

Deliver the token to the host through your usual secure channel: configuration management, cloud-init user data, or an operator. It works **once** and expires after the TTL (maximum 1 h), so a leaked, used or expired token is worthless.

!!! tip "Let teams onboard their own services"
    Creating a token needs `create` on `sys/enroll-tokens/<service>`. Grant a team exactly the service names it owns:
    ```json
    { "name": "billing-team", "rules": [
        { "path": "sys/enroll-tokens/billing-api", "capabilities": ["create"] },
        { "path": "sys/enroll-tokens/billing-worker", "capabilities": ["create"] } ] }
    ```

## 2a. On a VM: systemd

```bash
sudo install -m 0755 sm-agent /usr/local/bin/
sudo install -d -m 0700 -o billing /etc/sm
sudo install -m 0600 -o billing root.pem /etc/sm/root.pem
printf '%s' 'smt_…' | sudo install -m 0600 -o billing /dev/stdin /etc/sm/billing.token
```

```ini title="/etc/systemd/system/sm-agent-billing.service"
[Unit]
Description=sm-agent for billing-api
After=network-online.target
Before=billing-api.service

[Service]
User=billing
ExecStart=/usr/local/bin/sm-agent -addr sm-1.internal:8200,sm-2.internal:8200,sm-3.internal:8200 \
  -ca /etc/sm/root.pem -auth token -token-file /etc/sm/billing.token \
  -out /run/billing-secrets \
  -secret prod/billing/stripe-key=stripe-key \
  -secret prod/billing/db-url=db-url
RuntimeDirectory=billing-secrets
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now sm-agent-billing
ls /run/billing-secrets        # ca.crt  db-url  stripe-key  tls.crt  tls.key
sudo rm /etc/sm/billing.token  # no longer needed once the first login succeeded
```

The application runs as the same user and reads `/run/billing-secrets/stripe-key`. `/run` is memory-backed, so secrets never touch the disk.

## 2b. With Docker Compose: a sidecar container

The agent and the application share a memory-backed volume:

```yaml title="compose.yaml"
services:
  sm-agent:
    image: registry.internal/sm-agent:0.1.0
    command:
      - -addr=sm-1.internal:8200,sm-2.internal:8200,sm-3.internal:8200
      - -ca=/etc/sm/root.pem
      - -auth=token
      - -token-file=/etc/sm/token
      - -out=/run/secrets/sm
      - -secret=prod/billing/stripe-key=stripe-key
    user: "10001:10001"
    volumes:
      - sm-secrets:/run/secrets/sm
      - ./sm/root.pem:/etc/sm/root.pem:ro
      - ./sm/billing.token:/etc/sm/token:ro
    restart: unless-stopped

  billing-api:
    image: registry.internal/billing-api:1.0.0
    user: "10001:10001"          # same UID: the files are mode 0600
    environment:
      SM_AGENT_DIR: /run/secrets/sm
      SM_ADDR: sm-1.internal:8200,sm-2.internal:8200,sm-3.internal:8200
    volumes:
      - sm-secrets:/run/secrets/sm:ro
    depends_on: [sm-agent]

volumes:
  sm-secrets:
    driver: local
    driver_opts: { type: tmpfs, device: tmpfs, o: "size=1m,uid=10001,mode=0700" }
```

Build the agent image with `docker build -f deploy/docker/Dockerfile --build-arg CMD=sm-agent -t registry.internal/sm-agent:0.1.0 .`.

## 3. Read the secrets

Any of the three ways in [Your first application](../getting-started/first-app.md#6-read-the-secret-from-your-app): the files, the [Python SDK](../components/python-sdk.md) with `Client.from_agent_dir(...)`, or [HTTPS from any language](other-languages.md).

## Lifecycle notes

- **Restarts.** The agent logs in once. After that it renews with its certificate, so restarts just continue.
- **If the agent is down for more than 24 h**, the certificate expires and can't be renewed. Create a new token and restart it.
- **After 30 days** (`-max-cert-lineage`), renewal is refused until the service logs in again with a fresh token. Plan a monthly re-enrollment (automate it in configuration management), or use [Kubernetes](kubernetes.md) login, which re-logs in by itself.
- **Decommissioning.** Remove the binding (`smctl identity unbind svc/billing-api`) and, if the host may be compromised, [revoke](revocation.md) the identity.

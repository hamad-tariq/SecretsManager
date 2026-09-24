# Build and verify releases

Release artifacts are **reproducible**: the same commit, built with the same Go version, gives byte-identical files. Anyone can rebuild a release and compare checksums. The checksum file is **signed** with an SSH key you hold, and no signing service is involved.

## Building a release

On a clean machine with exactly the Go version named in `go.mod`:

```bash
git checkout v0.1.0
scripts/release.sh v0.1.0 ~/.ssh/release_ed25519
```

```text
dist/v0.1.0/
├── smd-v0.1.0-linux-amd64        smd-v0.1.0-linux-arm64
├── smctl-v0.1.0-linux-amd64      smctl-v0.1.0-linux-arm64
├── sm-agent-v0.1.0-linux-amd64   sm-agent-v0.1.0-linux-arm64
├── smclient-v0.1.0.tar.gz        (Python SDK source)
├── sentinel-v0.1.0.tar.gz        (Sentinel source)
├── SHA256SUMS
└── SHA256SUMS.sig                (ssh-keygen -Y sign, namespace "sm-release")
```

What makes it reproducible:

- `-trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.version=…"` and `CGO_ENABLED=0`: no paths, build IDs, VCS stamps or timestamps.
- Tarballs with sorted names, a fixed owner and mtime, and no gzip timestamp.
- `GOTOOLCHAIN=local`. The script refuses to build with any Go version other than `go.mod`'s, and never downloads a toolchain.

## Verifying a release

**Anyone can check it came from the release key:**

```bash
# allowed_signers holds the project's public key:
#   release@example.internal namespaces="sm-release" ssh-ed25519 AAAA…
ssh-keygen -Y verify -f allowed_signers -I release@example.internal -n sm-release \
           -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c SHA256SUMS
```

**And that it matches the source,** by rebuilding it independently:

```bash
git checkout v0.1.0
scripts/release.sh v0.1.0            # no key: builds and prints the checksums only
diff dist/v0.1.0/SHA256SUMS downloaded/SHA256SUMS && echo "identical"
```

Install only binaries whose checksums verify. For a production rollout, have a **second person** do the independent rebuild (see the [production checklist](../production-checklist.md)).

## Container images

Build from the verified binaries or with `deploy/docker/Dockerfile` (a `FROM scratch` image with one static binary, running as UID 10001). Pin the base Go image by digest in your own registry. If you sign images, use a key you hold (e.g. `cosign sign --key`) and verify signatures at admission.

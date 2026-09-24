# Installation

Secrets Manager has five installable parts:

- three Go binaries: `smd`, `smctl` and `sm-agent`;
- two Python packages: the `smclient` SDK and Sentinel.

None of them needs anything at runtime beyond what's listed here.

## Go binaries

=== "From source (recommended)"

    ```bash
    git clone https://github.com/hamad-tariq/SecretsManager.git
    cd SecretsManager
    go build -o bin/ ./cmd/...      # builds bin/smd, bin/smctl, bin/sm-agent
    bin/smctl -version
    ```

    This needs the Go version in `go.mod`. The binaries are static; copy them wherever you need them.

=== "go install"

    ```bash
    go install github.com/hamad-tariq/SecretsManager/cmd/smd@latest
    go install github.com/hamad-tariq/SecretsManager/cmd/smctl@latest
    go install github.com/hamad-tariq/SecretsManager/cmd/sm-agent@latest
    ```

    The binaries land in `$(go env GOPATH)/bin`. `-version` prints `dev` for these builds.

=== "Signed release build"

    For production, build reproducible, signed artifacts yourself from a tagged commit:

    ```bash
    scripts/release.sh v0.1.0 ~/.ssh/release_ed25519
    ls dist/v0.1.0/
    # smd-v0.1.0-linux-amd64  smctl-v0.1.0-linux-amd64  sm-agent-v0.1.0-linux-amd64
    # (the same three for linux-arm64)
    # smclient-v0.1.0.tar.gz  sentinel-v0.1.0.tar.gz  SHA256SUMS  SHA256SUMS.sig
    ```

    See [Build and verify releases](../guides/releases.md) for how others can check your build is identical and signed.

=== "Container image"

    ```bash
    docker build -f deploy/docker/Dockerfile --build-arg CMD=sm-agent -t registry.internal/sm-agent:0.1.0 .
    docker build -f deploy/docker/Dockerfile --build-arg CMD=smd      -t registry.internal/smd:0.1.0 .
    ```

    The image is `FROM scratch` with one static binary, running as UID 10001. Set `--build-arg GO_IMAGE=` to a Go image mirrored in your own registry if builds must not pull from Docker Hub.

Check what you built:

```console
$ smd -version
smd dev
$ smctl -version
smctl dev
$ sm-agent -version
sm-agent dev
```

!!! info "Platforms"
    Production release builds target **Linux amd64 and arm64**. The binaries also build and run on Windows and macOS, which is fine for development and the local quick start.

## Python SDK (`smclient`)

Standard library only, Python 3.10+.

=== "From a clone"

    ```bash
    pip install ./sdk/python
    ```

=== "Straight from GitHub"

    ```bash
    pip install "git+https://github.com/hamad-tariq/SecretsManager.git#subdirectory=sdk/python"
    ```

=== "Vendored"

    It's a single file. Copy `sdk/python/smclient/__init__.py` into your project as `smclient/__init__.py`.

```python
from smclient import Client  # check the import works
```

## Sentinel

Standard library only, Python 3.11+.

```bash
pip install ./sentinel          # installs the `sentinel` command
sentinel -h
# or, without installing:
cd sentinel && python -m sentinel -h
```

## Uninstalling

Delete the binaries, then `pip uninstall smclient sentinel`. A node's state is entirely in its `-data` directory, and the local try-out cluster is entirely in `try/`.

## Next

[Quick start :material-arrow-right:](quickstart.md){ .md-button .md-button--primary }

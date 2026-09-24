#!/usr/bin/env sh
# Reproducible, signed release artifacts.
#
#   scripts/release.sh VERSION [SSH_SIGNING_KEY]
#
# Builds smd, smctl and sm-agent for linux/amd64 and linux/arm64, plus source
# tarballs of the Python SDK and Sentinel, into dist/VERSION/, writes
# SHA256SUMS, and signs it with your own SSH key (ssh-keygen -Y sign; no
# external service involved).
#
# Reproducible: the same commit built with the same Go version gives
# byte-identical files (no paths, build IDs, VCS stamps or timestamps).
# Anyone can rebuild and compare SHA256SUMS. Verify a signature with:
#
#   ssh-keygen -Y verify -f allowed_signers -I release@example.internal -n sm-release \
#       -s SHA256SUMS.sig < SHA256SUMS
#
# where allowed_signers holds: release@example.internal namespaces="sm-release" ssh-ed25519 AAAA...
set -eu
cd "$(dirname "$0")/.."
VERSION=${1:?usage: scripts/release.sh VERSION [ssh-signing-key]}
KEY=${2:-}
OUT="dist/$VERSION"
# Reproducibility needs the exact Go version, not just go.mod's minimum.
# GOTOOLCHAIN=local stops Go from downloading a different toolchain from
# outside to satisfy go.mod; use a locally installed matching version instead.
export GOTOOLCHAIN=local
want="go$(sed -n 's/^go //p' go.mod)"
have=$(go env GOVERSION)
[ "$have" = "$want" ] || { echo "release builds need $want (go.mod); this is $have" >&2; exit 1; }
rm -rf "$OUT"
mkdir -p "$OUT"

export CGO_ENABLED=0
for target in linux/amd64 linux/arm64; do
  for cmd in smd smctl sm-agent; do
    GOOS=${target%/*} GOARCH=${target#*/} go build -trimpath -buildvcs=false \
      -ldflags="-s -w -buildid= -X main.version=$VERSION" \
      -o "$OUT/$cmd-$VERSION-${target%/*}-${target#*/}" "./cmd/$cmd"
  done
done

# Deterministic tarballs: sorted names, fixed owner and mtime, no gzip timestamp.
for py in sdk/python:smclient sentinel:sentinel; do
  dir=${py%%:*}
  name=${py##*:}
  tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
      --exclude='__pycache__' --exclude='*.pyc' -C "$dir" -cf - . | gzip -9n > "$OUT/$name-$VERSION.tar.gz"
done

(cd "$OUT" && sha256sum -- * > SHA256SUMS)
if [ -n "$KEY" ]; then
  ssh-keygen -Y sign -q -f "$KEY" -n sm-release "$OUT/SHA256SUMS"
  echo "signed: $OUT/SHA256SUMS.sig"
fi
cat "$OUT/SHA256SUMS"

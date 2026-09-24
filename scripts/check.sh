#!/usr/bin/env sh
# Every quality gate, in one place. CI runs this; run it locally before pushing.
# RACE=1 enables the race detector (needs cgo/gcc; on by default in CI).
set -eu
cd "$(dirname "$0")/.."

tool() { go tool -modfile=tools/go.mod "$@"; }

echo "== gofmt";        test -z "$(gofmt -l .)" || { gofmt -l .; exit 1; }
echo "== vet";          go vet ./...
echo "== staticcheck";  tool staticcheck ./...
echo "== gosec";        tool gosec -quiet ./...
# Queries vuln.go.dev by default. Offline: mirror the DB and set GOVULNDB=file:///path.
echo "== govulncheck";  tool govulncheck ./...
echo "== test";         go test ${RACE:+-race} -cover ./...
# Python: the SDK (3.10+) and Sentinel (3.11+). Their live tests also run from Go above.
PY=${PYTHON:-$(command -v python3 || command -v python || true)}
test -n "$PY" || { echo "python 3.11+ is required (set PYTHON)"; exit 1; }
echo "== python";       (cd sdk/python && "$PY" -m unittest -q tests.test_smclient) && (cd sentinel && "$PY" -m unittest discover -q -s tests)

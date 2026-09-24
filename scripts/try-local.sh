#!/usr/bin/env bash
# Try the secrets manager on one machine: a 3-node cluster on 127.0.0.1.
#
#   scripts/try-local.sh          build, create certificates, start, init, unseal
#   scripts/try-local.sh stop     stop the nodes (data is kept in try/)
#   scripts/try-local.sh start    start the stopped nodes again (they come up sealed)
#   scripts/try-local.sh clean    stop and delete try/
#
# Everything lives in ./try: binaries, CA, certificates, node data, logs and
# the unseal shares. It's for trying things out only: the root CA key and all
# shares sit next to each other on disk, which defeats the point in production.
set -euo pipefail
cd "$(dirname "$0")/.."
T=try
EXE=$(go env GOEXE)
SMD=$T/bin/smd$EXE
SMCTL=$T/bin/smctl$EXE

node_ports() { # node number -> "api rpc raft"
	echo "82${1}0 82${1}1 82${1}2"
}

start_node() { # n [extra flags...]
	local n=$1
	shift
	read -r api rpc raft < <(node_ports "$n")
	mkdir -p "$T/data/node-$n" "$T/logs"
	"$SMD" -id "node-$n" -data "$T/data/node-$n" \
		-api-addr "127.0.0.1:$api" -rpc-addr "127.0.0.1:$rpc" -raft-addr "127.0.0.1:$raft" \
		-cert "$T/certs/node-$n.pem" -key "$T/certs/node-$n.key" -ca "$T/ca/root.pem" \
		"$@" >>"$T/logs/node-$n.log" 2>&1 &
	echo $! >"$T/node-$n.pid"
}

wait_api() { # n: until the node answers health (any state)
	local api
	read -r api _ _ < <(node_ports "$1")
	for _ in $(seq 100); do
		curl -sk -o /dev/null "https://127.0.0.1:$api/v1/sys/health" && return 0
		sleep 0.2
	done
	echo "node-$1 didn't start; see $T/logs/node-$1.log" >&2
	exit 1
}

stop_nodes() {
	for f in "$T"/node-*.pid; do
		[ -f "$f" ] || continue
		kill "$(cat "$f")" 2>/dev/null || true
		rm -f "$f"
	done
}

export SM_ADDR=127.0.0.1:8210,127.0.0.1:8220,127.0.0.1:8230
export SM_CA=$T/ca/root.pem SM_CERT=$T/certs/alice.pem SM_KEY=$T/certs/alice.key

unseal_all() {
	for i in 0 1; do # threshold 2 of 3
		python -c "import json,sys; print(json.load(open(sys.argv[1]))['shares'][$i])" "$T/init.json" | "$SMCTL" operator unseal >/dev/null
	done
}

case "${1:-up}" in
stop)
	stop_nodes
	echo "stopped; data kept in $T/ (scripts/try-local.sh start to bring it back)"
	exit 0
	;;
clean)
	stop_nodes
	sleep 1
	rm -rf "$T"
	echo "removed $T/"
	exit 0
	;;
start)
	for n in 1 2 3; do start_node "$n"; done
	for n in 1 2 3; do wait_api "$n"; done
	sleep 2 # let them elect a leader
	unseal_all
	"$SMCTL" operator status
	exit 0
	;;
up) ;;
*)
	sed -n '2,12p' "$0"
	exit 2
	;;
esac

[ -d "$T/data" ] && {
	echo "$T/ already exists: scripts/try-local.sh start (or clean to begin again)" >&2
	exit 1
}

echo "== build"
mkdir -p "$T/bin"
for c in smd smctl sm-agent; do go build -o "$T/bin/$c$EXE" "./cmd/$c"; done

echo "== certificates (normally on an offline machine)"
"$SMCTL" pki root-init -out "$T/ca" >/dev/null
"$SMCTL" pki intermediate -ca-cert "$T/ca/root.pem" -ca-key "$T/ca/root.key" -out "$T/ca" >/dev/null
issue() { "$SMCTL" pki issue -ca-cert "$T/ca/intermediate.pem" -ca-key "$T/ca/intermediate.key" -out "$T/certs" "$@" >/dev/null; }
# Without -ttl every certificate lasts 24 h: nodes may have up to 1 year, admins 30 days.
for n in 1 2 3; do issue -kind node -name "node-$n" -ttl 8760h -host 127.0.0.1 -host localhost; done
issue -kind admin -name alice -ttl 720h

echo "== start 3 nodes"
start_node 1 -bootstrap
wait_api 1
for n in 2 3; do
	start_node "$n" -join 127.0.0.1:8211
	wait_api "$n"
done
sleep 2

echo "== init (alice becomes root admin) and unseal"
"$SMCTL" operator init -shares 3 -threshold 2 >"$T/init.json"
unseal_all
"$SMCTL" operator status

echo "== first secret"
printf 'hunter2' | "$SMCTL" kv put demo/db-password
"$SMCTL" kv get -reveal demo/db-password

cat <<EOF

Cluster is up. In this shell (Git Bash), set:

  export PATH="\$PWD/$T/bin:\$PATH"
  export SM_ADDR=$SM_ADDR
  export SM_CA=$SM_CA SM_CERT=$SM_CERT SM_KEY=$SM_KEY

then try:  smctl kv list   |   smctl operator members   |   smctl -h
Logs: $T/logs/   Audit logs: $T/data/node-*/   Shares: $T/init.json
Stop: scripts/try-local.sh stop    Start again: scripts/try-local.sh start
EOF

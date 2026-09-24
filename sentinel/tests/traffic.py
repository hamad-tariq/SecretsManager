"""Synthetic audit traffic for testing Sentinel: two weeks of normal use by
two services and an admin, plus injectable attack scenarios.

Records are what the audit logger writes: a request and an outcome record per
operation, per-node hash chains, canonical JSON with real chain hashes.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone

DAY = 86400
START = datetime(2026, 8, 3, tzinfo=timezone.utc).timestamp()  # a Monday

ORDERS = "spiffe://sm/svc/orders-api"
BILLING = "spiffe://sm/svc/billing-api"
ALICE = "spiffe://sm/admin/alice"
POD_NET = "10.42.0.0/16"
VPN_NET = "10.8.0.0/24"


@dataclass
class Event:
    t: float
    identity: str
    op: str
    path: str
    result: str = "ok"
    ip: str = ""
    serial: str = ""
    tag: str = ""  # scenario name for injected events


@dataclass
class Pod:
    ip: str
    serial: str
    renew_at: float
    restart_at: float


@dataclass
class Traffic:
    events: list[Event] = field(default_factory=list)
    pods: dict[str, list[Pod]] = field(default_factory=dict)


def _serial(rng: random.Random) -> str:
    return f"{rng.getrandbits(64):x}"


def normal(days: int = 14, seed: int = 1) -> Traffic:
    rng = random.Random(seed)
    tr = Traffic()
    services = {
        ORDERS: (3, 60, ["kv/prod/orders/db", "kv/prod/orders/api-key", "kv/prod/orders/stripe"], "10.42.1."),
        BILLING: (2, 120, ["kv/prod/billing/db", "kv/prod/billing/ledger-key"], "10.42.2."),
    }
    end = START + days * DAY
    for ident, (npods, every, paths, net) in services.items():
        pods = []
        for _ in range(npods):
            pods.append(Pod(net + str(rng.randint(2, 250)), _serial(rng), START + 16 * 3600, START + rng.uniform(0.5, 1.5) * DAY))
        tr.pods[ident] = pods
        for pod in pods:
            t = START + rng.uniform(0, every)
            while t < end:
                if t >= pod.restart_at:  # rescheduled: new pod IP (same network), new certificate
                    pod.ip, pod.serial = net + str(rng.randint(2, 250)), _serial(rng)
                    pod.restart_at, pod.renew_at = t + rng.uniform(0.5, 1.5) * DAY, t + 16 * 3600
                    tr.events.append(Event(t, "", "auth.kubernetes", "/v1/auth/kubernetes", ip=pod.ip))
                if t >= pod.renew_at:
                    tr.events.append(Event(t, ident, "auth.renew", "/v1/auth/renew", ip=pod.ip, serial=pod.serial))
                    pod.serial, pod.renew_at = _serial(rng), t + 16 * 3600
                # Busier by day: the SDK cache refreshes more often under load.
                hour = int((t % DAY) // 3600)
                gap = every * (0.6 if 8 <= hour < 20 else 1.0) * rng.uniform(0.7, 1.3)
                tr.events.append(Event(t, ident, "kv.read", rng.choice(paths), ip=pod.ip, serial=pod.serial))
                if rng.random() < 0.0005:  # a stray request outside its policy
                    tr.events.append(Event(t + 1, ident, "kv.read", "kv/prod/other/x", "denied:403", pod.ip, pod.serial))
                t += gap

    # Alice works weekdays 09-17: policy tweaks, secret writes, reading around.
    admin_paths = [f"kv/prod/{a}/{b}" for a in ("orders", "billing", "shipping", "web") for b in ("db", "api-key", "token")]
    alice_serial = _serial(rng)
    for d in range(days):
        day = START + d * DAY
        if d % 7 >= 5:
            continue
        for _ in range(rng.randint(0, 6)):
            t = day + rng.uniform(9, 17) * 3600
            op = rng.choice(["kv.read", "kv.write", "sys.policy.write", "sys.binding.read"])
            path = rng.choice(admin_paths) if op.startswith("kv") else "sys/policies/orders"
            tr.events.append(Event(t, ALICE, op, path, ip="10.8.0." + str(rng.randint(2, 40)), serial=alice_serial))
        if d % 7 == 2:  # weekly backup, inside the window
            tr.events.append(Event(day + 10 * 3600, ALICE, "sys.snapshot.save", "sys/snapshot", ip="10.8.0.5", serial=alice_serial))
    tr.events.sort(key=lambda e: e.t)
    return tr


# ---- attack scenarios (each returns its events; all tagged) ----

def stolen_cert(tr: Traffic, t: float) -> list[Event]:
    """A live orders-api certificate and key, used from an outside host."""
    _, serial = _live(tr, ORDERS, t)
    return [Event(t + i * 20, ORDERS, "kv.read", p, ip="203.0.113.50", serial=serial, tag="stolen_cert")
            for i, p in enumerate(["kv/prod/orders/db", "kv/prod/orders/api-key", "kv/prod/orders/stripe"])]


def bulk_read(tr: Traffic, t: float) -> list[Event]:
    """A compromised orders-api pod reads everything it can reach, and tries what it can't."""
    ip, serial = _live(tr, ORDERS, t)
    ev = [Event(t + i * 2, ORDERS, "kv.read", f"kv/prod/orders/extra-{i}", ip=ip, serial=serial, tag="bulk_read")
          for i in range(20)]
    ev += [Event(t + 40 + i * 2, ORDERS, "kv.read", f"kv/prod/{s}/db", "denied:403", ip, serial, "bulk_read")
           for i, s in enumerate(["billing", "web", "shipping", "hr", "infra", "ci", "vpn", "mail", "ldap", "backup", "dns", "crm"])]
    return ev


def rate_spike(tr: Traffic, t: float) -> list[Event]:
    """A pod hammering the secrets it normally reads (e.g. exfiltration loop)."""
    ip, serial = _live(tr, BILLING, t)
    return [Event(t + i * 0.5, BILLING, "kv.read", "kv/prod/billing/db", ip=ip, serial=serial, tag="rate_spike")
            for i in range(1200)]


def admin_night(tr: Traffic, t: float) -> list[Event]:
    """Alice's certificate used at 03:00 on a Sunday."""
    return [Event(t + i * 30, ALICE, "kv.read", "kv/prod/orders/db", ip="10.8.0.7", serial="a11ce", tag="admin_night")
            for i in range(3)]


def _live(tr: Traffic, ident: str, t: float) -> tuple[str, str]:
    """(address, certificate serial) of the identity's most recent request before t:
    a pod that is running, with the certificate it holds at that moment."""
    last = [e for e in tr.events if e.identity == ident and e.op == "kv.read" and e.t <= t]
    return last[-1].ip, last[-1].serial


# ---- to audit records ----

def records(events: list[Event], nodes: int = 3, seed: int = 2) -> dict[str, list[dict]]:
    """Spread operations over nodes and build each node's chain: a request
    record and an outcome record per operation, like the API writes them."""
    rng = random.Random(seed)
    chains: dict[str, list[dict]] = {f"node-{i + 1}": [] for i in range(nodes)}
    last: dict[str, float] = {}  # a node's log is time-ordered (one lock, one clock)
    for e in sorted(events, key=lambda e: e.t):
        host = f"node-{rng.randint(1, nodes)}"
        for result, dt in (("request", 0.0), (e.result, 0.004)):
            chain = chains[host]
            prev = chain[-1]["hash"] if chain else "0" * 64
            seq = len(chain) + 1
            t = last[host] = max(e.t + dt, last.get(host, 0) + 1e-6)
            rec = {"seq": seq, "time": _iso(t)}
            for k, v in (("identity", e.identity), ("op", e.op), ("path", e.path), ("result", result),
                         ("source_ip", e.ip), ("cert_serial", e.serial)):
                if v or k in ("op", "result"):  # Go omits empty optional fields
                    rec[k] = v
            rec["prev"] = prev
            rec["hash"] = hashlib.sha256(bytes.fromhex(prev) + canonical(rec).encode()).hexdigest()
            chain.append(rec)
    return chains


def canonical(rec: dict) -> str:
    """The logger's encoding: compact JSON in field order, without "hash"."""
    return json.dumps({k: v for k, v in rec.items() if k != "hash"}, separators=(",", ":"))


def line(rec: dict) -> str:
    """A record as the logger writes it."""
    return json.dumps(rec, separators=(",", ":"))


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def interleave(chains: dict[str, list[dict]]) -> list[tuple[str, dict]]:
    """All nodes' records in time order, as a collector would receive them."""
    return sorted(((h, r) for h, rs in chains.items() for r in rs), key=lambda hr: (hr[1]["time"], hr[1]["seq"]))

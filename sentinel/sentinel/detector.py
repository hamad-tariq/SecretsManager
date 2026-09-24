"""Stage A of Sentinel: rules over the audit stream.

The detector works in *event time* (each record's own timestamp), so replaying
a recorded log gives exactly the alerts a live run would have given.

Records are the audit log's JSON lines (see internal/audit). Only outcome
records are judged; the "request" record written before each operation is
used for chain continuity only.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

HOUR = 3600
GENESIS = "0" * 64  # the prev of a chain's first record
# The logger writes each record in one exact encoding with "hash" last, and
# `smctl audit verify` rejects anything else, so the hashed body is the line
# minus its trailing hash field.
_HASHED = re.compile(r'(\{.*),"hash":"([0-9a-f]{64})"\}')


def hash_ok(raw: str, prev: str) -> bool:
    """Recompute a record's chain hash from its raw line: sha256(prev bytes || body)."""
    m = _HASHED.fullmatch(raw.strip())
    if not m:
        return False
    try:
        prev_bytes = bytes.fromhex(prev)
    except ValueError:
        return False
    return hashlib.sha256(prev_bytes + (m.group(1) + "}").encode()).hexdigest() == m.group(2)


@dataclass
class Config:
    learn_days: float = 7  # new-path / new-source rules stay quiet while an identity is new
    trusted_networks: list[str] = field(default_factory=list)  # e.g. the pod CIDR: new IPs there are normal
    spike_factor: float = 3  # alert when this hour exceeds factor x the identity's p99 hourly count
    spike_min: int = 50  # ... and at least this many requests (small numbers are noise)
    spike_min_history_hours: int = 24
    history_hours: int = 14 * 24
    bulk_new_paths: int = 5  # this many never-read paths within bulk_window is a bulk read
    bulk_window_s: int = 600
    denials: int = 10  # this many denials within denial_window is a probe
    denial_window_s: int = 300
    serial_window_s: int = HOUR  # one certificate seen from two IPs within this window
    # Maintenance windows for admin activity, in the given UTC offset.
    # Each: {"days": [0..6] (Mon=0), "start_hour": 8, "end_hour": 18}
    admin_windows: list[dict] = field(default_factory=lambda: [{"days": [0, 1, 2, 3, 4], "start_hour": 8, "end_hour": 18}])
    admin_utc_offset_hours: float = 0
    governance_ops: list[str] = field(default_factory=lambda: [
        "sys.init", "sys.unseal", "sys.seal", "sys.rekey", "sys.snapshot.save", "sys.snapshot.restore",
        "sys.pki.intermediate", "sys.cluster.remove"])
    dedup_s: int = HOUR  # same alert (rule + subject) at most once per this long

    @classmethod
    def load(cls, path: str | None) -> "Config":
        if not path:
            return cls()
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        unknown = set(raw) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"unknown config keys: {sorted(unknown)}")
        return cls(**raw)


@dataclass
class Alert:
    time: str
    rule: str
    severity: str  # critical | high | medium | info
    identity: str
    summary: str
    evidence: dict

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


def parse_time(s: str) -> float:
    return datetime.fromisoformat(s).timestamp()


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")


def p99(values: list[int]) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, math.ceil(0.99 * len(s)) - 1)]


class _Identity:
    def __init__(self, first_seen: float):
        self.first_seen = first_seen
        self.paths: set[str] = set()
        self.ips: set[str] = set()
        self.hours: dict[int, int] = {}  # hour number -> requests
        self.limit_hour = -1  # the hour `limit` was computed for
        self.limit: float | None = None  # spike threshold for that hour (None: not enough history)
        self.p99 = 0.0
        self.new_paths: deque[float] = deque()
        self.denials: deque[float] = deque()


class Detector:
    def __init__(self, cfg: Config | None = None):
        self.cfg = cfg or Config()
        self.nets = [ipaddress.ip_network(n) for n in self.cfg.trusted_networks]
        self.ids: dict[str, _Identity] = {}
        self.serials: dict[str, dict[str, float]] = {}  # cert serial -> {ip: last seen}
        self.chains: dict[str, tuple[int, str]] = {}  # host -> (seq, hash) of the confirmed chain tip
        self.pending: dict[str, str] = {}  # host -> hash of a record that arrived after a broken link
        self.sent: dict[str, float] = {}  # dedup key -> last alert time
        self.stats = {"records": 0, "duplicates": 0, "malformed": 0}

    # ---- entry point ----

    def feed(self, rec: dict, host: str = "", raw: str | None = None) -> list[Alert]:
        """Judge one audit record. Returns the alerts it raised. With `raw`
        (the record's JSON text, as read from the log), its hash is checked."""
        try:
            ts = parse_time(rec["time"])
            seq, op, result = int(rec["seq"]), rec["op"], rec["result"]
        except (KeyError, ValueError, TypeError):
            self.stats["malformed"] += 1
            return []
        out: list[Alert] = []
        if raw is not None and not hash_ok(raw, str(rec.get("prev", ""))):
            # Not what the logger wrote: edited, or injected by whoever can
            # write to the collector. Report it and don't let it move anything.
            self.stats["forged"] = self.stats.get("forged", 0) + 1
            self._alert(out, ts, "audit_forged", "critical", "", f"a record claiming to be {host or 'log'} seq {seq} fails its hash",
                        {"host": host, "seq": seq}, key=f"{host}|{seq}")
            return out
        chain = self._chain(rec, host, seq, ts, out)
        if chain == "duplicate":
            self.stats["duplicates"] += 1
            return out
        self.stats["records"] += 1
        if result == "request":
            return out

        ident = rec.get("identity") or ""
        ip = rec.get("source_ip") or ""
        subject = ident or f"ip:{ip}"
        st = self.ids.get(subject)
        if st is None:
            st = self.ids[subject] = _Identity(ts)
        learned = ts - st.first_seen >= self.cfg.learn_days * 86400
        path = rec.get("path") or ""

        if op in self.cfg.governance_ops:
            self._alert(out, ts, "governance", "info", subject, f"{op} ({result})",
                        {"op": op, "result": result, "source_ip": ip, "host": host}, key=f"{op}|{subject}")
        if result.startswith("denied"):
            self._denials(out, st, ts, subject, op, path, ip)
        if ident.startswith("spiffe://sm/admin/") and not self._in_window(ts):
            self._alert(out, ts, "admin_off_hours", "medium", ident, f"admin activity outside maintenance windows: {op}",
                        {"op": op, "path": path, "source_ip": ip})
        if not ident:
            return out  # the rest needs an identity (unauthenticated calls are covered by denials)

        self._rate(out, st, ts, ident)
        self._source(out, st, ts, ident, ip, rec.get("cert_serial") or "", learned)
        if result == "ok" and op in ("kv.read", "db.creds") and path:
            self._path(out, st, ts, ident, path, learned)
        return out

    # ---- rules ----

    def _chain(self, rec: dict, host: str, seq: int, ts: float, out: list[Alert]) -> str:
        """Audit chain continuity per host: a missing or edited line breaks the link."""
        last = self.chains.get(host)
        prev, h = rec.get("prev"), rec.get("hash", "")
        if last is None or prev == last[1]:
            self.chains[host] = (seq, h)  # links: the normal case
            self.pending.pop(host, None)
            return "ok"
        if seq == 1 and prev == GENESIS:
            # A new chain under a known name: a rebuilt node (e.g. after a
            # restore), or a wiped log. Follow it, and say so.
            self._alert(out, ts, "audit_restart", "high", "", f"audit chain of {host or 'log'} started over (was at seq {last[0]})",
                        {"host": host, "previous_seq": last[0]}, dedup=False)
            self.chains[host] = (seq, h)
            self.pending.pop(host, None)
            return "ok"
        if prev == self.pending.get(host):
            # The record after a break links to it: the break was real (lines
            # missing), already reported. Continue from here.
            self.chains[host] = (seq, h)
            del self.pending[host]
            return "ok"
        if seq <= last[0]:
            return "duplicate"  # re-sent by the forwarder after a reconnect
        # Broken link. Don't move the tip yet: if this record was injected
        # (say with a huge seq), the real records that follow still link to
        # the tip and are judged normally rather than dropped as "duplicates".
        self._alert(out, ts, "audit_gap", "critical", "", f"audit chain of {host or 'log'} broken after seq {last[0]}",
                    {"host": host, "last_seq": last[0], "next_seq": seq, "missing": seq - last[0] - 1}, dedup=False)
        self.pending[host] = h
        return "ok"

    def _denials(self, out, st, ts, subject, op, path, ip):
        d = st.denials
        d.append(ts)
        while d and d[0] < ts - self.cfg.denial_window_s:
            d.popleft()
        if len(d) >= self.cfg.denials:
            self._alert(out, ts, "denial_burst", "high", subject,
                        f"{len(d)} denied requests in {self.cfg.denial_window_s // 60} min",
                        {"last_op": op, "last_path": path, "source_ip": ip, "count": len(d)})

    def _rate(self, out, st, ts, ident):
        hour = int(ts // HOUR)
        if hour != st.limit_hour:  # new hour: drop old buckets, recompute the threshold once
            for h in [h for h in st.hours if h <= hour - self.cfg.history_hours]:
                del st.hours[h]
            first = max(int(st.first_seen // HOUR), hour - self.cfg.history_hours + 1)
            past = [st.hours.get(h, 0) for h in range(first, hour)]  # completed hours, zeros included
            st.limit_hour, st.limit = hour, None
            if len(past) >= self.cfg.spike_min_history_hours:
                st.p99 = p99(past)
                st.limit = max(self.cfg.spike_factor * st.p99, self.cfg.spike_min)
        st.hours[hour] = st.hours.get(hour, 0) + 1
        if st.limit is not None and st.hours[hour] > st.limit:
            self._alert(out, ts, "rate_spike", "high", ident, f"{st.hours[hour]} requests this hour, over {st.limit:.0f}",
                        {"this_hour": st.hours[hour], "p99_hourly": st.p99, "limit": st.limit})

    def _source(self, out, st, ts, ident, ip, serial, learned):
        # One service or node certificate lives on one pod/host; an admin's
        # laptop legitimately moves between addresses (new_source covers it).
        if serial and ip and not ident.startswith("spiffe://sm/admin/"):
            seen = self.serials.setdefault(serial, {})
            seen[ip] = ts
            for other in [o for o, t in seen.items() if t < ts - self.cfg.serial_window_s]:
                del seen[other]
            if len(seen) > 1:
                self._alert(out, ts, "cert_multiple_hosts", "high", ident,
                            f"one certificate used from {len(seen)} addresses: copied to another host?",
                            {"cert_serial": serial, "addresses": sorted(seen)}, key=f"{serial}")
        if ip and ip not in st.ips:
            st.ips.add(ip)
            if learned and not self._trusted(ip):
                self._alert(out, ts, "new_source", "high", ident, f"first request from {ip}",
                            {"source_ip": ip, "known_addresses": len(st.ips) - 1}, key=f"{ip}")

    def _path(self, out, st, ts, ident, path, learned):
        if path in st.paths:
            return
        st.paths.add(path)
        if not learned:
            return
        # One new path is only notable for services, whose access pattern is
        # fixed; admins browse. Many new paths at once is notable for anyone.
        if ident.startswith("spiffe://sm/svc/"):
            self._alert(out, ts, "new_path", "medium", ident, f"first read of {path}", {"path": path}, key=path)
        n = st.new_paths
        n.append(ts)
        while n and n[0] < ts - self.cfg.bulk_window_s:
            n.popleft()
        if len(n) >= self.cfg.bulk_new_paths:
            self._alert(out, ts, "bulk_read", "high", ident,
                        f"{len(n)} never-read paths in {self.cfg.bulk_window_s // 60} min",
                        {"count": len(n), "latest": path})

    # ---- helpers ----

    def _trusted(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.nets)

    def _in_window(self, ts: float) -> bool:
        local = datetime.fromtimestamp(ts, timezone.utc) + timedelta(hours=self.cfg.admin_utc_offset_hours)
        return any(local.weekday() in w["days"] and w["start_hour"] <= local.hour < w["end_hour"]
                   for w in self.cfg.admin_windows)

    def _alert(self, out, ts, rule, severity, identity, summary, evidence, key="", dedup=True):
        k = f"{rule}|{identity}|{key}"
        if dedup and ts - self.sent.get(k, -math.inf) < self.cfg.dedup_s:
            return
        self.sent[k] = ts
        out.append(Alert(iso(ts), rule, severity, identity, summary, evidence))

    # ---- persistence (learned baselines survive restarts) ----

    def state(self) -> dict:
        return {
            "ids": {k: {"first_seen": v.first_seen, "paths": sorted(v.paths), "ips": sorted(v.ips),
                        "hours": v.hours} for k, v in self.ids.items()},
            "serials": self.serials,
            "chains": self.chains,
            "sent": self.sent,
        }

    def load_state(self, s: dict) -> None:
        for k, v in s.get("ids", {}).items():
            st = _Identity(v["first_seen"])
            st.paths, st.ips = set(v["paths"]), set(v["ips"])
            st.hours = {int(h): c for h, c in v["hours"].items()}
            self.ids[k] = st
        self.serials = s.get("serials", {})
        self.chains = {h: (c[0], c[1]) for h, c in s.get("chains", {}).items()}
        self.sent = s.get("sent", {})


def parse_line(line: str) -> tuple[str, dict, str] | None:
    """Accept a bare audit JSON line or a syslog line ("<110>1 TS HOST smd - - - {json}").
    Returns (syslog host or "", record, the record's raw JSON), or None."""
    i = line.find("{")
    if i < 0:
        return None
    host = ""
    prefix = line[:i].split()
    if len(prefix) >= 3 and prefix[0].startswith("<"):
        host = prefix[2]
    raw = line[i:].rstrip("\r\n")
    try:
        rec = json.loads(raw)
    except ValueError:
        return None
    return (host, rec, raw) if isinstance(rec, dict) else None

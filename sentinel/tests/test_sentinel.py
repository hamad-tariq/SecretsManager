"""Sentinel tests. Standard library only: python -m unittest (from sentinel/)."""

import http.server
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import unittest.mock
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import traffic  # noqa: E402
from sentinel.__main__ import Sinks, main  # noqa: E402
from sentinel.detector import Alert, Config, Detector, parse_line  # noqa: E402
from traffic import ALICE, BILLING, DAY, ORDERS, POD_NET, START, VPN_NET  # noqa: E402

CFG = Config(trusted_networks=[POD_NET, VPN_NET])


def run(events, cfg=CFG, drop=None):
    """Feed events (as audit records spread over 3 nodes) through a detector.
    drop=(host, seq) removes one record first, as tampering would."""
    chains = traffic.records(events)
    if drop:
        host, seq = drop
        chains[host] = [r for r in chains[host] if r["seq"] != seq]
    det = Detector(cfg)
    alerts = []
    for host, rec in traffic.interleave(chains):
        alerts += det.feed(rec, host, traffic.line(rec))  # raw line: hashes are checked too
    return det, alerts


def ts(alert):
    return traffic.datetime.fromisoformat(alert.time).timestamp()


class Baseline:
    """Two weeks of normal traffic, generated once."""
    _tr = None

    @classmethod
    def get(cls):
        if cls._tr is None:
            cls._tr = traffic.normal(days=14)
        return cls._tr


class RuleTests(unittest.TestCase):
    def rec(self, t, ident, op="kv.read", path="kv/a", result="ok", ip="10.42.0.5", serial=None, seq=None, host="n1"):
        serial = serial or f"s-{ip}"  # one certificate per host unless a test says otherwise
        self.seq = getattr(self, "seq", 0) + 1
        return {"seq": seq or self.seq, "time": traffic._iso(START + t), "identity": ident, "op": op, "path": path,
                "result": result, "source_ip": ip, "cert_serial": serial, "prev": getattr(self, "prev", "0"),
                "hash": f"h{self.seq}"}

    def feed(self, det, rec, host="n1"):
        out = det.feed(rec, host)
        self.prev = rec["hash"]
        return out

    def test_learning_period_then_new_path_and_source(self):
        det = Detector(Config(learn_days=1))
        self.assertEqual(self.feed(det, self.rec(0, ORDERS)), [])
        self.assertEqual(self.feed(det, self.rec(3600, ORDERS, path="kv/b", ip="198.51.100.1")), [])  # still learning
        rules = [a.rule for a in self.feed(det, self.rec(DAY + 60, ORDERS, path="kv/c", ip="198.51.100.2", serial="s1"))]
        self.assertIn("new_path", rules)
        self.assertIn("new_source", rules)
        # Known path and address: quiet.
        self.assertEqual([a.rule for a in self.feed(det, self.rec(DAY + 120, ORDERS, path="kv/a", ip="198.51.100.2"))], [])

    def test_trusted_networks_and_admin_paths(self):
        det = Detector(Config(learn_days=0, trusted_networks=["10.42.0.0/16"]))
        self.feed(det, self.rec(0, ORDERS))
        self.assertEqual([a.rule for a in self.feed(det, self.rec(60, ORDERS, ip="10.42.9.9"))], [])
        det2 = Detector(Config(learn_days=0, admin_windows=[{"days": list(range(7)), "start_hour": 0, "end_hour": 24}]))
        self.feed(det2, self.rec(0, ALICE, path="kv/a"))
        self.assertEqual(self.feed(det2, self.rec(60, ALICE, path="kv/new")), [])  # admins browse

    def test_admin_window_with_offset(self):
        det = Detector(Config(admin_utc_offset_hours=5))  # 04:00 UTC Monday = 09:00 local
        self.assertEqual(self.feed(det, self.rec(4 * 3600, ALICE)), [])
        self.assertEqual([a.rule for a in self.feed(det, self.rec(14 * 3600, ALICE))], ["admin_off_hours"])  # 19:00 local

    def test_denial_burst_and_dedup(self):
        det = Detector(Config(denials=3, denial_window_s=60))
        rules = []
        for i in range(8):
            rules += [a.rule for a in self.feed(det, self.rec(i * 5, "", result="denied:401", ip="203.0.113.9"))]
        self.assertEqual(rules, ["denial_burst"])  # once, not per denial
        spread = Detector(Config(denials=3, denial_window_s=60))
        self.assertEqual([a for i in range(5) for a in self.feed(spread, self.rec(i * 100, ORDERS, result="denied:403"))], [])

    def test_rate_spike_uses_p99_of_history(self):
        det = Detector(Config(spike_min=10, spike_min_history_hours=24))
        for h in range(48):  # 20 requests every hour for two days
            for i in range(20):
                self.feed(det, self.rec(h * 3600 + i * 60, ORDERS))
        rules = [a.rule for i in range(61) for a in self.feed(det, self.rec(48 * 3600 + i, ORDERS))]
        self.assertEqual(rules, ["rate_spike"])  # crosses 3 x 20 = 60 once

    def test_certificate_on_two_hosts(self):
        det = Detector(Config())
        self.feed(det, self.rec(0, ORDERS, ip="10.42.0.5", serial="abc"))
        a = self.feed(det, self.rec(30, ORDERS, ip="10.42.0.6", serial="abc"))
        self.assertEqual([x.rule for x in a], ["cert_multiple_hosts"])
        self.assertEqual(a[0].evidence["addresses"], ["10.42.0.5", "10.42.0.6"])
        det2 = Detector(Config())
        self.feed(det2, self.rec(0, ORDERS, ip="10.42.0.5", serial="abc"))
        self.assertEqual(self.feed(det2, self.rec(7200, ORDERS, ip="10.42.0.6", serial="abc")), [])  # an hour apart: a move
        det3 = Detector(Config(admin_windows=[{"days": list(range(7)), "start_hour": 0, "end_hour": 24}]))
        self.feed(det3, self.rec(0, ALICE, ip="10.8.0.5", serial="lap"))
        self.assertEqual(self.feed(det3, self.rec(30, ALICE, ip="10.8.0.9", serial="lap")), [])  # a laptop changing network

    def test_chain_gaps_and_duplicates(self):
        det = Detector(Config())
        r1 = self.rec(0, ORDERS)
        self.feed(det, r1)
        r2 = self.rec(1, ORDERS)
        self.feed(det, r2)
        self.assertEqual(det.feed(r2, "n1"), [])  # re-sent line: ignored
        self.assertEqual(det.stats["duplicates"], 1)
        self.rec(2, ORDERS)  # seq 3 is "lost"
        r4 = self.rec(3, ORDERS)
        r4["prev"] = "h3"
        a = det.feed(r4, "n1")
        self.assertEqual([x.rule for x in a], ["audit_gap"])
        self.assertEqual(a[0].evidence["missing"], 1)
        # Another node's chain is independent.
        self.assertEqual([x.rule for x in det.feed(dict(r1, seq=1), "n2")], [])
        # A chain that starts over (rebuilt node, or wiped log) is followed and
        # reported. (The tip is still seq 2: seq 4 came after a break and
        # nothing has linked to it yet.)
        a = det.feed(dict(r1, seq=1, prev="0" * 64, hash="new1"), "n1")
        self.assertEqual([(x.rule, x.evidence["previous_seq"]) for x in a], [("audit_restart", 2)])
        self.assertEqual(det.feed(dict(r1, seq=2, prev="new1", hash="new2"), "n1"), [])

    def test_governance_events(self):
        det = Detector(Config())
        a = self.feed(det, self.rec(3600 * 10, "", op="sys.unseal", path="/v1/sys/unseal", ip="10.0.0.9"))
        self.assertEqual([(x.rule, x.severity) for x in a], [("governance", "info")])

    def test_parse_line_and_malformed(self):
        self.assertEqual(parse_line('<110>1 2026-01-01T00:00:00Z node-2 smd - - - {"seq":1}\n'), ("node-2", {"seq": 1}, '{"seq":1}'))
        self.assertEqual(parse_line('{"seq":1}'), ("", {"seq": 1}, '{"seq":1}'))
        self.assertIsNone(parse_line("garbage"))
        self.assertIsNone(parse_line("{not json"))
        det = Detector()
        self.assertEqual(det.feed({"seq": "x"}), [])
        self.assertEqual(det.stats["malformed"], 1)

    def test_config_rejects_typos(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"denail_window_s": 5}, f)
        try:
            with self.assertRaises(ValueError):
                Config.load(f.name)
        finally:
            os.unlink(f.name)


def chained(bodies, prev="0" * 64, first_seq=1):
    """Give records seq, prev and real hashes, as the logger does."""
    out = []
    for i, b in enumerate(bodies):
        rec = {"seq": first_seq + i, **b, "prev": prev}
        rec["hash"] = traffic.hashlib.sha256(bytes.fromhex(prev) + traffic.canonical(rec).encode()).hexdigest()
        prev = rec["hash"]
        out.append(rec)
    return out


class TamperTests(unittest.TestCase):
    def test_edited_record_fails_its_hash(self):
        recs = chained([{"time": traffic._iso(START + i), "identity": ORDERS, "op": "kv.read", "path": "kv/a",
                         "result": "ok"} for i in range(3)])
        det = Detector(CFG)
        det.feed(recs[0], "node-1", traffic.line(recs[0]))
        edited = traffic.line(recs[1]).replace('"identity":"spiffe://sm/svc/orders-api"', '"identity":"spiffe://sm/svc/innocent"')
        a = det.feed(json.loads(edited), "node-1", edited)
        self.assertEqual([x.rule for x in a], ["audit_forged"])
        self.assertEqual(det.stats["forged"], 1)

    def test_injected_line_cannot_blind_a_node(self):
        """Someone who can write to the collector injects a well-formed line
        with a huge seq for node-1. Before the fix, every real node-1 record
        after it was dropped as a "duplicate"."""
        recs = chained([{"time": traffic._iso(START + i), "op": "kv.read", "result": "denied:401",
                         "source_ip": "203.0.113.9"} for i in range(12)])
        det = Detector(Config(denials=10))
        alerts = []
        for r in recs[:2]:
            alerts += det.feed(r, "node-1", traffic.line(r))
        fake = chained([{"time": traffic._iso(START + 2), "op": "kv.read", "result": "ok"}], prev="ab" * 32,
                       first_seq=999_999_999)[0]
        alerts += det.feed(fake, "node-1", traffic.line(fake))
        for r in recs[2:]:
            alerts += det.feed(r, "node-1", traffic.line(r))
        rules = [a.rule for a in alerts]
        self.assertEqual(rules.count("audit_gap"), 1)  # the injection is reported once
        self.assertIn("denial_burst", rules)  # and the real records after it were still judged
        self.assertEqual(det.stats["duplicates"], 0)
        self.assertEqual(det.chains["node-1"][0], 12)


class ScenarioTests(unittest.TestCase):
    """Exit criterion: injected attacks in two weeks of recorded-style traffic
    raise alerts within 1 minute (event time) of the first malicious request."""

    def detect(self, scenario, when, expect, within=60):
        tr = Baseline.get()
        attack = scenario(tr, when)
        _, alerts = run(tr.events + attack)
        first = min(e.t for e in attack)
        hits = [a for a in alerts if a.rule in expect and ts(a) >= first]
        got = {a.rule for a in hits}
        self.assertEqual(got, set(expect), f"{scenario.__name__}: got {got}")
        latency = max(min(ts(a) for a in hits if a.rule == r) - first for r in expect)
        self.assertLessEqual(latency, within, f"{scenario.__name__}: slowest rule took {latency:.1f}s")
        return latency

    def test_stolen_certificate_from_new_host(self):
        lat = self.detect(traffic.stolen_cert, START + 10 * DAY + 11 * 3600, ["cert_multiple_hosts", "new_source"])
        print(f"\n  stolen certificate: alerted after {lat:.1f}s", file=sys.stderr)

    def test_bulk_read_of_every_path(self):
        lat = self.detect(traffic.bulk_read, START + 11 * DAY + 15 * 3600, ["new_path", "bulk_read", "denial_burst"])
        print(f"\n  bulk read: alerted after {lat:.1f}s", file=sys.stderr)

    def test_admin_certificate_at_night(self):
        self.detect(traffic.admin_night, START + 13 * DAY + 3 * 3600, ["admin_off_hours"])

    def test_rate_spike(self):
        # Needs volume by nature: at 2 requests/s it crosses 3 x p99 in minutes.
        lat = self.detect(traffic.rate_spike, START + 12 * DAY + 14 * 3600, ["rate_spike"], within=600)
        print(f"\n  rate spike: alerted after {lat:.1f}s", file=sys.stderr)

    def test_deleted_audit_line(self):
        tr = Baseline.get()
        _, alerts = run(tr.events[: len(tr.events) // 3], drop=("node-2", 500))
        gaps = [a for a in alerts if a.rule == "audit_gap"]
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0].evidence["last_seq"], 499)


class FalsePositiveTest(unittest.TestCase):
    def test_two_clean_weeks(self):
        """Proxy for the exit criterion's "false-positive rate over 2 weeks of
        real traffic", which can only be measured after deployment."""
        tr = Baseline.get()
        det, alerts = run(tr.events)
        noisy = Counter(a.rule for a in alerts if a.severity != "info")
        info = Counter(a.rule for a in alerts if a.severity == "info")
        print(f"\n  clean 2 weeks: {det.stats['records']} records, non-info alerts {dict(noisy)}, info {dict(info)}",
              file=sys.stderr)
        self.assertEqual(sum(noisy.values()), 0)
        self.assertEqual(info["governance"], 2)  # the two weekly snapshots


class SinkTests(unittest.TestCase):
    def test_webhook_formats_and_log(self):
        got = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{srv.server_port}/"
        alert = Alert("2026-01-01T00:00:00Z", "new_source", "high", ORDERS, "first request from x", {"source_ip": "x"})
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "sentinel_alerts.log")
            for fmt in ("alertmanager", "text", "json"):
                s = Sinks(log, url, fmt, None, quiet=True)
                s.send(alert)
                s.close()
            with open(log, encoding="utf-8") as f:
                self.assertEqual(len(f.readlines()), 3)
            s = Sinks(log, "http://127.0.0.1:1/", "json", None, quiet=True)  # webhook down: logged anyway
            with unittest.mock.patch("sys.stderr", io.StringIO()):
                s.send(alert)
            s.close()
            with open(log, encoding="utf-8") as f:
                self.assertEqual(len(f.readlines()), 4)
        srv.shutdown()
        srv.server_close()
        self.assertEqual(got[0][0]["labels"]["alertname"], "sentinel_new_source")
        self.assertIn("first request from x", got[1]["text"])
        self.assertEqual(got[2]["rule"], "new_source")


class StateTest(unittest.TestCase):
    def test_restart_keeps_baseline(self):
        tr = Baseline.get()
        half = [e for e in tr.events if e.t < START + 9 * DAY]
        rest = [e for e in tr.events if e.t >= START + 9 * DAY] + traffic.stolen_cert(tr, START + 10 * DAY)
        chains = traffic.records(half + rest)
        cut = START + 9 * DAY
        det = Detector(CFG)
        stream = traffic.interleave(chains)
        for host, rec in stream:
            if traffic.datetime.fromisoformat(rec["time"]).timestamp() >= cut:
                break
            det.feed(rec, host)
        saved = json.loads(json.dumps(det.state()))  # through JSON, as on disk
        det2 = Detector(CFG)
        det2.load_state(saved)
        alerts = [a for host, rec in stream if traffic.datetime.fromisoformat(rec["time"]).timestamp() >= cut
                  for a in det2.feed(rec, host)]
        rules = {a.rule for a in alerts}
        self.assertIn("new_source", rules)  # baselines carried over: the attacker's IP is new...
        self.assertNotIn("audit_gap", rules)  # ...and chains continue where they left off
        self.assertNotIn("new_path", rules)  # known paths stayed known


class CLITest(unittest.TestCase):
    def test_replay_syslog_and_plain_files(self):
        tr = traffic.normal(days=9, seed=3)
        chains = traffic.records(tr.events + traffic.stolen_cert(tr, START + 8 * DAY))
        with tempfile.TemporaryDirectory() as d:
            paths = []
            for i, (host, recs) in enumerate(chains.items()):
                p = os.path.join(d, f"{host}.log")
                with open(p, "w", encoding="utf-8") as f:
                    for r in recs:  # node-1 as a collector's syslog file, the others as plain audit logs
                        prefix = f"<110>1 {r['time']} {host} smd - - - " if i == 0 else ""
                        f.write(prefix + traffic.line(r) + "\n")
                paths.append(p)
            cfg = os.path.join(d, "cfg.json")
            with open(cfg, "w", encoding="utf-8") as f:
                json.dump({"trusted_networks": [POD_NET, VPN_NET]}, f)
            out = subprocess.run([sys.executable, "-m", "sentinel", "replay", "--config", cfg, *paths],
                                 capture_output=True, text=True, cwd=os.path.join(os.path.dirname(__file__), ".."), check=True)
            rules = {json.loads(line)["rule"] for line in out.stdout.splitlines()}
            summary = json.loads(out.stderr)["summary"]
        self.assertEqual(rules, {"cert_multiple_hosts", "new_source", "governance"})
        self.assertEqual(summary["malformed"], 0)
        self.assertGreater(summary["records"], 50000)

    def test_watch_follows_growing_and_truncated_files(self):
        import time
        with tempfile.TemporaryDirectory() as d:
            log, alerts = os.path.join(d, "audit.log"), os.path.join(d, "alerts.log")
            open(log, "w").close()
            p = subprocess.Popen([sys.executable, "-m", "sentinel", "watch", "--quiet", "--alerts", alerts, log],
                                 cwd=os.path.join(os.path.dirname(__file__), ".."))
            try:
                def rules():
                    try:
                        with open(alerts, encoding="utf-8") as f:
                            return [json.loads(x)["rule"] for x in f]
                    except FileNotFoundError:
                        return []

                def wait_for(rule):
                    for _ in range(100):
                        if rule in rules():
                            return
                        time.sleep(0.1)
                    self.fail(f"watch never raised {rule}; got {rules()}")

                recs = [traffic.line(r) for r in chained([{"time": traffic._iso(START + i), "op": "kv.read",
                                                            "result": "denied:401", "source_ip": "203.0.113.9"} for i in range(10)])]
                with open(log, "a", encoding="utf-8") as f:
                    f.write("\n".join(recs[:9]) + "\n" + recs[9][:20])  # the last line arrives in two writes
                    f.flush()
                    time.sleep(0.8)
                    self.assertNotIn("denial_burst", rules())  # 9 denials plus half a line: not yet
                    f.write(recs[9][20:] + "\n")
                wait_for("denial_burst")
                # Log rotated / truncated: read from the start of the new file.
                with open(log, "w", encoding="utf-8") as f:
                    f.write(traffic.line(chained([{"time": traffic._iso(START + 99), "op": "sys.seal", "result": "ok",
                                                   "source_ip": "10.0.0.1"}])[0]) + "\n")
                wait_for("governance")
                self.assertIn("audit_restart", rules())
            finally:
                p.terminate()
                p.wait(10)

    def test_main_rejects_unknown_mode(self):
        with self.assertRaises(SystemExit), unittest.mock.patch("sys.stderr", io.StringIO()):
            main(["explode", "x"])


if __name__ == "__main__":
    unittest.main()

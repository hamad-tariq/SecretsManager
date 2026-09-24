"""Sentinel command line.

    python -m sentinel replay [--config c.json] [--alerts a.log] FILE...
    python -m sentinel watch  [--config c.json] [--alerts a.log] [--state s.json]
                              [--webhook URL [--webhook-format alertmanager|text|json] [--webhook-ca ca.pem]] FILE...

FILEs are copies of the audit stream: the collector's syslog files (one per
node, or one shared file; the syslog HOSTNAME tells nodes apart) or plain
audit logs. "-" reads stdin. Sentinel never contacts the secrets cluster.

replay reads the files once, merged in time order, prints the alerts and a
summary, and exits. watch follows the files as they grow (like tail -F).
"""

from __future__ import annotations

import argparse
import heapq
import json
import os
import signal
import ssl
import sys
import time
import urllib.request
from collections import Counter
from typing import Iterator

from .detector import Alert, Config, Detector, parse_line, parse_time


class Sinks:
    """Where alerts go: stdout, the sentinel_alerts log, and optionally a webhook."""

    def __init__(self, alerts_path: str | None, webhook: str | None, fmt: str, ca: str | None, quiet: bool = False):
        self.log = open(alerts_path, "a", encoding="utf-8") if alerts_path else None  # noqa: SIM115
        self.webhook, self.fmt, self.quiet = webhook, fmt, quiet
        self.ctx = ssl.create_default_context(cafile=ca) if ca else None

    def send(self, a: Alert) -> None:
        line = a.to_json()
        if not self.quiet:
            print(line, flush=True)
        if self.log:
            self.log.write(line + "\n")
            self.log.flush()
        if self.webhook:
            try:
                self._post(a)
            except OSError as e:  # the log still has it; don't stop watching
                print(f"sentinel: webhook failed: {e}", file=sys.stderr)

    def _post(self, a: Alert) -> None:
        if self.fmt == "alertmanager":  # Alertmanager /api/v2/alerts
            body = [{"labels": {"alertname": f"sentinel_{a.rule}", "severity": a.severity, "identity": a.identity},
                     "annotations": {"summary": a.summary, "evidence": json.dumps(a.evidence, sort_keys=True)},
                     "startsAt": a.time}]
        elif self.fmt == "text":  # Mattermost / Rocket.Chat / Slack-compatible incoming webhooks
            body = {"text": f"[{a.severity}] {a.rule}: {a.identity or '-'}: {a.summary} {json.dumps(a.evidence, sort_keys=True)}"}
        else:
            body = json.loads(a.to_json())
        req = urllib.request.Request(self.webhook, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10, context=self.ctx) as resp:  # noqa: S310 -- operator-configured URL
            resp.read()

    def close(self) -> None:
        if self.log:
            self.log.close()


def _records(path: str) -> Iterator[tuple[float, str, dict, str]]:
    """(time, host, record, raw JSON) from one file; plain audit logs get the file name as host."""
    f = sys.stdin if path == "-" else open(path, encoding="utf-8")  # noqa: SIM115
    default_host = "" if path == "-" else os.path.basename(path)
    with f:
        for line in f:
            parsed = parse_line(line)
            if parsed is None:
                continue
            host, rec, raw = parsed
            try:
                ts = parse_time(rec["time"])
            except (KeyError, ValueError, TypeError):
                ts = 0.0
            yield ts, host or default_host, rec, raw


def replay(det: Detector, sinks: Sinks, paths: list[str]) -> Counter:
    counts: Counter = Counter()
    for _, host, rec, raw in heapq.merge(*(_records(p) for p in paths), key=lambda r: r[0]):
        for a in det.feed(rec, host, raw):
            counts[a.rule] += 1
            sinks.send(a)
    return counts


def watch(det: Detector, sinks: Sinks, paths: list[str], state: str | None, poll: float = 0.5) -> None:
    files: dict[str, tuple] = {}  # path -> (file, inode, pending partial line)
    stop = False

    def _stop(*_):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    last_save = time.monotonic()
    while not stop:
        for p in paths:
            try:
                st = os.stat(p)
            except FileNotFoundError:
                continue
            f, ino, partial = files.get(p, (None, None, ""))
            if f is None or ino != st.st_ino or f.tell() > st.st_size:  # new, rotated or truncated
                if f:
                    f.close()
                f, partial = open(p, encoding="utf-8"), ""  # noqa: SIM115
            chunk = f.read()
            lines = (partial + chunk).split("\n")
            partial = lines.pop()  # incomplete last line: wait for the rest
            files[p] = (f, st.st_ino, partial)
            for line in lines:
                parsed = parse_line(line)
                if parsed:
                    host, rec, raw = parsed
                    for a in det.feed(rec, host or os.path.basename(p), raw):
                        sinks.send(a)
        if state and time.monotonic() - last_save > 60:
            save_state(det, state)
            last_save = time.monotonic()
        time.sleep(poll)
    if state:
        save_state(det, state)


def save_state(det: Detector, path: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(det.state(), f)
    os.replace(tmp, path)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sentinel", description="Alerts on suspicious use of the secrets manager, from its audit log.")
    ap.add_argument("mode", choices=["replay", "watch"])
    ap.add_argument("files", nargs="+")
    ap.add_argument("--config")
    ap.add_argument("--alerts", default=None, help="append alerts here (JSON lines); default: sentinel_alerts.log in watch mode")
    ap.add_argument("--state", help="learned baselines are kept here across restarts")
    ap.add_argument("--webhook")
    ap.add_argument("--webhook-format", default="alertmanager", choices=["alertmanager", "text", "json"])
    ap.add_argument("--webhook-ca", help="CA for a self-hosted webhook's TLS certificate")
    ap.add_argument("--quiet", action="store_true", help="don't print alerts to stdout")
    args = ap.parse_args(argv)

    det = Detector(Config.load(args.config))
    if args.state and os.path.exists(args.state):
        with open(args.state, encoding="utf-8") as f:
            det.load_state(json.load(f))
    alerts = args.alerts or ("sentinel_alerts.log" if args.mode == "watch" else None)
    sinks = Sinks(alerts, args.webhook, args.webhook_format, args.webhook_ca, args.quiet)
    try:
        if args.mode == "replay":
            counts = replay(det, sinks, args.files)
            summary = {"alerts": dict(counts), **det.stats}
            print(json.dumps({"summary": summary}, sort_keys=True), file=sys.stderr)
            if args.state:
                save_state(det, args.state)
        else:
            watch(det, sinks, args.files, args.state)
    finally:
        sinks.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

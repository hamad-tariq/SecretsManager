"""Python client for the self-hosted secrets manager.

Standard library only. Talks mTLS to the API, caches values in memory,
refreshes them in the background, and keeps serving the last known value for
a while if every node is unreachable.

    from smclient import Client

    sm = Client.from_agent_dir(["sm-1:8200", "sm-2:8200"], "/run/secrets/sm")
    db_password = sm.get("prod/orders/db")        # SecretStr
    connect(password=db_password.reveal())
    sm.on_rotate("prod/orders/db", lambda s: pool.reconnect(s.reveal()))

Per-pod database users: let sm-agent (-db role=file) get and renew them and
read the file with DBCredentials.from_file, or call db_creds / renew_lease /
revoke_lease yourself.
"""

from __future__ import annotations

import json
import logging
import os
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional

__all__ = ["Client", "DBCredentials", "SecretStr", "SecretsError", "NotFound", "PermissionDenied", "Unavailable"]

log = logging.getLogger("smclient")


class SecretStr:
    """A secret value that doesn't print itself. Use .reveal() where needed."""

    __slots__ = ("_value", "version")

    def __init__(self, value: str, version: int = 0):
        self._value = value
        self.version = version

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "SecretStr('**********')"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SecretStr) and other._value == self._value

    def __hash__(self) -> int:
        return hash(self._value)

    def __reduce__(self):  # refuse pickling (it would bypass the redaction)
        raise TypeError("SecretStr cannot be pickled")


@dataclass(frozen=True)
class DBCredentials:
    """A database user issued for this caller; dropped when its lease ends."""

    username: str
    password: SecretStr
    lease_id: str
    expires: str  # RFC 3339
    max_expires: str

    @classmethod
    def from_dict(cls, d: dict) -> "DBCredentials":
        return cls(d["username"], SecretStr(d["password"]), d["lease_id"], d["expires"], d["max_expires"])

    @classmethod
    def from_file(cls, path: str) -> "DBCredentials":
        """Read what sm-agent -db role=file wrote (re-read it when it changes)."""
        with open(path, encoding="utf-8") as f:
            return cls.from_dict(json.load(f))


class SecretsError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"{status}: {message}")
        self.status = status


class NotFound(SecretsError):
    pass


class PermissionDenied(SecretsError):
    pass


class Unavailable(SecretsError):
    """No node could serve the request and no usable cached value exists."""


@dataclass
class _Entry:
    secret: SecretStr
    fetched: float


class Client:
    def __init__(
        self,
        addrs: list[str],
        cert: str,
        key: str,
        ca: str,
        *,
        ttl: float = 300.0,
        max_stale: float = 3600.0,
        timeout: float = 10.0,
        background: bool = True,
    ):
        """
        addrs: node API addresses ("host:port").
        cert/key/ca: PEM file paths (cert may include the intermediate).
        ttl: seconds a cached value is used before re-fetching.
        max_stale: while every node is down, serve cached values up to this age.
        background: refresh cached secrets in a daemon thread before they expire.
        """
        if not addrs:
            raise ValueError("at least one address is required")
        self._addrs = list(addrs)
        self._cert, self._key, self._ca = cert, key, ca
        self._ttl, self._max_stale, self._timeout = ttl, max_stale, timeout
        self._cache: dict[str, _Entry] = {}
        self._callbacks: dict[str, list[Callable[[SecretStr], None]]] = {}
        self._lock = threading.Lock()
        self._ctx: Optional[ssl.SSLContext] = None
        self._ctx_mtime = 0.0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        if background:
            self._thread = threading.Thread(target=self._refresher, name="smclient-refresh", daemon=True)
            self._thread.start()

    @classmethod
    def from_agent_dir(cls, addrs: list[str], path: str, **kw) -> "Client":
        """Use the certificate sm-agent keeps renewed in `path`."""
        return cls(addrs, os.path.join(path, "tls.crt"), os.path.join(path, "tls.key"), os.path.join(path, "ca.crt"), **kw)

    # ---- public API ----

    def get(self, path: str, *, version: Optional[int] = None, label: Optional[str] = None) -> SecretStr:
        """Return a secret. Specific versions/labels bypass the cache."""
        path = path.strip("/")
        if version is not None or label is not None:
            return self._fetch(path, version, label)
        with self._lock:
            entry = self._cache.get(path)
        if entry and time.monotonic() - entry.fetched < self._ttl:
            return entry.secret
        try:
            return self._refresh(path)
        except Unavailable:
            if entry and time.monotonic() - entry.fetched < self._max_stale:
                log.warning("secrets manager unreachable; serving cached %s (version %d)", path, entry.secret.version)
                return entry.secret
            raise

    def on_rotate(self, path: str, callback: Callable[[SecretStr], None]) -> None:
        """Call callback(new_secret) whenever a background refresh sees a new version."""
        with self._lock:
            self._callbacks.setdefault(path.strip("/"), []).append(callback)

    def db_creds(self, role: str, ttl: Optional[str] = None) -> DBCredentials:
        """Create a database user for role (e.g. ttl="30m"; default: the role's)."""
        body = {"ttl": ttl} if ttl else None
        return DBCredentials.from_dict(self._request("POST", "/v1/db/creds/" + urllib.parse.quote(role, safe=""), body))

    def renew_lease(self, lease_id: str, increment: Optional[str] = None) -> dict:
        """Extend a lease (never past its max TTL). Returns the lease record."""
        body = {"lease_id": lease_id}
        if increment:
            body["increment"] = increment
        return self._request("POST", "/v1/leases/renew", body)

    def revoke_lease(self, lease_id: str) -> None:
        """Drop the user now, e.g. on shutdown."""
        self._request("POST", "/v1/leases/revoke", {"lease_id": lease_id})

    def close(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- internals ----

    def _refresh(self, path: str) -> SecretStr:
        new = self._fetch(path)
        with self._lock:
            old = self._cache.get(path)
            self._cache[path] = _Entry(new, time.monotonic())
            callbacks = list(self._callbacks.get(path, [])) if old and old.secret.version != new.version else []
        for cb in callbacks:
            try:
                cb(new)
            except Exception:  # a broken callback must not stop refreshing
                log.exception("on_rotate callback for %s failed", path)
        return new

    def _refresher(self) -> None:
        interval = max(1.0, self._ttl * 2 / 3)
        while not self._stop.wait(interval):
            with self._lock:
                paths = list(self._cache)
            for p in paths:
                try:
                    self._refresh(p)
                except SecretsError as e:
                    log.warning("background refresh of %s failed: %s", p, e)

    def _context(self) -> ssl.SSLContext:
        # Rebuild when the certificate file changes (sm-agent renews it).
        try:
            mtime = os.stat(self._cert).st_mtime
        except OSError:
            mtime = 0.0
        if self._ctx is None or mtime != self._ctx_mtime:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.load_verify_locations(self._ca)
            ctx.load_cert_chain(self._cert, self._key)
            self._ctx, self._ctx_mtime = ctx, mtime
        return self._ctx

    def _fetch(self, path: str, version: Optional[int] = None, label: Optional[str] = None) -> SecretStr:
        query = {}
        if version is not None:
            query["version"] = str(version)
        if label is not None:
            query["label"] = label
        suffix = "?" + urllib.parse.urlencode(query) if query else ""
        body = self._request("GET", "/v1/kv/" + urllib.parse.quote(path) + suffix)
        return SecretStr(body["value"], int(body.get("version", 0)))

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        last: Optional[Exception] = None
        data = json.dumps(body).encode() if body is not None else None
        for addr in self._addrs:
            req = urllib.request.Request(f"https://{addr}{path}", data=data, method=method,
                                         headers={"Content-Type": "application/json"} if data else {})
            try:
                with urllib.request.urlopen(req, context=self._context(), timeout=self._timeout) as resp:
                    raw = resp.read()
                    return json.loads(raw) if raw.strip() not in (b"", b"null") else {}
            except urllib.error.HTTPError as e:
                try:
                    msg = json.loads(e.read()).get("error", e.reason)
                except ValueError:
                    msg = str(e.reason)
                if e.code == 404:
                    raise NotFound(e.code, msg) from None
                if e.code in (401, 403):
                    raise PermissionDenied(e.code, msg) from None
                if e.code in (429, 503):  # sealed/busy node: try the next
                    last = SecretsError(e.code, msg)
                    continue
                raise SecretsError(e.code, msg) from None
            except (urllib.error.URLError, OSError, ssl.SSLError) as e:
                last = e
        raise Unavailable(0, f"no node could serve {path}: {last}")

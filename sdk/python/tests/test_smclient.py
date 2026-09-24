"""Tests for smclient. Unit tests run anywhere; the integration test runs when
SM_TEST_ADDR / SM_TEST_AGENT_DIR / SM_TEST_PATH / SM_TEST_VALUE are set
(the Go test in internal/agent sets them against a live server)."""

import json
import os
import pickle
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from smclient import Client, DBCredentials, NotFound, PermissionDenied, SecretStr, Unavailable  # noqa: E402


class FakeClient(Client):
    """Client with the network replaced by a dict (value, version) or an exception."""

    def __init__(self, **kw):
        self.backend = {}
        self.calls = 0
        kw.setdefault("background", False)
        super().__init__(["unused:1"], "c", "k", "ca", **kw)

    def _fetch(self, path, version=None, label=None):
        self.calls += 1
        v = self.backend.get(path)
        if isinstance(v, Exception):
            raise v
        if v is None:
            raise NotFound(404, "not found")
        return SecretStr(*v)


class SecretStrTest(unittest.TestCase):
    def test_redacted(self):
        s = SecretStr("hunter2", 3)
        for text in (str(s), repr(s), f"{s}", "%s" % s, str([s]), str({"k": s})):
            self.assertNotIn("hunter2", text)
        self.assertEqual(s.reveal(), "hunter2")
        self.assertEqual(s.version, 3)
        self.assertEqual(s, SecretStr("hunter2"))
        with self.assertRaises(TypeError):
            pickle.dumps(s)


class CacheTest(unittest.TestCase):
    def test_ttl_cache(self):
        c = FakeClient(ttl=60)
        c.backend["a"] = ("v1", 1)
        self.assertEqual(c.get("a").reveal(), "v1")
        self.assertEqual(c.get("/a/").reveal(), "v1")
        self.assertEqual(c.calls, 1, "second read should come from cache")
        c.get("a", version=1)
        self.assertEqual(c.calls, 2, "explicit version bypasses the cache")

    def test_expired_refetches(self):
        c = FakeClient(ttl=0)
        c.backend["a"] = ("v1", 1)
        c.get("a")
        c.backend["a"] = ("v2", 2)
        self.assertEqual(c.get("a").reveal(), "v2")

    def test_stale_on_outage_then_raise(self):
        c = FakeClient(ttl=0, max_stale=0.2)
        c.backend["a"] = ("v1", 1)
        c.get("a")
        c.backend["a"] = Unavailable(0, "down")
        self.assertEqual(c.get("a").reveal(), "v1", "serve stale during outage")
        time.sleep(0.25)
        with self.assertRaises(Unavailable):
            c.get("a")

    def test_errors_are_not_masked_by_cache(self):
        c = FakeClient(ttl=0)
        c.backend["a"] = ("v1", 1)
        c.get("a")
        c.backend["a"] = PermissionDenied(403, "denied")
        with self.assertRaises(PermissionDenied):
            c.get("a")  # access revoked: must not keep serving the old value
        with self.assertRaises(NotFound):
            c.get("missing")

    def test_on_rotate(self):
        c = FakeClient(ttl=0)
        seen = []
        c.on_rotate("a", lambda s: seen.append(s.reveal()))
        c.on_rotate("a", lambda s: 1 / 0)  # a broken callback doesn't break others
        c.backend["a"] = ("v1", 1)
        c.get("a")
        c.get("a")
        c.backend["a"] = ("v2", 2)
        with self.assertLogs("smclient", "ERROR"):  # the broken callback is logged, not raised
            c.get("a")
        self.assertEqual(seen, ["v2"])

    def test_background_refresh(self):
        c = FakeClient(ttl=1.5, background=True)
        try:
            c.backend["a"] = ("v1", 1)
            got = threading.Event()
            c.on_rotate("a", lambda s: got.set())
            c.get("a")
            c.backend["a"] = ("v2", 2)
            self.assertTrue(got.wait(5), "background thread should pick up v2")
        finally:
            c.close()

    def test_requires_address(self):
        with self.assertRaises(ValueError):
            Client([], "c", "k", "ca", background=False)


class DBCredentialsTest(unittest.TestCase):
    def test_from_file_redacts(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"username": "v_x_1", "password": "hunter2", "lease_id": "db/x/1",
                       "expires": "2026-01-01T01:00:00Z", "max_expires": "2026-01-02T00:00:00Z"}, f)
        try:
            c = DBCredentials.from_file(f.name)
        finally:
            os.unlink(f.name)
        self.assertEqual(c.password.reveal(), "hunter2")
        self.assertNotIn("hunter2", repr(c))


@unittest.skipUnless(os.environ.get("SM_TEST_DB_ROLE"), "needs a live server with a database role (run via the Go agent test)")
class DBLiveTest(unittest.TestCase):
    def test_issue_renew_revoke(self):
        addrs = os.environ["SM_TEST_ADDR"].split(",")
        with Client.from_agent_dir(addrs, os.environ["SM_TEST_AGENT_DIR"], background=False) as c:
            creds = c.db_creds(os.environ["SM_TEST_DB_ROLE"], ttl="10m")
            self.assertTrue(creds.username.startswith("v_"))
            self.assertEqual(len(creds.password.reveal()), 32)
            self.assertNotIn(creds.password.reveal(), repr(creds))
            self.assertEqual(c.renew_lease(creds.lease_id, "20m")["lease_id"], creds.lease_id)
            c.revoke_lease(creds.lease_id)
            with self.assertRaises(NotFound):
                c.revoke_lease(creds.lease_id)
            with self.assertRaises(PermissionDenied):
                c.db_creds("not-allowed")


@unittest.skipUnless(os.environ.get("SM_TEST_ADDR"), "needs a live server (run via the Go agent test)")
class LiveTest(unittest.TestCase):
    def test_read_with_agent_identity(self):
        addrs = os.environ["SM_TEST_ADDR"].split(",")
        with Client.from_agent_dir(addrs, os.environ["SM_TEST_AGENT_DIR"], background=False) as c:
            s = c.get(os.environ["SM_TEST_PATH"])
            self.assertEqual(s.reveal(), os.environ["SM_TEST_VALUE"])
            self.assertGreaterEqual(s.version, 1)
            with self.assertRaises(PermissionDenied):
                c.get("not/allowed")
        # All nodes down, nothing cached.
        with Client.from_agent_dir(["127.0.0.1:1"], os.environ["SM_TEST_AGENT_DIR"], background=False, timeout=2) as c:
            with self.assertRaises(Unavailable):
                c.get(os.environ["SM_TEST_PATH"])


if __name__ == "__main__":
    unittest.main()

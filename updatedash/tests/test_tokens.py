"""Read-only API tokens and the summary endpoint that Homarr's Custom API widget reads."""
import json
import time
import unittest
from pathlib import Path

from tests.helpers import AppCase, Client
from udash import tokens as T

SERVICES = '''discover: true
services:
  - name: sonarr
    ctid: 114
    current: "echo 1.0"
    latest: {type: command, cmd: "echo 2.0"}
  - name: radarr
    ctid: 115
    current: "echo 2.0"
    latest: {type: command, cmd: "echo 2.0"}
  - name: ssh-only-vm
    ctid: 116
'''


def bearer(tok):
    return {"Authorization": f"Bearer {tok}"}


class TestTokenStore(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.d, True)
        self.path = Path(self.d) / "tokens.json"
        self.s = T.TokenStore(self.path)

    def test_token_is_shown_once_and_only_its_hash_is_stored(self):
        tok, rec = self.s.create("homarr")
        self.assertTrue(tok.startswith("udt_") and len(tok) > 40)
        self.assertNotIn(tok, self.path.read_text())
        self.assertNotIn("hash", rec)
        self.assertNotIn("hash", json.dumps(self.s.list()))
        self.assertEqual(self.s.verify(tok)["name"], "homarr")
        self.assertIsNone(self.s.verify(tok + "x"))
        self.assertIsNone(self.s.verify("udt_" + "a" * 40))
        self.assertEqual(oct(self.path.stat().st_mode & 0o777), "0o600")
        self.assertEqual(T.TokenStore(self.path).verify(tok)["name"], "homarr")     # survives a restart

    def test_revoke_and_limits(self):
        tok, rec = self.s.create("a")
        self.assertTrue(self.s.revoke(rec["id"]))
        self.assertIsNone(self.s.verify(tok))
        self.assertFalse(self.s.revoke(rec["id"]))
        for bad in ("", "x;y", "a" * 50, None):
            with self.assertRaises(T.ValidationError):
                self.s.create(bad)
        self.s.create("dup")
        with self.assertRaises(T.ValidationError):
            self.s.create("DUP")
        for i in range(T.MAX_TOKENS - 1):
            self.s.create(f"t{i}")
        with self.assertRaises(T.ValidationError):
            self.s.create("one-too-many")

    def test_malformed_tokens_are_rejected_cheaply(self):
        for bad in (None, "", "Bearer x", "udt_", "x" * 500, "udt_" + "A" * 400):
            self.assertIsNone(self.s.verify(bad))

    def test_rate_limit(self):
        _, rec = self.s.create("r")
        self.assertTrue(all(self.s.allow(rec["id"]) == 0 for _ in range(T.RATE_LIMIT)))
        self.assertGreater(self.s.allow(rec["id"]), 0)
        self.assertEqual(self.s.allow("another-token"), 0)                          # per token, not global


class TestSummaryEndpoint(AppCase):
    extra_config = SERVICES

    def setUp(self):
        super().setUp()
        self.c = self.signed_in()
        self.app.dash.check_all()
        self.anon = Client(self.base)

    def make(self, name="homarr", detail=False):
        st, out, _ = self.c.post("/api/tokens/create", {"name": name, "detail": detail})
        self.assertEqual(st, 200)
        return out["token"], out["info"]

    def test_counts_for_the_homarr_widget(self):
        tok, _ = self.make()
        st, out, h = self.anon.get("/api/v1/summary", headers=bearer(tok))
        self.assertEqual(st, 200)
        self.assertEqual(h["Content-Type"], "application/json")
        self.assertEqual((out["total"], out["app_updates"], out["security_updates"]), (3, 1, 0))
        for key in ("running", "stopped", "unknown", "system_updates", "needs_attention", "unreachable", "hosts",
                    "generated_at", "last_check", "stale"):
            self.assertIn(key, out)
        self.assertEqual(out["running"] + out["stopped"] + out["unknown"], out["total"])
        self.assertFalse(out["stale"])
        self.assertNotIn("containers", out)                                         # no names unless the token allows it

    def test_names_only_for_tokens_created_with_detail(self):
        plain, _ = self.make("plain", False)
        rich, _ = self.make("rich", True)
        self.assertNotIn("containers", self.anon.get("/api/v1/summary?detail=1", headers=bearer(plain))[1])
        out = self.anon.get("/api/v1/summary?detail=1", headers=bearer(rich))[1]
        self.assertEqual(sorted(x["name"] for x in out["containers"]), ["radarr", "sonarr", "ssh-only-vm"])
        self.assertNotIn("containers", self.anon.get("/api/v1/summary", headers=bearer(rich))[1])   # only when asked

    def test_only_a_valid_bearer_token_works(self):
        tok, _ = self.make()
        self.assertEqual(self.anon.get("/api/v1/summary")[0], 401)
        self.assertEqual(self.anon.get("/api/v1/summary", headers={"Authorization": f"Basic {tok}"})[0], 401)
        self.assertEqual(self.anon.get("/api/v1/summary", headers=bearer(tok + "0"))[0], 401)
        st, _, h = self.anon.get("/api/v1/summary", headers=bearer("udt_nope"))
        self.assertEqual(st, 401)
        self.assertIn("Bearer", h["WWW-Authenticate"])
        # a logged-in browser session is not a token
        self.assertEqual(self.c.get("/api/v1/summary")[0], 401)

    def test_a_token_cannot_reach_anything_else(self):
        tok, _ = self.make()
        for path in ("/api/services", "/api/me", "/api/tokens", "/api/audit", "/api/inventory", "/api/settings", "/api/summary-preview"):
            self.assertEqual(self.anon.get(path, headers=bearer(tok))[0], 401, path)
        self.assertEqual(self.anon.post("/api/update", {"ctid": 114, "kind": "app"}, headers=bearer(tok))[0], 401)
        self.assertEqual(self.anon.post("/api/tokens/create", {"name": "x"}, headers=bearer(tok))[0], 401)

    def test_revoking_stops_it_immediately_and_listings_never_show_secrets(self):
        tok, info = self.make()
        self.assertEqual(self.anon.get("/api/v1/summary", headers=bearer(tok))[0], 200)
        listing = json.dumps(self.c.get("/api/tokens")[1])
        self.assertNotIn(tok, listing)
        self.assertNotIn("hash", listing)
        self.assertIsNotNone(self.c.get("/api/tokens")[1]["tokens"][0]["last_used"])
        self.assertEqual(self.c.post("/api/tokens/revoke", {"id": info["id"]})[0], 200)
        self.assertEqual(self.anon.get("/api/v1/summary", headers=bearer(tok))[0], 401)
        self.assertNotIn(tok, (Path(self.app.state_dir) / "audit.log").read_text())
        actions = [e["action"] for e in self.c.get("/api/audit")[1]["events"]]
        self.assertIn("token.create", actions)
        self.assertIn("token.revoke", actions)

    def test_guessing_tokens_locks_the_address_out(self):
        tok, _ = self.make()
        for _ in range(5):
            self.assertEqual(self.anon.get("/api/v1/summary", headers=bearer("udt_wrong"))[0], 401)
        st, _, h = self.anon.get("/api/v1/summary", headers=bearer(tok))             # even the right token is refused for a while
        self.assertEqual(st, 429)
        self.assertIn("Retry-After", h)

    def test_rate_limit_per_token(self):
        tok, _ = self.make()
        codes = [self.anon.get("/api/v1/summary", headers=bearer(tok))[0] for _ in range(T.RATE_LIMIT + 3)]
        self.assertEqual(codes[:T.RATE_LIMIT], [200] * T.RATE_LIMIT)
        self.assertEqual(set(codes[T.RATE_LIMIT:]), {429})

    def test_creating_tokens_needs_a_login_and_the_csrf_header(self):
        self.assertEqual(self.anon.post("/api/tokens/create", {"name": "x"})[0], 401)
        self.assertEqual(self.c.post("/api/tokens/create", {"name": "x"}, csrf=False)[0], 403)
        self.assertEqual(self.c.post("/api/tokens/create", {"name": "bad;name"})[0], 400)

    def test_stale_flag_when_checks_stopped_running(self):
        tok, _ = self.make()
        self.app.dash.last_sweep = time.time() - 13 * 3600          # more than two check intervals (6 h each)
        self.assertTrue(self.anon.get("/api/v1/summary", headers=bearer(tok))[1]["stale"])


if __name__ == "__main__":
    unittest.main()

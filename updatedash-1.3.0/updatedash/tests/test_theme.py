"""Themes: validated values only, a generated stylesheet, and nothing that could inject CSS or script."""
import json
import re
import tempfile
import unittest
from pathlib import Path

from tests.helpers import ROOT, AppCase, Client
from udash import theme as T
from udash.store import ValidationError

assert ROOT.is_dir()
GOOD = {"mode": "dark", "accent": "#7C98FF", "background": {"type": "linear", "colors": ["#0B1020", "#1b2a4a"], "angle": 160}}


class TestValidation(unittest.TestCase):
    def test_a_good_theme_is_normalised(self):
        t = T.clean_theme(GOOD)
        self.assertEqual(t["accent"], "#7c98ff")
        self.assertEqual(t["background"]["colors"], ["#0b1020", "#1b2a4a"])

    def test_every_preset_is_valid_and_readable(self):
        for name, p in T.PRESETS.items():
            t = T.clean_theme(p)
            self.assertEqual(T.clean_theme(name), t, name)
            if t["accent"]:
                self.assertGreaterEqual(T.contrast(t["accent"], T.text_on(t["accent"])), 4.5, name)    # button text is legible

    def test_hostile_values_are_rejected(self):
        evil = ["#fff;}body{display:none", "red", "#12345", "#1234567", "url(http://evil/x)", "expression(alert(1))",
                "#00000g", "#fff\n", "var(--x)", "#ffffff;background:url(//evil)", "", None, 123]
        for c in evil:
            for theme in ({"accent": c}, {"background": {"type": "solid", "colors": [c]}},
                          {"background": {"type": "linear", "colors": ["#000000", c]}}):
                if c in ("", None) and "accent" in theme:
                    continue                                                    # an empty accent means "use the default"
                with self.assertRaises(ValidationError, msg=(c, theme)):
                    T.clean_theme(theme)
        for bad in ({"mode": "sepia"}, {"mode": "dark;x"}, {"background": {"type": "conic", "colors": []}},
                    {"background": {"type": "linear", "colors": ["#000000"]}},
                    {"background": {"type": "linear", "colors": ["#000000"] * 4}},
                    {"background": {"type": "solid", "colors": ["#000000", "#ffffff"]}},
                    {"background": {"type": "linear", "colors": ["#000000", "#ffffff"], "angle": -1}},
                    {"background": {"type": "linear", "colors": ["#000000", "#ffffff"], "angle": 361}},
                    {"background": {"type": "linear", "colors": ["#000000", "#ffffff"], "angle": "90deg"}},
                    {"background": {"type": "linear", "colors": ["#000000", "#ffffff"], "angle": True}},
                    {"background": "none"}, "no-such-preset", [], 5):
            with self.assertRaises(ValidationError, msg=bad):
                T.clean_theme(bad)

    def test_css_contains_only_validated_values(self):
        css = T.theme_css(GOOD)
        self.assertIn("linear-gradient(160deg, #0b1020, #1b2a4a)", css)
        self.assertIn("--accent: #7c98ff;", css)
        self.assertIn("--accent-text:", css)
        body = css.split("{", 1)[1]
        self.assertEqual(re.sub(r"[#0-9a-f(),:;\s\-a-z.]", "", body.replace("}", "")), "")      # nothing but safe characters
        self.assertNotIn("url(", css)
        self.assertNotIn("@import", css)
        self.assertEqual(T.theme_css("default").count("--accent"), 0)                      # default leaves the stylesheet's own colours
        self.assertIn("--page-bg-color: #f6f1e7;", T.theme_css("paper"))
        self.assertIn("radial-gradient", T.theme_css({"background": {"type": "radial", "colors": ["#000000", "#ffffff"], "angle": 30}}))

    def test_accent_text_picks_the_readable_colour(self):
        self.assertEqual(T.text_on("#ffffff"), "#0b0f17")
        self.assertEqual(T.text_on("#000000"), "#ffffff")
        for accent in ("#7c98ff", "#2f5bea", "#fb923c", "#4ade80", "#b45309", "#ff0000", "#808080"):
            self.assertGreaterEqual(T.contrast(accent, T.text_on(accent)), 4.0, accent)

    def test_store_persists_and_survives_a_corrupt_file(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, d, True)
        s = T.ThemeStore(d / "theme.json")
        s.set(GOOD)
        self.assertEqual(T.ThemeStore(d / "theme.json").theme["accent"], "#7c98ff")
        (d / "theme.json").write_text('{"mode": "sepia"}')
        self.assertEqual(T.ThemeStore(d / "theme.json").theme["mode"], "auto")               # falls back, never crashes
        (d / "theme.json").write_text("not json")
        self.assertEqual(T.ThemeStore(d / "theme.json").theme, T.clean_theme("default"))
        self.assertEqual(oct((d / "theme.json").stat().st_mode & 0o777), "0o600")


class TestThemeOverHttp(AppCase):
    def test_the_stylesheet_is_public_so_the_login_page_matches(self):
        c = self.signed_in()
        self.assertEqual(c.post("/api/theme", {"preset": "midnight"})[0], 200)
        anon = Client(self.base)
        st, body, h = anon.get("/theme.css")
        self.assertEqual(st, 200)
        self.assertIn("text/css", h["Content-Type"])
        self.assertIn("linear-gradient(160deg, #0b1020, #1b2a4a)", body.decode() if isinstance(body, bytes) else body)
        self.assertIn("no-cache", h["Cache-Control"])
        self.assertNotIn("unsafe-inline", h["Content-Security-Policy"])                       # a theme never needs it

    def test_a_fixed_mode_is_applied_to_the_html_before_it_paints(self):
        anon = Client(self.base)
        self.assertNotIn(b"data-mode", self.raw(anon, "/login"))
        self.signed_in().post("/api/theme", {"preset": "midnight"})
        self.assertIn(b'<html lang="en" data-mode="dark">', self.raw(anon, "/login"))
        self.c.post("/api/theme", {"preset": "paper"})
        self.assertIn(b'data-mode="light"', self.raw(anon, "/login"))
        self.assertIn(b'<link rel="stylesheet" href="/theme.css"', self.raw(anon, "/login"))

    def raw(self, client, path):
        import urllib.request
        return urllib.request.urlopen(client.base + path, timeout=10).read()

    def test_changing_it_needs_a_login_and_the_csrf_header_and_is_validated(self):
        anon = Client(self.base)
        self.assertEqual(anon.post("/api/theme", {"preset": "midnight"})[0], 401)
        self.assertEqual(anon.get("/api/theme")[0], 401)
        c = self.signed_in()
        self.assertEqual(c.post("/api/theme", {"preset": "midnight"}, csrf=False)[0], 403)
        for body in ({"theme": {"accent": "#fff;}body{display:none"}}, {"preset": "nope"}, {"theme": {"mode": "x"}}, {}):
            self.assertEqual(c.post("/api/theme", body)[0], 400, body)
        self.assertEqual(c.get("/api/theme")[1]["theme"]["mode"], "auto")                    # nothing was applied

    def test_custom_theme_reset_and_audit(self):
        c = self.signed_in()
        custom = {"theme": {"mode": "light", "accent": "#aa3355", "background": {"type": "radial", "colors": ["#ffffff", "#ffe0ea"], "angle": 30}}}
        st, out, _ = c.post("/api/theme", custom)
        self.assertEqual((st, out["theme"]["background"]["type"]), (200, "radial"))
        self.assertIn("--accent: #aa3355;", Client(self.base).get("/theme.css")[1].decode())
        self.assertEqual(c.post("/api/theme/reset")[1]["theme"]["mode"], "auto")
        self.assertNotIn("--accent", Client(self.base).get("/theme.css")[1].decode())
        actions = [e["action"] for e in c.get("/api/audit")[1]["events"]]
        self.assertIn("theme.change", actions)
        self.assertIn("theme.reset", actions)
        self.assertEqual(json.loads((Path(self.app.state_dir) / "theme.json").read_text())["mode"], "auto")

    def test_presets_are_offered_to_the_ui(self):
        out = self.signed_in().get("/api/theme")[1]
        self.assertIn("midnight", out["presets"])
        self.assertEqual(len(out["presets"]), len(T.PRESETS))


class TestAllowlistStillApplies(AppCase):
    extra_config = 'allow_from: ["203.0.113.0/24"]\n'

    def test_theme_css_is_not_a_way_around_the_network_allowlist(self):
        self.assertEqual(Client(self.base).get("/theme.css")[0], 403)


if __name__ == "__main__":
    unittest.main()

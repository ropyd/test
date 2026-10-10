"""The script catalog and the install plan: parsing untrusted headers and producing a safe, reviewable command."""
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from tests.helpers import ROOT
from udash import scripts_catalog as C
from udash.store import ValidationError

SHA = "a" * 40
CORE = "b" * 40
HOMARR = (Path(__file__).parent / "fixture_homarr.sh").read_text()


def header(app="demo", cpu="1", ram="512", disk="4", tags="", os_="debian", extra=""):
    return (f'#!/usr/bin/env bash\n# Source: https://github.com/example/{app}\nAPP="{app}"\nvar_tags="${{var_tags:-{tags}}}"\n'
            f'var_cpu="${{var_cpu:-{cpu}}}"\nvar_ram="${{var_ram:-{ram}}}"\nvar_disk="${{var_disk:-{disk}}}"\n'
            f'var_os="${{var_os:-{os_}}}"\nvar_version="${{var_version:-13}}"\nvar_unprivileged="${{var_unprivileged:-1}}"\n{extra}')


class FakeGitHub:
    """Canned GitHub: a repo with a few ct scripts."""
    def __init__(self, scripts, broken=()):
        self.scripts, self.broken, self.calls = scripts, set(broken), []

    def __call__(self, url, limit=0, token="", range_bytes=None):
        self.calls.append(url)
        if "/repos/community-scripts/ProxmoxVE/commits/main" in url:
            return json.dumps({"sha": SHA}).encode()
        if "/repos/community-scripts/core/commits/main" in url:
            return json.dumps({"sha": CORE}).encode()
        if f"/git/trees/{SHA}" in url:
            return json.dumps({"tree": [{"path": "README.md", "type": "blob", "sha": "r"}, {"path": "ct", "type": "tree", "sha": "c" * 40}]}).encode()
        if "/git/trees/" in url:
            tree = [{"path": f"{s}.sh", "type": "blob"} for s in self.scripts] + [{"path": "notes.txt", "type": "blob"},
                                                                                  {"path": "Bad Name.sh", "type": "blob"},
                                                                                  {"path": "sub", "type": "tree"}]
            return json.dumps({"tree": tree}).encode()
        if "/ct/" in url:
            slug = url.rsplit("/", 1)[1][:-3]
            if slug in self.broken:
                raise OSError("boom")
            return self.scripts[slug].encode()
        raise AssertionError(url)


assert ROOT.is_dir()


class TmpCase(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="udcat-"))
        self.addCleanup(shutil.rmtree, self.d, True)

    def catalog(self, scripts=None, **kw):
        scripts = scripts or {"homarr": HOMARR, "sonarr": header("Sonarr", "2", "2048", "8", "arr;media"),
                              "adguard": header("AdGuard Home", tags="dns;adblock"), "jellyfin": header("Jellyfin", "2", "4096", "16", "media")}
        fake = FakeGitHub(scripts, **kw)
        cat = C.ScriptCatalog(self.d / "catalog.json", fetch=fake)
        cat.refresh()
        return cat, fake


class TestHeaderParsing(unittest.TestCase):
    def test_real_script(self):
        e = C.parse_ct_header("homarr", HOMARR)
        self.assertEqual((e["app"], e["cpu"], e["ram"], e["disk"], e["os"], e["version"], e["unprivileged"]),
                         ("homarr", 2, 2048, 8, "debian", "13", True))
        self.assertEqual(e["tags"], ["arr", "dashboard"])
        self.assertEqual(e["source"], "https://github.com/homarr-labs/homarr")
        self.assertEqual(e["page"], "https://community-scripts.org/scripts/homarr")

    def test_hostile_values_are_neutralised(self):
        e = C.parse_ct_header("evil", header("$(touch /tmp/pwn)", cpu="$(id)", ram="999999999999", disk="-4",
                                              tags="a;$(id);b b;UPPER;ok", os_="../../etc"))
        self.assertEqual(e["app"], "evil")                                      # not echoed anywhere: falls back to the slug
        self.assertEqual((e["cpu"], e["ram"], e["disk"], e["os"]), (1, 512, 4, "debian"))
        self.assertEqual(e["tags"], ["a", "ok"])
        e = C.parse_ct_header("x", 'APP="Name; rm -rf /"\n')
        self.assertEqual(e["app"], "x")
        e = C.parse_ct_header("x", "# Source: javascript:alert(1)\n# Source: http://insecure\n")
        self.assertIsNone(e["source"])

    def test_empty_or_binary_input(self):
        e = C.parse_ct_header("x", "")
        self.assertEqual((e["app"], e["cpu"], e["tags"]), ("x", 1, []))
        C.parse_ct_header("x", "\x00\x01 garbage \n" * 500)

    def test_only_the_top_of_the_file_is_read(self):
        text = "\n" * 100 + 'APP="late"\nvar_cpu="${var_cpu:-32}"\n'
        self.assertEqual(C.parse_ct_header("x", text)["cpu"], 1)


class TestCatalog(TmpCase):
    def test_refresh_builds_a_searchable_catalog(self):
        cat, fake = self.catalog()
        st = cat.status()
        self.assertEqual((st["count"], st["commit"], st["error"], st["loading"]), (4, SHA, None, False))
        self.assertEqual(cat.search("jelly")["results"][0]["slug"], "jellyfin")
        self.assertEqual([e["slug"] for e in cat.search("", tag="media")["results"]], ["jellyfin", "sonarr"])
        self.assertEqual(cat.search("adguard home")["total"], 1)                # multi-word, matches the app name
        self.assertEqual(cat.search("zzz")["total"], 0)
        self.assertEqual(cat.search("a", limit=2, offset=1)["results"][0]["slug"] != cat.search("a", limit=2)["results"][0]["slug"], True)
        self.assertIn("media", cat.tags())
        self.assertFalse(any("Bad Name" in u or "notes.txt" in u for u in fake.calls))     # only valid ct/*.sh names are fetched

    def test_exact_matches_rank_first(self):
        cat, _ = self.catalog({"sonarr": header("Sonarr"), "sonarr-extra": header("Sonarr Extra"), "x": header("my sonarr helper")})
        self.assertEqual(cat.search("sonarr")["results"][0]["slug"], "sonarr")

    def test_the_cache_is_saved_and_reloaded(self):
        cat, _ = self.catalog()
        again = C.ScriptCatalog(self.d / "catalog.json", fetch=FakeGitHub({}))
        self.assertEqual((again.status()["count"], again.commit, again.core_commit), (4, SHA, CORE))
        self.assertEqual(oct((self.d / "catalog.json").stat().st_mode & 0o777), "0o600")
        self.assertFalse(again.status()["stale"])
        self.assertFalse(again.refresh_async())                                  # fresh: no refetch

    def test_one_unreadable_script_does_not_break_the_rest_and_keeps_the_old_entry(self):
        cat, _ = self.catalog()
        old_cpu = cat.get("sonarr")["cpu"]
        cat2 = C.ScriptCatalog(self.d / "catalog.json", fetch=FakeGitHub({"sonarr": "", "homarr": HOMARR}, broken={"sonarr"}))
        cat2.refresh()
        self.assertEqual(cat2.get("sonarr")["cpu"], old_cpu)
        self.assertEqual(cat2.get("homarr")["cpu"], 2)

    def test_failures_are_reported_and_leave_the_old_catalog(self):
        cat, _ = self.catalog()

        def down(*a, **k):
            raise OSError("network is unreachable")

        bad = C.ScriptCatalog(self.d / "catalog.json", fetch=down)
        bad.refresh()
        self.assertIn("unreachable", bad.status()["error"])
        self.assertEqual(bad.status()["count"], 4)
        self.assertFalse(bad.status()["loading"])

    def test_a_commit_id_that_is_not_a_hash_is_refused(self):
        class Odd(FakeGitHub):
            def __call__(self, url, *a, **k):
                if url.endswith("/commits/main") and "ProxmoxVE" in url:
                    return json.dumps({"sha": "main; rm -rf /"}).encode()
                return super().__call__(url, *a, **k)

        cat = C.ScriptCatalog(self.d / "c2.json", fetch=Odd({"x": header()}))
        cat.refresh()
        self.assertIn("unexpected commit", cat.status()["error"])
        self.assertEqual(cat.status()["count"], 0)

    def test_fetching_is_limited_to_github(self):
        for url in ("http://raw.githubusercontent.com/x", "https://evil.example/x", "file:///etc/passwd",
                    "https://raw.githubusercontent.com.evil.example/x", "ftp://api.github.com/x"):
            with self.assertRaises(ValueError, msg=url):
                C.default_fetch(url)


class TestPlan(TmpCase):
    def setUp(self):
        super().setUp()
        self.cat, _ = self.catalog()

    def plan(self, apps, **kw):
        return C.build_plan(self.cat, apps, **kw)

    def test_pinned_reviewable_command(self):
        p = self.plan([{"slug": "homarr", "hostname": "homarr", "cpu": 2, "ram": 4096, "net": "10.10.56.30/24", "gateway": "10.10.56.1",
                        "bridge": "vmbr0", "storage": "kingston_store"}], node_name="pve1")
        a = p["apps"][0]
        self.assertEqual(p["commit"], SHA)
        self.assertIn(f"https://raw.githubusercontent.com/community-scripts/ProxmoxVE/{SHA}/ct/homarr.sh", a["command"])
        self.assertIn(f"COMMUNITY_SCRIPTS_URL=https://raw.githubusercontent.com/community-scripts/ProxmoxVE/{SHA}", a["command"])
        self.assertIn(f"COMMUNITY_SCRIPTS_CORE_URL=https://raw.githubusercontent.com/community-scripts/core/{CORE}", a["command"])
        for expected in ("PHS_SILENT=1", "mode=default", "var_hostname=homarr", "var_cpu=2", "var_ram=4096", "var_net=10.10.56.30/24",
                         "var_gateway=10.10.56.1", "var_brg=vmbr0", "var_container_storage=kingston_store"):
            self.assertIn(expected, a["command"])
        self.assertNotIn("var_disk", a["command"])                               # untouched settings keep the script's own default
        self.assertEqual(a["sha256"], hashlib.sha256(HOMARR.encode()).hexdigest())
        self.assertEqual(a["review"], f"https://github.com/community-scripts/ProxmoxVE/blob/{SHA}/ct/homarr.sh")
        self.assertIn("for pve1", p["script"])
        self.assertIn("NOT run by it", p["script"])

    def test_the_script_is_valid_bash_for_one_and_many_apps(self):
        for apps in ([{"slug": "homarr"}], [{"slug": "homarr"}, {"slug": "sonarr", "hostname": "sonarr"}, {"slug": "jellyfin", "ctid": 130}]):
            for opt in (True, False):
                script = self.plan(apps, opt_out_diagnostics=opt)["script"]
                r = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_diagnostics_opt_out_never_overwrites_an_existing_choice(self):
        s = self.plan([{"slug": "homarr"}])["script"]
        self.assertIn("[ -f /usr/local/community-scripts/diagnostics ] ||", s)
        self.assertIn("DIAGNOSTICS=no", s)
        self.assertNotIn("DIAGNOSTICS", self.plan([{"slug": "homarr"}], opt_out_diagnostics=False)["script"])

    def test_running_the_script_passes_the_settings_and_stops_at_the_first_failure(self):
        """Run the real generated script with a fake curl/id, to see exactly what each installer would receive."""
        bindir = self.d / "bin"
        bindir.mkdir()
        (bindir / "id").write_text('#!/bin/sh\n[ "$1" = "-u" ] && echo 0 || /usr/bin/id "$@"\n')
        # the shim prints an "installer" script; its $-variables must reach the script unexpanded, as the real one would see them
        (bindir / "curl").write_text(r"""#!/bin/sh
url=""; for a; do url="$a"; done
slug="${url##*/}"; slug="${slug%.sh}"
printf '%s\n' "echo INSTALLER slug=$slug host=\"\$var_hostname\" cpu=\"\$var_cpu\" mode=\$mode silent=\$PHS_SILENT base=\$COMMUNITY_SCRIPTS_URL"
[ "$slug" = sonarr ] && printf '%s\n' "exit 3"
exit 0
""")
        for f in ("id", "curl"):
            os.chmod(bindir / f, os.stat(bindir / f).st_mode | stat.S_IEXEC)
        apps = [{"slug": "homarr", "hostname": "h1", "cpu": 4}, {"slug": "sonarr"}, {"slug": "jellyfin"}]
        script = self.plan(apps, opt_out_diagnostics=False)["script"]
        r = subprocess.run(["bash", "-c", script], env={**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"}, capture_output=True, text=True)
        self.assertIn(f"INSTALLER slug=homarr host=h1 cpu=4 mode=default silent=1 base=https://raw.githubusercontent.com/community-scripts/ProxmoxVE/{SHA}", r.stdout)
        self.assertIn("slug=sonarr", r.stdout)
        self.assertNotIn("slug=jellyfin", r.stdout)                              # stopped after sonarr failed
        self.assertEqual(r.returncode, 1)
        self.assertIn("Sonarr failed; stopping.", r.stderr)

    def test_a_hostile_script_header_cannot_inject_into_the_plan(self):
        cat, _ = self.catalog({"evil": header("$(touch /tmp/pwned_by_header)"), "evil2": 'APP="x\\"; touch /tmp/pwned2; echo \\""\n'})
        for slug in ("evil", "evil2"):
            script = C.build_plan(cat, [{"slug": slug}])["script"]
            self.assertNotIn("pwned", script)
            self.assertEqual(subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True).returncode, 0)

    def test_every_field_is_validated(self):
        bad = [{"slug": "homarr", "hostname": "Bad Host"}, {"slug": "homarr", "hostname": "a;b"}, {"slug": "homarr", "hostname": "-x"},
               {"slug": "homarr", "cpu": 0}, {"slug": "homarr", "cpu": 65}, {"slug": "homarr", "cpu": "2; id"}, {"slug": "homarr", "cpu": True},
               {"slug": "homarr", "ram": 64}, {"slug": "homarr", "disk": 0}, {"slug": "homarr", "ctid": 99}, {"slug": "homarr", "ctid": "12 3"},
               {"slug": "homarr", "net": "10.10.56.30"}, {"slug": "homarr", "net": "300.1.1.1/24", "gateway": "10.0.0.1"},
               {"slug": "homarr", "net": "10.0.0.5/40", "gateway": "10.0.0.1"}, {"slug": "homarr", "net": "10.0.0.5/24"},
               {"slug": "homarr", "net": "dhcp", "gateway": "10.0.0.1"}, {"slug": "homarr", "net": "10.0.0.5/24", "gateway": "10.0.0.1; id"},
               {"slug": "homarr", "bridge": "vmbr0; id"}, {"slug": "homarr", "storage": "a b"}, {"slug": "homarr", "storage": "$(id)"},
               {"slug": "../../etc/passwd"}, {"slug": "nope"}, {"slug": ""}, {}, "homarr", None]
        for req in bad:
            with self.assertRaises(ValidationError, msg=req):
                self.plan([req])
        for apps in ([], None, "x", [{"slug": "homarr"}] * (C.MAX_APPS_PER_PLAN + 1)):
            with self.assertRaises(ValidationError):
                self.plan(apps)

    def test_duplicates_are_caught(self):
        with self.assertRaises(ValidationError):
            self.plan([{"slug": "homarr", "hostname": "x"}, {"slug": "sonarr", "hostname": "x"}])
        with self.assertRaises(ValidationError):
            self.plan([{"slug": "homarr", "ctid": 130}, {"slug": "sonarr", "ctid": 130}])
        two = self.plan([{"slug": "homarr", "hostname": "h1"}, {"slug": "homarr", "hostname": "h2"}])
        self.assertTrue(two["warnings"] or len(two["apps"]) == 2)

    def test_it_never_executes_anything(self):
        # building a plan only fetches text; no subprocess is involved in the module at all
        import inspect
        src = inspect.getsource(C)
        for banned in ("subprocess", "os.system", "Popen", "exec(", "eval(", "importlib"):
            self.assertNotIn(banned, src)

    def test_plan_needs_a_loaded_catalog(self):
        empty = C.ScriptCatalog(self.d / "none.json", fetch=FakeGitHub({}))
        with self.assertRaises(ValidationError):
            C.build_plan(empty, [{"slug": "homarr"}])


class TestAsync(TmpCase):
    def test_refresh_async_runs_once_and_reports_progress(self):
        cat = C.ScriptCatalog(self.d / "a.json", fetch=FakeGitHub({"homarr": HOMARR}))
        self.assertTrue(cat.refresh_async())
        end = time.time() + 5
        while cat.status()["loading"] and time.time() < end:
            time.sleep(0.05)
        self.assertEqual(cat.status()["count"], 1)
        self.assertEqual(cat.status()["progress"], [1, 1])


if __name__ == "__main__":
    unittest.main()


class TestCatalogApi(unittest.TestCase):
    def setUp(self):
        import threading

        from tests.helpers import App, Client, LimitedServer, load_config, make_handler, write_config, wrap_tls
        self.tmp = tempfile.mkdtemp(prefix="udcatapi-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.app = App(load_config(write_config(self.tmp)), state_dir=Path(self.tmp) / "state", base_dir=ROOT)
        self.app.catalog._fetch = FakeGitHub({"homarr": HOMARR, "sonarr": header("Sonarr", "2", "2048", "8", "arr;media")})
        srv = LimitedServer(("127.0.0.1", 0), make_handler(self.app), max_connections=64)
        wrap_tls(srv, self.app)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.c = Client(f"http://127.0.0.1:{srv.server_address[1]}")
        self.anon = Client(self.c.base)
        self.c.login()

    def wait_loaded(self):
        end = time.time() + 8
        while time.time() < end:
            st = self.c.get("/api/catalog")[1]
            if st["status"]["count"] and not st["status"]["loading"]:
                return st
            time.sleep(0.1)
        self.fail("catalog did not load")

    def test_browse_search_and_plan(self):
        st = self.wait_loaded()
        self.assertEqual(st["total"], 2)
        self.assertIn("media", st["tags"])
        res = self.c.get("/api/catalog?q=sonarr")[1]["results"]
        self.assertEqual([e["slug"] for e in res], ["sonarr"])
        self.assertEqual(self.c.get("/api/catalog?tag=arr")[1]["total"], 2)       # homarr is tagged arr;dashboard
        st, plan, _ = self.c.post("/api/install/plan", {"apps": [{"slug": "homarr", "hostname": "homarr"}, {"slug": "sonarr"}], "host": 0})
        self.assertEqual(st, 200)
        self.assertEqual([a["slug"] for a in plan["apps"]], ["homarr", "sonarr"])
        self.assertIn(SHA, plan["script"])
        self.assertIn("install.plan", [e["action"] for e in self.c.get("/api/audit")[1]["events"]])

    def test_it_requires_a_login_and_validates(self):
        self.wait_loaded()
        for path in ("/api/catalog", "/api/catalog?q=x"):
            self.assertEqual(self.anon.get(path)[0], 401)
        self.assertEqual(self.anon.post("/api/install/plan", {"apps": [{"slug": "homarr"}]})[0], 401)
        self.assertEqual(self.c.post("/api/install/plan", {"apps": [{"slug": "homarr"}]}, csrf=False)[0], 403)
        for body in ({"apps": []}, {"apps": [{"slug": "nope"}]}, {"apps": [{"slug": "homarr", "cpu": "9;id"}]},
                     {"apps": [{"slug": "homarr"}], "host": "x"}, {"apps": "homarr"}):
            self.assertEqual(self.c.post("/api/install/plan", body)[0], 400, body)
        self.assertEqual(self.c.get("/api/catalog?limit=abc")[0], 400)

    def test_nothing_was_executed_or_changed_on_any_host(self):
        self.wait_loaded()
        before = {p.name for p in Path(self.tmp).rglob("*")}
        self.c.post("/api/install/plan", {"apps": [{"slug": "homarr"}]})
        after = {p.name for p in Path(self.tmp).rglob("*")}
        self.assertEqual(after - before - {"audit.log"}, set())                    # a plan writes nothing but the audit entry

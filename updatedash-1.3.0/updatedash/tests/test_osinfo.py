import unittest

from tests.helpers import ROOT, Client  # importing helpers puts the project on sys.path
from udash.osinfo import OS_INFO, cmd_os_pending, parse_os_info, parse_pending

DEBIAN_12 = [
    "Inst libc6 [2.36-9+deb12u9] (2.36-9+deb12u10 Debian-Security:12/stable-security [amd64])",
    "Inst openssl [3.0.15-1~deb12u1] (3.0.16-1~deb12u1 Debian-Security:12/stable-security [amd64])",
    "Inst tzdata [2024b-0+deb12u1] (2025a-0+deb12u1 Debian:12.9/stable-updates, Debian:12.9/stable [all])",
    "Inst base-files [12.4+deb12u9] (12.4+deb12u10 Debian:12.10/stable [amd64])",
    "Inst curl [7.88.1-10+deb12u8] (7.88.1-10+deb12u12 Debian:12.10/stable, Debian-Security:12/stable-security [amd64])",
    "Conf libc6 (2.36-9+deb12u10 Debian-Security:12/stable-security [amd64])",
    "Remv something [1.0]",
    "",
]
UBUNTU = [
    "Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-security, Ubuntu:24.04/noble-updates [amd64])",
    "Inst vim [2:9.1.0016-1ubuntu7.3] (2:9.1.0016-1ubuntu7.5 Ubuntu:24.04/noble-updates [amd64])",
    "Inst base-files [13ubuntu10.1] (13ubuntu10.2 Ubuntu:24.04/noble-updates [amd64])",
]


assert ROOT.is_dir()


class TestPending(unittest.TestCase):
    def test_debian(self):
        r = parse_pending(DEBIAN_12)
        self.assertEqual((r["total"], r["security"]), (5, 3))
        self.assertEqual([p["pkg"] for p in r["packages"]], ["curl", "libc6", "openssl", "base-files", "tzdata"])   # security first, then by name
        libc = next(p for p in r["packages"] if p["pkg"] == "libc6")
        self.assertEqual((libc["from"], libc["to"], libc["security"]), ("2.36-9+deb12u9", "2.36-9+deb12u10", True))
        self.assertFalse(next(p for p in r["packages"] if p["pkg"] == "tzdata")["security"])
        self.assertEqual(r["point"], ("12.9", "12.10"))                              # Debian 12.9 -> 12.10 via base-files

    def test_ubuntu_has_security_but_no_point_release_arrow(self):
        r = parse_pending(UBUNTU)
        self.assertEqual((r["total"], r["security"], r["point"]), (3, 1, None))

    def test_nothing_pending_and_garbage(self):
        self.assertEqual(parse_pending([])["total"], 0)
        r = parse_pending(["Inst", "Inst x", "random text", "Inst weird ((("])
        self.assertEqual(r["total"], 0)
        self.assertIsNone(r["point"])

    def test_the_list_is_capped_but_the_counts_are_exact(self):
        lines = [f"Inst pkg{i:04d} [1.0] (1.1 Debian-Security:12/stable-security [amd64])" for i in range(450)]
        r = parse_pending(lines)
        self.assertEqual((r["total"], r["security"], len(r["packages"])), (450, 450, 300))

    def test_new_dependency_without_an_old_version(self):
        r = parse_pending(["Inst libnew (1.0 Debian:12.10/stable [amd64])"])
        self.assertEqual((r["total"], r["packages"][0]["from"]), (1, ""))


class TestOsInfo(unittest.TestCase):
    def test_parse(self):
        info = parse_os_info(["UD_NAME=Debian GNU/Linux 12 (bookworm)", "UD_ID=debian", "UD_VERSION=12", "UD_CODENAME=bookworm",
                              "UD_DEBIAN=12.9", "UD_APT=1", "noise"])
        self.assertEqual(info["name"], "Debian GNU/Linux 12 (bookworm)")
        self.assertEqual((info["debian"], info["apt"], info["codename"]), ("12.9", True, "bookworm"))

    def test_alpine_has_no_apt(self):
        info = parse_os_info(["UD_NAME=Alpine Linux v3.19", "UD_ID=alpine", "UD_VERSION=3.19.1", "UD_CODENAME=", "UD_DEBIAN="])
        self.assertFalse(info["apt"])
        self.assertIsNone(info["debian"])

    def test_commands_are_fixed_strings(self):
        self.assertIn("/etc/os-release", OS_INFO)
        self.assertTrue(cmd_os_pending(True).startswith("apt-get update -qq"))
        self.assertFalse(cmd_os_pending(False).startswith("apt-get update"))
        self.assertNotIn("\n", OS_INFO)


if __name__ == "__main__":
    unittest.main()


class TestSystemPaneEndToEnd(unittest.TestCase):
    """Real check + API with canned container output (the gate vocabulary is the only thing run)."""

    def make(self):
        import shutil
        import tempfile
        import threading
        from pathlib import Path

        from tests.helpers import App, LimitedServer, load_config, make_handler, write_config, wrap_tls
        tmp = tempfile.mkdtemp(prefix="udos-")
        self.addCleanup(shutil.rmtree, tmp, True)
        extra = 'services:\n  - name: debian-box\n    ctid: 501\n  - name: alpine-box\n    ctid: 502\n  - name: down-box\n    ctid: 503\n'
        app = App(load_config(write_config(tmp, extra)), state_dir=Path(tmp) / "state", base_dir=ROOT)
        srv = LimitedServer(("127.0.0.1", 0), make_handler(app), max_connections=64)
        wrap_tls(srv, app)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        c = Client(f"http://127.0.0.1:{srv.server_address[1]}")
        self.assertEqual(c.login()[0], 200)
        return app, c

    def test_debian_alpine_and_unreachable(self):
        app, c = self.make()
        info_deb = ["UD_NAME=Debian GNU/Linux 12 (bookworm)", "UD_ID=debian", "UD_VERSION=12", "UD_CODENAME=bookworm",
                    "UD_DEBIAN=12.9", "UD_APT=1"]
        info_alp = ["UD_NAME=Alpine Linux v3.19", "UD_ID=alpine", "UD_VERSION=3.19.1", "UD_CODENAME=", "UD_DEBIAN="]

        def fake_exec(uid, cmd, timeout=60, on_line=None, holder=None):
            if uid == 503:
                return 255, ["updatedash-gate: request not permitted"]
            if cmd == OS_INFO:
                return 0, info_deb if uid == 501 else info_alp
            if cmd in (cmd_os_pending(True), cmd_os_pending(False)):
                return 0, DEBIAN_12
            return 0, []

        app.dash.runner.exec = fake_exec
        app.dash.check_all()
        svc = {s["ctid"]: s for s in c.get("/api/services")[1]["services"]}
        d = svc[501]
        self.assertEqual((d["os_updates"], d["os_security"], d["status"]), (5, 3, "os"))
        self.assertEqual(d["os_info"]["name"], "Debian GNU/Linux 12 (bookworm)")
        self.assertEqual(d["os_point"], ["12.9", "12.10"])
        self.assertNotIn("os_packages", d)                                       # the list is fetched on demand, not on every poll
        a = svc[502]
        self.assertIsNone(a["os_updates"])                                       # no apt: not "0 pending", but "not checked"
        self.assertFalse(a["os_info"]["apt"])
        self.assertEqual(a["status"], "nocheck")
        self.assertEqual(svc[503]["status"], "error")
        out = c.get("/api/services")[1]
        self.assertEqual((out["os_pending"], out["security"]), (1, 1))
        full = c.get("/api/system?ctid=501")[1]
        self.assertEqual((full["total"], full["security"]), (5, 3))
        self.assertEqual([p["pkg"] for p in full["packages"]][:3], ["curl", "libc6", "openssl"])
        self.assertTrue(all(p["security"] for p in full["packages"][:3]))
        self.assertEqual(c.get("/api/system?ctid=999999")[0], 404)
        self.assertEqual(c.get("/api/system?ctid=x")[0], 400)
        self.assertEqual(Client(c.base).get("/api/system?ctid=501")[0], 401)       # needs a login like everything else

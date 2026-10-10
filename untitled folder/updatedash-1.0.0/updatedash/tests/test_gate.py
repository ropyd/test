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

LIST = ("VMID       Status     Lock         Name\n101        running                 secure01\n"
        "106        running                 homarr\n113        running                 autobrr\n"
        "126        running                 updatedash\n")


def load_gate():
    spec = importlib.util.spec_from_file_location("gate", ROOT / "pve-gate.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestGate(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.g = load_gate()
        self.g.ALLOW_FILE = f"{self.d}/allow"
        self.g.MANAGE_FLAG = f"{self.d}/manage"
        self.g.PROTECTED_FILE = f"{self.d}/protected"
        Path(self.g.ALLOW_FILE).write_text("106\n113\n")

    def run_gate(self, cmd):
        """Returns (exit code, stdout, stderr, execv args or None)."""
        out, err, called = io.StringIO(), io.StringIO(), []

        def fake_run(argv, **kw):
            if argv[1] == "list":
                return mock.Mock(stdout=LIST, stderr="", returncode=0)
            if argv[1] == "status":
                return mock.Mock(stdout="status: running", stderr="", returncode=0 if argv[2] in ("101", "106", "113", "126") else 2)
            raise AssertionError(argv)

        code = 0
        with mock.patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": cmd}), \
                mock.patch.object(self.g.subprocess, "run", fake_run), \
                mock.patch.object(self.g.os, "execv", lambda p, a: called.append(a)), \
                redirect_stdout(out), redirect_stderr(err):
            try:
                self.g.main()
            except SystemExit as e:
                code = e.code or 0
        return code, out.getvalue(), err.getvalue(), (called[0] if called else None)

    def allowed(self):
        return {x for x in Path(self.g.ALLOW_FILE).read_text().split() if x.isdigit()}

    def test_container_commands_only_for_allowed_ids(self):
        self.assertEqual(self.run_gate("pct exec 106 -- bash -c 'id'")[3], ["pct", "exec", "106", "--", "bash", "-c", "id"])
        self.assertEqual(self.run_gate("pct exec 101 -- bash -c id")[0], 126)
        self.assertEqual(self.run_gate("pct snapshot 113 pre-update-20261010-005216")[0], 0)
        self.assertEqual(self.run_gate("pct snapshot 113 evil;rm")[0], 126)
        self.assertEqual(self.run_gate("pct listsnapshot 106")[3][:2], ["pct", "listsnapshot"])

    def test_everything_else_is_refused(self):
        for cmd in ("", "bash -c id", "pct destroy 106", "pct exec 106 -- bash -c id; reboot", "pct exec 106 -- sh -c id",
                    "pct exec 106 -- bash -c id extra", "pct stop 106", "pct list --all", "allow add 101",
                    "pct rollback 106 x", "id", "pct exec 106 -- bash -c 'unterminated"):
            code = self.run_gate(cmd)[0]
            self.assertEqual(code, 126, cmd)

    def test_list_is_filtered(self):
        code, out, _, _ = self.run_gate("pct list")
        self.assertEqual(code, 0)
        self.assertIn("homarr", out)
        self.assertNotIn("secure01", out)
        self.assertNotIn("updatedash", out)
        self.assertEqual(self.run_gate("allow list")[1].split(), ["106", "113"])

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
        self.assertEqual(self.run_gate("pct exec 113 -- bash -c id")[0], 126)    # removal is immediate
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
        # already-allowed protected containers can still be updated
        self.assertEqual(self.run_gate("pct exec 113 -- bash -c id")[3][2], "113")

    def test_allow_file_written_atomically_with_header(self):
        Path(self.g.MANAGE_FLAG).write_text("126\n")
        self.run_gate("allow add 101")
        text = Path(self.g.ALLOW_FILE).read_text()
        self.assertTrue(text.startswith("#"))
        self.assertEqual(oct(os.stat(self.g.ALLOW_FILE).st_mode & 0o777), "0o644")
        self.assertFalse(list(Path(self.d).glob("*.tmp")))


if __name__ == "__main__":
    unittest.main()

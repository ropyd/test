"""Several independent Proxmox nodes: ids, the registry, the setup script and the API."""
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import ROOT, AppCase
from udash import store as S
from udash.hostsetup import SetupError, build_setup_script

PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPLdK7BLlUcB11piKVQaDMvrqbwTJ1EKaYiG3COPM56z updatedash"
LIST0 = "VMID Status Lock Name\n114 running  sonarr\n115 running  radarr\n130 stopped  tailscale\n"
LIST1 = "VMID Status Lock Name\n114 running  jellyfin\n120 running  autobrr\n"


class TestIds(unittest.TestCase):
    def test_host_zero_keeps_plain_ct_numbers(self):
        self.assertEqual(S.make_uid(0, 114), 114)
        self.assertEqual(S.split_uid(114), (0, 114))
        uid = S.make_uid(1, 114)
        self.assertNotEqual(uid, 114)
        self.assertEqual(S.split_uid(uid), (1, 114))
        self.assertEqual(S.split_uid(S.make_uid(7, 999_999_999)), (7, 999_999_999))

    def test_custom_ssh_hosts_are_not_confused_with_second_node_containers(self):
        self.assertTrue(S.is_custom_uid(S.CUSTOM_BASE))
        self.assertFalse(S.is_custom_uid(114))
        self.assertFalse(S.is_custom_uid(S.make_uid(1, 114)))
        self.assertFalse(S.is_custom_uid(S.make_uid(1, S.CUSTOM_BASE + 5)))        # a big CT number on node 1 is still a container
        self.assertLess(S.make_uid(7, 999_999_999), 2 ** 53)                       # safe as a JavaScript number


class TestRegistry(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.d, True)
        self.path = Path(self.d) / "hosts.json"

    def reg(self, **primary):
        return S.HostRegistry(self.path, dict({"host": "10.10.56.5", "name": "pve1"}, **primary))

    def test_primary_comes_from_config_and_others_are_added(self):
        r = self.reg()
        self.assertEqual([h["name"] for h in r.all()], ["pve1"])
        idx = r.add("pve2", "10.10.56.6")
        self.assertEqual(idx, 1)
        self.assertEqual([(h["idx"], h["name"], h["primary"]) for h in r.all()], [(0, "pve1", True), (1, "pve2", False)])
        self.assertEqual(r.by_name("PVE2")["host"], "10.10.56.6")
        self.assertEqual(self.reg().get(1)["name"], "pve2")                         # persisted

    def test_indexes_are_never_reused(self):
        r = self.reg()
        a = r.add("pve2", "10.10.56.6")
        self.assertTrue(r.remove(a))
        b = r.add("pve3", "10.10.56.7")
        self.assertEqual((a, b), (1, 2))
        self.assertEqual(self.reg().next_idx, 3)
        self.assertFalse(r.remove(0))                                               # the primary can't be removed

    def test_validation(self):
        r = self.reg()
        r.add("pve2", "10.10.56.6")
        for name, host, user in (("pve2", "10.10.56.9", "root"), ("PVE2", "10.10.56.9", "root"), ("new", "10.10.56.6", "root"),
                                 ("new", "10.10.56.5", "root"), ("", "10.0.0.1", "root"), ("x", "-oProxyCommand=id", "root"),
                                 ("x", "a b", "root"), ("x", "10.0.0.1", "Root"), ("x;y", "10.0.0.1", "root")):
            with self.assertRaises(S.ValidationError, msg=(name, host, user)):
                r.add(name, host, user)

    def test_a_maximum_number_of_nodes(self):
        r = self.reg()
        for i in range(1, S.MAX_HOSTS):
            r.add(f"n{i}", f"10.0.0.{i}")
        with self.assertRaises(S.ValidationError):
            r.add("one-too-many", "10.0.1.1")

    def test_an_ssh_only_install_has_no_usable_primary(self):
        r = S.HostRegistry(None, {})
        self.assertEqual(r.all()[0]["host"], "")


class TestSetupScript(unittest.TestCase):
    def run_script(self, script, root, **env):
        p = Path(root) / "setup.sh"
        p.write_text(script)
        return subprocess.run(["bash", str(p)], env=dict(os.environ, UD_ROOT=str(root / "fs"), **env), capture_output=True, text=True)

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.d, True)
        self.gate = (ROOT / "pve-gate.py").read_bytes()

    def fs(self, rel):
        return self.d / "fs" / rel

    def test_it_installs_the_exact_gate_and_a_restricted_key(self):
        script = build_setup_script(self.gate, PUB, ["10.10.56.16"], "201 202", "202")
        self.assertEqual(subprocess.run(["bash", "-n", "/dev/stdin"], input=script, text=True).returncode, 0)
        r = self.run_script(script, self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.fs("usr/local/sbin/updatedash-gate").read_bytes(), self.gate)       # byte for byte
        line = self.fs("var/lib/updatedash-gate/.ssh/authorized_keys").read_text().strip()
        self.assertEqual(line, f'command="sudo -n /usr/local/sbin/updatedash-gate",from="10.10.56.16",restrict {PUB}')
        sudoers = self.fs("etc/sudoers.d/updatedash-gate").read_text().splitlines()
        self.assertIn("updatedash-gate ALL=(root) NOPASSWD: /usr/local/sbin/updatedash-gate", sudoers)   # exactly one command, no wildcard
        self.assertTrue(any("env_keep" in ln and "SSH_ORIGINAL_COMMAND" in ln for ln in sudoers))
        self.assertEqual(len([ln for ln in sudoers if "NOPASSWD" in ln]), 1)
        self.assertNotIn("ALL=(ALL)", "".join(sudoers))
        self.assertEqual(self.fs("etc/updatedash-gate.allow").read_text().split(), ["201", "202"])
        self.assertEqual([x for x in self.fs("etc/updatedash-gate.protected").read_text().split() if x.isdigit()], ["202"])
        self.assertTrue(self.fs("etc/updatedash-gate.manage").exists())
        self.assertTrue(self.fs("etc/updatedash-gate.commands").exists())

    def test_gate_user_can_be_root_for_the_old_behaviour(self):
        script = build_setup_script(self.gate, PUB, ["10.10.56.16"], "201", gate_user="root")
        self.assertEqual(self.run_script(script, self.d).returncode, 0)
        self.assertEqual(self.fs("root/.ssh/authorized_keys").read_text().strip(),
                         f'command="/usr/local/sbin/updatedash-gate",from="10.10.56.16",restrict {PUB}')
        self.assertFalse(self.fs("etc/sudoers.d/updatedash-gate").exists())

    def test_builder_and_setup_script_install_the_same_sudo_rule(self):
        builder = (ROOT.parent / "ct" / "updatedash.sh").read_text()
        script = build_setup_script(self.gate, PUB, ["10.0.0.1"])
        for needle in ('env_keep += "SSH_ORIGINAL_COMMAND SSH_CONNECTION SSH_CLIENT"', "NOPASSWD: ", "usermod -p '*'",
                       "visudo -cf", "sudo -n "):
            self.assertIn(needle, builder, needle)
            self.assertIn(needle, script, needle)
        self.assertIn('GATE_USER="${GATE_USER:-updatedash-gate}"', builder)

    def test_bad_gate_user_is_refused(self):
        for bad in ("a b", "x;rm", "Root", "", "a" * 40):
            with self.assertRaises(SetupError):
                build_setup_script(self.gate, PUB, ["10.0.0.1"], gate_user=bad)

    def test_it_is_safe_to_repeat_and_replaces_an_old_key_line(self):
        script = build_setup_script(self.gate, PUB, ["10.10.56.16"], "201")
        ak = self.fs("var/lib/updatedash-gate/.ssh/authorized_keys")
        ak.parent.mkdir(parents=True)
        ak.write_text(f'command="/old/gate",from="1.2.3.4",no-pty {PUB}\nssh-ed25519 AAAAOTHERUSERSKEY someone\n')
        for _ in range(2):
            self.assertEqual(self.run_script(script, self.d).returncode, 0)
        lines = ak.read_text().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(sum(PUB.split()[1] in ln for ln in lines), 1)              # one line for the dashboard, no duplicates
        self.assertIn("someone", ak.read_text())                                    # other keys untouched
        self.assertNotIn("/old/gate", ak.read_text())
        self.assertEqual(self.fs("etc/updatedash-gate.allow").read_text().split().count("201"), 1)

    def test_environment_can_change_what_is_allowed_and_turn_gui_management_off(self):
        script = build_setup_script(self.gate, PUB, ["10.10.56.16"], "201")
        r = self.run_script(script, self.d, ALLOW_CTIDS="300 301", GUI_MANAGE="0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.fs("etc/updatedash-gate.allow").read_text().split(), ["300", "301"])
        self.assertFalse(self.fs("etc/updatedash-gate.manage").exists())
        self.assertNotEqual(self.run_script(script, self.d, ALLOW_CTIDS="300; rm -rf /").returncode, 0)

    def test_hostile_or_malformed_input_is_refused_when_generating(self):
        for pub in ("", "ssh-rsa AAAA", PUB + "\nssh-ed25519 AAAAEVIL x", PUB.replace("updatedash", "x'; touch /tmp/pwn; '"), "x" * 5000):
            with self.assertRaises(SetupError, msg=pub[:40]):
                build_setup_script(self.gate, pub, ["10.0.0.1"])
        for ips in (["10.0.0.1; id"], ["not-an-ip"], ["10.0.0.1\n10.0.0.2"]):
            with self.assertRaises(SetupError):
                build_setup_script(self.gate, PUB, ips)
        for ids in ("1; rm", "abc", "1 2 $(id)", "9999999999"):
            with self.assertRaises(SetupError):
                build_setup_script(self.gate, PUB, ["10.0.0.1"], ids)

    def test_without_an_address_the_key_is_unrestricted_and_the_script_says_so(self):
        script = build_setup_script(self.gate, PUB, [])
        self.assertIn("WARNING", script)
        self.assertEqual(self.run_script(script, self.d).returncode, 0)
        self.assertNotIn("from=", self.fs("var/lib/updatedash-gate/.ssh/authorized_keys").read_text())

    def test_two_addresses(self):
        script = build_setup_script(self.gate, PUB, ["10.0.0.1", "fd00::5"])
        self.assertEqual(self.run_script(script, self.d).returncode, 0)
        self.assertIn('from="10.0.0.1,fd00::5"', self.fs("var/lib/updatedash-gate/.ssh/authorized_keys").read_text())


class TwoNodes(AppCase):
    """Local transport, but two nodes with their own fake `pct list` output."""
    extra_config = ('discover: true\npve:\n  name: pve1\n  host: 10.10.56.5\n  key: __TMP__/id_ed25519\n'
                    'services:\n  - name: override-on-node-2\n    ctid: 114\n    host: pve2\n    os_updates: false\n')

    def prepare(self):
        (Path(self.tmp) / "l0").write_text(LIST0)
        (Path(self.tmp) / "l1").write_text(LIST1)
        (Path(self.tmp) / "id_ed25519.pub").write_text(PUB + "\n")
        p = mock.patch.dict(os.environ, {"UPDATEDASH_FAKE_LIST": f"{self.tmp}/l0", "UPDATEDASH_FAKE_LIST_1": f"{self.tmp}/l1"})
        p.start()
        self.addCleanup(p.stop)

    def setUp(self):
        super().setUp()
        self.app.dash.runner.hostkey_known = lambda host, port: True               # the host-key step has its own tests
        self.c = self.signed_in()

    def add_second(self, **kw):
        return self.c.post("/api/hosts/add", dict({"name": "pve2", "host": "10.10.56.6"}, **kw))

    def names(self):
        return {s["ctid"]: (s["name"], s["host"], s["real_ctid"]) for s in self.c.get("/api/services")[1]["services"]}

    def test_the_same_ct_number_on_two_nodes_is_two_containers(self):
        self.assertEqual(self.add_second()[0], 200)
        svc = self.names()
        self.assertEqual(svc[114][:1] + svc[114][2:], ("sonarr", 114))
        self.assertEqual(svc[1_000_000_114][1:], ("pve2", 114))
        self.assertEqual(svc[1_000_000_114][0], "override-on-node-2")                 # the config override names the node
        self.assertEqual(svc[1_000_000_120][0], "autobrr")
        self.assertEqual(len(svc), 5)
        hosts = self.c.get("/api/hosts")[1]["hosts"]
        self.assertEqual([(h["name"], h["containers"]) for h in hosts], [("pve1", 3), ("pve2", 2)])

    def test_each_node_has_its_own_manage_list(self):
        self.add_second()
        a = self.c.get("/api/inventory?host=0")[1]
        b = self.c.get("/api/inventory?host=1")[1]
        self.assertEqual([r["name"] for r in a["containers"]], ["sonarr", "radarr", "tailscale"])
        self.assertEqual([r["name"] for r in b["containers"]], ["jellyfin", "autobrr"])
        self.assertEqual(self.c.post("/api/allow", {"host": 1, "ctid": 120, "action": "add"})[0], 200)
        self.assertEqual(self.c.get("/api/inventory?host=1")[1]["containers"][1]["managed"], True)
        self.assertEqual(self.c.get("/api/inventory?host=0")[1]["containers"][1]["managed"], False)    # node 1's change stayed on node 1
        self.assertEqual(self.c.post("/api/allow", {"host": 99, "ctid": 1, "action": "add"})[0], 400)       # no such node

    def test_a_node_that_is_down_does_not_hide_the_others(self):
        self.add_second()
        time.sleep(1.5)                                                               # let the sweep started by add_host finish
        real = self.app.dash.runner.pct

        def flaky(*a, host=0, **k):
            return (255, ["ssh: connect to host 10.10.56.6 port 22: No route to host"]) if host == 1 else real(*a, host=host, **k)

        self.app.dash.runner.pct = flaky
        self.app.dash.sync_inventory()
        svc = self.names()
        self.assertIn(114, svc)                                                       # node 1 still listed...
        self.assertIn(1_000_000_120, svc)                                             # ...with its last known containers
        out = self.c.get("/api/services")[1]
        self.assertIn("pve2", out["inventory_error"])
        self.assertIn("No route to host", out["inventory_error"])
        self.assertEqual([h["error"] is not None for h in out["hosts"]], [False, True])

    def test_adding_a_node_requires_a_confirmed_host_key_and_a_working_gate(self):
        self.app.dash.runner.hostkey_known = lambda host, port: False
        st, out, _ = self.add_second()
        self.assertEqual(st, 400)
        self.assertIn("not trusted yet", out["error"])
        self.assertEqual(len(self.c.get("/api/hosts")[1]["hosts"]), 1)
        trusted = []
        self.app.dash.runner.trust_hostkey = lambda host, port, fp: trusted.append((host, fp)) or fp == "SHA256:good"
        self.assertEqual(self.add_second(trust_fingerprint="SHA256:wrong")[0], 400)
        self.assertEqual(self.add_second(trust_fingerprint="SHA256:good")[0], 200)
        self.assertEqual(trusted[-1], ("10.10.56.6", "SHA256:good"))
        self.app.dash.runner.gate_ping = lambda hcfg: (False, "The node refused the dashboard's key. Run the setup script on that node first.")
        self.app.dash.runner.hostkey_known = lambda host, port: True
        st, out, _ = self.c.post("/api/hosts/add", {"name": "pve3", "host": "10.10.56.7"})
        self.assertEqual(st, 400)
        self.assertIn("setup script", out["error"])
        self.assertEqual(len(self.c.get("/api/hosts")[1]["hosts"]), 2)

    def test_removing_a_node(self):
        self.add_second()
        self.assertEqual(self.c.post("/api/hosts/remove", {"idx": 0})[0], 400)       # the primary lives in the config
        self.assertEqual(self.c.post("/api/hosts/remove", {"idx": 9})[0], 400)
        self.assertEqual(self.c.post("/api/hosts/remove", {"idx": 1})[0], 200)
        self.assertEqual(sorted(self.names()), [114, 115, 130])
        self.assertEqual(self.add_second(name="pve2b", host="10.10.56.8")[1]["idx"], 2)  # the old index is not reused

    def test_setup_script_endpoint(self):
        st, out, _ = self.c.get("/api/hosts/setup-script?ips=10.10.56.16&allow=201,202&protected=202")
        self.assertEqual(st, 200)
        self.assertIn('from=\\"10.10.56.16\\"', out["script"])
        self.assertIn("ALLOW_CTIDS", out["script"])
        self.assertEqual(self.c.get("/api/hosts/setup-script?ips=nope")[0], 400)
        self.assertEqual(self.c.get("/api/hosts/setup-script?ips=10.0.0.1&allow=1;id")[0], 400)

    def test_snapshots_go_to_the_node_that_owns_the_container(self):
        self.add_second()
        end = time.time() + 10                                                        # adding a node starts a background sweep; let it finish first
        while any(st["checking"] for st in self.app.dash.state.values()) and time.time() < end:
            time.sleep(0.05)
        time.sleep(0.3)
        dash, calls = self.app.dash, []
        dash.runner.local = False
        dash.runner.pct = lambda *a, host=0, **k: calls.append((a, host)) or (0, [])
        dash.runner.exec = lambda *a, **k: (0, ["ok"])
        dash.gate_managed = {114, 1_000_000_114}
        uid = 1_000_000_114
        job = dash.start_update(uid, "os")
        end = time.time() + 10
        while dash.jobs[job]["status"] in ("running", "queued") and time.time() < end:
            time.sleep(0.05)
        snap = next(c for c in calls if c[0][0] == "snapshot")
        self.assertEqual((snap[0][1], snap[1]), ("114", 1))                           # CT 114 on node 1, not node 0
        self.assertTrue(all(c[1] == 1 for c in calls))                                # every call for this container targeted node 1

    def test_logs_and_credentials_of_the_two_114s_do_not_mix(self):
        self.add_second()
        self.assertEqual(self.c.get("/api/logs?ctid=114")[1]["logs"], [])
        job = self.c.post("/api/update", {"ctid": 1_000_000_114, "kind": "os"})[1]["job"]
        time.sleep(1)
        self.assertEqual(len(self.c.get("/api/logs?ctid=1000000114")[1]["logs"]), 1)
        self.assertEqual(self.c.get("/api/logs?ctid=114")[1]["logs"], [])
        self.assertTrue(job)


if __name__ == "__main__":
    unittest.main()


class TestNodeInfoAndMyIp(AppCase):
    def test_node_info_endpoint_with_local_transport_and_my_ip(self):
        import os
        os.environ["UPDATEDASH_FAKE_NODEINFO"] = "storage rootdir local-lvm;storage vztmpl local;bridge vmbr0;bogus line;storage nope x"
        self.addCleanup(os.environ.pop, "UPDATEDASH_FAKE_NODEINFO", None)
        self.app.dash.hosts.primary["host"] = "10.0.0.5"
        self.signed_in()
        st, out, _ = self.c.get("/api/node-info?host=0")
        self.assertEqual(st, 200)
        self.assertEqual(out, {"rootdir": ["local-lvm"], "vztmpl": ["local"], "bridges": ["vmbr0"]})
        self.assertEqual(self.c.get("/api/node-info?host=x")[0], 400)
        st, out, _ = self.c.get("/api/hosts/my-ip?host=127.0.0.1")
        self.assertEqual((st, out["ip"]), (200, "127.0.0.1"))
        self.assertEqual(self.c.get("/api/hosts/my-ip?host=bad;rm")[0], 400)

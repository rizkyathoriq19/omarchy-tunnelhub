"""Command-surface tests for the shared password store.

Run with: python3 -m unittest discover -s tests -v

Each test uses its own XDG_STATE_HOME so the real state directory is never
touched. Keyring tests use throwaway identities and clear them afterwards.
"""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable


def run_cli(args, state, path=None):
    env = dict(os.environ, XDG_STATE_HOME=state)
    if path is not None:
        env["PATH"] = path
    return subprocess.run([PY, str(ROOT / "profiles.py"), *args], capture_output=True, text=True, env=env, timeout=60)


def run_module(code, state, path=None):
    env = dict(os.environ, XDG_STATE_HOME=state, PYTHONPATH=str(ROOT))
    if path is not None:
        env["PATH"] = path
    return subprocess.run([PY, "-c", code], capture_output=True, text=True, env=env, timeout=60)


class SecretStorageTest(unittest.TestCase):
    def setUp(self):
        self.state = tempfile.mkdtemp(prefix="tunnelhub-state-")
        self.addCleanup(shutil.rmtree, self.state, True)
        self.ident = "test-" + uuid.uuid4().hex

    def test_keyring_round_trip(self):
        code = f"""
import json
import secrets_store
print(json.dumps(secrets_store.store("nm", {self.ident!r}, "pw-keyring", {{"secret": "cert-pass"}})))
print(json.dumps([v.decode() for v in secrets_store.lookup("nm", {self.ident!r}, {{"secret": "cert-pass"}})[:1]]))
print(json.dumps(secrets_store.clear("nm", {self.ident!r}, {{"secret": "cert-pass"}})))
print(json.dumps(secrets_store.lookup("nm", {self.ident!r}, {{"secret": "cert-pass"}})[1]))
"""
        out = run_module(code, self.state)
        self.assertEqual(out.returncode, 0, out.stderr)
        lines = [json.loads(line) for line in out.stdout.strip().splitlines()]
        self.assertTrue(lines[0]["saved"], lines[0])
        self.assertEqual(lines[0]["backend"], "keyring")
        self.assertEqual(lines[1], ["pw-keyring"])
        self.assertTrue(lines[2])
        self.assertEqual(lines[3], "no-credential")

    def test_no_keyring_without_consent_is_refused(self):
        bindir = tempfile.mkdtemp(prefix="tunnelhub-bin-")
        self.addCleanup(shutil.rmtree, bindir, True)
        code = """
import json
import secrets_store
print(json.dumps(secrets_store.store("nm", "no-consent", "pw", plaintext=True)))
"""
        out = run_module(code, self.state, path=bindir)
        self.assertEqual(out.returncode, 0, out.stderr)
        result = json.loads(out.stdout)
        self.assertFalse(result["saved"])
        self.assertEqual(result["reason"], "consent-required")
        self.assertFalse((Path(self.state) / "airzy.vpn/secrets.json").exists())

    def test_plaintext_round_trip_with_consent(self):
        bindir = tempfile.mkdtemp(prefix="tunnelhub-bin-")
        self.addCleanup(shutil.rmtree, bindir, True)
        code = """
import json
import secrets_store
print(json.dumps(secrets_store.store("forti", "plain", "pw-file", {"host": "vpn.example", "username": "u"}, plaintext=True)))
secrets_store.record_consent()
print(json.dumps(secrets_store.store("forti", "plain", "pw-file", {"host": "vpn.example", "username": "u"}, plaintext=True)))
value, reason = secrets_store.lookup("forti", "plain", {"host": "vpn.example", "username": "u"})
print(json.dumps([value.decode(), reason]))
"""
        out = run_module(code, self.state, path=bindir)
        self.assertEqual(out.returncode, 0, out.stderr)
        lines = [json.loads(line) for line in out.stdout.strip().splitlines()]
        self.assertEqual(lines[0]["reason"], "consent-required")
        self.assertEqual(lines[1]["backend"], "plaintext")
        self.assertEqual(lines[2], ["pw-file", ""])
        stored = Path(self.state) / "airzy.vpn/secrets.json"
        self.assertTrue(stored.exists())
        self.assertEqual(stat.S_IMODE(stored.stat().st_mode), 0o600)
        self.assertNotIn("pw-file", json.loads((Path(self.state) / "airzy.vpn/secret-policy.json").read_text()).__str__())

    def test_consent_action_and_status(self):
        before = json.loads(run_cli(["secret-status"], self.state).stdout)
        self.assertFalse(before["plaintextAllowed"])
        after = json.loads(run_cli(["secret-consent"], self.state).stdout)
        self.assertTrue(after["plaintextAllowed"])
        status = json.loads(run_cli(["secret-status"], self.state).stdout)
        self.assertTrue(status["plaintextAllowed"])
        self.assertEqual(stat.S_IMODE((Path(self.state) / "airzy.vpn/secret-policy.json").stat().st_mode), 0o600)

    def test_status_never_returns_the_secret(self):
        code = """
import json
import secrets_store
secrets_store.store("nm", "status-check", "super-secret", {"secret": "cert-pass"})
secrets_store.clear("nm", "status-check", {"secret": "cert-pass"})
print("ok")
"""
        out = run_module(code, self.state)
        self.assertEqual(out.returncode, 0, out.stderr)
        status = run_cli(["secret-status"], self.state)
        self.assertNotIn("super-secret", status.stdout)
        self.assertIn("backend", status.stdout)

    def test_corrupt_plaintext_file_is_not_a_crash(self):
        target = Path(self.state) / "airzy.vpn"
        target.mkdir(parents=True)
        (target / "secrets.json").write_text("{not json")
        (target / "secret-policy.json").write_text(json.dumps({"plaintextAllowed": True}))
        code = """
import json
import secrets_store
value, reason = secrets_store.lookup("forti", "x", {"host": "h", "username": "u"})
print(json.dumps([value.decode("utf-8", "replace"), reason]))
"""
        out = run_module(code, self.state)
        self.assertEqual(out.returncode, 0, out.stderr)
        value, reason = json.loads(out.stdout)
        self.assertEqual(value, "")
        self.assertEqual(reason, "store-unreadable")

    def test_state_directory_is_tightened(self):
        target = Path(self.state) / "airzy.vpn"
        target.mkdir(parents=True)
        os.chmod(target, 0o755)
        code = """
import secrets_store
secrets_store.record_consent()
print("ok")
"""
        out = run_module(code, self.state)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)

    def test_symlinked_store_is_refused(self):
        target = Path(self.state) / "airzy.vpn"
        target.mkdir(parents=True)
        elsewhere = Path(self.state) / "elsewhere.json"
        elsewhere.write_text(json.dumps({"plaintextAllowed": True}))
        (target / "secret-policy.json").symlink_to(elsewhere)
        status = json.loads(run_cli(["secret-status"], self.state).stdout)
        self.assertFalse(status["plaintextAllowed"])

    def test_networkmanager_store_reads_back(self):
        profile = "zz-secret-test-" + uuid.uuid4().hex[:8]
        add = subprocess.run(["nmcli", "connection", "add", "type", "vpn", "con-name", profile,
                              "ifname", "*", "vpn-type", "sstp", "+vpn.data", "gateway=probe.invalid"],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(add.returncode, 0, add.stderr)
        self.addCleanup(subprocess.run, ["nmcli", "connection", "delete", profile],
                        capture_output=True, text=True, timeout=30)
        uuid_value = subprocess.run(["nmcli", "-g", "connection.uuid", "connection", "show", profile],
                                    capture_output=True, text=True, timeout=15).stdout.strip()
        code = f"""
import json
import secrets_store
print(json.dumps(secrets_store.nm_store({uuid_value!r}, "tls-user-key-secret", "arg-secret")))
"""
        out = run_module(code, self.state)
        self.assertEqual(out.returncode, 0, out.stderr)
        result = json.loads(out.stdout)
        self.assertTrue(result["saved"], result)
        data = subprocess.run(["nmcli", "-g", "vpn.data", "connection", "show", "uuid", uuid_value],
                              capture_output=True, text=True, timeout=15).stdout
        self.assertIn("tls-user-key-secret-flags = 0", data)
        check = """
import json
import secrets_store
uuid = {uuid!r}
print(json.dumps(secrets_store.nm_status(uuid)))
print(json.dumps(secrets_store.nm_clear(uuid)))
print(json.dumps(secrets_store.nm_status(uuid)))
""".format(uuid=uuid_value)
        out = run_module(check, self.state)
        self.assertEqual(out.returncode, 0, out.stderr)
        lines = [json.loads(line) for line in out.stdout.strip().splitlines()]
        self.assertTrue(lines[0]["saved"])
        self.assertTrue(lines[1])
        self.assertFalse(lines[2]["saved"])
        after = subprocess.run(["nmcli", "-g", "vpn.data", "connection", "show", "uuid", uuid_value],
                               capture_output=True, text=True, timeout=15).stdout
        self.assertIn("tls-user-key-secret-flags = 2", after)
        secrets = subprocess.run(["nmcli", "--show-secrets", "-g", "vpn.secrets",
                                  "connection", "show", "uuid", uuid_value],
                                 capture_output=True, text=True, timeout=15).stdout
        self.assertNotIn("arg-secret", secrets)


if __name__ == "__main__":
    unittest.main()

"""python3 test_gui.py — mocked VPN/sudo, real benign supervisor + user unit."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch
import profiles as p

idle = dict(running=False, stopping=False, error="")
with patch.object(p, "require", side_effect=lambda n: n), patch.dict(os.environ, {"WAYLAND_DISPLAY": "mock-wayland"}):
    env = p.gui_environment()
    assert env["PATH"].split(os.pathsep)[0] == str(Path(p.__file__).parent / "gui-bin")
    assert env["SUDO_ASKPASS"] == str(Path(p.__file__).parent / "askpass")
with patch.dict(os.environ, {}, clear=True), patch.object(p, "require", return_value="mock"):
    try:
        p.gui_environment()
        assert False
    except ValueError:
        pass

for raw, expected in [("ActiveState=active\nSubState=running\n", "running"),
                      ("ActiveState=deactivating\nSubState=stop-sigterm\n", "stopping"),
                      ("ActiveState=failed\nExecMainStatus=5\nSECRET=token\n", "error")]:
    with patch.object(p, "require", return_value="/mock/systemctl"), patch.object(p.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=raw)):
        result = p.operation_status()
        assert result[expected] and "SECRET" not in json.dumps(result) and "token" not in json.dumps(result)

with patch.object(p, "load", return_value=["/fake/profile.xml"]), patch.object(p, "require", side_effect=lambda n: "/mock/" + n), patch.object(p, "connection_settings", return_value=("/mock/trusted CA.pem", True)), patch.object(p, "preflight"), patch.object(Path, "is_file", return_value=True), patch.object(p, "gui_environment"), patch.object(p, "control"), patch.object(p, "status", return_value={"state": "disconnected"}), patch.object(p.subprocess, "run") as run:
    for operation in [dict(idle, running=True), dict(idle, stopping=True)]:
        with patch.object(p, "operation_status", return_value=operation):
            try:
                p.launch("/fake/profile.xml")
                assert False
            except ValueError:
                pass
    run.assert_not_called()
    with patch.object(p, "operation_status", return_value=idle):
        run.return_value = SimpleNamespace(returncode=1, stdout="SECRET", stderr="SECRET")
        try:
            p.launch("/fake/profile.xml")
            assert False
        except ValueError as error:
            assert "SECRET" not in str(error)
with patch.object(p, "operation_status", return_value=dict(idle, running=True)), patch.object(p, "control") as control, patch.object(p, "status", return_value={"state": "disconnected"}), patch.object(p, "supervise") as supervise:
    p.disconnect()
    control.assert_called_once_with("stop")
    supervise.assert_not_called()
with patch.object(p, "operation_status", return_value=idle), patch.object(p, "status", return_value={"state": "connected"}), patch.object(p, "require", return_value="/mock/openp2s"), patch.object(p, "supervise", return_value=5):
    try:
        p.disconnect()
        assert False
    except ValueError as error:
        assert "cancelled" in str(error)

with patch.object(p, "load", return_value=["/fake/a space.xml"]), patch.object(p, "require", return_value="/mock/openp2s"), patch.object(p, "connection_settings", return_value=("/mock/trusted CA.pem", True)), patch.object(p, "preflight") as preflight, patch.object(p, "supervise", return_value=4) as supervised:
    assert p.run_connection("/fake/a space.xml") == 4
    assert supervised.call_args.args[0] == ["/mock/openp2s", "connect", "/fake/a space.xml", "--ca", "/mock/trusted CA.pem", "--experimental-azure-compat"]
    preflight.assert_called_once_with("/mock/openp2s", True)

# Signals reach the native child, and its exit code is preserved. No real VPN.
handlers = {}
child = SimpleNamespace(poll=lambda: None, send_signal=lambda sig: handlers.update(sent=sig))
def wait():
    handlers[signal.SIGTERM](signal.SIGTERM, None)
    return 5
child.wait = wait
def register(sig, handler):
    handlers[sig] = handler
    return signal.SIG_DFL
with patch.object(p, "Lease", return_value=__import__("contextlib").nullcontext("mock-capability")), patch.object(p.signal, "signal", side_effect=register), patch.object(p, "gui_environment", return_value={"SUDO_ASKPASS": "mock"}), patch.object(p.subprocess, "Popen", return_value=child) as popen:
    assert p.supervise(["/mock/backend", "connect", "/fake/profile.xml"]) == 5
    assert handlers["sent"] == signal.SIGTERM
    assert popen.call_args.kwargs["stdout"] == subprocess.DEVNULL
    assert popen.call_args.kwargs["stderr"] == subprocess.DEVNULL

# Execute bridge scripts with mocked exec targets: no sudo/password prompt.
with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as tmp:
    tmp = Path(tmp)
    recorder = tmp / "record"
    recorder.write_text('#!/usr/bin/python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n')
    recorder.chmod(0o700)
    for name, target, args, expected in [
        ("gui-bin/sudo", "/usr/bin/sudo", ["--", "/safe/program", "a space", "--dash"], ["-A", "--", "/safe/program", "a space", "--dash"]),
        ("askpass", "/usr/bin/python3", ["private prompt ignored"], [str(tmp / "permission.py"), "askpass"])]:
        text = Path(p.__file__).with_name("profiles.py").parent.joinpath(name).read_text()
        script = tmp / "bridge"
        script.write_text(text.replace(target, str(recorder)))
        script.chmod(0o700)
        result = subprocess.run([str(script)] + args, capture_output=True, text=True, check=True)
        assert json.loads(result.stdout) == expected
    # Real long-lived supervisor survives start helper completion under native systemd.
    # Unique test unit; benign Python only, never production unit/backend.
    unit = "airzy-vpn-check-" + str(os.getpid()) + ".service"
    probe = tmp / "probe.py"
    marker = tmp / "stopped"
    probe.write_text("import sys\nsys.path.insert(0, " + repr(str(Path(p.__file__).parent)) + ")\nimport profiles as p\nimport contextlib\np.Lease = lambda: contextlib.nullcontext('mock-capability')\n"
                     "raise SystemExit(p.supervise(['/usr/bin/python3', '-c', " + repr("import signal,time,pathlib; signal.signal(signal.SIGTERM, lambda *a: (pathlib.Path(" + repr(str(marker)) + ").write_text('clean'), exit(0))); time.sleep(60)") + "]))\n")
    try:
        subprocess.run(["systemd-run", "--user", "--quiet", "--unit=" + unit, "--service-type=exec", "--property=KillMode=mixed", "--property=TimeoutStopSec=10", "--property=StandardOutput=null", "--property=StandardError=null", "--setenv=WAYLAND_DISPLAY=mock", "/usr/bin/python3", str(probe)], check=True)
        # Read back exact test unit, not production state. Wait for benign child readiness.
        for _ in range(30):
            active = subprocess.run(["systemctl", "--user", "show", unit, "--property=SubState", "--value"], capture_output=True, text=True)
            if active.stdout.strip() == "running":
                break
            time.sleep(0.05)
        assert active.stdout.strip() == "running"
        time.sleep(0.3)
        subprocess.run(["systemctl", "--user", "stop", unit], check=True)
        assert marker.read_text() == "clean", "SIGTERM failed to reach supervised child"
        stopped = subprocess.run(["systemctl", "--user", "is-active", unit], capture_output=True, text=True)
        assert stopped.stdout.strip() in ("inactive", "unknown")
        subprocess.run(["systemd-run", "--user", "--quiet", "--unit=" + unit, "/usr/bin/python3", "-c", "raise SystemExit(5)"], check=True)
        with patch.object(p, "UNIT", unit):
            for _ in range(40):
                failure = p.operation_status()
                if failure["error"]:
                    break
                time.sleep(0.05)
            assert "cleanup incomplete" in failure["error"]
            p.control("reset-failed", check=False)
        subprocess.run(["systemd-run", "--user", "--quiet", "--unit=" + unit, "/usr/bin/python3", "-c", "import time; time.sleep(60)"], check=True)
        duplicate = subprocess.run(["systemd-run", "--user", "--quiet", "--unit=" + unit, "/usr/bin/true"], capture_output=True)
        assert duplicate.returncode != 0, "Duplicate unit unexpectedly started"
        assert subprocess.run(["systemctl", "--user", "is-active", "--quiet", unit]).returncode == 0
    finally:
        subprocess.run(["systemctl", "--user", "stop", unit], capture_output=True)
        subprocess.run(["systemctl", "--user", "reset-failed", unit], capture_output=True)
print("PASS GUI env/argv, duplicate guards, redacted errors, cancel/disconnect routing, supervisor signals, mocked askpass; real benign durable user-unit lifecycle")

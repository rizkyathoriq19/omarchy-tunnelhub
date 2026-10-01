"""Run: python3 test_profiles.py. Never reads/imports/connects real profiles."""
import os
from pathlib import Path
import tempfile
from unittest.mock import patch
from types import SimpleNamespace
import profiles as p

with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR", str(Path.home() / ".cache"))) as tmp:
    p.STORE = Path(tmp) / "azure.json"
    azure = "/not-real/a space ' quote;$(touch nope).xml"
    with patch.object(Path, "open", side_effect=AssertionError("No XML reads")):
        # Store does not yet exist, so registration only opens its temporary metadata fd.
        assert p.import_path(azure)["azure"] == [azure]
    assert p.load() == [azure]
    assert p.import_path(azure)["azure"] == [azure]
    assert p.STORE.stat().st_mode & 0o777 == 0o600
    with patch.object(p.shutil, "which", side_effect=lambda n: "/mock/" + n), patch.object(p.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="", stderr="")) as run:
        for suffix, kind in [(".ovpn", "openvpn"), (".conf", "wireguard")]:
            path = "/fake/a ' quoted; name" + suffix
            assert "imported" in p.import_path(path)["message"]
            assert run.call_args.args[0] == ["/mock/nmcli", "connection", "import", "type", kind, "file", path]
        run.return_value = SimpleNamespace(returncode=1, stdout="SECRET", stderr="SECRET")
        try:
            p.import_path("/fake/x.ovpn")
            assert False
        except ValueError as error:
            assert "SECRET" not in str(error)
    with patch.object(p.shutil, "which", side_effect=lambda n: "/mock/" + n), patch.object(Path, "is_file", return_value=True), patch.object(p, "gui_environment"), patch.object(p, "operation_status", return_value={"running": False, "stopping": False}), patch.object(p, "status", return_value={"state": "disconnected"}), patch.object(p, "control"), patch.object(p.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run, patch.object(p, "connection_settings", return_value=("/mock/trusted CA.pem", True)), patch.object(p, "preflight") as preflight:
        assert p.launch(azure)["message"] == "Connecting…"
        preflight.assert_called_once_with("/mock/openp2s", True)
        args = run.call_args.args[0]
        assert args[:4] == ["/mock/systemd-run", "--user", "--quiet", "--unit=" + p.UNIT]
        assert args[-4:] == ["/usr/bin/python3", str(Path(p.__file__).resolve()), "run", azure]
        assert "--expand-environment=no" in args and "--property=KillMode=mixed" in args
    with patch.object(p.shutil, "which", return_value=None):
        try:
            p.import_path("/fake/x.ovpn")
            assert False
        except ValueError as error:
            assert "Missing backend: nmcli" in str(error)
    with patch.object(p.sys, "argv", ["profiles.py", "import"]), patch.object(p.shutil, "which", return_value="/mock/zenity"), patch.object(p.subprocess, "run", return_value=SimpleNamespace(returncode=1)):
        assert p.main() == {"cancelled": True}
with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR", str(Path.home() / ".cache"))) as tmp:
    client = Path(tmp) / "openp2s"
    binary = Path(tmp) / "openvpn-openp2s"
    binary.write_bytes(b"test binary, not executable")
    metadata = Path(tmp) / "BUILDINFO"
    with patch.dict(os.environ, {"OPENP2S_OPENVPN_BINARY": str(binary)}):
        for contents in [None, "binary_sha256=wrong\nazure_compat_available=1\n"]:
            if contents is not None:
                metadata.write_text(contents)
            try:
                p.preflight(str(client))
                assert False, "Missing/mismatched BUILDINFO must block launch"
            except ValueError as error:
                assert "BUILDINFO" in str(error)
        import hashlib
        metadata.write_text("binary_sha256=" + hashlib.sha256(binary.read_bytes()).hexdigest() + "\nazure_compat_available=1\n")
        p.preflight(str(client))
        metadata.write_text(metadata.read_text().replace("azure_compat_available=1", "azure_compat_available=0"))
        p.preflight(str(client), False)
        try:
            p.preflight(str(client), True)
            assert False, "Unsupported experimental flag must block launch"
        except ValueError as error:
            assert "experimental Azure" in str(error)
        p.STORE = Path(tmp) / "paths.json"
        p.register("/not-real/profile.xml")
        metadata.unlink()
        with patch.object(p, "require", return_value=str(client)), patch.object(p, "connection_settings", return_value=("/mock/ca.pem", False)), patch.object(p.subprocess, "Popen") as popen:
            try:
                p.launch("/not-real/profile.xml")
                assert False, "Preflight must fail before opening terminal"
            except ValueError as error:
                assert "BUILDINFO" in str(error)
            popen.assert_not_called()
# Settings defaults, fail-closed migration, and both connection paths use one source.
import json
manifest = json.loads(Path(__file__).with_name("manifest.json").read_text())
assert manifest["barWidget"]["defaults"]["azureCaPath"] == ""
assert manifest["barWidget"]["defaults"]["azureExperimentalCompat"] is False
with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as tmp:
    config = Path(tmp) / "omarchy/shell.json"
    config.parent.mkdir()
    ca = Path(tmp) / "trusted root ;$.pem"
    ca.write_text("synthetic certificate placeholder")
    def save(entry):
        config.write_text(json.dumps({"bar": {"layout": {"right": [dict(id="airzy.vpn", **entry)]}}}))
    with patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp}):
        for entry in [{}, {"azureCaPath": ""}, {"azureCaPath": "relative.pem"},
                      {"azureCaPath": str(ca), "azureExperimentalCompat": "false"}]:
            save(entry)
            try:
                p.connection_settings()
                assert False, "Unsafe/default settings must block connection"
            except ValueError:
                pass
        for enabled in [False, True]:
            save({"azureCaPath": str(ca), "azureExperimentalCompat": enabled})
            assert p.connection_settings() == (str(ca), enabled)
            with patch.object(p, "load", return_value=["/fake/profile.xml"]), patch.object(p, "require", return_value="/mock/openp2s"), patch.object(p, "preflight") as preflight, patch.object(p, "supervise", return_value=0) as supervise:
                assert p.run_connection("/fake/profile.xml") == 0
                preflight.assert_called_once_with("/mock/openp2s", enabled)
                assert supervise.call_args.args[0] == ["/mock/openp2s", "connect", "/fake/profile.xml", "--ca", str(ca)] + (["--experimental-azure-compat"] if enabled else [])
            with patch.object(p, "load", return_value=["/fake/profile.xml"]), patch.object(p, "require", side_effect=lambda name: "/mock/" + name), patch.object(p, "preflight") as preflight, patch.object(p, "gui_environment"), patch.object(p, "operation_status", return_value={"running": False, "stopping": False}), patch.object(p, "status", return_value={"state": "disconnected"}), patch.object(p, "control"), patch.object(p.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
                p.launch("/fake/profile.xml")
                preflight.assert_called_once_with("/mock/openp2s", enabled)
                assert run.call_args.args[0][-4:] == ["/usr/bin/python3", str(Path(p.__file__).resolve()), "run", "/fake/profile.xml"]
        save({"azureCaPath": str(ca)})
        assert p.connection_settings() == (str(ca), False)
panel = Path(__file__).with_name("Panel.qml").read_text()
assert panel.index("model: vpn.profiles") < panel.index("model: vpn.azureProfiles") < panel.index('text: vpn.importing ?')
assert "width: profileColumn.width" in panel[panel.index("model: vpn.azureProfiles"):]
print("PASS: path-only Azure persistence/mode/dedup, safe import/launch argv, cancellation, backend/error handling, BUILDINFO preflight, Azure row ordering")

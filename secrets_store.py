"""Shared password storage for profile secrets.

The plugin owns no password file. FortiClient passwords live in GNOME
Keyring. NetworkManager certificate passwords can live in GNOME Keyring or,
after an explicit choice, in NetworkManager's own keyfile. Keyring
availability is decided by a store/lookup/clear probe, because an installed
secret-tool says nothing about a usable default collection.

Secrets never enter the environment, logs or status output. NetworkManager
accepts a secret only as an nmcli argument, so that one call exposes the
value in its argv for its short lifetime; callers document it.
"""
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time

SERVICE = "airzy.vpn"
KEYRING_TIMEOUT = 10
LIMIT = 4092

STATE_DIR = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))) / "airzy.vpn"
POLICY_FILE = STATE_DIR / "secret-policy.json"

_probe = None


def valid_secret(value):
    if isinstance(value, bytes):
        return bool(value) and len(value) <= LIMIT and not any(b < 32 or b == 127 for b in value)
    if not isinstance(value, str):
        return False
    return valid_secret(value.encode("utf-8"))


def safe_identifier(value):
    return isinstance(value, str) and 0 < len(value) <= 256 and not any(c in value for c in "\x00\r\n")


def attributes(kind, ident, extra=None):
    if kind not in ("forti", "nm") or not safe_identifier(ident):
        raise ValueError("Invalid secret identity.")
    attrs = ["service", SERVICE, "kind", kind, "profile", ident]
    for key, value in (extra or {}).items():
        if key not in ("host", "username", "secret") or not safe_identifier(value):
            raise ValueError("Invalid secret attribute.")
        attrs += [key, value]
    return attrs


def _secret_tool():
    return shutil.which("secret-tool")


def _run(args, stdin=None):
    return subprocess.run(args, input=stdin, capture_output=True, timeout=KEYRING_TIMEOUT)


def keyring_available():
    """Probe store, lookup and clear with a throwaway item. Result is cached."""
    global _probe
    if _probe is not None:
        return _probe
    tool = _secret_tool()
    if not tool:
        _probe = False
        return False
    attrs = ["service", SERVICE, "kind", "probe", "profile", secrets.token_hex(16)]
    try:
        if _run([tool, "store", "--label", "TunnelHub storage probe", *attrs], b"probe").returncode:
            _probe = False
            return False
        found = _run([tool, "lookup", *attrs])
        _probe = found.returncode == 0 and found.stdout.strip() == b"probe"
        _run([tool, "clear", *attrs])
    except (OSError, subprocess.TimeoutExpired):
        _probe = False
    return _probe


def _ensure_state_dir():
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STATE_DIR, 0o700)


def _read_json(path):
    if path.is_symlink():
        raise ValueError("Policy files must not be symlinks.")
    return json.loads(path.read_text())


def _atomic_write(path, text):
    _ensure_state_dir()
    fd, temp = tempfile.mkstemp(dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def nm_storage_allowed():
    """The user accepted NetworkManager's own keyfile for a saved secret."""
    try:
        data = _read_json(POLICY_FILE)
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and data.get("networkManagerStorageAllowed") is True


def allow_nm_storage():
    payload = {"networkManagerStorageAllowed": True,
               "acceptedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    _atomic_write(POLICY_FILE, json.dumps(payload, indent=2) + "\n")


def lookup(kind, ident, extra=None):
    """Return (secret bytes, reason). Reason is empty when a secret was found."""
    attrs = attributes(kind, ident, extra)
    if not keyring_available():
        return b"", "keyring-unavailable"
    try:
        res = _run([_secret_tool(), "lookup", *attrs])
    except (OSError, subprocess.TimeoutExpired):
        return b"", "keyring-unavailable"
    if res.returncode != 0:
        return b"", "keyring-unavailable" if res.stderr.strip() else "no-credential"
    value = res.stdout
    for suffix in (b"\r\n", b"\n"):
        if value.endswith(suffix):
            value = value[:-len(suffix)]
            break
    if not valid_secret(value):
        return b"", "keyring-unavailable"
    return value, ""


def store(kind, ident, value, extra=None):
    """Save a secret in GNOME Keyring. Returns {"backend", "saved", "reason"}."""
    attrs = attributes(kind, ident, extra)
    if not valid_secret(value):
        return {"backend": "", "saved": False, "reason": "invalid-secret"}
    if not keyring_available():
        return {"backend": "", "saved": False, "reason": "keyring-unavailable"}
    text = value.decode("utf-8") if isinstance(value, bytes) else value
    tool = _secret_tool()
    label = "TunnelHub " + kind.upper() + " " + ident
    try:
        _run([tool, "clear", *attrs])
        stored = _run([tool, "store", "--label", label, *attrs], text.encode("utf-8"))
        verify = _run([tool, "lookup", *attrs]) if stored.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return {"backend": "", "saved": False, "reason": "keyring-unavailable"}
    if stored.returncode == 0 and verify is not None and verify.returncode == 0 \
            and verify.stdout.rstrip(b"\r\n") == text.encode("utf-8"):
        return {"backend": "keyring", "saved": True, "reason": ""}
    return {"backend": "", "saved": False, "reason": "store-failed"}


def clear(kind, ident, extra=None):
    attrs = attributes(kind, ident, extra)
    if not keyring_available():
        return True
    try:
        res = _run([_secret_tool(), "clear", *attrs])
    except (OSError, subprocess.TimeoutExpired):
        return False
    # secret-tool exits 1 for no match; only stderr signals a real failure.
    return res.returncode == 0 or not res.stderr.strip()


# NetworkManager's own secret store. It accepts secrets only as nmcli
# arguments; the caller must keep the call short and must not log it.

NM_SECRET_KEYS = {
    "org.freedesktop.NetworkManager.openvpn": "cert-pass",
    "org.freedesktop.NetworkManager.sstp": "tls-user-key-secret",
}


def nm_service_type(uuid):
    try:
        res = subprocess.run(["nmcli", "-g", "vpn.service-type", "connection", "show", "uuid", uuid],
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if res.returncode:
        return ""
    return res.stdout.strip()


def nm_secret_key(uuid):
    return NM_SECRET_KEYS.get(nm_service_type(uuid), "")


def _pairs(text):
    pairs = {}
    for item in text.strip().split(", "):
        if " = " not in item:
            continue
        key, value = item.strip().split(" = ", 1)
        pairs[key.lstrip("+")] = value
    return pairs


def _nm_pairs(args):
    try:
        res = subprocess.run(["nmcli", *args], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if res.returncode:
        return {}
    return _pairs(res.stdout)


def nm_store(uuid, key, value):
    """Save the secret in NetworkManager's keyfile. Verified by read-back."""
    if key not in NM_SECRET_KEYS.values() or not valid_secret(value):
        return {"backend": "", "saved": False, "reason": "invalid-secret"}
    text = value.decode("utf-8") if isinstance(value, bytes) else value
    flags = key + "-flags"
    current = _nm_pairs(["-g", "vpn.data", "connection", "show", "uuid", uuid])
    flag_arg = (flags + "=0") if flags in current else ("+" + flags + "=0")
    flag_mode = "vpn.data" if flags in current else "+vpn.data"
    try:
        modified = subprocess.run(["nmcli", "connection", "modify", "uuid", uuid,
                                   flag_mode, flag_arg,
                                   "+vpn.secrets", key + "=" + text],
                                  capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return {"backend": "", "saved": False, "reason": "store-failed"}
    if modified.returncode:
        return {"backend": "", "saved": False, "reason": "store-failed"}
    saved = _nm_pairs(["--show-secrets", "-g", "vpn.secrets", "connection", "show", "uuid", uuid])
    if saved.get(key) != text:
        return {"backend": "", "saved": False, "reason": "verify-failed"}
    return {"backend": "networkmanager", "saved": True, "reason": ""}


def nm_status(uuid):
    key = nm_secret_key(uuid)
    if not key:
        return {"saved": False, "key": ""}
    data = _nm_pairs(["-g", "vpn.data", "connection", "show", "uuid", uuid])
    if data.get(key + "-flags") != "0":
        return {"saved": False, "key": key}
    saved = _nm_pairs(["--show-secrets", "-g", "vpn.secrets", "connection", "show", "uuid", uuid])
    return {"saved": bool(saved.get(key)), "key": key}


def nm_clear(uuid):
    """Remove a NetworkManager keyfile secret and restore ask-every-time."""
    key = nm_secret_key(uuid)
    if not key or not nm_status(uuid)["saved"]:
        return True
    try:
        res = subprocess.run(["nmcli", "connection", "modify", "uuid", uuid,
                              "vpn.data", key + "-flags=2",
                              "-vpn.secrets", key],
                             capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if res.returncode:
        return False
    data = _nm_pairs(["-g", "vpn.data", "connection", "show", "uuid", uuid])
    return data.get(key + "-flags") == "2" and not nm_status(uuid)["saved"]

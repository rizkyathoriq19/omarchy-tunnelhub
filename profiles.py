"""Native import/launch bridge. Azure XML is never opened by this plugin."""
import hashlib
import json
import os
import re
import secrets
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from permission import Lease
import ovpn_source

def connection_settings():
    # Read the same inline widget settings in actions and the durable supervisor.
    config = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "omarchy/shell.json"
    data = json.loads(config.read_text()) if config.exists() else {}
    entries = [entry for section in data.get("bar", {}).get("layout", {}).values()
               for entry in section if entry.get("id") == "airzy.vpn"]
    if len(entries) > 1:
        raise ValueError("Duplicate VPN widget settings; keep one airzy.vpn entry.")
    settings = entries[0] if entries else {}
    ca = settings.get("azureCaPath", "")
    experimental = settings.get("azureExperimentalCompat", False)
    if not isinstance(ca, str) or not isinstance(experimental, bool):
        raise ValueError("Invalid Azure settings: CA path must be a string and experimental compatibility a boolean.")
    if ca.startswith("~"):
        ca = str(Path(ca).expanduser())
    if not ca or not ca.startswith("/") or any(c in ca for c in "\x00\r\n"):
        raise ValueError("Configure azureCaPath with an absolute trusted CA certificate path before connecting.")
    if not Path(ca).is_file():
        raise ValueError("Configured Azure CA certificate is missing. Check azureCaPath.")
    return ca, experimental

STORE = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))) / "airzy.vpn/azure-profiles.json"


def require(name):
    executable = shutil.which(name)
    if not executable:
        raise ValueError(f"Missing backend: {name}. Install/configure it before retrying.")
    return executable


def load():
    if not STORE.exists():
        return []
    data = json.loads(STORE.read_text())
    if not isinstance(data, list) or any(not isinstance(p, str) or not p.startswith("/") or not p.lower().endswith(".xml") for p in data):
        raise ValueError("Invalid Azure path registry; restore or remove the registry file.")
    return data


def save(paths):
    STORE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(dir=STORE.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(paths, stream)
        os.replace(temp, STORE)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def register(path):
    paths = load()
    if path not in paths:
        paths.append(path)
        save(paths)
    return paths


def remove(path):
    paths = load()
    if path not in paths:
        raise ValueError("Azure path is not registered.")
    operation = operation_status()
    current = status()
    if not operation.get("known", False) or operation["running"] or operation["stopping"]:
        raise ValueError("Disconnect VPN and confirm status before removing a profile.")
    # Removal only unregisters the path; it never touches a running tunnel.
    # Unknown status (e.g. missing openp2s backend) with an idle unit must not
    # lock the entry forever, but a live or transitioning session still blocks.
    if current.get("connected") or current.get("state") not in ("disconnected", "unknown"):
        raise ValueError("Disconnect VPN and confirm status before removing a profile.")
    # Remove only the registry entry; source XML and certificates are untouched.
    paths = [p for p in paths if p != path]
    save(paths)
    return {"azure": paths, "message": "Profile removed. Source files kept."}


def delete_nm(profile):
    if not ovpn_source.valid_uuid(profile):
        raise ValueError("Select a profile UUID.")
    sources = ovpn_source.load()
    result = subprocess.run([require("nmcli"), "--wait", "30", "connection", "delete", "uuid", profile],
                            capture_output=True, text=True, timeout=35)
    if result.returncode:
        raise ValueError("NetworkManager profile deletion failed. Refresh and retry.")
    if profile in sources:
        del sources[profile]
        ovpn_source.save(sources)
    return {"message": "Profile removed. Source files kept."}


def prepare_nm_certificate(profile):
    # New imports only. Native OpenVPN asks only when its key needs a password;
    # this policy permits that request without storing the password in NM.
    import re
    result = subprocess.run([require("nmcli"), "-g", "vpn.data", "connection", "show", "uuid", profile],
                            capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise ValueError("Profile imported, but certificate secret policy could not be checked. Refresh before connecting.")
    data = dict(item.strip().split(" = ", 1) for item in re.split(r"(?<!\\),", result.stdout.strip()) if " = " in item)
    if data.get("connection-type") not in ("tls", "password-tls") or "cert-pass-flags" in data:
        return
    result = subprocess.run([require("nmcli"), "connection", "modify", "uuid", profile,
                             "+vpn.data", "cert-pass-flags=2"], capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise ValueError("Profile imported, but certificate secret policy setup failed. Refresh and repair cert-pass-flags before connecting.")
    result = subprocess.run([require("nmcli"), "-g", "vpn.data", "connection", "show", "uuid", profile],
                            capture_output=True, text=True, timeout=15)
    if result.returncode or not re.search(r"(?:^|, )cert-pass-flags = 2(?:,|$)", result.stdout.strip()):
        raise ValueError("Profile imported, but certificate secret policy verification failed. Refresh before connecting.")


def nm_details(profile):
    if not ovpn_source.valid_uuid(profile):
        raise ValueError("Select a profile UUID.")
    result = subprocess.run([require("nmcli"), "--escape", "no", "-g", "IP4.ADDRESS,IP6.ADDRESS", "connection", "show", "--active", "uuid", profile],
                            capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise ValueError("Could not read active VPN details.")
    import ipaddress
    addresses = []
    for line in result.stdout.splitlines():
        try:
            addresses.append(str(ipaddress.ip_interface(line).ip))
        except ValueError:
            pass
    address = addresses[0] if addresses else ""
    # GENERAL.DEVICES/IP-IFACE refer to the VPN's physical parent, not its tun.
    # Match native active VPN addresses to native kernel interfaces; never guess.
    result = subprocess.run([require("ip"), "-j", "address", "show"], capture_output=True, text=True, timeout=5)
    devices = json.loads(result.stdout) if result.returncode == 0 else []
    matches = set()
    for device in devices:
        for item in device.get("addr_info", []):
            try:
                if str(ipaddress.ip_address(item.get("local", ""))) in addresses:
                    matches.add(device["ifname"])
            except ValueError:
                pass
    return {"uuid": profile, "address": address, "interface": matches.pop() if len(matches) == 1 else ""}


def parse_forti_xml(path):
    import xml.etree.ElementTree as ET
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        if root.tag not in ("forticlient_configuration", "fortivpn_configuration") and not root.find(".//connection"):
            return []
        conns = []
        for conn in root.iter("connection"):
            name = conn.findtext("name") or ""
            server = conn.findtext("server") or ""
            user = conn.findtext("username") or ""
            host = server
            port = "443"
            if ":" in server:
                host, port = server.split(":", 1)
            if name and host:
                conns.append({"name": name, "host": host, "port": port, "username": user})
        return conns
    except Exception:
        return []


def parse_forti_conf(path):
    try:
        lines = Path(path).read_text(errors="ignore").splitlines()
        host = ""
        port = "443"
        username = ""
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                k = k.strip().lower()
                v = v.strip().strip('"').strip("'")
                if k in ("host", "gateway", "server", "remote"):
                    if ":" in v:
                        host, port = v.split(":", 1)
                    else:
                        host = v
                elif k == "port":
                    port = v
                elif k in ("user", "username"):
                    username = v
        if host:
            name = Path(path).stem
            return {"name": name, "host": host, "port": port, "username": username}
    except Exception:
        pass
    return None


def forti_installed():
    return shutil.which("forticlient") is not None


def forti_list_result():
    """Return (profiles, readable) so callers never mistake a CLI hiccup for "no profiles"."""
    if not forti_installed():
        return [], False
    for _attempt in range(3):
        try:
            res = subprocess.run(["forticlient", "vpn", "list"], capture_output=True, text=True, timeout=5)
        except Exception:
            res = None
        if res is not None and res.returncode == 0:
            profiles = []
            in_vpns = False
            for line in res.stdout.splitlines():
                stripped = line.strip()
                if "Personal VPNs:" in line or "VPNs:" in line:
                    in_vpns = True
                    continue
                if in_vpns and stripped and not stripped.endswith(":"):
                    profiles.append(stripped)
            if in_vpns:
                return profiles, True
        time.sleep(0.2)
    return [], False


def forti_list():
    return forti_list_result()[0]


def forti_profile_payload():
    profiles, readable = forti_list_result()
    return {"forti": profiles, "fortiOk": readable}


FORTI_ATTEMPT_FILE = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")) / "airzy.vpn-forti-attempt.json"
FORTI_LEGACY_ERROR_FILE = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")) / "airzy.vpn-forti-error.txt"
FORTI_CONNECT_TIMEOUT = 90
FORTI_DISCONNECT_TIMEOUT = 30
FORTI_KEYRING_TIMEOUT = 10
FORTI_CONFIRM_LIMIT = 3
FORTI_PIN_FILE = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))) / "airzy.vpn/forti-pins.json"


def forti_fingerprint_digits(value):
    return re.sub(r"[^0-9A-F]", "", str(value).upper())


def forti_pins_load():
    try:
        data = json.loads(FORTI_PIN_FILE.read_text())
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def forti_pin_get(name):
    pin = forti_pins_load().get(name)
    if not isinstance(pin, dict):
        return None
    host = pin.get("host")
    sha1 = pin.get("sha1")
    if not isinstance(host, str) or not isinstance(sha1, str) or not host:
        return None
    digits = forti_fingerprint_digits(sha1)
    if len(digits) != 40:
        return None
    return {"host": host.lower(), "sha1": digits}


def forti_pins_write(pins):
    FORTI_PIN_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(dir=FORTI_PIN_FILE.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(pins, stream, indent=2)
        os.replace(temp, FORTI_PIN_FILE)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def forti_pin_set(name, host, sha1):
    host = (host or "").strip().lower()
    digits = forti_fingerprint_digits(sha1)
    if not host or len(host) > 255 or any(ord(c) < 32 or ord(c) == 127 for c in host):
        raise ValueError("The certificate hostname is missing or invalid; nothing was pinned.")
    if len(digits) != 40:
        raise ValueError("The certificate fingerprint is not a SHA-1 digest; nothing was pinned.")
    pins = forti_pins_load()
    pins[name] = {"host": host, "sha1": digits}
    forti_pins_write(pins)
    return {"profile": name, "host": host, "sha1": digits}


def forti_pin_clear(name):
    pins = forti_pins_load()
    if name not in pins:
        return True
    pins.pop(name, None)
    try:
        if pins:
            forti_pins_write(pins)
        else:
            FORTI_PIN_FILE.unlink(missing_ok=True)
    except Exception:
        return False
    return True


def _forti_attempt_read():
    try:
        data = json.loads(FORTI_ATTEMPT_FILE.read_text())
    except Exception:
        return {}
    if not isinstance(data, dict) or data.get("version") != 1:
        return {}
    return data


def _forti_attempt_write(record):
    FORTI_ATTEMPT_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp = tempfile.mkstemp(dir=FORTI_ATTEMPT_FILE.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(record, stream)
        os.replace(temp, FORTI_ATTEMPT_FILE)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def _proc_start(pid):
    try:
        raw = Path("/proc", str(int(pid)), "stat").read_text()
        return raw[raw.rfind(")") + 2:].split()[19]
    except Exception:
        return ""


def _forti_helper_live(record):
    return bool(record.get("pid")) and _proc_start(record["pid"]) == record.get("pid_start")


def forti_attempt_start(profile, phase, timeout):
    now = time.time()
    record = {
        "version": 1,
        "id": secrets.token_hex(8),
        "profile": profile,
        "phase": phase,
        "started": now,
        "deadline": now + timeout,
        "pid": os.getpid(),
        "pid_start": _proc_start(os.getpid()),
        "reason": "",
        "error": "",
        "password_required": "",
        "cleanup_required": False,
        "warning": "",
        "updated": now,
    }
    _forti_attempt_write(record)
    return record


def forti_attempt_update(record, **changes):
    current = _forti_attempt_read()
    if current.get("id") != record.get("id"):
        return False
    current.update(changes)
    current["updated"] = time.time()
    _forti_attempt_write(current)
    record.update(changes)
    return True


def forti_attempt_finish(record, phase, reason="", error="", password_required="",
                        cleanup_required=False, warning="", certificate=None):
    return forti_attempt_update(record, phase=phase, reason=reason, error=error,
                                password_required=password_required,
                                cleanup_required=cleanup_required, warning=warning,
                                certificate=certificate)


def forti_attempt_clear(record=None):
    if record is not None:
        current = _forti_attempt_read()
        if current.get("id") != record.get("id"):
            return False
    try:
        FORTI_ATTEMPT_FILE.unlink(missing_ok=True)
    except Exception:
        return False
    return True


def _forti_require_idle():
    current = _forti_attempt_read()
    if current.get("phase") in ("connecting", "disconnecting") and _forti_helper_live(current):
        raise ValueError("A FortiClient operation is already in progress. Wait for it to finish.")
    return current


def get_fctvpn_interface():
    try:
        ip = require("ip")
        res = subprocess.run([ip, "-j", "addr", "show"], capture_output=True, text=True, timeout=2)
        if res.returncode == 0:
            for dev in json.loads(res.stdout):
                ifname = dev.get("ifname", "")
                if ifname.startswith("fctvpn"):
                    addrs = dev.get("addr_info", [])
                    ipv4 = next((a.get("local", "") for a in addrs if a.get("family") == "inet"), "")
                    return ifname, ipv4
    except Exception:
        pass
    return "", ""


def parse_forti_view(text):
    host = ""
    username = ""
    for line in text.splitlines():
        value = line.strip()
        if value.startswith("Remote Gateway:"):
            host = value.split(":", 1)[1].strip()
        elif value.startswith("Username:"):
            username = value.split(":", 1)[1].strip()
    return host, username


def normalize_forti_host(value):
    value = value.strip()
    if not value:
        return ""
    if value.startswith("["):
        end = value.find("]")
        return value[1:end].lower() if end > 1 else ""
    if value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value.lower()


def forti_identity(name):
    try:
        res = subprocess.run(["forticlient", "vpn", "view", name], capture_output=True, text=True, timeout=5)
    except Exception:
        return None
    if res.returncode != 0:
        return None
    host, username = parse_forti_view(res.stdout)
    host = normalize_forti_host(host)
    if not host or not username:
        return None
    return {"profile": name, "host": host, "username": username}


def _forti_secret_attrs(identity):
    return ["service", "airzy.vpn", "kind", "forti",
            "profile", identity["profile"], "host", identity["host"],
            "username", identity["username"]]


def _forti_valid_secret(value):
    return bool(value) and len(value) <= 4092 and not any(byte < 32 or byte == 127 for byte in value)


def secret_tool_lookup(identity):
    tool = shutil.which("secret-tool")
    if not tool:
        return b"", "keyring-unavailable"
    try:
        res = subprocess.run([tool, "lookup", *_forti_secret_attrs(identity)],
                             capture_output=True, timeout=FORTI_KEYRING_TIMEOUT)
    except Exception:
        return b"", "keyring-unavailable"
    if res.returncode != 0:
        return b"", "keyring-unavailable" if res.stderr.strip() else "no-credential"
    value = res.stdout
    if value.endswith(b"\r\n"):
        value = value[:-2]
    elif value.endswith(b"\n"):
        value = value[:-1]
    if not _forti_valid_secret(value):
        return b"", "keyring-unavailable"
    return value, ""


def secret_tool_store(identity, password):
    tool = shutil.which("secret-tool")
    if not tool:
        return False
    label = f"TunnelHub Forti {identity['profile']} ({identity['username']}@{identity['host']})"
    try:
        res = subprocess.run([tool, "store", "--label", label, *_forti_secret_attrs(identity)],
                             input=password, capture_output=True, timeout=FORTI_KEYRING_TIMEOUT)
    except Exception:
        return False
    return res.returncode == 0


def secret_tool_clear(identity):
    tool = shutil.which("secret-tool")
    if not tool:
        return False
    try:
        res = subprocess.run([tool, "clear", *_forti_secret_attrs(identity)],
                             capture_output=True, timeout=FORTI_KEYRING_TIMEOUT)
    except Exception:
        return False
    # secret-tool returns 1 when no matching item exists; only stderr indicates a real failure.
    return res.returncode == 0 or not res.stderr.strip()


def forti_credential_lookup(name):
    identity = forti_identity(name)
    if not identity:
        return b"", "identity-unavailable"
    return secret_tool_lookup(identity)


def forti_credential_status(name):
    identity = forti_identity(name)
    if not identity:
        return {"profile": name, "identity": None, "saved": False, "length": 0,
                "reason": "identity-unavailable"}
    password, reason = secret_tool_lookup(identity)
    return {"profile": name, "identity": identity, "saved": bool(password),
            "length": len(password), "reason": "" if password else reason}


def forti_credential_store(name, password):
    identity = forti_identity(name)
    if not identity:
        return "Password was not saved: Forti profile identity is unavailable."
    secret_tool_clear(identity)
    if secret_tool_store(identity, password):
        return ""
    return "Password was not saved: GNOME Keyring is unavailable."


def forti_credential_clear(name):
    identity = forti_identity(name)
    if not identity:
        raise ValueError("Could not resolve the Forti profile identity; the profile was not deleted so a saved password cannot be orphaned.")
    if not secret_tool_clear(identity):
        raise ValueError("Could not remove the saved Forti password; the profile was not deleted.")


def forti_native_status():
    if not forti_installed():
        return {"installed": False, "state": "not_installed", "connected": False,
                "profile": "", "interface": "", "address": ""}
    ifname, ip_addr = get_fctvpn_interface()
    state = "connected" if (ifname and ip_addr) else "disconnected"
    connected = bool(ifname and ip_addr)
    profile = ""
    address = ip_addr
    interface = ifname
    try:
        res = subprocess.run(["forticlient", "vpn", "status"], capture_output=True, text=True, timeout=3)
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.startswith("Status:"):
                st = line.split(":", 1)[1].strip().lower()
                if "connected" in st:
                    state = "connected"
                elif "connecting" in st or "re-connecting" in st or "xauth" in st:
                    if not connected:
                        state = "connecting"
                elif "not running" in st or "disconnected" in st:
                    if not connected:
                        state = "disconnected"
                else:
                    if not connected:
                        state = "unknown"
            elif line.startswith("VPN name:"):
                profile = line.split(":", 1)[1].strip()
            elif line.startswith("IP:") and not address:
                address = line.split(":", 1)[1].strip()
    except Exception:
        pass
    if connected and not profile:
        profiles = forti_list()
        profile = profiles[0] if len(profiles) == 1 else "FortiClient"
    return {"installed": True, "state": state, "connected": connected,
            "profile": profile, "interface": interface, "address": address}


def merge_forti_status(native, attempt=None, now=None, helper_live=None):
    now = time.time() if now is None else now
    attempt = attempt or {}
    live = _forti_helper_live(attempt) if helper_live is None else helper_live
    phase = attempt.get("phase", "")
    try:
        deadline = float(attempt.get("deadline") or 0)
    except (TypeError, ValueError):
        deadline = 0
    native_state = native.get("state", "unknown")
    ifname = native.get("interface", "")
    address = native.get("address", "")
    connected = bool(ifname and address and native.get("connected"))
    profile = attempt.get("profile") or native.get("profile") or ""
    error = ""
    password_required = ""
    password_reason = ""
    cleanup = False
    warning = attempt.get("warning", "")
    certificate = attempt.get("certificate")
    if not isinstance(certificate, dict):
        certificate = None
    state = "disconnected"

    if not native.get("installed", True):
        return {"installed": False, "state": "not_installed", "connected": False,
                "profile": profile, "interface": "", "address": "",
                "error": "", "passwordRequired": "", "passwordReason": "",
                "cleanupRequired": False, "warning": "", "certificateRequired": None,
                "attempt": {"phase": phase, "profile": attempt.get("profile", ""),
                            "deadline": deadline, "warning": "", "cleanupRequired": False}}

    if connected:
        state = "connected"
        certificate = None
        if phase == "failed":
            phase = "connected"
    elif phase == "connecting":
        if live and now < deadline:
            state = "connecting"
        else:
            state = "failed"
            error = attempt.get("error") or ("FortiClient connection helper exited before the tunnel was established."
                                             if not live else "FortiClient did not connect before the deadline.")
            password_required = attempt.get("password_required", "")
            password_reason = attempt.get("reason", "") if password_required else ""
            cleanup = native_state not in ("disconnected", "not_installed") or bool(attempt.get("cleanup_required"))
    elif phase == "disconnecting":
        if live and now < deadline:
            state = "disconnecting"
        else:
            state = "failed"
            error = attempt.get("error") or "FortiClient disconnection did not complete before the deadline."
            cleanup = native_state not in ("disconnected", "not_installed") or bool(attempt.get("cleanup_required"))
    elif phase == "failed":
        state = "failed"
        error = attempt.get("error", "")
        password_required = attempt.get("password_required", "")
        password_reason = attempt.get("reason", "") if password_required else ""
        cleanup = bool(attempt.get("cleanup_required")) or native_state not in ("disconnected", "not_installed")
        if attempt.get("reason") in ("certificate-untrusted", "certificate-mismatch"):
            # The connect helper clears any leftover session itself, so a
            # pending approval must not be blocked behind Clean up.
            cleanup = False
    else:
        if native_state == "connecting":
            state = "unknown"
            cleanup = True
            error = "FortiClient reports a stale connecting state. Clean up before retrying."
        elif native_state == "connected" and not connected:
            state = "unknown"
            cleanup = True
            error = "FortiClient reports connected but no fctvpn address is available. Clean up before retrying."
        elif native_state in ("disconnected", "not_installed"):
            state = "disconnected"
        else:
            state = "unknown"
            cleanup = native_state != "disconnected"

    return {
        "installed": native.get("installed", True),
        "state": state,
        "connected": state == "connected",
        "profile": profile,
        "interface": ifname if state == "connected" else "",
        "address": address if state == "connected" else "",
        "error": error,
        "passwordRequired": password_required,
        "passwordReason": password_reason,
        "cleanupRequired": cleanup,
        "warning": warning,
        "certificateRequired": certificate if state == "failed" else None,
        "attempt": {"phase": phase, "profile": attempt.get("profile", ""),
                    "deadline": deadline, "warning": warning,
                    "cleanupRequired": cleanup},
    }


def forti_status():
    try:
        FORTI_LEGACY_ERROR_FILE.unlink(missing_ok=True)
    except Exception:
        pass
    return merge_forti_status(forti_native_status(), _forti_attempt_read())


def forti_clear_auth():
    try:
        FORTI_LEGACY_ERROR_FILE.unlink(missing_ok=True)
    except Exception:
        pass
    record = _forti_attempt_read()
    if not record:
        return {"cleared": True}
    if record.get("cleanup_required"):
        record.update({"error": "", "password_required": "", "reason": "", "warning": ""})
        _forti_attempt_write(record)
    else:
        forti_attempt_clear(record)
    return {"cleared": True}


def read_forti_password_from_stdin():
    try:
        return sys.stdin.buffer.readline().rstrip(b"\r\n")
    except Exception:
        return b""

def active_physical_device():
    try:
        nmcli = require("nmcli")
        res = subprocess.run([nmcli, "-t", "-f", "DEVICE,TYPE,STATE,CON-UUID", "device", "status"],
                             capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                parts = line.split(":")
                if len(parts) >= 4 and parts[2] == "connected" and parts[1] in ("wifi", "ethernet"):
                    return parts[0], parts[3]
    except Exception:
        pass
    return None, None


def has_physical_default_route():
    try:
        ip = require("ip")
        res = subprocess.run([ip, "-j", "route", "show", "default"],
                             capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            routes = json.loads(res.stdout)
            for r in routes:
                dev = r.get("dev", "")
                if dev and not dev.startswith(("fctvpn", "tun", "tap", "ppp", "wg")):
                    return True
    except Exception:
        pass
    return False


def current_dns_provider():
    try:
        res = subprocess.run(["omarchy-dns"], capture_output=True, text=True, timeout=3)
        p = res.stdout.strip()
        if p in ("DHCP", "Cloudflare", "Google"):
            return p
    except Exception:
        pass
    return "DHCP"


def heal_network_on_connect(vpn_iface=None):
    phys_dev, _ = active_physical_device()
    if not phys_dev:
        return

    if not vpn_iface:
        try:
            ip = require("ip")
            res = subprocess.run([ip, "-j", "link", "show"], capture_output=True, text=True, timeout=3)
            if res.returncode == 0:
                for link in json.loads(res.stdout):
                    name = link.get("ifname", "")
                    if name.startswith("fctvpn"):
                        vpn_iface = name
                        break
        except Exception:
            pass

    if vpn_iface:
        try:
            nmcli = require("nmcli")
            subprocess.run([nmcli, "device", "set", vpn_iface, "managed", "no"],
                           capture_output=True, text=True, timeout=3)
        except Exception:
            pass

    if not has_physical_default_route():
        try:
            nmcli = require("nmcli")
            subprocess.run([nmcli, "device", "reapply", phys_dev],
                           capture_output=True, text=True, timeout=5)
        except Exception:
            pass


def dns_resolves():
    try:
        res = subprocess.run(["getent", "hosts", "google.com"],
                             capture_output=True, text=True, timeout=2)
    except Exception:
        return False
    return res.returncode == 0


def restore_network_on_disconnect():
    # FortiClient replaces /etc/resolv.conf on connect and restores it from its
    # own daemon on disconnect. Wait for that restore before re-asserting
    # NetworkManager state, otherwise a stale VPN nameserver set survives.
    backup_file = Path("/etc/resolv.conf.forticlient.backup")
    wait_end = time.monotonic() + 5.0
    while backup_file.exists() and time.monotonic() < wait_end:
        time.sleep(0.1)

    phys_dev, _ = active_physical_device()
    if phys_dev:
        try:
            nmcli = require("nmcli")
            # network-control is granted to active local sessions; this never prompts.
            subprocess.run([nmcli, "device", "reapply", phys_dev],
                           capture_output=True, text=True, timeout=10)
        except Exception:
            pass

    end = time.monotonic() + 3.0
    while time.monotonic() < end:
        if dns_resolves():
            return
        time.sleep(0.2)

    # FortiClient's own resolver restart shells out to /usr/sbin/service, which
    # Arch does not ship, so resolution can keep pointing at VPN nameservers.
    # Reapply the desktop DNS provider instead: those three names are NOPASSWD
    # in Omarchy's sudoers and `sudo -n` can never open a password prompt.
    provider = current_dns_provider()
    if provider in ("DHCP", "Cloudflare", "Google"):
        try:
            subprocess.run(["sudo", "-n", "/usr/bin/omarchy-dns", provider],
                           capture_output=True, text=True, timeout=10)
        except Exception:
            pass
    end = time.monotonic() + 3.0
    while time.monotonic() < end:
        if dns_resolves():
            return
        time.sleep(0.2)

STATE_FILE = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")) / "airzy.vpn-runtime-state.json"


def write_forti_state(connected):
    try:
        state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    except Exception:
        state = {}
    state["forti_connected"] = bool(connected)
    try:
        STATE_FILE.write_text(json.dumps(state))
    except Exception:
        pass

def check_and_heal_network(res):
    try:
        last_state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    except Exception:
        last_state = {}

    forti_info = res.get("forti", {})
    forti_now = forti_info.get("connected", False)
    azure_now = res.get("connected", False)
    forti_prev = last_state.get("forti_connected", False)
    azure_prev = last_state.get("azure_connected", False)

    if forti_now:
        if not forti_prev or not has_physical_default_route():
            heal_network_on_connect(forti_info.get("interface"))
    elif (forti_prev and not forti_now) or (azure_prev and not azure_now):
        restore_network_on_disconnect()
    elif not forti_now and not azure_now and not has_physical_default_route():
        restore_network_on_disconnect()
    try:
        STATE_FILE.write_text(json.dumps({"forti_connected": forti_now, "azure_connected": azure_now}))
    except Exception:
        pass




def _forti_pty_open(command):
    import pty
    import termios
    master, slave = pty.openpty()
    attrs = termios.tcgetattr(slave)
    attrs[3] &= ~termios.ECHO
    termios.tcsetattr(slave, termios.TCSANOW, attrs)
    pid = os.fork()
    if pid == 0:
        os.close(master)
        os.dup2(slave, 0)
        os.dup2(slave, 1)
        os.dup2(slave, 2)
        os.close(slave)
        try:
            os.execv("/usr/bin/forticlient", command)
        finally:
            os._exit(127)
    os.close(slave)
    return master, pid


def _forti_read(master):
    try:
        return os.read(master, 4096)
    except OSError:
        return b""


def _forti_write(master, data):
    try:
        os.write(master, data)
        return True
    except OSError:
        return False


def _forti_password_prompt(buf):
    return re.search(rb"(?m)^[ \t]*Password:[ \t]*\r?$", bytes(buf)) is not None


def _forti_replace_password_prompt(buf):
    match = re.search(rb"(?m)^[ \t]*Password:[ \t]*\r?$", bytes(buf))
    if match is not None:
        buf[match.start():match.end()] = b"SENT_PASSWORD"


def _forti_certificate_prompt(buf):
    text = bytes(buf)
    if b"Confirm (y/n)" not in text and b"Accept (y/n)" not in text:
        return None
    if b"untrusted server" not in text.lower() and b"X509 verify certificate failed" not in text:
        return None
    host = re.search(rb"(?mi)^[ \t]*Hostname:[ \t]*(\S+)[ \t]*\r?$", text)
    fingerprint = re.search(rb"(?mi)^[ \t]*Fingerprint \(SHA1\):[ \t]*([0-9A-Fa-f: \t]+)", text)
    return {
        "host": host[1].decode(errors="replace").strip().lower() if host else "",
        "sha1": forti_fingerprint_digits(fingerprint[1].decode(errors="replace")) if fingerprint else "",
        "reason": "X509 verify certificate failed",
    }


def _forti_connect_unknown_prompt(buf, sent_password, cert_trusted=False):
    probe = bytes(buf).lower()
    probe = probe.replace(b"please input password.", b"")
    probe = probe.replace(b"sent_password", b"")

    if not sent_password:
        match = re.search(rb"(?m)^[ \t]*password:[ \t]*\r?$", probe)
        if match is not None:
            probe = probe[:match.start()] + probe[match.end():]

    if not cert_trusted and any(m in probe for m in (b"confirm", b"accept", b"certificate",
                                                     b"fingerprint", b"untrusted", b"x509")):
        return "FortiClient requested an untrusted server certificate confirmation or unsupported prompt."

    if any(m in probe for m in (b"password", b"token")):
        return "FortiClient requested an unsupported authentication prompt."

    return ""


def _forti_connect_prompts(buf, master, password, pin, state):
    cert = _forti_certificate_prompt(buf)
    if cert is not None:
        if not cert["host"] or not cert["sha1"]:
            return ("FortiClient requested an untrusted server certificate confirmation but did not report a usable hostname and SHA-1 fingerprint.",
                    cert)
        if pin and str(pin.get("host", "")).lower() == cert["host"] \
                and forti_fingerprint_digits(pin.get("sha1", "")) == cert["sha1"]:
            if not _forti_write(master, b"y\n"):
                return "FortiClient closed the connection while a pinned certificate confirmation was pending.", None
            state["cert_trusted"] = True
            buf.clear()
            return "", None
        setting = ("does not match the fingerprint pinned for this profile" if pin
                   else "is not pinned for this profile")
        return (f"FortiClient reported an untrusted server certificate that {setting}. "
                "Review the hostname and SHA-1 fingerprint, then approve it in the panel.", cert)

    prompt_error = _forti_connect_unknown_prompt(buf, state["sent_password"], state["cert_trusted"])
    if prompt_error:
        return prompt_error, None

    if _forti_password_prompt(buf):
        if password and not state["sent_password"]:
            if not _forti_write(master, password + b"\n"):
                return "FortiClient closed the connection while a password was pending.", None
            state["sent_password"] = True
            _forti_replace_password_prompt(buf)
        else:
            return "FortiClient requested a password prompt that could not be answered safely.", None

    return "", None


def _forti_disconnect_unknown_prompt(buf):
    probe = bytes(buf).lower()
    for marker in (b"confirm (y/n)", b"confirmation required", b"confirmed"):
        probe = probe.replace(marker, b"")
    if any(m in probe for m in (b"confirm", b"accept", b"certificate",
                               b"fingerprint", b"untrusted", b"x509")):
        return "FortiClient requested an unsupported confirmation or certificate prompt during disconnection."
    if any(m in probe for m in (b"password", b"token")):
        return "FortiClient requested an unsupported authentication prompt during disconnection."
    return ""


def _forti_disconnect_prompts(buf, master, confirmations):
    prompt_error = _forti_disconnect_unknown_prompt(buf)
    if prompt_error:
        return prompt_error, confirmations

    while b"Confirm (y/n)" in buf and confirmations < FORTI_CONFIRM_LIMIT:
        if not _forti_write(master, b"y\n"):
            return "FortiClient closed the connection while a confirmation was pending.", confirmations
        confirmations += 1
        buf[:] = buf.replace(b"Confirm (y/n)", b"CONFIRMED", 1)

    if confirmations >= FORTI_CONFIRM_LIMIT and b"Confirm (y/n)" in buf:
        return "FortiClient requested too many confirmation prompts.", confirmations

    return "", confirmations


def _forti_wait_child(pid, timeout):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            done, _ = os.waitpid(pid, os.WNOHANG)
            if done == pid:
                return True
        except ChildProcessError:
            return True
        time.sleep(0.05)
    return False


def _forti_stop_child(pid):
    try:
        os.kill(pid, signal.SIGTERM)
    except Exception:
        pass
    end = time.monotonic() + 2
    while time.monotonic() < end:
        try:
            done, _ = os.waitpid(pid, os.WNOHANG)
            if done == pid:
                return
        except ChildProcessError:
            return
        time.sleep(0.05)
    try:
        os.kill(pid, signal.SIGKILL)
    except Exception:
        pass
    try:
        os.waitpid(pid, 0)
    except Exception:
        pass


def forti_connect_pty(name, password, store=False):
    import select
    if not password:
        record = forti_attempt_start(name, "connecting", FORTI_CONNECT_TIMEOUT)
        forti_attempt_finish(record, "failed", reason="no-credential",
                             error="No Forti password was available for this connection.")
        return
    record = forti_attempt_start(name, "connecting", FORTI_CONNECT_TIMEOUT)
    pin = forti_pin_get(name)
    master, pid = _forti_pty_open(["forticlient", "vpn", "connect", name, "-p"])
    buf = bytearray()
    state = {"sent_password": False, "cert_trusted": False}
    connected = False
    auth_rejected = False
    cancelled = False
    unsupported = ""
    certificate = None
    child_alive = True
    exited_early = False
    restarted = False
    password_timer = False
    deadline = record["deadline"]
    connect_deadline = deadline
    try:
        while time.time() < deadline:
            if child_alive:
                readable, _, _ = select.select([master], [], [], 0.2)
                if readable:
                    chunk = _forti_read(master)
                    if not chunk:
                        child_alive = False
                        try:
                            os.close(master)
                        except Exception:
                            pass
                    else:
                        buf.extend(chunk)
                        if len(buf) > 65536:
                            del buf[:-8192]
                        if b"already running" in buf and not restarted:
                            restarted = True
                            if child_alive:
                                _forti_stop_child(pid)
                                child_alive = False
                            try:
                                os.close(master)
                            except Exception:
                                pass
                            cleared = False
                            for _attempt in range(2):
                                _forti_disconnect_run(25)
                                if forti_native_status().get("state") in ("disconnected", "not_installed"):
                                    cleared = True
                                    break
                                time.sleep(1.0)
                            if not cleared:
                                unsupported = ("FortiClient kept a previous session running and did not disconnect it. "
                                               "Use Clean up, then retry.")
                                break
                            master, pid = _forti_pty_open(["forticlient", "vpn", "connect", name, "-p"])
                            buf = bytearray()
                            state = {"sent_password": False, "cert_trusted": False}
                            child_alive = True
                            exited_early = False
                            password_timer = False
                            connect_deadline = deadline
                            continue
                        if b"Insufficient credential" in buf or b"Login failed" in buf:
                            auth_rejected = True
                            break
                        if b"Login canceled" in buf:
                            cancelled = True
                            break
                        prompt_error, cert = _forti_connect_prompts(buf, master, password, pin, state)
                        if prompt_error:
                            unsupported = prompt_error
                            certificate = cert
                            break
                        if state["sent_password"] and not password_timer:
                            password_timer = True
                            connect_deadline = time.monotonic() + 25.0
                if child_alive:
                    try:
                        done, _ = os.waitpid(pid, os.WNOHANG)
                        if done == pid:
                            child_alive = False
                            if not state["sent_password"]:
                                exited_early = True
                            try:
                                os.close(master)
                            except Exception:
                                pass
                    except ChildProcessError:
                        child_alive = False
                        if not state["sent_password"]:
                            exited_early = True

            ifname, ip_addr = get_fctvpn_interface()
            if ifname and ip_addr:
                connected = True
                break

            native = forti_native_status()
            if native.get("connected") and native.get("interface"):
                connected = True
                ifname = native.get("interface")
                break

            if not child_alive:
                if not state["sent_password"]:
                    exited_early = True
                    break
                if time.monotonic() > connect_deadline:
                    break
                time.sleep(0.2)
        if connected:
            ifname, ip_addr = get_fctvpn_interface()
            if not (ifname and ip_addr):
                connected = False

        if connected:
            heal_network_on_connect(ifname)
            write_forti_state(True)
            forti_attempt_finish(record, "connected")
            if store:
                warning = forti_credential_store(name, password)
                if warning:
                    forti_attempt_update(record, warning=warning)
            replaced = False
            while True:
                current = _forti_attempt_read()
                if current.get("id") != record.get("id"):
                    replaced = True
                    break
                ifname, ip_addr = get_fctvpn_interface()
                if not (ifname and ip_addr):
                    break
                time.sleep(1.0)
            if child_alive and not replaced:
                _forti_stop_child(pid)
            write_forti_state(False)
            restore_network_on_disconnect()
            forti_attempt_clear(record)
            return

        if child_alive:
            _forti_stop_child(pid)
            child_alive = False
        try:
            os.close(master)
        except Exception:
            pass
        native = forti_native_status()
        cleanup = native.get("state") not in ("disconnected", "not_installed")
        if auth_rejected:
            error = "Incorrect password or authentication rejected by VPN server."
            if cleanup:
                error = "Authentication was rejected, but FortiClient still reports an active or stale state. Clean up before retrying."
                password_required = ""
            else:
                password_required = name
            forti_attempt_finish(record, "failed", reason="auth-rejected", error=error,
                                 password_required=password_required, cleanup_required=cleanup)
        elif cancelled:
            forti_attempt_finish(record, "failed", reason="cancelled",
                                 error="Connection cancelled by FortiClient.",
                                 cleanup_required=cleanup)
        elif unsupported:
            if certificate is not None:
                reason = "certificate-mismatch" if pin else "certificate-untrusted"
                forti_attempt_finish(record, "failed", reason=reason, error=unsupported,
                                     certificate=certificate, cleanup_required=cleanup)
            else:
                forti_attempt_finish(record, "failed", reason="unsupported-prompt",
                                     error=unsupported, cleanup_required=cleanup)
        else:
            early_exit = exited_early and native.get("state") in ("disconnected", "not_installed")
            if early_exit:
                error = "FortiClient connect process exited before the tunnel was established."
                reason = "helper-exited"
            else:
                error = "FortiClient did not connect within 90 seconds."
                reason = "timeout"
            forti_attempt_finish(record, "failed", reason=reason, error=error,
                                 cleanup_required=cleanup)
    finally:
        try:
            os.close(master)
        except Exception:
            pass


def _forti_disconnect_run(timeout):
    import select
    master, pid = _forti_pty_open(["forticlient", "vpn", "disconnect"])
    buf = bytearray()
    confirmations = 0
    child_alive = True
    success = False
    unsupported = ""
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            if child_alive:
                readable, _, _ = select.select([master], [], [], 0.2)
                if readable:
                    chunk = _forti_read(master)
                    if not chunk:
                        child_alive = False
                        try:
                            os.close(master)
                        except Exception:
                            pass
                    else:
                        buf.extend(chunk)
                        if len(buf) > 65536:
                            del buf[:-8192]
                        if b"VPN is not running" in buf:
                            success = True
                            break
                        prompt_error, confirmations = _forti_disconnect_prompts(
                            buf, master, confirmations)
                        if prompt_error:
                            unsupported = prompt_error
                            break
                if not success:
                    native = forti_native_status()
                    if native.get("state") in ("disconnected", "not_installed"):
                        success = True
                        break
                if child_alive:
                    try:
                        done, _ = os.waitpid(pid, os.WNOHANG)
                        if done == pid:
                            child_alive = False
                    except ChildProcessError:
                        child_alive = False
            else:
                native = forti_native_status()
                if native.get("state") in ("disconnected", "not_installed"):
                    success = True
                    break
                time.sleep(0.2)

        if success:
            if child_alive and not _forti_wait_child(pid, 5):
                _forti_stop_child(pid)
            return True, ""
        if child_alive:
            _forti_stop_child(pid)
        return False, unsupported
    finally:
        try:
            os.close(master)
        except Exception:
            pass


def forti_disconnect_bg():
    current = _forti_attempt_read()
    profile = current.get("profile") or forti_native_status().get("profile", "")
    record = forti_attempt_start(profile, "disconnecting", FORTI_DISCONNECT_TIMEOUT)
    success, unsupported = _forti_disconnect_run(FORTI_DISCONNECT_TIMEOUT)
    if success:
        write_forti_state(False)
        restore_network_on_disconnect()
        forti_attempt_clear(record)
        return
    native = forti_native_status()
    cleanup = native.get("state") not in ("disconnected", "not_installed")
    error = unsupported or "FortiClient did not disconnect within 30 seconds."
    forti_attempt_finish(record, "failed",
                         reason="unsupported-prompt" if unsupported else "timeout",
                         error=error, cleanup_required=cleanup)


def _spawn_forti_helper(action, name, password):
    process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), action, name],
                               stdin=subprocess.PIPE, start_new_session=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        process.stdin.write(password + b"\n")
        process.stdin.close()
    except Exception:
        pass


def _forti_prepare_connect():
    merged = forti_status()
    if merged.get("connected"):
        raise ValueError("A FortiClient VPN is already connected. Disconnect it first.")
    if not merged.get("cleanupRequired"):
        return
    # A failed attempt can leave a daemon session behind. Clear it here instead
    # of making the user press Clean up and retry by hand.
    _forti_disconnect_run(25)
    record = _forti_attempt_read()
    if record.get("phase") == "failed":
        forti_attempt_clear(record)
    end = time.monotonic() + 6.0
    while time.monotonic() < end:
        merged = forti_status()
        if merged.get("connected"):
            raise ValueError("A FortiClient VPN is already connected. Disconnect it first.")
        if not merged.get("cleanupRequired"):
            return
        time.sleep(0.4)
    raise ValueError("FortiClient kept a stale connection state after cleanup. Refresh and retry.")


def forti_connect_with_password(name, password):
    require("forticlient")
    if name not in forti_list():
        raise ValueError(f"FortiClient profile '{name}' is not registered.")
    if not _forti_valid_secret(password):
        raise ValueError("Forti password is empty or contains invalid characters.")
    _forti_require_idle()
    _forti_prepare_connect()
    _spawn_forti_helper("bg-connect-forti-pass", name, password)
    return {"message": f"Connecting to FortiClient '{name}'…"}


def forti_connect(name):
    require("forticlient")
    if name not in forti_list():
        raise ValueError(f"FortiClient profile '{name}' is not registered.")
    _forti_require_idle()
    _forti_prepare_connect()
    password, reason = forti_credential_lookup(name)
    if not password:
        return {"passwordRequired": name, "reason": reason}
    _spawn_forti_helper("bg-connect-forti", name, password)
    return {"message": f"Connecting to FortiClient '{name}'…"}


def forti_disconnect():
    require("forticlient")
    current = _forti_attempt_read()
    if current.get("phase") == "connecting" and _forti_helper_live(current):
        raise ValueError("A FortiClient connection is in progress. Wait for it to finish before disconnecting.")
    if current.get("phase") == "disconnecting" and _forti_helper_live(current):
        return {"message": "Disconnecting FortiClient…"}
    subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "bg-disconnect-forti"],
                     start_new_session=True, stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"message": "Disconnecting FortiClient…"}


def forti_delete(name):
    client = require("forticlient")
    merged = forti_status()
    if merged.get("connected"):
        raise ValueError("Disconnect FortiClient before removing the profile.")
    if merged.get("cleanupRequired"):
        raise ValueError("FortiClient has a stale connection state. Clean up before removing the profile.")
    current = _forti_attempt_read()
    if current.get("phase") in ("connecting", "disconnecting") and _forti_helper_live(current):
        raise ValueError("A FortiClient operation is in progress. Wait for it to finish before removing the profile.")
    forti_credential_clear(name)
    res = subprocess.run([client, "vpn", "remove", name], capture_output=True, text=True, timeout=10)
    if res.returncode != 0:
        raise ValueError(f"Failed to remove FortiClient profile '{name}'.")
    forti_pin_clear(name)
    record = _forti_attempt_read()
    if record.get("profile") == name:
        forti_attempt_clear(record)
    return {**forti_profile_payload(), "message": f"FortiClient profile '{name}' removed."}


def forti_create(name, host, port, username):
    client = require("forticlient")
    if name in forti_list():
        identity = forti_identity(name)
        if identity is None:
            raise ValueError("Could not resolve the existing Forti profile identity; the profile was not replaced, so a saved password cannot be orphaned.")
        if not secret_tool_clear(identity):
            raise ValueError("Could not remove the existing saved Forti password; the profile was not replaced.")
        subprocess.run([client, "vpn", "remove", name], capture_output=True, text=True, timeout=5)
        forti_pin_clear(name)
    p = subprocess.Popen([client, "vpn", "edit", name],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    inputs = f"{host}\n{port}\n1\n{username}\n3\n"
    stdout, stderr = p.communicate(inputs, timeout=10)
    if p.returncode != 0:
        raise ValueError(f"Failed to create FortiClient profile '{name}'.")
    return {**forti_profile_payload(), "message": f"FortiClient profile '{name}' created."}


def form_forti():
    picker = subprocess.run([
        require("zenity"), "--forms", "--title=Add FortiClient VPN Profile",
        "--text=Enter FortiClient VPN Connection Details",
        "--add-entry=Profile Name",
        "--add-entry=Remote Gateway (Host/IP)",
        "--add-entry=Port (Default: 443)",
        "--add-entry=Username"
    ], capture_output=True, text=True, timeout=60)
    if picker.returncode == 1:
        return {"cancelled": True}
    if picker.returncode:
        raise ValueError("Dialog failed. Check zenity.")
    parts = picker.stdout.strip().split("|")
    if len(parts) < 4:
        raise ValueError("Incomplete profile details entered.")
    name, host, port, username = [p.strip() for p in parts[:4]]
    if not name or not host:
        raise ValueError("Profile name and Remote Gateway are required.")
    port = port or "443"
    return forti_create(name, host, port, username)


def import_path(path):
    if not path.startswith("/") or any(c in path for c in "\x00\r\n"):
        raise ValueError("Select an absolute file path without newlines.")
    suffix = Path(path).suffix.lower()
    if suffix == ".xml":
        forti_conns = parse_forti_xml(path)
        if forti_conns:
            for c in forti_conns:
                forti_create(c["name"], c["host"], c["port"], c["username"])
            return {**forti_profile_payload(), "message": "FortiClient profile(s) imported from XML."}
        # Path metadata only: no open, parse, copy, or validation of XML contents.
        return {"azure": register(path), "message": "Profile imported."}
    if suffix in (".conf", ".sconf"):
        forti_info = parse_forti_conf(path)
        if forti_info:
            forti_create(forti_info["name"], forti_info["host"], forti_info["port"], forti_info["username"])
            return {**forti_profile_payload(), "message": f"FortiClient profile '{forti_info['name']}' imported."}
    kind = {".ovpn": "openvpn", ".conf": "wireguard"}.get(suffix)
    if not kind:
        raise ValueError("Supported files: OpenVPN .ovpn, WireGuard .conf, Azure .xml, FortiClient .conf/.xml.")
    env = dict(os.environ, LC_ALL="C")
    result = subprocess.run([require("nmcli"), "connection", "import", "type", kind, "file", path],
                            capture_output=True, text=True, timeout=30, env=env)
    if result.returncode:
        # Backend diagnostics can contain profile content; do not echo them into the panel.
        raise ValueError(f"NetworkManager {kind} import failed (exit {result.returncode}). Check the file, backend and NetworkManager permissions. WireGuard filenames must be valid interface names.")
    if kind == "openvpn":
        # Bind only the UUID returned by this import, never a global list diff.
        match = re.fullmatch(r"Connection '[^\r\n]*' \(([0-9a-f-]{36})\) successfully added\.\n?", result.stdout)
        profile = match[1] if match else ""
        if not ovpn_source.valid_uuid(profile):
            return {"message": "Profile imported, but its source could not be identified safely. Askpass-file support was not registered."}
        verified = subprocess.run([require("nmcli"), "-g", "connection.uuid,connection.type,vpn.service-type",
                                   "connection", "show", "uuid", profile],
                                  capture_output=True, text=True, timeout=15, env=env)
        if verified.returncode or verified.stdout.splitlines() != [profile, "vpn", "org.freedesktop.NetworkManager.openvpn"]:
            raise ValueError("Profile imported, but its identity could not be verified. Source was not registered.")
        subprocess.run([require("nmcli"), "connection", "modify", profile,
                        "ipv4.never-default", "yes", "ipv6.never-default", "yes"],
                       capture_output=True, text=True, timeout=10)
        sources = ovpn_source.load()
        sources[profile] = path
        ovpn_source.save(sources)
        prepare_nm_certificate(profile)
    elif kind == "wireguard":
        match = re.fullmatch(r"Connection '[^\r\n]*' \(([0-9a-f-]{36})\) successfully added\.\n?", result.stdout)
        profile = match[1] if match else ""
        if profile and ovpn_source.valid_uuid(profile):
            subprocess.run([require("nmcli"), "connection", "modify", profile,
                            "ipv4.never-default", "yes", "ipv6.never-default", "yes"],
                           capture_output=True, text=True, timeout=10)
    return {"message": "Profile imported."}


def preflight(client, experimental=False):
    # Installed OpenP2S 0.2.1 lookup order; never inspect a profile or run connect.
    directory = Path(client).resolve().parent
    candidates = [os.environ.get("OPENP2S_OPENVPN_BINARY"), directory / "openvpn-openp2s",
                  directory / "../lib/openp2s/openvpn", directory / "../libexec/openp2s/openvpn",
                  "/usr/lib/openp2s/openvpn", "/usr/libexec/openp2s/openvpn",
                  "/usr/local/lib/openp2s/openvpn", "/opt/openp2s/sbin/openvpn"]
    binary = next((Path(candidate) for candidate in candidates if candidate and Path(candidate).exists()), None)
    if binary is None:
        raise ValueError("Missing OpenP2S OpenVPN binary. Restore the complete verified bundle.")
    metadata = binary.parent / "BUILDINFO"
    if not metadata.is_file():
        raise ValueError(f"Missing BUILDINFO beside {binary}. Restore it only from a verified matching bundle; see README.")
    values = dict(line.split("=", 1) for line in metadata.read_text().splitlines() if "=" in line and not line.startswith("#"))
    values = {key.strip(): value.strip() for key, value in values.items()}
    if values.get("binary_sha256") != hashlib.sha256(binary.read_bytes()).hexdigest():
        raise ValueError(f"BUILDINFO hash missing or mismatched for {binary}. Restore the complete verified bundle; see README.")
    if experimental and values.get("azure_compat_available") != "1":
        raise ValueError("BUILDINFO does not advertise experimental Azure support required by this launcher.")


def launch(path):
    if path not in load():
        raise ValueError("Azure path is not registered. Import it first.")
    client = require("openp2s")
    _, experimental = connection_settings()
    preflight(client, experimental)
    gui_environment()  # Fail before scheduling if native GUI prerequisites are missing.
    operation = operation_status()
    if not operation.get("known", False) or operation["running"] or operation["stopping"] or status()["state"] != "disconnected":
        raise ValueError("VPN is active, starting, or status unavailable. Disconnect/clean up before connecting again.")
    control("reset-failed", check=False)
    args = [require("systemd-run"), "--user", "--quiet", "--unit=" + UNIT,
            "--service-type=exec", "--expand-environment=no",
            "--property=KillMode=mixed", "--property=TimeoutStopSec=120",
            "--property=StandardOutput=null", "--property=StandardError=null"]
    # Pass desktop identity, not the user's entire environment or OAuth data.
    for key in ("HOME", "PATH", "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR",
                "DBUS_SESSION_BUS_ADDRESS", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
                "OPENP2S_OPENVPN_BINARY"):
        if key in os.environ:
            args.append("--setenv=" + key + "=" + os.environ[key])
    args += ["/usr/bin/python3", str(Path(__file__).resolve()), "run", path]
    result = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise ValueError("Could not start VPN user process. Check the systemd user manager; another launch may already own the unit.")
    return {"message": "Connecting…"}


UNIT = "airzy-vpn-azure.service"


def gui_environment():
    require("/usr/bin/sudo")
    require("xdg-open")
    if not (os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY")):
        raise ValueError("Azure needs a desktop display for browser sign-in and graphical sudo.")
    directory = Path(__file__).resolve().parent
    if any(not os.access(directory / helper, os.X_OK) for helper in ("askpass", "gui-bin/sudo")):
        raise ValueError("Azure graphical sudo helpers are missing or not executable. Restore the plugin helpers.")
    env = dict(os.environ)
    env["PATH"] = str(directory / "gui-bin") + os.pathsep + env.get("PATH", "/usr/bin")
    env["SUDO_ASKPASS"] = str(directory / "askpass")
    return env


def control(action, check=True):
    result = subprocess.run([require("systemctl"), "--user", action, UNIT],
                            capture_output=True, text=True, timeout=130 if action == "stop" else 5)
    if check and result.returncode:
        raise ValueError("VPN process control failed. Refresh status and retry cleanup; privilege requests may have been cancelled.")
    return result


def supervisor_path(pid):
    try:
        proc = Path("/proc") / str(int(pid))
        if int(pid) <= 0 or proc.stat().st_uid != os.getuid():
            return ""
        args = proc.joinpath("cmdline").read_bytes().decode().split("\x00")
        if (len(args) == 5 and args[0] == "/usr/bin/python3"
                and args[1] == str(Path(__file__).resolve()) and args[2] == "run"
                and args[3] in load()):
            return args[3]
    except (OSError, ValueError, UnicodeError):
        pass
    return ""


def operation_status():
    empty = {"known": False, "running": False, "stopping": False, "path": "",
             "error": "VPN process status unavailable. Check the systemd user manager and refresh."}
    try:
        result = subprocess.run([require("systemctl"), "--user", "show", UNIT,
                                 "--property=LoadState,ActiveState,SubState,Result,ExecMainStatus,MainPID"],
                                capture_output=True, text=True, timeout=5)
        if result.returncode:
            return empty
        values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        if (values.get("LoadState") not in ("loaded", "not-found")
                or values.get("ActiveState") not in ("active", "activating", "deactivating", "inactive", "failed")
                or not values.get("SubState") or "Result" not in values
                or not values.get("ExecMainStatus", "").isdecimal()
                or not values.get("MainPID", "").isdecimal()
                or (values["LoadState"] == "not-found" and
                    (values["ActiveState"] != "inactive" or values["SubState"] != "dead" or values["MainPID"] != "0"))
                or (values["ActiveState"] == "inactive" and values["MainPID"] != "0")):
            return empty
        failed = values.get("ActiveState") == "failed"
        code = values.get("ExecMainStatus", "")
        error = ""
        if failed:
            error = {"4": "VPN tunnel ended unexpectedly. Refresh before reconnecting.",
                     "5": "VPN cleanup incomplete. Retry Disconnect / clean up.",
                     "6": "VPN GUI backend could not start. Check installed GUI prerequisites."}.get(
                         code, "Connection failed or privilege/sign-in was cancelled. Check profile, browser sign-in, sudo permissions and gateway.")
        return {"known": True, "running": values.get("ActiveState") in ("active", "activating"),
                "stopping": values.get("ActiveState") == "deactivating", "error": error,
                "path": supervisor_path(values.get("MainPID", "0")) if values.get("ActiveState") in ("active", "activating", "deactivating") else ""}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return empty


def supervise(command):
    # The user unit owns this foreground supervisor until the native client exits.
    # KillMode=mixed lets SIGTERM reach native cleanup before a bounded group kill.
    child = None
    stopping = False
    def stop(signum, frame):
        nonlocal stopping
        stopping = True
        if child is not None and child.poll() is None:
            try:
                child.send_signal(signal.SIGTERM)
            except ProcessLookupError:
                pass
    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    try:
        with Lease() as capability:
            env = gui_environment()
            env["AIRZY_VPN_PERMISSION"] = capability  # Random authorization, never a password.
            child = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if stopping:
                stop(signal.SIGTERM, None)
            code = child.wait()
            return code if code >= 0 else 1
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def run_connection(path):
    if path not in load():
        raise ValueError("Azure path is not registered.")
    client = require("openp2s")
    ca, experimental = connection_settings()
    preflight(client, experimental)
    command = [client, "connect", path, "--ca", ca]
    if experimental:
        command.append("--experimental-azure-compat")
    return supervise(command)


def status():
    # Native status checks PID start time and interface liveness; never read XML/cache.
    unknown = {"state": "unknown", "connected": False, "path": "", "interface": "", "address": ""}
    try:
        result = subprocess.run([require("openp2s"), "status", "--json"], capture_output=True, text=True, timeout=5)
        data = json.loads(result.stdout)
        state = data.get("state")
        if state not in ("connected", "disconnected", "disconnecting", "reconnecting", "stale") or data.get("connected") is not (state == "connected") or result.returncode != (0 if state == "connected" else 1):
            return unknown
        path = ""
        # Native `profile` is the XML's display name, NOT its file path.
        # Match only the running owner's connect argv against registered paths.
        if state in ("connected", "reconnecting", "disconnecting"):
            registered = load()
            matches = set()
            for proc in Path("/proc").iterdir():
                if not proc.name.isdecimal():
                    continue
                try:
                    if proc.stat().st_uid != os.getuid():
                        continue
                    args = proc.joinpath("cmdline").read_bytes().decode().split("\x00")
                    # Packaged clients can rename comm to MainThread. Verify argv
                    # and the executable, never the mutable thread name.
                    if (len(args) > 2 and args[1] == "connect"
                            and Path(args[0]).resolve() == Path(require("openp2s")).resolve()
                            and proc.joinpath("exe").resolve() == Path(require("openp2s")).resolve()):
                        matches.add(args[2])
                except (OSError, UnicodeError):
                    continue
            if len(matches) == 1:
                candidate = matches.pop()
                if candidate in registered:
                    path = candidate
        import ipaddress
        import re
        interface = data.get("interface")
        interface = interface if isinstance(interface, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface) else ""
        address = ""
        if isinstance(data.get("address"), str):
            try:
                address = str(ipaddress.ip_interface(data["address"]).ip)
            except ValueError:
                pass
        return {"state": state, "connected": state == "connected", "path": path,
                "interface": interface if state == "connected" else "", "address": address if state == "connected" else ""}
    except (OSError, ValueError, TypeError, AttributeError, subprocess.TimeoutExpired):
        return unknown


def disconnect():
    operation = operation_status()
    if not operation.get("known", False):
        raise ValueError("VPN process status unavailable; no disconnect launched. Refresh and retry cleanup.")
    if operation["running"] or operation["stopping"]:
        control("stop")  # Cancels pending browser auth too; native SIGTERM owns cleanup.
        operation = operation_status()
        if (status()["state"] != "disconnected" or not operation.get("known", False)
                or operation["running"] or operation["stopping"] or operation["error"]):
            raise ValueError("Disconnection/cleanup is not confirmed. Refresh and retry Disconnect / clean up.")
        return {"message": "Disconnected."}
    if status()["state"] not in ("connected", "reconnecting", "disconnecting", "stale"):
        raise ValueError("VPN status unavailable or already disconnected; no disconnect launched.")
    code = supervise([require("openp2s"), "disconnect"])
    if code:
        raise ValueError("Disconnect failed or graphical sudo was cancelled. Refresh and retry cleanup.")
    operation = operation_status()
    if (status()["state"] != "disconnected" or not operation.get("known", False)
            or operation["running"] or operation["stopping"]):
        raise ValueError("Disconnection is not confirmed. Refresh and retry cleanup.")
    control("reset-failed", check=False)  # Clear a prior unit failure only after native cleanup is confirmed.
    restore_network_on_disconnect()
    return {"message": "Disconnected."}


def main():
    action = sys.argv[1]
    if action == "status":
        res = dict(status(), operation=operation_status(), forti=forti_status())
        check_and_heal_network(res)
        return res
    if action == "disconnect":
        return disconnect()
    if action == "bg-connect-forti":
        forti_connect_pty(sys.argv[2], read_forti_password_from_stdin(), store=False)
        return {"done": True}
    if action == "bg-connect-forti-pass":
        forti_connect_pty(sys.argv[2], read_forti_password_from_stdin(), store=True)
        return {"done": True}
    if action == "connect-forti":
        return forti_connect(sys.argv[2])
    if action == "restore-network":
        restore_network_on_disconnect()
        return {"done": True}
    if action == "bg-disconnect-forti":
        forti_disconnect_bg()
        return {"done": True}
    if action == "disconnect-forti":
        return forti_disconnect()
    if action == "delete-forti":
        return forti_delete(sys.argv[2])
    if action == "form-forti":
        return form_forti()
    if action == "clear-forti-auth":
        return forti_clear_auth()
    if action == "approve-forti-cert":
        return dict(forti_pin_set(sys.argv[2], sys.argv[3], sys.argv[4]), approved=True)
    if action == "forget-forti-cert":
        return {"profile": sys.argv[2], "forgotten": forti_pin_clear(sys.argv[2])}
    if action == "connect-forti-pass":
        return forti_connect_with_password(sys.argv[2], read_forti_password_from_stdin())
    if action == "list":
        return {**forti_profile_payload(), "azure": load()}
    if action == "credential-status":
        return forti_credential_status(sys.argv[2])
    if action == "details-nm":
        return nm_details(sys.argv[2])
    if action == "delete-nm":
        return delete_nm(sys.argv[2])
    if action == "remove":
        return remove(sys.argv[2])
    if action == "launch":
        return launch(sys.argv[2])
    if action != "import":
        raise ValueError("Unknown action")
    picker = subprocess.run([require("zenity"), "--file-selection", "--title=Import VPN profile", "--file-filter=VPN profiles | *.ovpn *.conf *.xml *.sconf", "--file-filter=FortiClient profiles | *.conf *.sconf *.xml", "--file-filter=All files | *"], capture_output=True, text=True)
    if picker.returncode == 1:
        return {"cancelled": True}
    if picker.returncode:
        raise ValueError("File picker failed. Check zenity and the desktop display.")
    path = picker.stdout.removesuffix("\n")
    return import_path(path) if path else {"cancelled": True}


if __name__ == "__main__":
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "run":
            try:
                sys.exit(run_connection(sys.argv[2]))
            except (OSError, ValueError, IndexError):
                sys.exit(6)
        print(json.dumps(main()))
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"error": str(error)}))
        sys.exit(1)

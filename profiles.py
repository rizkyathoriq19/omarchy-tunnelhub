"""Native import/launch bridge. Azure XML is never opened by this plugin."""
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
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
    if not operation.get("known", False) or operation["running"] or operation["stopping"] or status()["state"] != "disconnected":
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


def forti_list():
    if not forti_installed():
        return []
    try:
        res = subprocess.run(["forticlient", "vpn", "list"], capture_output=True, text=True, timeout=5)
        if res.returncode != 0:
            return []
        lines = res.stdout.splitlines()
        profiles = []
        in_vpns = False
        for line in lines:
            stripped = line.strip()
            if "Personal VPNs:" in line or "VPNs:" in line:
                in_vpns = True
                continue
            if in_vpns and stripped and not stripped.endswith(":"):
                profiles.append(stripped)
        return profiles
    except Exception:
        return []


FORTI_ERROR_FILE = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")) / "airzy.vpn-forti-error.txt"


def forti_status():
    if not forti_installed():
        return {"installed": False, "state": "not_installed", "connected": False, "profile": "", "interface": "", "address": "", "error": "", "passwordRequired": "", "saved": {}}
    try:
        res = subprocess.run(["forticlient", "vpn", "status"], capture_output=True, text=True, timeout=5)
        lines = [l.strip() for l in res.stdout.splitlines()]
        state = "disconnected"
        connected = False
        profile = ""
        address = ""
        for line in lines:
            if line.startswith("Status:"):
                st = line.split(":", 1)[1].strip().lower()
                if "connected" in st:
                    state = "connected"
                    connected = True
                elif "connecting" in st or "re-connecting" in st or "xauth" in st:
                    state = "connecting"
                elif "not running" in st or "disconnected" in st:
                    state = "disconnected"
                else:
                    state = "unknown"
            elif line.startswith("VPN name:"):
                profile = line.split(":", 1)[1].strip()
            elif line.startswith("IP:"):
                address = line.split(":", 1)[1].strip()
        interface = ""
        if connected:
            try:
                ip_res = subprocess.run([require("ip"), "-j", "link", "show"], capture_output=True, text=True, timeout=3)
                if ip_res.returncode == 0:
                    links = json.loads(ip_res.stdout)
                    for link in links:
                        if link.get("ifname", "").startswith("fctvpn"):
                            interface = link["ifname"]
                            break
            except Exception:
                pass
        error = ""
        password_req = ""
        if state == "connected":
            try:
                FORTI_ERROR_FILE.unlink(missing_ok=True)
            except Exception:
                pass
        elif FORTI_ERROR_FILE.exists():
            try:
                raw_err = FORTI_ERROR_FILE.read_text().strip()
                if raw_err.startswith("PASSWORD_REQUIRED:"):
                    password_req = raw_err.split(":", 1)[1].strip()
                else:
                    error = raw_err
            except Exception:
                pass
        saved = {p: forti_has_password(p) for p in forti_list()}
        return {
            "installed": True,
            "state": state,
            "connected": connected,
            "profile": profile,
            "interface": interface,
            "address": address,
            "error": error,
            "passwordRequired": password_req,
            "saved": saved
        }
    except Exception:
        return {"installed": True, "state": "unknown", "connected": False, "profile": "", "interface": "", "address": "", "error": "", "passwordRequired": "", "saved": {}}


def forti_connect_pty(name, password):
    import pty
    import select
    import time
    master, slave = pty.openpty()
    pid = os.fork()
    if pid == 0:
        os.close(master)
        os.dup2(slave, 0)
        os.dup2(slave, 1)
        os.dup2(slave, 2)
        os.close(slave)
        os.execv("/usr/bin/forticlient", ["forticlient", "vpn", "connect", name, "-p", "-s"])
    else:
        os.close(slave)
        buf = b""
        state = 0
        start = time.time()
        connected = False
        try:
            while time.time() - start < 25:
                r, _, _ = select.select([master], [], [], 0.5)
                if not r:
                    continue
                try:
                    chunk = os.read(master, 1024)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                if state == 0 and b"Password:" in buf:
                    os.write(master, (password + "\n").encode())
                    state = 1
                elif state == 1 and b"Confirm (y/n)" in buf:
                    os.write(master, b"y\n")
                    state = 2
                elif state >= 1 and (b"Status: Connected" in buf or b"Notification:" in buf or b"Status: Disconnected" in buf):
                    if b"Status: Connected" in buf:
                        connected = True
                    time.sleep(0.5)
                    try:
                        buf += os.read(master, 1024)
                    except Exception:
                        pass
                    break
        finally:
            try:
                os.close(master)
            except Exception:
                pass
            if not connected:
                try:
                    os.kill(pid, 9)
                except Exception:
                    pass
            try:
                os.waitpid(pid, 0)
            except Exception:
                pass
        return buf.decode(errors="replace")

def forti_has_password(name):
    try:
        res = subprocess.run(["forticlient", "vpn", "view", name], capture_output=True, text=True, timeout=5)
        for line in res.stdout.splitlines():
            if line.strip().startswith("Save Password:"):
                return line.split(":", 1)[1].strip().lower() == "enabled"
    except Exception:
        pass
    return False


def forti_connect_pass_bg(name, password):
    try:
        pty_out = forti_connect_pty(name, password)
        if "Status: Connected" in pty_out:
            try:
                FORTI_ERROR_FILE.unlink(missing_ok=True)
            except Exception:
                pass
        elif "Insufficient credential" in pty_out or "Login failed" in pty_out:
            FORTI_ERROR_FILE.write_text("Incorrect password or authentication rejected by VPN server.")
        elif "Login canceled" in pty_out:
            FORTI_ERROR_FILE.write_text("Connection cancelled by FortiClient.")
        else:
            for line in pty_out.splitlines():
                if "Notification:" in line:
                    FORTI_ERROR_FILE.write_text(line.strip())
                    break
    except Exception as err:
        try:
            FORTI_ERROR_FILE.write_text(str(err))
        except Exception:
            pass


def forti_connect_with_password(name, password):
    client = require("forticlient")
    if name not in forti_list():
        raise ValueError(f"FortiClient profile '{name}' is not registered.")
    try:
        FORTI_ERROR_FILE.unlink(missing_ok=True)
    except Exception:
        pass
    env = dict(os.environ, AIRZY_FORTI_PASS=password)
    p = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "bg-connect-forti-pass", name],
                         stdin=subprocess.PIPE, start_new_session=True, env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        p.stdin.write(password.encode() + b"\n")
        p.stdin.close()
    except Exception:
        pass
    return {"message": f"Connecting to FortiClient '{name}'…"}


def forti_connect_bg(name):
    client = require("forticlient")
    try:
        p = subprocess.Popen([client, "vpn", "connect", name],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        stdout, _ = p.communicate(input="y\n", timeout=10)
        if "Insufficient credential" in stdout:
            FORTI_ERROR_FILE.write_text(f"PASSWORD_REQUIRED:{name}")
        elif "Login canceled" in stdout:
            FORTI_ERROR_FILE.write_text("Connection cancelled by FortiClient.")
        elif "Status: Connected" not in stdout:
            for line in stdout.splitlines():
                if "Notification:" in line:
                    FORTI_ERROR_FILE.write_text(line.strip())
                    break
    except Exception as err:
        try:
            FORTI_ERROR_FILE.write_text(str(err))
        except Exception:
            pass
def forti_connect(name):
    client = require("forticlient")
    if name not in forti_list():
        raise ValueError(f"FortiClient profile '{name}' is not registered.")
    try:
        FORTI_ERROR_FILE.unlink(missing_ok=True)
    except Exception:
        pass
    subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "bg-connect-forti", name],
                     start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    return {"message": f"Connecting to FortiClient '{name}'…"}

def forti_disconnect():
    client = require("forticlient")
    try:
        FORTI_ERROR_FILE.unlink(missing_ok=True)
    except Exception:
        pass
    res = subprocess.run([client, "vpn", "disconnect"], capture_output=True, text=True, timeout=10)
    if res.returncode != 0:
        raise ValueError("Failed to disconnect FortiClient.")
    return {"message": "FortiClient disconnected."}

def forti_delete(name):
    client = require("forticlient")
    res = subprocess.run([client, "vpn", "remove", name], capture_output=True, text=True, timeout=10)
    if res.returncode != 0:
        raise ValueError(f"Failed to remove FortiClient profile '{name}'.")
    return {"message": f"FortiClient profile '{name}' removed.", "forti": forti_list()}


def forti_create(name, host, port, username):
    client = require("forticlient")
    if name in forti_list():
        subprocess.run([client, "vpn", "remove", name], capture_output=True, text=True, timeout=5)
    p = subprocess.Popen([client, "vpn", "edit", name],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    inputs = f"{host}\n{port}\n2\n{username}\n3\n"
    stdout, stderr = p.communicate(inputs, timeout=10)
    if p.returncode != 0:
        raise ValueError(f"Failed to create FortiClient profile '{name}'.")
    return {"message": f"FortiClient profile '{name}' created.", "forti": forti_list()}


def form_forti():
    picker = subprocess.run([
        require("zenity"), "--forms", "--title=Add FortiClient VPN Profile",
        "--text=Enter FortiClient VPN Connection Details",
        "--add-entry=Profile Name",
        "--add-entry=Remote Gateway (Host/IP)",
        "--add-entry=Port (Default: 443)",
        "--add-entry=Username"
    ], capture_output=True, text=True)
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
            return {"forti": forti_list(), "message": "FortiClient profile(s) imported from XML."}
        # Path metadata only: no open, parse, copy, or validation of XML contents.
        return {"azure": register(path), "message": "Profile imported."}
    if suffix in (".conf", ".sconf"):
        forti_info = parse_forti_conf(path)
        if forti_info:
            forti_create(forti_info["name"], forti_info["host"], forti_info["port"], forti_info["username"])
            return {"forti": forti_list(), "message": f"FortiClient profile '{forti_info['name']}' imported.", "forti": forti_list()}
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
        sources = ovpn_source.load()
        sources[profile] = path
        ovpn_source.save(sources)
        prepare_nm_certificate(profile)
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
    return {"message": "Disconnected."}


def main():
    action = sys.argv[1]
    if action == "status":
        return dict(status(), operation=operation_status(), forti=forti_status())
    if action == "disconnect":
        return disconnect()
    if action == "bg-connect-forti":
        forti_connect_bg(sys.argv[2])
        return {"done": True}
    if action == "connect-forti":
        return forti_connect(sys.argv[2])
    if action == "disconnect-forti":
        return forti_disconnect()
    if action == "delete-forti":
        return forti_delete(sys.argv[2])
    if action == "form-forti":
        return form_forti()
    if action == "connect-forti-pass":
        name = sys.argv[2]
        password = os.environ.get("AIRZY_FORTI_PASS", "")
        if not password and not sys.stdin.isatty():
            password = sys.stdin.readline().rstrip("\r\n")
        return forti_connect_with_password(name, password)
    if action == "bg-connect-forti-pass":
        name = sys.argv[2]
        password = os.environ.get("AIRZY_FORTI_PASS", "")
        if not password and not sys.stdin.isatty():
            password = sys.stdin.readline().rstrip("\r\n")
        forti_connect_pass_bg(name, password)
        return {"done": True}
    if action == "list":
        profiles = forti_list()
        saved = {p: forti_has_password(p) for p in profiles}
        return {"azure": load(), "forti": profiles, "fortiSaved": saved}
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

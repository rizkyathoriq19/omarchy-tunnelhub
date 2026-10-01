"""python3 test_permission.py: synthetic credentials only, no sudo/VPN/network."""
import os
from pathlib import Path
import secrets
import select
import socket
import struct
import subprocess
import tempfile
import time
from unittest.mock import patch
import permission as p

base = Path(__file__).parent.resolve()
assert not p.supervisor(os.getpid())
for args, expected in [(b'/usr/bin/python3\0' + os.fsencode(base / 'profiles.py') + b'\0run\0/mock.xml\0', True),
                       (b'/usr/bin/python3\0' + os.fsencode(base / 'profiles.py') + b'\0disconnect\0', True),
                       (b'/usr/bin/python3\0/unknown.py\0run\0/mock.xml\0', False)]:
    with patch.object(Path, 'read_bytes', return_value=args):
        assert p.supervisor(1) == expected
with patch.object(socket.socket, 'getsockopt', return_value=struct.pack('3i', 1, os.getuid() + 1, 1)):
    try:
        p.peer(socket.socket(socket.AF_UNIX))
        raise AssertionError('Other uid accepted')
    except ValueError:
        pass

with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as directory:
    tmp = Path(directory)
    runtime = tmp / 'runtime'
    runtime.mkdir(mode=0o700)
    env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime))
    # Only this test's pid may register; production has no test-mode switch.
    runner = tmp / 'broker.py'
    runner.write_text('import sys\nsys.path.insert(0, ' + repr(str(base)) + ')\nimport permission as p\np.supervisor = lambda pid: pid == ' + str(os.getpid()) + '\np.serve(timeout=1.2)\n')
    broker = subprocess.Popen(['/usr/bin/python3', str(runner)], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    endpoint = runtime / 'airzy.vpn-permission.sock'
    def event(kind):
        assert select.select([broker.stdout], [], [], 3)[0], 'Missing broker event: ' + kind
        line = broker.stdout.readline().decode().strip()
        assert line.startswith(kind + ' '), line
        return line.split()[1]
    def client(message):
        sock = socket.socket(socket.AF_UNIX)
        sock.settimeout(3)
        sock.connect(str(endpoint))
        sock.sendall(message)
        return sock
    children = []
    def ask(token):
        child = subprocess.Popen([str(base / 'askpass'), 'ignored native prompt'], env=dict(env, AIRZY_VPN_PERMISSION=token), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        children.append(child)
        return child
    def result(child, expected=None):
        out, err = child.communicate(timeout=4)
        assert not err
        assert (child.returncode == 0 and out == expected + b'\n') if expected else (child.returncode != 0 and not out)
    try:
        for _ in range(100):
            if endpoint.exists(): break
            assert broker.poll() is None
            time.sleep(.01)
        assert endpoint.stat().st_mode & 0o777 == 0o700  # AF_UNIX created under umask 077.
        unknown = client(b'ASK ' + b'0' * 64 + b'\n')
        assert unknown.recv(10) == b''
        unknown.close()
        token = secrets.token_hex(32)
        lease = client(('LEASE ' + token + '\n').encode())
        assert lease.recv(16) == b'OK\n'
        unknown = client(('ASK ' + token + '\n').encode())
        assert unknown.recv(10) == b''  # Even a known token cannot authorize arbitrary IPC.
        unknown.close()
        first = ask(token)
        ident = event('REQUEST')
        secret = secrets.token_urlsafe(24).encode()  # Never serialized in fixtures/argv/env.
        for process in (first, broker):
            for name in ('cmdline', 'environ'):
                assert secret not in Path('/proc', str(process.pid), name).read_bytes()
        # A stale/unknown response cannot release the active request.
        broker.stdin.write(b'0' * 32 + b'\tignored\n')
        broker.stdin.flush()
        assert first.poll() is None
        broker.stdin.write(ident.encode() + b'\t' + secret + b'\n')
        broker.stdin.flush()
        assert event('DONE') == ident
        result(first, secret)
        second = ask(token)
        ident2 = event('REQUEST')
        third = ask(token)
        time.sleep(.05)
        assert not select.select([broker.stdout], [], [], .05)[0], 'Concurrent prompt not serialized'
        broker.stdin.write(ident2.encode() + b'\n'); broker.stdin.flush()
        assert event('DONE') == ident2
        result(second)
        ident3 = event('REQUEST')
        assert ident3 != ident2
        assert event('DONE') == ident3  # Native askpass timeout cancels with no response.
        result(third)
        fourth = ask(token)
        ident4 = event('REQUEST')
        lease.close()
        assert event('DONE') == ident4
        result(fourth)
        result(ask(token))  # Expired capabilities cannot be reused.
        # Competing broker fails without unlinking the live owner's socket.
        duplicate = subprocess.run(['/usr/bin/python3', str(base / 'permission.py'), 'serve'], env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=3)
        assert duplicate.returncode != 0 and endpoint.exists() and not duplicate.stderr
        token2 = secrets.token_hex(32)
        lease2 = client(('LEASE ' + token2 + '\n').encode())
        assert lease2.recv(16) == b'OK\n'
        fifth = ask(token2)
        event('REQUEST')
        broker.stdin.close()  # Shell close/reload/pipe EOF cannot orphan a credential prompt.
        broker.wait(timeout=3)
        result(fifth)
        lease2.close()
        assert not endpoint.exists()
        output = broker.stdout.read() + broker.stderr.read()
        assert secret not in output
        for path in tmp.rglob('*'):
            if path.is_file(): assert secret not in path.read_bytes()
    finally:
        for child in children:
            if child.poll() is None: child.kill(); child.wait()
        if broker.poll() is None: broker.kill(); broker.wait()
print('PASS permission transport: owner uid, authorized live lease, stdin-only fake secret, no argv/env/file/log leaks, stale IDs, FIFO/duplicate, cancel, timeout, lease death, EOF/reload, socket cleanup')

# Exercise real installed masked field and actual Panel handlers offscreen.
# No Service instance and no backend commands. The dummy response exists only in QML memory.
panel = (base / 'Panel.qml').read_text()
prompt = panel[panel.index('          // Inline sudo permission prompt;'):panel.index('          //\n          // HERO')]
opened = panel[panel.index('  onOpenedChanged:'):panel.index('  Component.onDestruction:')]
handler = panel[panel.index('    onPermissionRequestChanged:'):panel.index('  readonly property int profileCount:')]
handler = handler[:handler.rfind('  }')]
with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as directory:
    tmp = Path(directory)
    for name in ['Ui', 'Commons']:
        (tmp / name).symlink_to(Path('/usr/share/omarchy/shell') / name, target_is_directory=True)
    (tmp / 'shell.qml').write_text('''import QtQuick
import QtTest
import QtQuick.Controls
import Quickshell
import qs.Commons
import qs.Ui
import qs.Ui as NativeUi
ShellRoot {
  Window {
    visible: true; width: 380; height: 400
    Item {
      id: root; anchors.fill: parent
      property bool opened: false
      property bool cursorActive: false
      property int profileIndex: 0
      property color foreground: "white"
      property color dim: "gray"
      property color accent: "red"
      property string fontFamily: "monospace"
      function open() { opened = true }
      function close() { opened = false }
      function check(value, message) { if (!value) throw Error(message) }
''' + opened + '''
      QtObject {
        id: vpn
        property string permissionRequest: ""
        property string response: ""
        property int submissions: 0
        property int cancellations: 0
        function refresh() {}
        function respondPermission(value) { response = value; submissions++; permissionRequest = "" }
        function cancelPermission() { if (permissionRequest) cancellations++; permissionRequest = "" }
''' + handler + '''
      }
      PanelKeyCatcher {
        id: keyCatcher; anchors.fill: parent
        blocked: vpn.permissionRequest !== ""
        property int textCalls: 0
        property int activateCalls: 0
        onTextKey: textCalls++
        onActivateRequested: activateCalls++
        Column {
          width: parent.width
''' + prompt + '''
        }
      }
      Item { id: panelFlick; property real contentY: 100 }
      TestCase { id: keys; name: "PermissionRouting"; when: false; function test_hold() {} }
      Timer {
        interval: 200; running: true
        onTriggered: {
          vpn.permissionRequest = "a"
          Qt.callLater(function() {
            root.check(root.opened && permissionField.activeFocus && panelFlick.contentY === 0, "Prompt did not open/focus/reset scroll")
            root.check(permissionField.echoMode === TextInput.Password && keyCatcher.blocked, "Unmasked field or unblocked shortcuts")
            // Key events go to the focused field; common j/k/r/i/d shortcuts must not run.
            keys.keyClick(Qt.Key_J)
            root.check(permissionField.text === "j" && keyCatcher.textCalls === 0 && keyCatcher.activateCalls === 0, "Typing intercepted")
            var fake = "fake-" + Math.random().toString(36)
            permissionField.text = fake
            keys.keyClick(Qt.Key_Return)
            root.check(vpn.response === fake && vpn.submissions === 1 && permissionField.text === "" && vpn.permissionRequest === "", "Enter submission/clear failed")
            vpn.response = ""
            vpn.permissionRequest = "b"; permissionField.text = fake
            keys.keyClick(Qt.Key_Escape)
            root.check(vpn.cancellations === 1 && permissionField.text === "" && vpn.permissionRequest === "", "Escape failed")
            vpn.permissionRequest = "c"; permissionField.text = fake
            root.close()
            root.check(vpn.cancellations === 2 && permissionField.text === "", "Close failed")
            vpn.permissionRequest = "d"; permissionField.text = fake
            vpn.permissionRequest = ""  // Broker timeout/DONE.
            root.check(permissionField.text === "", "Timeout did not clear")
            vpn.permissionRequest = "e"; permissionField.text = fake
            permissionSubmit.forceActiveFocus()
            keys.keyClick(Qt.Key_Return)
            root.check(vpn.submissions === 2 && permissionField.text === "", "Submit button keyboard failed")
            vpn.response = ""
            vpn.permissionRequest = "f"; permissionField.text = fake
            permissionCancel.forceActiveFocus()
            keys.keyClick(Qt.Key_Escape)
            root.check(vpn.cancellations === 3 && permissionField.text === "", "Cancel button Escape failed")
            root.check(keyCatcher.textCalls === 0 && keyCatcher.activateCalls === 0, "Submit routed to VPN profile")
            console.log("PASS offscreen permission masking, open/focus, typing isolation, Enter routing/clear, Esc cancel, close and timeout clear")
            Qt.quit()
          })
        }
      }
    }
  }
}
''')
    try:
        completed = subprocess.run(['quickshell', '--no-color', '-p', str(tmp / 'shell.qml')], capture_output=True, text=True, env=dict(os.environ, QT_QPA_PLATFORM='offscreen'), timeout=10)
    except subprocess.TimeoutExpired as error:
        print(error.stdout, error.stderr)
        raise
    output = completed.stdout + completed.stderr
    print(output)
    assert completed.returncode == 0 and 'PASS offscreen permission' in output and 'Error:' not in output

# Real Service Process.write -> broker -> executable askpass, with every backend mocked.
# The generated fixture contains no password: QML creates a fresh fake only in memory.
with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as directory:
    tmp = Path(directory)
    runtime = tmp / 'runtime'; runtime.mkdir(mode=0o700)
    env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), QT_QPA_PLATFORM='offscreen', QT_QPA_PLATFORMTHEME='generic', PATH=str(tmp) + ':' + os.environ['PATH'])
    (tmp / 'Service.qml').write_text((base / 'Service.qml').read_text())
    (tmp / 'profiles.py').write_text('''import json,os,subprocess,sys
from pathlib import Path
if sys.argv[1] == 'run':
    # Benign supervisor under the exact production argv shape, never native VPN.
    from permission import Lease
    with Lease() as token:
        env = dict(os.environ, AIRZY_VPN_PERMISSION=token)
        child = subprocess.run([str(Path(__file__).with_name('askpass')), 'ignored'], env=env, capture_output=True)
        os.write(1, child.stdout)
        raise SystemExit(child.returncode)
print(json.dumps({"azure":[]} if sys.argv[1]=='list' else {"state":"disconnected","connected":False,"path":"","interface":"","address":""}))
''')
    (tmp / 'permission.py').write_text((base / 'permission.py').read_text())
    (tmp / 'askpass').write_text((base / 'askpass').read_text())
    (tmp / 'askpass').chmod(0o700)
    for name in ['nmcli', 'curl']:
        f = tmp / name
        f.write_text('#!/usr/bin/python3\nimport sys\nassert "up" not in sys.argv and "down" not in sys.argv\n')
        f.chmod(0o700)
    (tmp / 'shell.qml').write_text('''import QtQuick
import Quickshell
ShellRoot {
  Service {
    id: service
    onPermissionRequestChanged: {
      if (!permissionRequest) return
      var fake = "fake-" + Math.random().toString(36)
      respondPermission(fake)
      fake = ""
      console.log("PASS real Service stdin response")
    }
  }
}
''')
    shell = subprocess.Popen(['quickshell', '--no-color', '-vv', '-p', str(tmp / 'shell.qml')], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    lease = None
    try:
        endpoint = runtime / 'airzy.vpn-permission.sock'
        for _ in range(200):
            if endpoint.exists(): break
            if shell.poll() is not None:
                stdout, stderr = shell.communicate()
                print(stdout.decode(), stderr.decode())
                raise AssertionError('QML shell failed to start')
            time.sleep(.01)
        child = subprocess.Popen(['/usr/bin/python3', str(tmp / 'profiles.py'), 'run', '/mock.xml'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        secret, error = child.communicate(timeout=5)
        assert child.returncode == 0 and secret.startswith(b'fake-') and secret.endswith(b'\n') and not error
        secret = secret.rstrip(b'\n')
        for process in (shell,):
            for name in ('cmdline', 'environ'):
                assert secret not in Path('/proc', str(process.pid), name).read_bytes()
        shell.terminate()
        stdout, stderr = shell.communicate(timeout=5)
        output = stdout + stderr
        assert b'PASS real Service stdin response' in output and secret not in output
        assert b'Error:' not in output and b'ReferenceError' not in output
        # Read only THIS synthetic test's log files, never the live shell's logs.
        import re
        match = re.search(rb'Saving logs to "([^"]+)"', output)
        if match:
            log = Path(os.fsdecode(match[1]))
            for f in log.parent.iterdir():
                if f.is_file(): assert secret not in f.read_bytes(), 'Credential leaked to Quickshell log'
        for f in tmp.rglob('*'):
            if f.is_file(): assert secret not in f.read_bytes()
        print('PASS real offscreen Service stdin -> owner socket -> executable askpass stdout; fake credential absent from argv/env/fixtures/verbose Quickshell logs')
    finally:
        if lease: lease.close()
        if shell.poll() is None: shell.kill(); shell.wait()

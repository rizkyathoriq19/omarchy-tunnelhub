"""python3 test_service.py — offscreen real Service, mocked commands, no network."""
import os
from pathlib import Path
import re
import subprocess
import tempfile

base = Path(__file__).parent
with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as tmp:
    tmp = Path(tmp)
    (tmp / 'Service.qml').write_text((base / 'Service.qml').read_text())
    (tmp / 'permission.py').write_text('import sys\nfor line in sys.stdin: pass\n')
    (tmp / 'profiles.py').write_text('import json,sys\nprint(json.dumps({"azure":[]} if sys.argv[1]=="list" else {"state":"connected","connected":True,"path":"/mock/profile.xml","interface":"tun0","address":"10.1.2.3"}))\n')
    for name in ['nmcli', 'curl']:
        f = tmp / name
        f.write_text('#!/usr/bin/python3\nimport sys\nassert "up" not in sys.argv and "down" not in sys.argv\n')
        f.chmod(0o700)
    (tmp / 'shell.qml').write_text('''import QtQuick
import Quickshell
ShellRoot {
  Service { id: s }
  Timer {
    interval: 1000; running: true
    onTriggered: {
      if (!s.azure.connected || s.interfaceName !== "tun0" || s.activeProfile !== "profile.xml") throw Error("Azure polling failed")
      if (s.azureRowStatus("/mock/profile.xml") !== "connected" || s.azureRowStatus("/other.xml") !== "disconnected") throw Error("Row association failed")
      s.pendingAction = "launch"; s.lastMessage = "Connecting…"; s.lastError = "Retain this error"
      s.clearResolvedMessage()
      if (s.lastMessage !== "" || s.lastError !== "Retain this error") throw Error("Stale message or lost error")
      s.azureOperation = {running:true,stopping:false,error:"",path:"/mock/profile.xml"}
      s.azure = {state:"disconnected",connected:false,path:"",interface:"",address:""}
      if (s.azureRowStatus("/mock/profile.xml") !== "connecting" || s.azureRowStatus("/other.xml") !== "disconnected") throw Error("Pending attribution failed")
      s.pendingAction = "disconnect"; s.lastMessage = "Disconnecting…"; s.azureOperation = {running:false,stopping:false,error:""}
      s.clearResolvedMessage()
      if (s.lastMessage !== "") throw Error("Disconnect message stale")
      s.azureOperation = {running:true,stopping:false,error:"",path:"/mock/profile.xml"}
      if (s.active || !s.azurePending || s.azureDisplayState !== "connecting") throw Error("Spawn counted connected")
      s.azureOperation = {running:false,stopping:true,error:""}
      if (s.azureDisplayState !== "disconnecting") throw Error("Stopping lost")
      s.azureOperation = {running:false,stopping:false,error:""}
      s.azure = {state:"connected",connected:true,path:"/mock/profile.xml",interface:"tun0",address:"10.1.2.3"}
      s.parseActive("mock-nm:uuid:vpn")
      s.nmTunnelIp = "10.9.9.9"; s.nmInterface = "nm0"
      if (!s.active || s.activeType !== "Azure OpenP2S" || s.tunnelIp !== "10.1.2.3" || s.statusTitle !== "VPN Connected" || s.statusDescription !== "2 connections active") throw Error("NM overwrote Azure")
      s.parseActive("")
      if (!s.active || s.interfaceName !== "tun0") throw Error("NM empty overwrote Azure")
      s.azure = {state:"unknown",connected:false,path:"",interface:"",address:""}
      if (s.active || s.azureRowStatus("/mock/profile.xml") !== "unknown") throw Error("Unknown counted active")
      s.azure = {state:"connected",connected:true,path:"",interface:"tun0",address:"10.1.2.3"}
      if (s.azureRowStatus("/mock/profile.xml") !== "unknown") throw Error("Unrelated session guessed")
      s.azure = {state:"unknown",connected:false,path:"",interface:"",address:""}
      s.parseActive("mock-nm:uuid:wireguard")
      if (!s.active || s.activeProfile !== "mock-nm" || s.activeType !== "WireGuard (NetworkManager)") throw Error("NM fallback failed")
      console.log("PASS offscreen Service polling, NM/Azure ordering, simultaneous state, unknown and NM fallback")
      Qt.quit()
    }
  }
}
''')
    env = dict(os.environ, QT_QPA_PLATFORM='offscreen', PATH=str(tmp) + ':' + os.environ['PATH'])
    result = subprocess.run(['quickshell', '--no-color', '-p', str(tmp / 'shell.qml')], capture_output=True, text=True, env=env, timeout=10)
    output = result.stdout + result.stderr
    print(output)
    assert result.returncode == 0 and 'PASS offscreen' in output
    assert 'Error:' not in output and 'ReferenceError' not in output
# qmlformat parses without shell imports; discard formatted output, do not edit.
for name in ['Service.qml', 'Panel.qml']:
    result = subprocess.run(['/usr/lib/qt6/bin/qmlformat', str(base / name)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
print('PASS QML syntax via qmlformat parser (no files rewritten)')

# Exercise the exact profile delegates with installed themed controls and a mock service.
# No Service instance: no commands, network, profile or credential reads.
panel = (base / 'Panel.qml').read_text()
rows = panel[panel.index('            Column {\n              id: profileColumn'):panel.index('          Button {\n            width: parent.width\n            text: vpn.importing ?')]
rows = rows[:rows.rfind('          }')]
rows = rows.replace('id: nmSwitch', 'id: nmSwitch; objectName: "nmSwitch"').replace('id: azureSwitch', 'id: azureSwitch; objectName: "azureSwitch"')
selected = panel[panel.index('  function selectedProfile()'):panel.index('  function moveCursor(')]
activate = panel[panel.index('  function activateCursor()'):panel.index('  IpcHandler {')]
service = (base / 'Service.qml').read_text()
azure_toggle = service[service.index('  function toggleAzure('):service.index('  function rowAction(')]
with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as directory:
    tmp = Path(directory)
    for name in ['Ui', 'Commons']:
        (tmp / name).symlink_to(Path('/usr/share/omarchy/shell') / name, target_is_directory=True)
    (tmp / 'shell.qml').write_text('''import QtQuick
import QtQuick.Controls
import Quickshell
import qs.Commons
import qs.Ui
ShellRoot {
  Window {
    visible: true; width: 380; height: 400
  Item {
    id: root
    width: 380; height: 400
    property int profileIndex: 0
    property bool cursorActive: false
    readonly property int profileCount: vpn.profiles.length + vpn.azureProfiles.length
    property color foreground: "white"
    property color accent: "red"
    property color dim: "gray"
    property string fontFamily: "monospace"
    QtObject {
      id: vpn
      property var profiles: [{name: "mock-nm"}]
      property var azureProfiles: ["/mock/profile.xml"]
      property string nmProfile: ""
      property bool importing: false
      property bool actionRunning: false
      property var azure: ({connected:false, path:"", state:"disconnected"})
      property var azureOperation: ({running:false, stopping:false, path:""})
      property int calls: 0
      property string last: ""
      function azureRowStatus(path) { return azure.connected ? "connected" : (azureOperation.running ? "connecting" : azure.state) }
      function toggleProfile(name) { if (!importing && !actionRunning) { calls++; last = "nm:" + name } }
      function profileAction(action, path) {
        if (importing || actionRunning) return
        if (action === "launch" && (azureOperation.running || azureOperation.stopping || azure.state !== "disconnected")) return
        calls++; last = "azure:" + (path === undefined ? "/mock/profile.xml" : path)
      }
''' + azure_toggle + '''
    }
''' + selected + activate + rows + '''
    function find(item, name) {
      if (item.objectName === name) return item
      for (var i = 0; i < item.children.length; i++) {
        var found = find(item.children[i], name)
        if (found) return found
      }
      return null
    }
    function check(ok, message) { if (!ok) throw Error(message) }
    Timer {
      interval: 200; running: true
      onTriggered: {
        var nm = root.find(root, "nmSwitch")
        var az = root.find(root, "azureSwitch")
        root.check(nm && az, "Missing native switches")
        root.check(Math.abs(nm.x + nm.width - (nm.parent.width)) < 1 && Math.abs(az.x + az.width - az.parent.width) < 1, "Switch right alignment")
        root.check(!nm.checked && !az.checked && vpn.calls === 0, "Initial mutation")
        vpn.nmProfile = "mock-nm"
        vpn.azure = {connected:true,path:"/mock/profile.xml",state:"connected"}
        root.check(nm.checked && az.checked && vpn.calls === 0, "Programmatic refresh mutated backend")
        nm.toggled()
        root.check(vpn.calls === 1 && vpn.last === "nm:mock-nm" && nm.checked, "NM route or optimistic state")
        az.toggled()
        root.check(vpn.calls === 2 && vpn.last === "azure:/mock/profile.xml" && az.checked, "Azure route or optimistic state")
        vpn.actionRunning = true
        nm.toggled(); az.toggled()
        root.check(vpn.calls === 2 && nm.busy && az.busy, "Pending operation guard")
        vpn.actionRunning = false
        vpn.azure = {connected:false,path:"",state:"disconnected"}
        vpn.azureOperation = {running:true,stopping:false,path:"/mock/profile.xml"}
        root.check(!az.checked && az.enabled, "Pending launch falsely checked or cannot cancel")
        az.toggled()
        root.check(vpn.calls === 3 && vpn.last === "azure:/mock/profile.xml", "Pending cancellation route")
        vpn.azureOperation = {running:false,stopping:false,path:""}
        vpn.azure = {connected:false,path:"",state:"unknown"}
        root.check(!az.checked && !az.enabled && vpn.calls === 3, "Unknown falsely checked or actionable")
        root.profileIndex = 0; root.activateCursor()
        root.check(vpn.calls === 4 && vpn.last === "nm:mock-nm", "Keyboard NM route")
        vpn.azure = {connected:false,path:"",state:"disconnected"}
        root.profileIndex = 1; root.activateCursor()
        root.check(vpn.calls === 5 && vpn.last === "azure:/mock/profile.xml", "Keyboard Azure route")
        vpn.azureOperation = {running:false,stopping:true,path:"/mock/profile.xml"}
        vpn.toggleAzure("/mock/profile.xml")
        root.check(vpn.calls === 5, "Stopping operation repeated")
        vpn.azureOperation = {running:false,stopping:false,path:""}
        vpn.azure = {connected:false,path:"/mock/profile.xml",state:"stale"}
        vpn.toggleAzure("/mock/profile.xml")
        root.check(vpn.calls === 6, "Recovery cleanup route lost")
        console.log("PASS offscreen native profile switches: refresh no mutation, routing, guards, pending cancellation, unknown, keyboard and alignment")
        Qt.quit()
      }
    }
  }
  }
}
''')
    try:
        result = subprocess.run(['quickshell', '--no-color', '-p', str(tmp / 'shell.qml')], capture_output=True, text=True,
                                env=dict(os.environ, QT_QPA_PLATFORM='offscreen'), timeout=10)
    except subprocess.TimeoutExpired as error:
        print(error.stdout, error.stderr)
        raise
    output = result.stdout + result.stderr
    print(output)
    assert result.returncode == 0 and 'PASS offscreen native profile' in output
    assert 'Error:' not in output and 'ReferenceError' not in output

import QtQuick
import Quickshell
import Quickshell.Io

Item {
  id: root

  property var settings: ({})

  // A separate stdin pipe carries responses; ordinary status never contains secrets.
  property string permissionRequest: ""
  property string certificateRequest: ""
  readonly property string authRequest: certificateRequest || permissionRequest
  readonly property bool certificatePrompt: certificateRequest !== ""
  function respondAuth(value) {
    if (!certificateRequest) { respondPermission(value); return }
    var ident = certificateRequest
    certificateRequest = ""
    if (!certificateProcess.running) return
    if (value && value.length <= 4092 && !/[\x00-\x1f\x7f]/.test(value))
      certificateProcess.write(ident + "\t" + value + "\n")
    else { _nmAttemptCancelled = true; certificateProcess.write(ident + "\n") }
  }
  function cancelAuth() {
    if (certificateProcess.running) { _nmAttemptCancelled = true; certificateProcess.write("CANCEL\n") }
    certificateRequest = ""
    cancelPermission()
  }
  function respondPermission(value) {
    var ident = permissionRequest
    permissionRequest = ""
    if (!ident || !permissionBridge.running) return
    if (value && value.length <= 4092 && !/[\r\n\x00]/.test(value))
      permissionBridge.write(ident + "\t" + value + "\n")
    else permissionBridge.write(ident + "\n")
  }
  function cancelPermission() { respondPermission("") }
  Process {
    id: permissionBridge
    command: ["/usr/bin/python3", decodeURIComponent(Qt.resolvedUrl("permission.py").toString().replace(/^file:\/\//, "")), "serve"]
    stdinEnabled: true
    running: true
    stdout: SplitParser {
      onRead: function(data) {
        var match = /^(REQUEST|DONE) ([0-9a-f]{32})$/.exec(data)
        if (!match) return
        if (match[1] === "REQUEST") root.permissionRequest = match[2]
        else if (root.permissionRequest === match[2]) root.permissionRequest = ""
      }
    }
    onExited: { root.permissionRequest = ""; permissionRestart.restart() }
  }
  Timer { id: permissionRestart; interval: 500; onTriggered: permissionBridge.running = true }
  Component.onDestruction: cancelAuth()

  property var profiles: []
  property var azureProfiles: []
  property var azure: ({state: "unknown", connected: false, path: "", interface: "", address: ""})
  property var azureOperation: ({known: false, running: null, stopping: null, error: ""})
  readonly property bool azureOperationKnown: azureOperation.known === true && typeof azureOperation.running === "boolean" && typeof azureOperation.stopping === "boolean"
  readonly property bool azurePending: azureOperation.running === true && !azure.connected
  readonly property string azureDisplayState: azureOperation.stopping ? "disconnecting" : (azurePending ? "connecting" : azure.state)
  readonly property string activeProfile: azure.connected ? (azure.path ? azure.path.split("/").pop() : "VPN") : nmProfile
  readonly property string activeType: azure.connected ? "Azure OpenP2S" : (nmType ? profileTypeLabel(nmType) + " (NetworkManager)" : "")
  readonly property string activeUuid: azure.connected ? "" : nmUuid
  readonly property string tunnelIp: azure.connected ? azure.address : nmTunnelIp
  readonly property string interfaceName: azure.connected ? azure.interface : nmInterface
  readonly property string statusTitle: active ? "VPN Connected" : (azureDisplayState === "connecting" || (certificateProcess.running && !_nmAttemptCancelled) ? "VPN Connecting" : (azureDisplayState === "disconnecting" || (certificateProcess.running && _nmAttemptCancelled) ? "VPN Disconnecting" : (azure.state === "unknown" || !azureOperationKnown || !nmStateKnown ? "VPN Status Unknown" : "VPN Disconnected")))
  readonly property int activeCount: (azure.connected ? 1 : 0) + (nmStateKnown ? _nmActiveUuids.length : 0)
  readonly property string statusDescription: activeCount > 1 ? activeCount + " connections active" : (active ? "Connection active" : "")
  function azureRowStatus(path) {
    if (azure.path === path) return azureOperation.stopping ? "disconnecting" : (!azureOperationKnown && azure.state === "disconnected" ? "unknown" : azure.state)
    if (azureOperation.path === path && (azureOperation.running || azureOperation.stopping) && !azure.connected) return azureDisplayState
    return !azureOperationKnown || azure.state === "unknown" || (["connected", "reconnecting", "disconnecting", "stale"].indexOf(azure.state) !== -1 && !azure.path) ? "unknown" : "disconnected"
  }
  function pollAzure() {
    if (!azureProcess.running) azureProcess.running = true
  }
  Process {
    id: azureProcess
    command: ["/usr/bin/python3", decodeURIComponent(Qt.resolvedUrl("profiles.py").toString().replace(/^file:\/\//, "")), "status"]
    stdout: StdioCollector { id: azureOutput; waitForEnd: true }
    onExited: {
      try {
        var result = JSON.parse(azureOutput.text)
        root.azure = result
        root.azureOperation = result.operation || {known: false, running: null, stopping: null, error: ""}
        if (root.azureOperation.error) {
          root.lastError = root.azureOperation.error
          root.lastMessage = ""
          root.pendingAction = ""
        } else root.clearResolvedMessage()
      } catch (e) {
        root.azure = {state: "unknown", connected: false, path: "", interface: "", address: ""}
        root.azureOperation = {known: false, running: null, stopping: null, error: ""}
      }
    }
  }
  property string lastMessage: ""
  property string pendingAction: ""
  function clearResolvedMessage() {
    if ((pendingAction === "launch" && azure.connected) ||
        (pendingAction === "disconnect" && azure.state === "disconnected" && azureOperationKnown && !azureOperation.running && !azureOperation.stopping)) {
      lastMessage = ""
      pendingAction = ""
    }
  }
  function toggleAzure(path) {
    if (azureOperation.stopping) return
    if (azure.path === path && (azure.connected || azureOperation.running || ["reconnecting", "disconnecting", "stale"].indexOf(azure.state) !== -1)) profileAction("disconnect")
    else if (azureOperation.path === path && azureOperation.running) profileAction("disconnect")
    else profileAction("launch", path)
  }
  function rowAction(state) {
    return ["connected", "connecting", "reconnecting"].indexOf(state) !== -1 ? "Disconnect" : "Connect"
  }
  Timer { interval: 4000; running: root.lastMessage !== "" && root.pendingAction === ""; onTriggered: root.lastMessage = "" }
  readonly property bool importing: importProcess.running

  function profileAction(action, path) {
    if (importProcess.running || actionRunning) return
    if (action === "launch" && (!azureOperationKnown || azureOperation.running || azureOperation.stopping || azure.state !== "disconnected")) return
    if (action === "launch" || action === "disconnect") {
      lastError = ""
      pendingAction = action
      lastMessage = action === "launch" ? "Connecting…" : "Disconnecting…"
    }
    importProcess.command = ["/usr/bin/python3", decodeURIComponent(Qt.resolvedUrl("profiles.py").toString().replace(/^file:\/\//, "")), action]
    if (path !== undefined) importProcess.command = importProcess.command.concat([path])
    importProcess.running = true
  }

  Component.onCompleted: profileAction("list")

  Process {
    id: importProcess
    stdout: StdioCollector { id: importOutput; waitForEnd: true }
    onExited: function(exitCode) {
      try {
        var result = JSON.parse(importOutput.text)
        if (result.cancelled) { root.pendingAction = ""; root.lastMessage = ""; return }
        if (result.azure !== undefined) root.azureProfiles = result.azure
        if (result.error || exitCode !== 0) { root.lastError = result.error || "Profile helper failed."; root.lastMessage = ""; root.pendingAction = "" }
        else if (result.message) {
          root.lastError = ""
          root.lastMessage = result.message
          root.clearResolvedMessage()
          root.refresh()
        }
      } catch (e) {
        root.lastError = "Profile helper failed. Check /usr/bin/python3 and profiles.py."
        root.lastMessage = ""
        root.pendingAction = ""
      }
    }
  }
  property string nmProfile: ""
  property string nmType: ""
  property string nmUuid: ""
  property var _nmActiveUuids: []
  property string _nmAttemptUuid: ""
  property bool _nmAttemptWasInactive: false
  property bool _nmAttemptCancelled: false
  property string _nmAttemptError: ""
  function nmRowStatus(uuid) {
    if (certificateProcess.running && _nmAttemptUuid === uuid) return _nmAttemptCancelled ? "disconnecting" : "connecting"
    if (!nmStateKnown) return "unknown"
    return _nmActiveUuids.indexOf(uuid) !== -1 ? "connected" : "disconnected"
  }
  property bool nmStateKnown: false
  function invalidateNmState() {
    nmStateKnown = false
    _nmActiveUuids = []
    nmUuid = ""
    nmProfile = ""
    nmType = ""
    nmTunnelIp = ""
    nmInterface = ""
  }
  function clearConfirmedNmError() {
    if (_nmAttemptWasInactive && !_nmAttemptCancelled && nmStateKnown && _nmActiveUuids.indexOf(_nmAttemptUuid) !== -1 &&
        _nmAttemptError && lastError === _nmAttemptError) {
      lastError = ""
      _nmAttemptError = ""
    }
  }

  property string publicIp: ""
  property string nmTunnelIp: ""
  property string nmInterface: ""

  property bool refreshing: false
  property bool actionRunning: false
  property string lastError: ""

  property string _profilesOutput: ""
  property string _activeOutput: ""
  property string _detailsOutput: ""
  property string _ipOutput: ""
  property string _actionOutput: ""

  readonly property bool active: azure.connected || (nmStateKnown && nmUuid !== "")
  readonly property int refreshIntervalSec: intSetting(
    "refreshIntervalSec",
    10,
    5,
    3600
  )

  readonly property bool busy:
    refreshing ||
    actionRunning ||
    profilesProcess.running ||
    activeProcess.running ||
    detailsProcess.running ||
    publicIpProcess.running || azureProcess.running

  function setting(name, fallback) {
    var value = settings ? settings[name] : undefined
    return value === undefined || value === null ? fallback : value
  }

  function intSetting(name, fallback, min, max) {
    var n = parseInt(String(setting(name, fallback)), 10)

    if (!isFinite(n))
      n = fallback

    if (n < min)
      n = min

    if (n > max)
      n = max

    return n
  }

  function refresh() {
    pollAzure()
    if (refreshing)
      return

    refreshing = true

    loadProfiles()
    loadActive()
  }

  function loadProfiles() {
    if (profilesProcess.running)
      return

    _profilesOutput = ""

    profilesProcess.command = [
      "nmcli",
      "-t",
      "-f",
      "NAME,UUID,TYPE",
      "connection",
      "show"
    ]

    profilesProcess.running = true
  }

  function loadActive() {
    if (activeProcess.running)
      return

    _activeOutput = ""

    activeProcess.command = [
      "nmcli",
      "-t",
      "-f",
      "NAME,UUID,TYPE",
      "connection",
      "show",
      "--active"
    ]

    activeProcess.running = true
  }

  function connectProfile(uuid) {
    if (actionRunning || importProcess.running || !nmStateKnown || !profiles.some(function(p) { return p.uuid === uuid }))
      return

    lastError = ""
    actionRunning = true
    _actionOutput = ""

    _nmAttemptUuid = uuid
    _nmAttemptWasInactive = _nmActiveUuids.indexOf(uuid) === -1
    _nmAttemptCancelled = false
    _nmAttemptError = ""
    certificateProcess.command = ["/usr/bin/python3", decodeURIComponent(Qt.resolvedUrl("nm-secret.py").toString().replace(/^file:\/\//, "")), uuid]
    certificateProcess.running = true
  }

  function deleteProfile(uuid) {
    if (actionRunning || importProcess.running || !nmStateKnown || !profiles.some(function(p) { return p.uuid === uuid })) return
    lastError = ""
    actionRunning = true
    _actionOutput = ""
    actionProcess.command = ["/usr/bin/python3", decodeURIComponent(Qt.resolvedUrl("profiles.py").toString().replace(/^file:\/\//, "")), "delete-nm", uuid]
    actionProcess.running = true
  }

  function canRemoveAzure(path) {
    return azureProfiles.indexOf(path) !== -1 && !actionRunning && !importProcess.running &&
      azure.state === "disconnected" && azureOperationKnown && !azureOperation.running && !azureOperation.stopping
  }

  function removeAzure(path) {
    if (canRemoveAzure(path)) profileAction("remove", path)
  }

  function disconnectActive() {
    if (certificateProcess.running) { cancelAuth(); return }
    if (azure.connected || azureOperation.running || azureOperation.stopping || ["reconnecting", "disconnecting", "stale"].indexOf(azure.state) !== -1) {
      profileAction("disconnect")
      return
    }
    disconnectNm()
  }

  function disconnectNm(uuid) {
    if (uuid === undefined) uuid = certificateProcess.running ? _nmAttemptUuid : nmUuid
    if (certificateProcess.running && uuid === _nmAttemptUuid) { cancelAuth(); return }
    if (actionRunning || importProcess.running || !nmStateKnown || _nmActiveUuids.indexOf(uuid) === -1)
      return

    lastError = ""
    actionRunning = true
    _actionOutput = ""

    actionProcess.command = [
      "nmcli",
      "--wait",
      "30",
      "connection",
      "down",
      "uuid",
      uuid
    ]

    actionProcess.running = true
  }

  function toggleProfile(uuid) {
    if (certificateProcess.running && uuid === _nmAttemptUuid) { cancelAuth(); return }
    if (actionRunning || importProcess.running || !nmStateKnown || !profiles.some(function(p) { return p.uuid === uuid }))
      return

    if (_nmActiveUuids.indexOf(uuid) !== -1) {
      disconnectNm(uuid)
      return
    }

    if (nmUuid !== "") {
      actionRunning = true
      lastError = ""

      switchProcess.target = uuid

      switchProcess.command = [
        "nmcli",
        "--wait",
        "30",
        "connection",
        "down",
        "uuid",
        nmUuid
      ]

      switchProcess.running = true
      return
    }

    connectProfile(uuid)
  }

  function lookupPublicIp() {
    if (publicIpProcess.running)
      return

    _ipOutput = ""

    publicIpProcess.command = [
      "curl",
      "-4",
      "-fsS",
      "--max-time",
      "8",
      "https://api.ipify.org"
    ]

    publicIpProcess.running = true
  }

  function loadActiveDetails() {
    if (nmUuid === "") {
      nmTunnelIp = ""
      nmInterface = ""
      return
    }

    if (detailsProcess.running)
      return

    _detailsOutput = ""
    detailsProcess.target = nmUuid
    detailsProcess.command = ["/usr/bin/python3", decodeURIComponent(Qt.resolvedUrl("profiles.py").toString().replace(/^file:\/\//, "")), "details-nm", nmUuid]

    detailsProcess.running = true
  }

  function parseProfiles(raw) {
    var result = []
    var lines = String(raw || "").split(/\r?\n/)

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i]

      if (line === "")
        continue

      var parts = line.split(":")

      if (parts.length < 3)
        continue

      var type = parts[parts.length - 1]
      var uuid = parts[parts.length - 2]
      var name = parts.slice(0, parts.length - 2).join(":")

      if (type !== "vpn" && type !== "wireguard")
        continue

      result.push({
        name: name,
        uuid: uuid,
        type: type,
        label: profileTypeLabel(type)
      })
    }

    result.sort(function(a, b) {
      return a.name.localeCompare(b.name)
    })

    return result
  }

  function profileTypeLabel(type) {
    if (type === "wireguard")
      return "WireGuard"

    if (type === "vpn")
      return "VPN"

    return type
  }

  function parseActive(raw) {
    var lines = String(raw || "").split(/\r?\n/)

    var previousUuid = nmUuid
    nmStateKnown = true
    _nmActiveUuids = parseProfiles(raw).map(function(p) { return p.uuid })
    if (_nmAttemptUuid && _nmActiveUuids.indexOf(_nmAttemptUuid) === -1) _nmAttemptWasInactive = true
    nmProfile = ""
    nmUuid = ""
    nmType = ""

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i]

      if (line === "")
        continue

      var parts = line.split(":")

      if (parts.length < 3)
        continue

      var type = parts[parts.length - 1]

      if (type !== "vpn" && type !== "wireguard")
        continue

      nmType = type
      nmUuid = parts[parts.length - 2]
      nmProfile = parts.slice(0, parts.length - 2).join(":")
      break
    }
    if (previousUuid !== nmUuid) { nmTunnelIp = ""; nmInterface = "" }
    clearConfirmedNmError()
  }

  Process {
    id: profilesProcess

    stdout: StdioCollector {
      id: profilesStdout
      waitForEnd: true
      onStreamFinished: root._profilesOutput = text
    }

    stderr: StdioCollector {
      id: profilesStderr
      waitForEnd: true
    }

    onExited: function(exitCode) {
      if (exitCode === 0) {
        root.profiles = root.parseProfiles(
          String(profilesStdout.text || root._profilesOutput || "")
        )
      } else {
        root.lastError =
          String(profilesStderr.text || "").trim()
          || "Could not read VPN profiles"
      }

      root.refreshing = false
    }
  }

  Process {
    id: activeProcess

    stdout: StdioCollector {
      id: activeStdout
      waitForEnd: true
      onStreamFinished: root._activeOutput = text
    }

    stderr: StdioCollector {
      id: activeStderr
      waitForEnd: true
    }

    onExited: function(exitCode) {
      if (exitCode === 0) {
        root.parseActive(
          String(activeStdout.text || root._activeOutput || "")
        )

        root.loadActiveDetails()
        root.lookupPublicIp()
      } else {
        root.invalidateNmState()
        root.lastError =
          String(activeStderr.text || "").trim()
          || "Could not read active VPN state"
      }

      root.refreshing = false
    }
  }

  Process {
    id: detailsProcess
    property string target: ""

    stdout: StdioCollector {
      id: detailsStdout
      waitForEnd: true
      onStreamFinished: root._detailsOutput = text
    }

    stderr: StdioCollector {
      id: detailsStderr
      waitForEnd: true
    }

    onExited: function(exitCode) {
      if (target !== root.nmUuid) { root.loadActiveDetails(); return }
      if (exitCode !== 0) {
        root.nmTunnelIp = ""
        root.nmInterface = ""
        return
      }

      try {
        var result = JSON.parse(String(detailsStdout.text || root._detailsOutput || ""))
        if (result.uuid !== root.nmUuid) return
        root.nmTunnelIp = result.address || ""
        root.nmInterface = result.interface || ""
      } catch (e) { root.nmTunnelIp = ""; root.nmInterface = "" }
    }
  }

  Process {
    id: publicIpProcess

    stdout: StdioCollector {
      id: publicIpStdout
      waitForEnd: true
      onStreamFinished: root._ipOutput = text
    }

    stderr: StdioCollector {
      id: publicIpStderr
      waitForEnd: true
    }

    onExited: function(exitCode) {
      if (exitCode === 0) {
        root.publicIp =
          String(publicIpStdout.text || root._ipOutput || "").trim()
      }
    }
  }

  Process {
    id: certificateProcess
    stdinEnabled: true
    stdout: SplitParser {
      onRead: function(data) {
        var match = /^(REQUEST|DONE) ([0-9a-f]{32})$/.exec(data)
        if (!match) return
        if (match[1] === "REQUEST") root.certificateRequest = match[2]
        else if (root.certificateRequest === match[2]) root.certificateRequest = ""
      }
    }
    onExited: function(exitCode) {
      root.certificateRequest = ""
      root.actionRunning = false
      root._nmAttemptError = exitCode === 0 ? "" : exitCode === 2
        ? "VPN activation timed out. This does not establish a password failure."
        : exitCode === 3 ? "Unsupported VPN authentication prompt or backend response."
        : "VPN activation failed or was cancelled. Check NetworkManager diagnostics."
      if (root._nmAttemptError && !root.lastError) root.lastError = root._nmAttemptError
      root.clearConfirmedNmError()
      refreshDelay.restart()
    }
  }

  Process {
    id: actionProcess

    stdout: StdioCollector {
      id: actionStdout
      waitForEnd: true
      onStreamFinished: root._actionOutput = text
    }

    stderr: StdioCollector {
      id: actionStderr
      waitForEnd: true
    }

    onExited: function(exitCode) {
      root.actionRunning = false

      if (exitCode !== 0) {
        root.lastError =
          String(
            actionStderr.text
            || actionStdout.text
            || root._actionOutput
            || ""
          ).trim()
          || "VPN action failed"
      } else {
        root.lastError = ""
      }

      refreshDelay.restart()
    }
  }

  Process {
    id: switchProcess

    property string target: ""

    stdout: StdioCollector {
      id: switchStdout
      waitForEnd: true
    }

    stderr: StdioCollector {
      id: switchStderr
      waitForEnd: true
    }

    onExited: function(exitCode) {
      if (exitCode !== 0) {
        root.lastError =
          String(switchStderr.text || switchStdout.text || "").trim()
          || "Could not disconnect current VPN"

        target = ""
        root.actionRunning = false
        return
      }

      var next = target
      target = ""
      root.actionRunning = false

      Qt.callLater(function() {
        root.connectProfile(next)
      })
    }
  }

  Timer {
    id: refreshDelay
    interval: 1200
    repeat: false
    onTriggered: root.refresh()
  }

  Timer {
    interval: root.refreshIntervalSec * 1000
    repeat: true
    running: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }
}

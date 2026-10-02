import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import qs.Ui as NativeUi

Panel {
  id: root

  moduleName: "airzy.vpn"
  ipcTarget: "airzy.vpn"
  manageIpc: false

  property int profileIndex: 0
  property bool cursorActive: false

  readonly property color foreground:
    bar ? bar.foreground : Color.foreground

  readonly property color urgent:
    bar ? bar.urgent : Color.urgent

  readonly property color dim:
    Qt.darker(foreground, 1.55)

  readonly property color accent:
    Color.accent

  readonly property string fontFamily:
    bar ? bar.fontFamily : Style.font.family

  readonly property color barIconColor:
    bar ? bar.foreground : Color.foreground

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onOpenedChanged: if (opened) {
    cursorActive = false
    profileIndex = 0

    if (panelFlick)
      panelFlick.contentY = 0

    vpn.refresh()

    Qt.callLater(function() {
      if (vpn.authRequest) permissionField.forceActiveFocus()
      else keyCatcher.forceActiveFocus()
    })
  } else {
    permissionField.text = ""
    vpn.cancelAuth()
  }

  Component.onDestruction: {
    permissionField.text = ""
    vpn.cancelAuth()
  }

  Service {
    id: vpn
    settings: root.settings
    onAuthRequestChanged: {
      permissionField.text = ""
      if (!authRequest) return
      root.cursorActive = false
      root.open()
      panelFlick.contentY = 0
      Qt.callLater(function() {
        if (vpn.authRequest && root.opened) permissionField.forceActiveFocus()
      })
    }
  }

  component DeleteControl: Row {
    id: deletion
    property string target: ""
    property string label: ""
    property bool azureRegistry: false
    property bool armed: false
    signal confirmed()
    spacing: Style.space(4)
    onTargetChanged: armed = false
    onEnabledChanged: if (!enabled) armed = false
    Connections {
      target: root
      function onOpenedChanged() { deletion.armed = false }
    }
    Button {
      focusable: true
      text: deletion.armed ? "Confirm" : "Delete"
      Accessible.role: Accessible.Button
      Accessible.name: (deletion.armed ? "Confirm delete " : "Delete ") + deletion.label
      Accessible.onPressAction: clicked()
      tooltipText: deletion.label + " · " + (deletion.azureRegistry ? "Remove registry entry only; source files kept" : "Delete this NetworkManager profile; an active connection may stop")
      onClicked: {
        if (!deletion.armed) deletion.armed = true
        else { deletion.armed = false; deletion.confirmed() }
      }
      Keys.onEscapePressed: deletion.armed = false
    }
    Button {
      visible: deletion.armed
      focusable: true
      text: "Cancel"
      Accessible.role: Accessible.Button
      Accessible.name: "Cancel delete " + deletion.label
      Accessible.onPressAction: clicked()
      onClicked: deletion.armed = false
      Keys.onEscapePressed: deletion.armed = false
    }
  }

  readonly property int profileCount: vpn.profiles.length + vpn.azureProfiles.length

  function selectedProfile() {
    if (profileIndex >= vpn.profiles.length)
      return { type: "azure", path: vpn.azureProfiles[profileIndex - vpn.profiles.length] }
    if (!vpn.profiles || root.profileCount === 0)
      return null

    var index = Math.max(
      0,
      Math.min(profileIndex, vpn.profiles.length - 1)
    )

    return vpn.profiles[index]
  }

  function moveCursor(dx, dy) {
    if (dy === 0 || profileCount === 0)
      return

    cursorActive = true

    profileIndex = Math.max(
      0,
      Math.min(
        profileCount - 1,
        profileIndex + dy
      )
    )
  }

  function disconnectSelected() {
    var profile = selectedProfile()
    if (profile && profile.uuid && ["connected", "connecting", "disconnecting"].indexOf(vpn.nmRowStatus(profile.uuid)) !== -1)
      vpn.disconnectNm(profile.uuid)
    else vpn.disconnectActive()
  }

  function activateCursor() {
    var profile = selectedProfile()

    if (!profile)
      return

    if (profile.type === "azure") {
      if (profile.path !== undefined) vpn.toggleAzure(profile.path)
    } else vpn.toggleProfile(profile.uuid)
  }

  IpcHandler {
    target: root.ipcTarget

    function open(): void {
      root.open()
    }

    function close(): void {
      root.close()
    }

    function show(): void {
      root.open()
    }

    function hide(): void {
      root.close()
    }

    function toggle(): void {
      root.toggle()
    }

    function refresh(): string {
      vpn.refresh()
      return "ok"
    }

    function disconnect(): string {
      root.disconnectSelected()
      return "ok"
    }

    function status(): string {
      return vpn.active
        ? "Connected: " + vpn.activeProfile
        : vpn.statusTitle
    }
  }

  BarIconButton {
    id: button

    anchors.fill: parent
    bar: root.bar

    iconComponent: Component {
      VpnIcon {
        anchors.centerIn: parent
        iconSize: Style.space(11)
        color: root.barIconColor
        badgeColor: root.urgent
        crossed: !vpn.active
        warning: false
      }
    }

    onPressed: function(buttonCode) {
      if (buttonCode === Qt.RightButton) {
        root.disconnectSelected()
      } else if (buttonCode === Qt.MiddleButton) {
        vpn.refresh()
      } else {
        root.toggle()
      }
    }
  }

  KeyboardPanel {
    id: panel

    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened

    focusTarget: vpn.authRequest ? permissionField : keyCatcher

    contentWidth:
      panel.fittedContentWidth(Style.space(380))

    contentHeight:
      panel.fittedContentHeight(
        column.implicitHeight,
        Style.space(560)
      )

    PanelKeyCatcher {
      id: keyCatcher
      blocked: vpn.authRequest !== ""

      anchors.fill: parent

      onMoveRequested: function(dx, dy) {
        if (!root.cursorActive) {
          root.cursorActive = true
          return
        }

        root.moveCursor(dx, dy)
      }

      onActivateRequested: {
        if (root.cursorActive)
          root.activateCursor()
      }

      onCloseRequested:
        root.close()

      onTabRequested: function(direction) {
        root.switchPanel(direction)
      }

      onTextKey: function(t) {
        if (t === "r" || t === "R")
          vpn.refresh()

        else if (t === "i" || t === "I")
          vpn.profileAction("import")

        else if (t === "d" || t === "D")
          root.disconnectSelected()
      }

      Flickable {
        id: panelFlick

        anchors.fill: parent

        contentWidth: width
        contentHeight: column.implicitHeight

        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height

        ScrollBar.vertical: ScrollBar {
          policy: ScrollBar.AsNeeded
        }

        Column {
          id: column

          width: panelFlick.width
          spacing: Style.space(12)

          // Separate certificate and sudo requests share only the masked native field.
          Column {
            id: permissionPrompt
            width: parent.width
            visible: vpn.authRequest !== ""
            spacing: Style.space(8)
            Text {
              width: parent.width
              text: vpn.certificatePrompt ? "VPN certificate password required" : "System permission required"
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
            Text {
              width: parent.width
              text: vpn.certificatePrompt ? "Enter the password that unlocks your VPN certificate/private key, not your system password. Cancel stops this connection attempt." : "Enter your system password for sudo. Cancel denies this request."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.Wrap
            }
            NativeUi.TextField {
              id: permissionField
              width: parent.width
              password: true
              maximumLength: 4092
              placeholderText: vpn.certificatePrompt ? "Certificate password" : "System password"
              foreground: root.foreground
              accent: root.accent
              inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
              Accessible.name: vpn.certificatePrompt ? "VPN certificate password" : "System password for sudo"
              function submit() {
                var response = text
                text = ""
                vpn.respondAuth(response)
                response = ""
              }
              onAccepted: submit()
              Keys.onReturnPressed: function(event) { event.accepted = true; submit() }
              Keys.onEnterPressed: function(event) { event.accepted = true; submit() }
              Keys.onEscapePressed: { text = ""; vpn.cancelAuth() }
            }
            Row {
              spacing: Style.space(8)
              Button {
                id: permissionSubmit
                focusable: true
                Accessible.role: Accessible.Button
                Accessible.name: vpn.certificatePrompt ? "Submit certificate password" : "Submit system password"
                Accessible.onPressAction: clicked()
                text: "Submit"
                enabled: permissionField.text.length > 0
                onClicked: permissionField.submit()
                Keys.onEscapePressed: { permissionField.text = ""; vpn.cancelAuth() }
              }
              Button {
                id: permissionCancel
                focusable: true
                Accessible.role: Accessible.Button
                Accessible.name: "Cancel permission request"
                Accessible.onPressAction: clicked()
                text: "Cancel"
                onClicked: { permissionField.text = ""; vpn.cancelAuth() }
                Keys.onEscapePressed: { permissionField.text = ""; vpn.cancelAuth() }
              }
            }
          }

          //
          // HERO
          //
          PanelHero {
            id: hero

            width: parent.width

            title:
              vpn.statusTitle

            meta: {
              if (vpn.activeProfile !== "")
                return vpn.activeProfile

              if (vpn.publicIp !== "")
                return vpn.publicIp

              return "No active connection"
            }

            foreground: root.foreground
            fontFamily: root.fontFamily

            iconOpacity:
              vpn.active ? 1.0 : 0.5

            iconComponent: Component {
              VpnIcon {
                iconSize: Style.font.display
                color: vpn.active
                  ? root.accent
                  : root.dim

                crossed: !vpn.active
                warning: false
              }
            }
          }

          Text {
            width: parent.width
            text: vpn.statusDescription
            visible: text !== ""
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.Wrap
          }

          //
          // ACTIVE CONNECTION
          //
          Column {
            width: parent.width
            spacing: Style.space(6)

            PanelSectionHeader {
              text: "CONNECTION"
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            Text {
              width: parent.width

              text:
                "Public IP   " +
                (vpn.publicIp !== ""
                  ? vpn.publicIp
                  : "—")

              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }

            Text {
              width: parent.width

              text:
                "Tunnel IP   " +
                (vpn.tunnelIp !== ""
                  ? vpn.tunnelIp
                  : "—")

              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }

            Text {
              width: parent.width

              text:
                "Interface   " +
                (vpn.interfaceName !== ""
                  ? vpn.interfaceName
                  : "—")

              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }

            Text {
              width: parent.width

              text:
                "Type        " +
                (vpn.activeType !== ""
                  ? vpn.activeType
                  : "—")

              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
          }

          PanelSeparator {
            width: parent.width
            foreground: root.foreground
          }

          //
          // PROFILES
          //
          Column {
            width: parent.width
            spacing: Style.space(8)

            Row {
              width: parent.width
              spacing: Style.space(8)

              PanelSectionHeader {
                width:
                  parent.width -
                  refreshButton.implicitWidth -
                  parent.spacing

                text: "VPN PROFILES"
                foreground: root.foreground
                fontFamily: root.fontFamily
              }

              Button {
                id: refreshButton

                text:
                  vpn.refreshing
                    ? "…"
                    : "󰑐"

                enabled:
                  !vpn.refreshing

                onClicked:
                  vpn.refresh()
              }
            }

            Text {
              width: parent.width

              visible:
                root.profileCount === 0

              text:
                vpn.refreshing
                  ? "Loading VPN profiles…"
                  : "No VPN profiles found."

              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              horizontalAlignment:
                Text.AlignHCenter
            }

            Column {
              id: profileColumn

              width: parent.width
              spacing: Style.space(6)

              Repeater {
                model: vpn.profiles

                delegate: Rectangle {
                  required property var modelData
                  required property int index

                  width:
                    profileColumn.width

                  implicitHeight:
                    profileRow.implicitHeight +
                    Style.space(12)

                  radius:
                    Style.space(4)

                  color: {
                    if (vpn.nmRowStatus(modelData.uuid) === "connected")
                      return Qt.rgba(
                        root.accent.r,
                        root.accent.g,
                        root.accent.b,
                        0.18
                      )

                    if (
                      root.cursorActive &&
                      root.profileIndex === index
                    )
                      return Qt.rgba(
                        root.foreground.r,
                        root.foreground.g,
                        root.foreground.b,
                        0.08
                      )

                    return "transparent"
                  }

                  Row {
                    id: profileRow

                    anchors {
                      left: parent.left
                      right: parent.right
                      verticalCenter: parent.verticalCenter
                      leftMargin: Style.space(8)
                      rightMargin: Style.space(8)
                    }

                    spacing: Style.space(8)

                    Text {
                      id: nmIndicator
                      text:
                        vpn.nmRowStatus(modelData.uuid) === "connected"
                          ? "●"
                          : "○"

                      color:
                        vpn.nmRowStatus(modelData.uuid) === "connected"
                          ? root.accent
                          : root.dim

                      font.family:
                        root.fontFamily

                      font.pixelSize:
                        Style.font.body
                    }

                    Column {
                      width:
                        Math.max(0, parent.width - nmIndicator.width - nmSwitch.width - nmDelete.width - parent.spacing * 3)

                      spacing: Style.space(1)

                      Text {
                        width: parent.width

                        text:
                          modelData.name

                        color:
                          root.foreground

                        font.family:
                          root.fontFamily

                        font.pixelSize:
                          Style.font.body

                        elide:
                          Text.ElideRight
                      }

                      Text {
                        width: parent.width

                        text:
                          vpn.nmRowStatus(modelData.uuid)

                        color:
                          root.dim

                        font.family:
                          root.fontFamily

                        font.pixelSize:
                          Style.font.caption

                        elide:
                          Text.ElideRight
                      }
                    }
                    ToggleSwitch {
                      id: nmSwitch
                      anchors.verticalCenter: parent.verticalCenter
                      checked: vpn.nmRowStatus(modelData.uuid) === "connected"
                      busy: vpn.importing || (vpn.nmRowStatus(modelData.uuid) !== "connecting" && (!vpn.nmStateKnown || vpn.actionRunning))
                      foreground: root.foreground
                      accent: root.accent
                      hasCursor: root.cursorActive && root.profileIndex === index
                      Accessible.role: Accessible.CheckBox
                      Accessible.name: modelData.name.split("/").pop()
                      Accessible.checked: checked
                      Accessible.onToggleAction: if (!busy) toggled()
                      onToggled: {
                        root.cursorActive = true
                        root.profileIndex = index
                        vpn.toggleProfile(modelData.uuid)
                      }
                    }
                    DeleteControl {
                      id: nmDelete
                      anchors.verticalCenter: parent.verticalCenter
                      target: modelData.uuid
                      label: modelData.name + " (" + modelData.uuid + ")"
                      enabled: vpn.nmStateKnown && !vpn.actionRunning && !vpn.importing && !vpn.authRequest
                      onConfirmed: vpn.deleteProfile(target)
                    }
                  }

                  HoverHandler { id: nmHover }
                  ToolTip.visible: nmHover.hovered
                  ToolTip.text: modelData.name + " · " + modelData.uuid + " · " + (vpn.nmRowStatus(modelData.uuid))
                }
              }

              Repeater {
                model: vpn.azureProfiles
                delegate: Rectangle {
                  required property string modelData
                  required property int index
                  width: profileColumn.width
                  implicitHeight: azureRow.implicitHeight + Style.space(12)
                  radius: Style.space(4)
                  color: vpn.azure.connected && vpn.azure.path === modelData
                    ? Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.18)
                    : (root.cursorActive && root.profileIndex === vpn.profiles.length + index
                      ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.08) : "transparent")
                  enabled: !vpn.importing && !vpn.actionRunning && !vpn.azureOperation.stopping && (vpn.azure.path === modelData || vpn.azureOperation.path === modelData || (!vpn.azure.connected && vpn.azureOperationKnown && !vpn.azureOperation.running && vpn.azure.state === "disconnected"))
                  Row {
                    id: azureRow
                    anchors {
                      left: parent.left
                      right: parent.right
                      verticalCenter: parent.verticalCenter
                      leftMargin: Style.space(8)
                      rightMargin: Style.space(8)
                    }
                    spacing: Style.space(8)
                    Text {
                      id: azureIndicator
                      text: vpn.azure.connected && vpn.azure.path === modelData ? "●" : "○"
                      color: vpn.azure.connected && vpn.azure.path === modelData ? root.accent : root.dim
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.body
                    }
                    Column {
                      width: Math.max(0, parent.width - azureIndicator.width - azureSwitch.width - azureDelete.width - parent.spacing * 3)
                      spacing: Style.space(1)
                      Text {
                        width: parent.width
                        text: modelData.split("/").pop()
                        color: root.foreground
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.body
                        elide: Text.ElideRight
                      }
                      Text {
                        width: parent.width
                        elide: Text.ElideRight
                        text: vpn.azureRowStatus(modelData)
                        color: root.dim
                        font.family: root.fontFamily
                        font.pixelSize: Style.font.caption
                      }
                    }
                    ToggleSwitch {
                      id: azureSwitch
                      anchors.verticalCenter: parent.verticalCenter
                      checked: vpn.azure.connected && vpn.azure.path === modelData
                      busy: vpn.importing || vpn.actionRunning || vpn.azureOperation.stopping
                      foreground: root.foreground
                      accent: root.accent
                      hasCursor: root.cursorActive && root.profileIndex === vpn.profiles.length + index
                      Accessible.role: Accessible.CheckBox
                      Accessible.name: modelData.split("/").pop()
                      Accessible.checked: checked
                      Accessible.onToggleAction: if (!busy) toggled()
                      onToggled: {
                        root.cursorActive = true
                        root.profileIndex = vpn.profiles.length + index
                        vpn.toggleAzure(modelData)
                      }
                    }
                    DeleteControl {
                      id: azureDelete
                      anchors.verticalCenter: parent.verticalCenter
                      target: modelData
                      label: modelData.split("/").pop()
                      azureRegistry: true
                      enabled: vpn.canRemoveAzure(target) && !vpn.authRequest
                      onConfirmed: vpn.removeAzure(target)
                    }
                  }
                  HoverHandler { id: azureHover }
                  ToolTip.visible: azureHover.hovered
                  ToolTip.text: modelData.split("/").pop() + " · " + (vpn.azureRowStatus(modelData))
                }
              }
            }
          }

          Button {
            width: parent.width
            text: vpn.importing ? "Working…" : "Import profile… (I)"
            enabled: !vpn.importing && !vpn.actionRunning
            Accessible.name: "Import VPN profile"
            onClicked: vpn.profileAction("import")
          }

          Text {
            width: parent.width
            visible: vpn.lastMessage !== ""
            text: vpn.lastMessage
            color: root.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.Wrap
          }

          //
          // ERROR
          //
          Text {
            width: parent.width

            visible:
              vpn.lastError !== ""

            text:
              vpn.lastError

            color:
              root.urgent

            font.family:
              root.fontFamily

            font.pixelSize:
              Style.font.caption

            wrapMode:
              Text.WordWrap
          }

          Text {
            width: parent.width

            text:
              "↑↓ select · Enter connect/disconnect · D disconnect · R refresh · I import"

            color:
              root.dim

            font.family:
              root.fontFamily

            font.pixelSize:
              Style.font.caption

            horizontalAlignment:
              Text.AlignHCenter
          }
        }
      }
    }
  }
}

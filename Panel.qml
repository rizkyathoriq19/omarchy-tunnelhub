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
      if (vpn.permissionRequest) permissionField.forceActiveFocus()
      else keyCatcher.forceActiveFocus()
    })
  } else {
    permissionField.text = ""
    vpn.cancelPermission()
  }

  Component.onDestruction: {
    permissionField.text = ""
    vpn.cancelPermission()
  }

  Service {
    id: vpn
    settings: root.settings
    onPermissionRequestChanged: {
      permissionField.text = ""
      if (!permissionRequest) return
      root.cursorActive = false
      root.open()
      panelFlick.contentY = 0
      Qt.callLater(function() {
        if (vpn.permissionRequest && root.opened) permissionField.forceActiveFocus()
      })
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

  function activateCursor() {
    var profile = selectedProfile()

    if (!profile)
      return

    if (profile.type === "azure") {
      if (profile.path !== undefined) vpn.toggleAzure(profile.path)
    } else vpn.toggleProfile(profile.name)
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
      vpn.disconnectActive()
      return "ok"
    }

    function status(): string {
      return vpn.active
        ? "Connected: " + vpn.activeProfile
        : "Disconnected"
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
        if (vpn.active || vpn.azureOperation.running)
          vpn.disconnectActive()
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

    focusTarget: vpn.permissionRequest ? permissionField : keyCatcher

    contentWidth:
      panel.fittedContentWidth(Style.space(380))

    contentHeight:
      panel.fittedContentHeight(
        column.implicitHeight,
        Style.space(560)
      )

    PanelKeyCatcher {
      id: keyCatcher
      blocked: vpn.permissionRequest !== ""

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
          vpn.disconnectActive()
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

          // Inline sudo permission prompt; native OAuth/browser flow is untouched.
          Column {
            id: permissionPrompt
            width: parent.width
            visible: vpn.permissionRequest !== ""
            spacing: Style.space(8)
            Text {
              width: parent.width
              text: "System permission required"
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
            Text {
              width: parent.width
              text: "Enter your system password for sudo. Cancel denies this request."
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
              placeholderText: "System password"
              foreground: root.foreground
              accent: root.accent
              inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
              Accessible.name: "System password for sudo"
              function submit() {
                var response = text
                text = ""
                vpn.respondPermission(response)
                response = ""
              }
              onAccepted: submit()
              Keys.onReturnPressed: function(event) { event.accepted = true; submit() }
              Keys.onEnterPressed: function(event) { event.accepted = true; submit() }
              Keys.onEscapePressed: { text = ""; vpn.cancelPermission() }
            }
            Row {
              spacing: Style.space(8)
              Button {
                id: permissionSubmit
                focusable: true
                Accessible.role: Accessible.Button
                Accessible.name: "Submit system password"
                Accessible.onPressAction: clicked()
                text: "Submit"
                enabled: permissionField.text.length > 0
                onClicked: permissionField.submit()
                Keys.onEscapePressed: { permissionField.text = ""; vpn.cancelPermission() }
              }
              Button {
                id: permissionCancel
                focusable: true
                Accessible.role: Accessible.Button
                Accessible.name: "Cancel permission request"
                Accessible.onPressAction: clicked()
                text: "Cancel"
                onClicked: { permissionField.text = ""; vpn.cancelPermission() }
                Keys.onEscapePressed: { permissionField.text = ""; vpn.cancelPermission() }
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
                    if (vpn.nmProfile === modelData.name)
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
                        vpn.nmProfile === modelData.name
                          ? "●"
                          : "○"

                      color:
                        vpn.nmProfile === modelData.name
                          ? root.accent
                          : root.dim

                      font.family:
                        root.fontFamily

                      font.pixelSize:
                        Style.font.body
                    }

                    Column {
                      width:
                        parent.width - nmIndicator.width - nmSwitch.width - parent.spacing * 2

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
                          vpn.nmProfile === modelData.name ? "connected" : "disconnected"

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
                      checked: vpn.nmProfile === modelData.name
                      busy: vpn.actionRunning || vpn.importing
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
                        vpn.toggleProfile(modelData.name)
                      }
                    }
                  }

                  HoverHandler { id: nmHover }
                  ToolTip.visible: nmHover.hovered
                  ToolTip.text: modelData.name + " · " + (vpn.nmProfile === modelData.name ? "connected" : "disconnected")
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
                  enabled: !vpn.importing && !vpn.actionRunning && !vpn.azureOperation.stopping && (vpn.azure.path === modelData || vpn.azureOperation.path === modelData || (!vpn.azure.connected && !vpn.azureOperation.running && vpn.azure.state === "disconnected"))
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
                      width: parent.width - azureIndicator.width - azureSwitch.width - parent.spacing * 2
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

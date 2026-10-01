import QtQuick
import qs.Commons

Item {
  id: root

  property real iconSize: Style.space(11)
  property color color: Color.foreground
  property color badgeColor: Color.accent
  property bool crossed: false
  property bool warning: false

  implicitWidth: iconSize
  implicitHeight: iconSize

  Text {
    anchors.centerIn: parent

    // Nerd Fonts Material Design VPN
    text: "\uDB81\uDD82"

    color: root.color
    opacity: 1.0

    font.family: "Symbols Nerd Font"
    font.pixelSize: root.iconSize
  }

  Rectangle {
    visible: !root.crossed

    width: Math.max(4, root.iconSize * 0.28)
    height: width
    radius: width / 2

    anchors.right: parent.right
    anchors.bottom: parent.bottom

    color: root.badgeColor

    border.width: 1
    border.color: root.color
  }
}

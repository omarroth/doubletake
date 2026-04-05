import QtQuick
import QtQuick.Controls as Controls
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents
import org.kde.plasma.core as PlasmaCore
import org.kde.plasma.extras as PlasmaExtras
import org.kde.plasma.plasma5support as P5Support
import org.kde.plasma.plasmoid

PlasmoidItem {
    id: root

    property string daemonState: "idle"
    property string connectedDevice: ""
    property string connectedIP: ""
    property var deviceList: []
    property string errorText: ""
    property var pendingCommands: (new Object())

    // Sorted device list: streaming device pinned to top, rest sorted by IP
    readonly property var sortedDeviceList: {
        var list = (root.deviceList || []).slice()
        list.sort(function(a, b) {
            var aStreaming = root.isStreaming && root.connectedIP === a.ip
            var bStreaming = root.isStreaming && root.connectedIP === b.ip
            if (aStreaming !== bStreaming) return aStreaming ? -1 : 1
            if (a.ip < b.ip) return -1
            if (a.ip > b.ip) return 1
            return 0
        })
        return list
    }

    readonly property string ctlBinary: "doubletake-ctl"
    readonly property bool isStreaming: root.daemonState === "streaming"
    readonly property bool isConnecting: root.daemonState === "connecting"
    readonly property bool needsPIN: root.daemonState === "pin_required"
    readonly property bool isBusy: root.daemonState === "discovering" || root.daemonState === "connecting"

    Plasmoid.icon: root.isStreaming ? "video-display" : "video-display-symbolic"
    Plasmoid.status: root.isStreaming
                     ? PlasmaCore.Types.ActiveStatus
                     : PlasmaCore.Types.PassiveStatus

    toolTipMainText: root.isStreaming ? "Mirroring to " + root.connectedDevice : "AirPlay Mirroring"
    toolTipSubText: root.isStreaming ? "Click to manage" : "No active session"

    // --- Daemon communication ---

    P5Support.DataSource {
        id: executable
        engine: "executable"
        connectedSources: []

        onNewData: function(source, data) {
            disconnectSource(source)
            var stdout = (data["stdout"] || "").trim()
            if (stdout === "") {
                root.handleResponse(source, {ok: false, error: "Empty response"})
                return
            }
            try {
                var resp = JSON.parse(stdout)
                root.handleResponse(source, resp)
            } catch (e) {
                root.handleResponse(source, {ok: false, error: "Parse error"})
            }
        }
    }

    function runCtl(args, action) {
        var cmd = root.ctlBinary + " " + args.join(" ")
        if (!root.pendingCommands) root.pendingCommands = new Object()
        root.pendingCommands[cmd] = action
        executable.connectSource(cmd)
    }

    function handleResponse(source, resp) {
        var action = root.pendingCommands[source]
        delete root.pendingCommands[source]

        if (action === "status") {
            if (resp.ok) {
                root.daemonState = resp.state || "idle"
                root.connectedDevice = resp.device || ""
                root.connectedIP = resp.device_ip || ""
                root.errorText = ""
            } else {
                root.daemonState = "idle"
                root.connectedDevice = ""
                root.connectedIP = ""
            }
        } else if (action === "discover") {
            if (resp.ok && resp.devices) {
                root.deviceList = resp.devices
            } else {
                root.errorText = resp.error || "Discovery failed"
            }
            root.runCtl(["status"], "status")
        } else if (action === "connect" || action === "pin") {
            if (!resp.ok) {
                root.errorText = resp.error || "Connection failed"
            }
            root.runCtl(["status"], "status")
        } else if (action === "disconnect") {
            root.runCtl(["status"], "status")
        }
    }

    // Poll daemon status + device list
    Timer {
        id: statusTimer
        interval: 3000
        running: true
        repeat: true
        triggeredOnStart: true
        onTriggered: {
            root.runCtl(["status"], "status")
            root.runCtl(["devices"], "discover")
        }
    }

    // --- UI ---

    switchWidth: Kirigami.Units.gridUnit * 10
    switchHeight: Kirigami.Units.gridUnit * 10

    compactRepresentation: Kirigami.Icon {
        source: Plasmoid.icon
        active: compactMouse.containsMouse

        MouseArea {
            id: compactMouse
            anchors.fill: parent
            hoverEnabled: true
            acceptedButtons: Qt.LeftButton | Qt.MiddleButton
            onClicked: function(mouse) {
                if (mouse.button === Qt.MiddleButton) {
                    // Quick toggle: disconnect if streaming, else connect to first device
                    if (root.isStreaming) {
                        root.runCtl(["disconnect"], "disconnect")
                    } else if (root.deviceList.length > 0) {
                        root.runCtl(["connect", root.deviceList[0].ip], "connect")
                    }
                } else {
                    root.expanded = !root.expanded
                }
            }
        }
    }

    fullRepresentation: PlasmaExtras.Representation {
        Layout.preferredWidth: Kirigami.Units.gridUnit * 20
        Layout.minimumWidth: Kirigami.Units.gridUnit * 16
        Layout.preferredHeight: Kirigami.Units.gridUnit * 20
        Layout.maximumHeight: Kirigami.Units.gridUnit * 24

        collapseMarginsHint: true

        ColumnLayout {
            id: mainColumn
            anchors.fill: parent
            spacing: 0

            // Header bar: title + refresh button
            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: Kirigami.Units.smallSpacing
                Layout.rightMargin: Kirigami.Units.smallSpacing
                Layout.topMargin: Kirigami.Units.smallSpacing
                PlasmaExtras.Heading {
                    Layout.fillWidth: true
                    level: 4
                    text: "AirPlay Devices"
                }
                Controls.ToolButton {
                    icon.name: "view-refresh"
                    display: Controls.ToolButton.IconOnly
                    Controls.ToolTip.text: "Refresh devices"
                    Controls.ToolTip.visible: hovered
                    enabled: !root.isBusy
                    onClicked: {
                        root.runCtl(["discover"], "discover")
                    }
                }
            }

            Kirigami.Separator {
                Layout.fillWidth: true
            }

            // PIN input section (shown when device requires pairing)
            ColumnLayout {
                Layout.fillWidth: true
                Layout.margins: Kirigami.Units.smallSpacing
                visible: root.needsPIN
                spacing: Kirigami.Units.smallSpacing

                PlasmaComponents.Label {
                    Layout.fillWidth: true
                    text: "Enter the PIN shown on " + (root.connectedDevice || "the device")
                    wrapMode: Text.WordWrap
                    horizontalAlignment: Text.AlignHCenter
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Kirigami.Units.smallSpacing

                    Controls.TextField {
                        id: pinField
                        Layout.fillWidth: true
                        placeholderText: "0000"
                        maximumLength: 4
                        inputMethodHints: Qt.ImhDigitsOnly
                        horizontalAlignment: Text.AlignHCenter
                        font.pointSize: Kirigami.Theme.defaultFont.pointSize * 1.2
                        onAccepted: {
                            if (pinField.text.length === 4) {
                                root.runCtl(["pin", pinField.text], "pin")
                                pinField.text = ""
                            }
                        }
                    }

                    Controls.ToolButton {
                        icon.name: "dialog-ok-apply"
                        enabled: pinField.text.length === 4
                        onClicked: {
                            root.runCtl(["pin", pinField.text], "pin")
                            pinField.text = ""
                        }
                    }

                    Controls.ToolButton {
                        icon.name: "dialog-cancel"
                        onClicked: {
                            pinField.text = ""
                            root.runCtl(["disconnect"], "disconnect")
                        }
                    }
                }
            }

            // Error banner
            RowLayout {
                Layout.fillWidth: true
                Layout.margins: Kirigami.Units.smallSpacing
                visible: root.errorText !== ""
                spacing: Kirigami.Units.smallSpacing

                Kirigami.Icon {
                    implicitWidth: Kirigami.Units.iconSizes.smallMedium
                    implicitHeight: Kirigami.Units.iconSizes.smallMedium
                    source: "dialog-warning"
                }

                PlasmaComponents.Label {
                    Layout.fillWidth: true
                    text: root.errorText
                    color: Kirigami.Theme.negativeTextColor
                    wrapMode: Text.WordWrap
                    font.pointSize: Kirigami.Theme.smallFont.pointSize
                }
            }

            // Device list (scrollable, streaming devices pinned to top)
            ListView {
                id: deviceListView
                Layout.fillWidth: true
                Layout.fillHeight: true
                model: root.sortedDeviceList
                clip: true
                boundsBehavior: Flickable.StopAtBounds

                delegate: PlasmaComponents.ItemDelegate {
                    id: deviceDelegate
                    width: deviceListView.width
                        topPadding: Kirigami.Units.smallSpacing
                        bottomPadding: Kirigami.Units.smallSpacing

                        readonly property bool isThisDeviceStreaming: root.isStreaming && root.connectedIP === modelData.ip
                        readonly property bool isThisDeviceConnecting: root.isConnecting && root.connectedIP === modelData.ip

                        contentItem: RowLayout {
                            spacing: Kirigami.Units.smallSpacing

                            // Device icon
                            Kirigami.Icon {
                                implicitWidth: Kirigami.Units.iconSizes.smallMedium
                                implicitHeight: Kirigami.Units.iconSizes.smallMedium
                                source: "video-television"
                            }

                            // Device name + model
                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 0

                                PlasmaComponents.Label {
                                    Layout.fillWidth: true
                                    text: modelData.name
                                    elide: Text.ElideRight
                                    font.bold: deviceDelegate.isThisDeviceStreaming
                                }

                                PlasmaComponents.Label {
                                    Layout.fillWidth: true
                                    text: modelData.model + " · " + modelData.ip
                                    elide: Text.ElideRight
                                    font: Kirigami.Theme.smallFont
                                    opacity: 0.6
                                }
                            }

                            // Streaming indicator (checkmark when connected)
                            Kirigami.Icon {
                                implicitWidth: Kirigami.Units.iconSizes.smallMedium
                                implicitHeight: Kirigami.Units.iconSizes.smallMedium
                                source: "checkmark"
                                visible: deviceDelegate.isThisDeviceStreaming
                            }

                            // Busy spinner when connecting
                            Controls.BusyIndicator {
                                implicitWidth: Kirigami.Units.iconSizes.smallMedium
                                implicitHeight: Kirigami.Units.iconSizes.smallMedium
                                running: deviceDelegate.isThisDeviceConnecting
                                visible: deviceDelegate.isThisDeviceConnecting
                            }

                            // Connect / Disconnect button
                            Controls.ToolButton {
                                icon.name: deviceDelegate.isThisDeviceStreaming ? "media-playback-stop" : "media-playback-start"
                                display: Controls.ToolButton.IconOnly
                                Controls.ToolTip.text: deviceDelegate.isThisDeviceStreaming ? "Stop mirroring" : "Mirror to " + modelData.name
                                Controls.ToolTip.visible: hovered
                                enabled: !root.isBusy
                                onClicked: {
                                    if (deviceDelegate.isThisDeviceStreaming) {
                                        root.runCtl(["disconnect"], "disconnect")
                                    } else {
                                        root.connectedIP = modelData.ip
                                        root.runCtl(["connect", modelData.ip], "connect")
                                    }
                                }
                            }
                        }

                        onClicked: {
                            if (deviceDelegate.isThisDeviceStreaming) {
                                root.runCtl(["disconnect"], "disconnect")
                            } else if (!root.isBusy) {
                                root.connectedIP = modelData.ip
                                root.runCtl(["connect", modelData.ip], "connect")
                            }
                        }
                    }

                    PlasmaExtras.PlaceholderMessage {
                        anchors.centerIn: parent
                        width: parent.width - Kirigami.Units.gridUnit * 4
                        visible: root.deviceList.length === 0
                        text: root.isBusy ? "Searching for devices…" : "No AirPlay devices found"
                        iconName: "video-television"
                    }
                }
            }
        }
    }

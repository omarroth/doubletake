# doubletake KDE Plasma System Tray Applet

A Plasma 6 system tray widget for controlling AirPlay screen mirroring via the doubletake daemon.

## Prerequisites

- KDE Plasma 6 (Plasma 5 should also work with minor QML import adjustments)
- `doubletake` running (provides the Unix socket control interface)
- `doubletake-ctl` on your `$PATH` (the applet shells out to it)

## Install

```sh
# Build the daemon and ctl binaries
cd /path/to/doubletake
go build -o doubletake ./cmd/doubletake
go build -o doubletake-ctl ./cmd/doubletake-ctl
sudo install -m755 doubletake doubletake-ctl /usr/local/bin/

# Install the plasmoid
kpackagetool6 -t Plasma/Applet -i plasmoid/
# Or for development (symlink, auto-reloads):
kpackagetool6 -t Plasma/Applet -i plasmoid/ -p
```

To update after changes:
```sh
kpackagetool6 -t Plasma/Applet -u plasmoid/
```

To remove:
```sh
kpackagetool6 -t Plasma/Applet -r org.doubletake.plasmoid
```

## Usage

1. Start the daemon:
   ```sh
   doubletake -creds ~/.config/doubletake/credentials.json &
   ```

2. Add "doubletake" to your system tray (right-click tray → Configure System Tray → Entries)

3. The icon shows:
   - **Dim** — idle, no active mirroring
   - **Active** — currently mirroring to a device

4. Click the tray icon to:
   - **Discover** AirPlay devices on your network
   - **Connect** to a device from the list
   - **Disconnect** from the current session

5. Middle-click the icon for quick toggle (connect/disconnect).

## Autostart

Create a systemd user service for the daemon:

```ini
# ~/.config/systemd/user/doubletake.service
[Unit]
Description=doubletake AirPlay Mirroring Daemon
After=graphical-session.target

[Service]
ExecStart=/usr/local/bin/doubletake -creds %h/.config/doubletake/credentials.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=graphical-session.target
```

```sh
systemctl --user enable --now doubletake.service
```

## Architecture

```
┌─────────────────┐     JSON/Unix socket      ┌──────────────────┐
│  Plasma Applet  │ ──── doubletake-ctl ─────▶ │ doubletake │
│  (QML/JS)       │                            │ (Go)             │
└─────────────────┘                            └──────────────────┘
                                                  │
                                                  ▼
                                              AirPlay protocol
                                              (mDNS, RTSP, FairPlay,
                                               H.264 streaming)
```

The applet runs `doubletake-ctl` as a subprocess to communicate with the daemon.
The daemon manages the full AirPlay lifecycle (discovery, pairing, FairPlay, mirroring).

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
   doubletake -daemonize -creds ~/.config/doubletake/credentials.json &
   ```

2. Add "doubletake" to your system tray (right-click tray → Configure System Tray → Entries)

3. The icon shows:
   - **Dim** — idle, no active mirroring
   - **Active** — currently mirroring to a device

4. Click the tray icon to:
   - **Discover** AirPlay devices on your network
   - **Connect** to one or more devices from the list
   - **Disconnect** a specific device from its row button
   - **Mute/Unmute** mirrored audio for all active streams
   - Enter the receiver credential once when requested. An on-screen PIN uses a
     visible four-digit field; a configured receiver password uses an
     unrestricted masked field and does not display a PIN on the receiver.

5. Middle-click the icon for quick toggle (connect/disconnect).

## Autostart

`make install` installs a systemd user service for the daemon. Enable it with:

```sh
systemctl --user enable --now doubletake.service
```

## Architecture

```
┌─────────────────┐     JSON/Unix socket      ┌──────────────────┐
│  Plasma Applet  │ ──── doubletake-ctl ────> │ doubletake       │
│  (QML/JS)       │                           │ (Go)             │
└─────────────────┘                           └──────────────────┘
                                                  │
                                                  v
                                              AirPlay protocol
                                              (mDNS, RTSP, FairPlay,
                                              H.264 streaming)
```

The applet runs `doubletake-ctl` as a subprocess to communicate with the daemon.
The daemon reports whether each pending credential is an on-screen PIN or a
configured password. The applet submits it to that specific receiver with
`doubletake-ctl connect TARGET CREDENTIAL`, so concurrent connection flows do
not consume one another's credentials. The daemon manages the full AirPlay
lifecycle (discovery, pairing, FairPlay, mirroring).

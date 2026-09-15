# Run a node at login

A machine that should be reachable whenever it is on (a home server, a media box, a relative's desktop)
is unreachable after every reboot until someone starts `swoosh serve` again. Point the OS service manager
at that same `serve` line, and it starts at login and restarts on its own.

Everything below runs on the machine that should stay reachable. The examples serve a
[gated](../keys.md#the-gate) shell; swap in the `serve` line that machine should run
([serve](../reference/commands/serve.md) covers every service form).

## On Linux: a systemd user service

Save the unit as `~/.config/systemd/user/swoosh.service`:

```ini
[Unit]
Description=swoosh node
[Service]
ExecStart=%h/.local/bin/swoosh serve ssh=sshd:
Restart=always
[Install]
WantedBy=default.target
```

Then enable it:

<!-- manual: runs on the machine that stays reachable, not here -->
```console
$ systemctl --user enable --now swoosh
$ sudo loginctl enable-linger "$USER"   # start it at boot, before anyone logs in
```

## On macOS: a launchd agent

Save the agent as `~/Library/LaunchAgents/com.theia.swoosh.plist` (the `ProgramArguments` path is the
installed `swoosh`):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.theia.swoosh</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/you/.local/bin/swoosh</string>
    <string>serve</string>
    <string>ssh=sshd:</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
```

Then load it into your login session:

<!-- manual: runs on the machine that stays reachable, not here -->
```console
$ launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.theia.swoosh.plist
```

## The limit

The service manager keeps the node up: it starts it at login or boot and restarts it when the process
exits, so `kill` does not stop it. Disable it for good with `systemctl --user disable --now swoosh`
(Linux) or `launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.theia.swoosh.plist` (macOS).

## Next

- [Remote IT for a relative](grandma-it.md) the same service on a machine you run for someone else.
- [Family media center](family-media-center.md) a box that has to stay up for the household.
- [Commands](../reference/commands.md#serve) serve, and every service form.

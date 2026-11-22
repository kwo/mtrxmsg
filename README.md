# mtrxmsg

mtrxmsg sends text messages to Matrix rooms and reads recent messages from them. It supports encrypted rooms and browser sign-in over SSH.

## Build and test

Use Go 1.27.4 or later. The build uses the pure-Go Olm backend and does not require cgo.

```sh
go tool task build
go tool task test
go tool task lint
```

## Sign in

1. Run `./mtrxmsg login --homeserver https://matrix.example.com`. Use the URL of your Matrix homeserver.
2. Open the sign-in URL in your browser.
3. After sign-in, run `./mtrxmsg whoami` to see the user and device IDs.

If the browser and CLI run on different machines, [paste the callback URL on the CLI host](DESIGN.md#paste-the-callback-url-no-tunnel). No SSH tunnel is necessary.

## Send and read messages

```sh
./mtrxmsg room list
./mtrxmsg room join '#example:matrix.example.com'
./mtrxmsg room info '#example:matrix.example.com'
./mtrxmsg send '#example:matrix.example.com' 'Hello'
./mtrxmsg read '#example:matrix.example.com' --limit 20
```

You can use a room ID instead of a room alias. `read` includes your own messages and shows the oldest of the selected messages first.

## Verify an encrypted device

1. Run `./mtrxmsg device verify`.
2. In a verified Matrix client such as Element, start verification for the device ID that mtrxmsg shows.
3. Compare the emoji or numbers. If the values match, confirm in both clients.

`read` shows `[cannot decrypt]` for messages without readable content. Verification does not recover older room keys from key backup.

## Session and diagnostics

The session and encryption database are private files in `$XDG_DATA_HOME/mtrxmsg`. If `XDG_DATA_HOME` is not set, mtrxmsg uses `~/.local/share/mtrxmsg`. `./mtrxmsg logout` revokes the session before it removes these files.

Run `./mtrxmsg version` to show the version. Use `-vv` to include commit and runtime details. Run `./mtrxmsg --help` to see the commands and options.

See [DESIGN.md](DESIGN.md) for the architecture and acceptance checks.

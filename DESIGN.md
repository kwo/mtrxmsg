# mtrxmsg design

[Project overview](README.md)

## First-release decisions

- Sign-in over SSH is required. The CLI runs on a remote host, and the browser runs on a different machine.
- Encrypted history uses the keys that the device receives. The CLI marks messages that it cannot decrypt. Key-backup recovery is outside the first release.
- The CLI uses mautrix-go's default device trust policy without overrides.
- `CGO_ENABLED=0` is a release requirement, including for encrypted messaging. A build that requires cgo does not meet the requirement.

## Project layout

The Go module path is `github.com/kwo/mtrxmsg`. The executable entry point is `main.go` in the project root. Its package is `main`.

All other Go packages live under `pkg/` and are importable by other modules. Do not use an `internal/` directory.

| Path | Planned responsibility |
| --- | --- |
| `main.go` | Start the Cobra CLI and return its exit status. |
| `go.mod` | Declare the module path, dependencies, and tools. |
| `Taskfile.yml` | Define build, test, and lint tasks. |
| `pkg/cli/` | Define Cobra commands and connect them to the library. |
| `pkg/matrix/` | Implement Matrix commands, including session storage and encryption. |
| `pkg/version/` | Provide build and runtime version information. |

The build command is `CGO_ENABLED=0 go build -tags goolm -o mtrxmsg .`. There is no `cmd/mtrxmsg/` directory.

### Command and library boundary

Each application command calls an exported library operation. Matrix commands call `pkg/matrix`. The `version` command calls `pkg/version`.

Cobra handlers parse flags and arguments, pass the command context to the library, and format results and errors. The library validates operation inputs and implements the workflows. Library operations do not import Cobra or write directly to standard output or standard error.

For interactive steps, the library passes data to the caller. For example, login gives the CLI the sign-in URL to print while the library waits for the OAuth callback.

## Dependencies

- Cobra (`github.com/spf13/cobra`) for the command-line interface.
- mautrix-go (`maunium.net/go/mautrix`, validated at `v0.33.0`) for the Matrix Client-Server API. Its `cryptohelper` package supports end-to-end encrypted rooms.
- `modernc.org/sqlite` (validated at `v1.63.0`) for persistent encryption state. This SQLite driver does not require cgo.

Build and test tasks that compile encryption code must set `CGO_ENABLED=0` and use `-tags goolm` with mautrix-go `v0.33.0`.

Open the crypto database with the modernc `sqlite` driver. Wrap the connection with `dbutil.NewWithDB` and pass it to `cryptohelper`. Do not pass a path to `cryptohelper`: that selects the cgo-based `sqlite3-fk-wal` driver.

## Tools

mtrxmsg will declare these tools in the `tool` block of `go.mod`:

- Go Task (`github.com/go-task/task/v3/cmd/task`): `go tool task` runs tasks from `Taskfile.yml`.
- golangci-lint (`github.com/golangci/golangci-lint/v2/cmd/golangci-lint`): `go tool golangci-lint run` lints Go code.

Use `go get -tool <package>@<version>` to add each tool to `go.mod`. Once declared, the tools run through `go tool` without a global install.

## Commands

| Planned command | Purpose |
| --- | --- |
| `mtrxmsg login --homeserver <url> [--callback-port <port>]` | Print an OIDC sign-in URL and wait for the callback. A tunnel requires a fixed port. |
| `mtrxmsg logout` | End the current Matrix session. |
| `mtrxmsg version` | Show the `mtrxmsg` version. |
| `mtrxmsg send <room> <message>` | Send a text message to a room by alias or ID. |
| `mtrxmsg read <room> --limit 20` | Read recent messages, including your own, and exit. Report messages that the client cannot decrypt. |
| `mtrxmsg room list` | List joined rooms with their names, aliases, and IDs where available. |
| `mtrxmsg room info <room>` | Show the room ID, alias, and encryption status. |
| `mtrxmsg room join <room>` | Join a room by alias or ID. |
| `mtrxmsg whoami` | Show the signed-in user, homeserver, and device ID. Do not show the access token. |
| `mtrxmsg device verify` | Verify the `mtrxmsg` device from another Matrix client such as Element. |

### Logging

The CLI uses `log/slog` with the standard text handler on standard error. It does not use `tint` or color. Logs do not contain tokens or OAuth callback codes, even at `DEBUG`.

The `log_level` environment variable sets the base level. It accepts `ERROR`, `WARN`, `INFO`, or `DEBUG`. If it is unset or empty, the base level is `ERROR`. If it contains an invalid value, the command reports an error before it does any work.

Each global `--verbose` or `-v` increases verbosity by one step, up to `DEBUG`. For example, `-vv` raises the default level to `INFO`. If `log_level=WARN`, one `-v` raises it to `INFO`.

### Version output

The CLI provides the `version` subcommand, not a `--version` flag. The command does not read the session, open the crypto database, or make network requests.

Like BaseRSS, `version` writes one line to standard output. At `ERROR` or `WARN`, it prints only the version. At `INFO` or `DEBUG`, it appends the eight-character commit hash, the UTC commit date (`YYYY-MM-DD`), and the Go runtime version.

```text
$ mtrxmsg version
v1.2.3
$ mtrxmsg -vv version
v1.2.3 3245e888 2026-03-31 go1.26.0
```

The build task stamps the version, Git commit hash, and Git committer date with Go linker `-X` flags. It follows BaseRSS: derive the version from `git describe --tags --always` and format commits after a `vX.Y.Z` tag as `vX.Y.Z.N`. Append `*` for staged, unstaged, or untracked changes. Unstamped builds use `devel` and `unknown` for the unavailable commit fields.

## Sign-in and session

### OAuth callback

The CLI will discover the Matrix OAuth endpoints and register as a public native client. The registered redirect URI is `http://127.0.0.1/callback`, without a port. The authorization and token requests will use the listener's actual port in the redirect URI.

The listener will bind to `127.0.0.1` before the CLI prints the sign-in URL. If `--callback-port` is absent, the OS will choose a port. If the requested port is unavailable, the CLI will report an error without printing a sign-in URL.

The CLI will use the authorization code flow with PKCE (`S256`) and request the Matrix API and device scopes. It will set `response_mode=query` so the HTTP handler can read the code and state. It will validate OAuth state before it exchanges the code. It will stop on timeout or Ctrl-C. After the exchange, it will call Matrix `whoami` before it saves the session.

On Skybox, Tuwunel sends the browser to Pocket ID and issues the Matrix credentials after sign-in. The CLI does not open a browser or ask for a Pocket ID password or passkey.

### Sign in over SSH

#### Paste the callback URL (no tunnel)

1. Connect to the CLI host with SSH.
2. Run the login command. Leave it open while you complete sign-in.

   ```sh
   mtrxmsg login --homeserver https://matrix.ostendorf.com
   ```

3. Open the printed sign-in URL in your browser.
4. After you approve sign-in, copy the full `http://127.0.0.1:<port>/callback?…` URL from the browser address bar. The browser can show a connection error because the listener runs on the CLI host.
5. Open a second terminal on the CLI host. Run the first command, paste the callback URL at the prompt, and press Enter. Then run the other two commands.

   ```sh
   IFS= read -r -s -p 'Paste the callback URL: ' callback_url; printf '\n'
   printf 'url = "%s"\n' "$callback_url" | curl --noproxy '*' -fsS --config -
   unset callback_url
   ```

6. Return to the first terminal for the login result.

The callback URL contains a one-time code. The commands do not put the URL in shell history or in the curl argument list.

#### Use an SSH tunnel (optional)

1. From the browser machine, start SSH with local port forwarding. This example runs the CLI on Skybox:

   ```sh
   ssh -o ExitOnForwardFailure=yes -L 127.0.0.1:8765:127.0.0.1:8765 skybox
   ```

2. On the remote host, run the CLI with the same callback port:

   ```sh
   mtrxmsg login --homeserver https://matrix.ostendorf.com --callback-port 8765
   ```

3. Open the printed sign-in URL in the browser on your machine. Keep the SSH connection open until the CLI reports success.

The browser returns to `127.0.0.1:8765` on its own machine. SSH forwards the callback to the CLI on the remote host. Neither end listens on a public interface.

### Session storage

The first release supports one session per local user. The session file stores the homeserver, OAuth client ID, Matrix user and device IDs, tokens, and token expiry. The CLI will restrict access to the session file and encryption database to that user.

The CLI will use the OAuth refresh grant and replace the session file as soon as it receives rotated credentials. Commands will not print tokens or callback codes. Logout will use the OAuth revocation endpoint before it deletes local session and encryption state. If revocation fails, the CLI will report the error and retain the local state.

## Message behavior

- The CLI resolves a room alias to a room ID. It uses a room ID directly.
- `send` checks the room encryption state before it sends a message. If the CLI cannot determine the state or encrypt a message in an encrypted room, it stops without sending plaintext.
- `read` returns the most recent messages in chronological order, including messages from the signed-in user. The default limit is 20.
- For an encrypted room, `read` processes available key updates within the command timeout. It uses the keys in the local store and the keys it receives during the command.
- `read` marks each message that it cannot decrypt and continues with the other messages. Device verification does not guarantee access to older messages.
- Command results go to standard output. Errors go to standard error. A command failure returns a nonzero exit status.

## Implementation plan

### 1. Root executable

- Add `go.mod`, root `main.go`, and the Cobra root command. Add help and wire the `version` subcommand to `pkg/version`.
- Add the `slog` handler and log level selection. Use the same effective level for logs and version output.
- Add `build`, `test`, and `lint` tasks. Declare Task and golangci-lint in `go.mod`. Stamp version metadata in the build task.

**Done:** The build and test tasks run from the root with `CGO_ENABLED=0`. Help and version work without a session or network. Tests cover log level selection, both version formats, and rejection of `--version`.

### 2. Compatibility tests

- Test OAuth metadata discovery, native client registration, and the callback through an SSH tunnel to the CLI host. Use Skybox Tuwunel and a browser on a separate machine.
- Test a pinned mautrix-go release with the pure-Go Olm backend and `modernc.org/sqlite`. Use a test room for an encrypted round trip and reopen the crypto store in another process.

**Done:** The forwarded callback returns Matrix credentials that pass `whoami`. The cgo-free test sends and decrypts encrypted messages and can reuse its crypto store after restart. Both checks must pass before work on the full command set.

### 3. Session commands

- Add `login`, `whoami`, and `logout`. Use the same callback handler for same-machine sign-in and sign-in over SSH.
- Add private session storage and OAuth token refresh. Keep the Matrix device ID across commands.

**Done:** A second process can use the saved session after login. Automated tests cover callback state rejection, timeout, credential rotation, and retention of local state if revocation fails.

### 4. Rooms and unencrypted messages

- Add the room commands and alias resolution. Add one-shot `send` and `read` for unencrypted rooms.
- Make `send` reject encrypted rooms until encrypted sends are available.

**Done:** A user can send by alias and read the same message by room ID. Automated tests cover invalid arguments, read limits and ordering, and refusal to send plaintext to an encrypted room.

### 5. Encrypted messages

- Add `device verify`, the persistent crypto store, and key sync. Use the saved Matrix device and mautrix-go's default trust policy.
- Add encrypted `send` and `read`. Make sure that each command can stop without a continuous sync process.

**Done:** An Element user can verify the device and exchange encrypted messages with the CLI across restarts. The test binary builds with `CGO_ENABLED=0`. Automated tests cover missing-key markers and refusal to send plaintext after an encryption error.

Test Matrix workflows through the library with a local HTTP test server and temporary storage. Test CLI argument parsing, delegation, and output separately. The Skybox and Element checks are manual.

`read --follow`, device-code login, password login, key-backup recovery, and multiple local sessions are outside the first release.

## Compatibility results (2026-11-22)

| Check | Result | Evidence |
| --- | --- | --- |
| Live Skybox discovery and authorization start | Pass | Tuwunel `2.0.0` exposed Matrix OAuth metadata. It accepted native client registration (HTTP `201`) and a fixed-port PKCE request, then redirected to Pocket ID. |
| Live SSH callback transport | Pass | An HTTP request on the local machine reached a loopback listener on Skybox. The listener accepted the synthetic callback with matching state and rejected the one with incorrect state. |
| Full OAuth exchange through SSH against disposable Tuwunel | Pass | A local HTTP client signed in to a test account and approved consent. An SSH tunnel carried the real callback to the probe on Skybox. The probe exchanged the code and confirmed the Matrix user and device with `whoami`. Refresh rotated both tokens. Revocation invalidated the new access token. |
| Live Pocket ID sign-in through SSH | Pass | The user approved passkey sign-in in a browser. The callback reached Skybox through SSH with matching state. The probe exchanged the code and confirmed the Matrix identity and device with `whoami`. Revocation invalidated the test access token. |
| cgo-free encrypted round trip | Pass | Two devices exchanged messages through a disposable Tuwunel `2.0.0` server with no trust overrides. The probe confirmed `m.room.encrypted` events with no plaintext body. A new process reopened the SQLite store and decrypted a message without syncing its key again. |

The crypto probe used Go `1.27.4` on Linux AMD64. `CGO_ENABLED=0 go build -tags goolm` produced a statically linked binary. The same build without `goolm` failed because cgo was unavailable for `libolm`.

The disposable server used the same Tuwunel binary as Skybox. It used a fresh database and test accounts, not the live server's data. Both phase 2 compatibility checks passed with temporary probes.

### CLI acceptance

- The automated tests cover OAuth callback validation, token rotation, revocation errors, room and message commands, persistent encryption state, and SAS device verification.
- The built CLI on Skybox completed OAuth sign-in through an SSH tunnel to a disposable Tuwunel server. A second process confirmed the saved device with `whoami`.
- On disposable Tuwunel, the CLI exchanged encrypted messages across restarts. The server received encrypted events with no plaintext body.
- On disposable Tuwunel, refresh rotated both tokens. Logout revoked the refreshed session and removed the local session and crypto files.
- The user confirmed live Pocket ID sign-in and Element device verification with the built CLI.
- The local and Skybox CLI devices exchanged fresh encrypted messages in both directions on the live server. Older messages without keys still show `[cannot decrypt]`.

## References

- BaseRSS CLI logging and version output: `../baserss/docs/design/cli/overview.md`
- BaseRSS version stamping: `../baserss/Taskfile.yml`
- Matrix Commander (Python): `~/dev/TRACKING/matrix-commander`
- Matrix Commander RS (Rust): `~/dev/TRACKING/matrix-commander-rs`
- [Matrix Client-Server API](https://spec.matrix.org/latest/client-server-api/)
- [Tuwunel OIDC authorization](https://matrix-construct.github.io/tuwunel/authentication/oidc-server.html)

# Deployment assets

`hepta-runtime.service` runs the controller as the dedicated `hepta-runtime`
account and exposes MCP only on `127.0.0.1:8787`. The installer creates a
root-owned, group-readable 256-bit token at `/etc/hepta-runtime/mcp-token`; the
MCP endpoint requires it in `X-Hepta-Runtime-Token`.

`install-target.sh` creates the same unprivileged account on a Linux target,
installs the controller public key with forwarding disabled, creates isolated
state/workspace directories, and enables a user systemd manager for transient
job units. Review existing `AllowUsers` and `Match` rules before access.

`install-controller.sh` installs a versioned runtime binary, policy and systemd
unit. It does not create OpenAI credentials or enable the tunnel service.

`install-tunnel-client.sh` builds the pinned OpenAI tunnel-client v0.0.19 source
at `01d67bb4da0d8359b808b4761f8db171ab682cd7` with the checksummed patch in
`tunnel-client-source.json`. It requires Python 3.11+, Git, and Go; the build pins
Go 1.27.3 and preserves the upstream `go.mod`/`go.sum`. The default artifact is the
runtime flavor; `--flavor full` retains the full CLI and embedded admin UI used
by Homebrew installations. The installer only writes the binary and its build
receipt; service activation remains a separate deployment step.

The patch adds explicit `mcp.max_concurrent_requests: 0` support. It maps zero
to ants v2.11.3's native unlimited pool (`-1`), whose dispatcher skips capacity
waiting. Positive settings retain their original behavior, and negative settings
are rejected. Upstream's omitted-value default remains 10; Hepta profiles must
set zero explicitly. Zero is also reported by dispatcher capacity metrics and
health details. Authentication, request ownership, cancellation, response
handling, and shutdown draining retain the upstream implementation.

Use an HTTP MCP binding with this zero setting. The system provisioning script
and `tunnel.env.example` already target the native loopback HTTP service and
provide its token through both normal and discovery headers. The read-only
`chatgpt/hepta-chatgpt.yaml` profile instead uses the existing private Unix HTTP
bridge; `hepta-openai-tunnel.service` starts that bridge and supplies its socket
path. This keeps the original seven-tool allowlist and local backend credential
handling. The full CLI patch makes `doctor` probe that same configured Unix
socket, including OAuth metadata absence checks.

The upstream generic stdio forwarding wrapper remains a compatibility path
with one request lifecycle at a time. Its response-identity lock and late-reply
tombstones are retained. Setting zero only removes the dispatcher pool limit;
it does not make this generic stdio wrapper concurrent. Do not select an
`mcp.commands` binding for an unbounded Hepta deployment.

Build reviewable artifacts without replacing an installed client:

```sh
./deploy/install-tunnel-client.sh --test --output ./dist/tunnel-client-runtime
./deploy/install-tunnel-client.sh --flavor full --goos darwin --goarch arm64 --output ./dist/tunnel-client-macos-arm64
```

Use `--go-bin /path/to/go` when Go is not on PATH, or `--source-dir /path/to/tunnel-client`
to reuse a local Git checkout at the pinned commit. Local edits are excluded from
the build: the installer creates a fresh checkout and verifies the patch checksum
before applying it. `--install-dir` changes the installation destination; its
default is `/usr/local/bin`. The adjacent `.build.json` records the source commit,
patch digest, target, build flavor, Go version, and binary digest. The patched
binary version includes the `.hepta-unbounded1` revision suffix.

Create the tunnel ID/runtime API key separately, then
install `/etc/hepta-runtime/tunnel.env` with owner `root:hepta-runtime` and mode 0640. The environment file supplies the control-plane credentials, loopback MCP target, static MCP token headers, and loopback health listener. Then enable the tunnel unit and require both its systemd state and `http://127.0.0.1:8788/health?details=true` to be healthy before use.

Never commit runtime API keys, private SSH keys or generated tunnel profiles.
Desktop Commander remains the rescue path until local MCP discovery, tunnel
health, reconnect, controller restart, target reboot and rollback tests pass.

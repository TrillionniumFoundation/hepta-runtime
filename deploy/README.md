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

`install-tunnel-client.sh` installs the checksum-pinned official OpenAI runtime
client release. Create the tunnel ID/runtime API key separately, initialize a
profile at `/etc/hepta-runtime/tunnel-profile.yaml`, install `tunnel.env` with
mode 0640, include the static MCP token header shown in `tunnel.env.example`, run
`tunnel-client doctor`, and only then enable the tunnel unit.

Never commit runtime API keys, private SSH keys or generated tunnel profiles.
Desktop Commander remains the rescue path until local MCP discovery, tunnel
health, reconnect, controller restart, target reboot and rollback tests pass.

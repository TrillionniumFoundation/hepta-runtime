# ChatGPT Secure MCP Tunnel deployment

This document describes the repository's seven-tool read-only tunnel profile.
An installed full-operator profile has a separate tool contract and keeps its
own authenticated HTTP target.

## Architecture

The custom MCP app reaches the outbound Secure MCP Tunnel client, which sends
HTTP requests to the read-only bridge over an account-owned Unix socket. The
bridge forwards permitted requests to the existing runtime at
`http://127.0.0.1:8790/mcp`.

There is no inbound Internet listener. tunnel-client initiates outbound HTTPS
to OpenAI. The private runtime token never becomes ChatGPT authentication: the
bridge reads the existing private token file locally and injects the runtime
X-Hepta-Runtime-Token header only on the loopback hop. Incoming Authorization,
Cookie, Forwarded, and similar caller credentials are not forwarded.

MCP requests, tool arguments, results, and stream events still traverse the
OpenAI product/tunnel path. This design keeps the backend credential local; it
does not claim that MCP payloads stay outside OpenAI.

## Read-only facade

The first ChatGPT contract exposes exactly seven tools:

- host_list
- process_status
- file_info
- stream_handoff_list
- stream_handoff_status
- stream_handoff_read
- document_read

Tool discovery is rewritten so all seven advertise read-only, non-destructive,
idempotent, closed-world annotations. Every tools/call is checked separately.
A direct attempt to call shell_start, host_signal, sudo_start, process_start,
pty_write, binary/document writes, or an unknown tool is rejected before the
private runtime is contacted.

The profile uses `mcp.server_urls` with the logical URL `http://localhost/mcp`
and `unix_socket: env:HEPTA_CHATGPT_BRIDGE_SOCKET`.
`hepta-openai-tunnel.service` requires `hepta-chatgpt-bridge.service` and supplies
`%t/hepta-chatgpt/bridge.sock`. The bridge service creates its runtime directory
with mode 0700 and the socket with mode 0600. Filesystem ownership authorizes
the local tunnel client; the separate backend token authorizes the bridge's
loopback connection to the runtime.

Independent HTTP calls retain independent workers and original response
identities. `mcp.max_concurrent_requests: 0` selects the patched tunnel pool's
unlimited mode. Both HTTP and the zero setting are required for this policy.

The generic upstream stdio forwarding wrapper remains a compatibility path
with one request lifecycle at a time. Its response-ownership lock and late-reply
tombstones are preserved. A zero dispatcher setting alone does not remove that
serialization, so `mcp.commands` must not be used for an unbounded Hepta profile.
The Python bridge still supports direct stdio clients, but that does not change
an external client's wrapper.

## tunnel-client

Build the source-pinned v0.0.19 full CLI described in
[Deployment assets](../deploy/README.md). The source manifest pins the upstream
commit, Go toolchain and patch digest; the build receipt records the binary
digest. This profile's helper uses `doctor` and `admin`, so it requires the full
flavor rather than the runtime-only CLI.

The patch makes `doctor` honor the Unix socket during HTTP reachability and
OAuth metadata probes. The bridge returns 405 for `GET /mcp` and 404 for absent
metadata paths. Diagnostics check the same endpoint as the daemon. Earlier
stdio guidance worked around that diagnostic mismatch and should not be reused
for this profile.

Profile:

~~~
~/.config/tunnel-client/hepta-chatgpt.yaml
~~~

Local tunnel health/UI, once credentials are present:

~~~
http://127.0.0.1:8792/healthz
http://127.0.0.1:8792/readyz
http://127.0.0.1:8792/ui
~~~

The long-lived service is `hepta-openai-tunnel.service`. Its two systemd
`ConditionPathExists` gates keep it inactive without the real account values:

~~~
~/.config/hepta-chatgpt-tunnel/runtime-api-key
~/.config/hepta-chatgpt-tunnel/tunnel.env
~~~

OPENAI_ADMIN_KEY is never used by the long-lived service.

## Account-side bootstrap

The two values cannot be generated from the private host alone. In OpenAI
Platform:

1. Open Organization Tunnels settings and create a tunnel associated with the
   target ChatGPT workspace. The operator needs Tunnels Read + Manage.
2. Create a separate Restricted Runtime API key whose principal has Tunnels
   Read + Use. Do not use an admin key for the daemon.
3. On qian-qi, run:

~~~
~/.local/bin/hepta-chatgpt-tunnel-bind
~~~

The helper requires an interactive TTY. It will not accept secrets over argv or
a pipe. Paste the tunnel ID normally and the Runtime API key into the hidden
prompt. It writes both local files mode 0600, starts the private bridge, exports
its Unix socket path, and runs:

~~~
tunnel-client doctor --profile hepta-chatgpt --explain
~~~

then starts hepta-openai-tunnel.service and checks /healthz, /readyz, and the
detailed health endpoint.

## ChatGPT app creation

Only after /readyz is 200:

1. In ChatGPT web, enable developer mode.
2. Go to Plugins/Apps and add a custom MCP server.
3. Choose Connection: Tunnel.
4. Select the created tunnel or paste its tunnel_id.
5. Use Authentication: None for this app. The backend credential is injected
   locally by the facade and is not a ChatGPT credential.
6. Accept the risk warning and run Scan Tools.
7. The scan must show exactly the seven read-only tools above. Any write,
   signal, shell, sudo, PTY-write, binary-write, or document-write tool is a
   release blocker.
8. Create the app only after the scan matches.

This profile is intentionally read-only. Its catalog is enforced by the local
bridge and is independent of other capabilities a workspace may support.

## Golden tests

After creating the app:

1. Ask ChatGPT to use host_list and compare the result with the deployment's
   configured hosts.
2. Ask it to call stream_handoff_list with a small limit and summarize the
   retained sessions without changing anything.
3. Ask for stream_handoff_status or stream_handoff_read on one returned
   session.
4. Use file_info or document_read only on a known non-sensitive fixture.
5. Confirm no mutating tool appears in the tool picker. A direct JSON-RPC
   shell_start attempt against the facade must return -32601.

Do not use a production secret or sensitive document as the first golden test.

## Verification

Repository tests verify the profile, service dependencies and native HTTP
provisioning headers. The Unix HTTP regression holds 32 original read-only
calls at the fixture simultaneously, then checks every response identity,
private-token injection, session header and rejection of a mutating tool. It
runs against both packaged bridges. These isolated fixture services require
a host that permits Unix sockets:

```sh
python3 -m unittest discover -s tests -p tunnel_deployment_config_tests.py
python3 -m unittest discover -s tests -p chatgpt_bridge_http_tests.py
python3 -m unittest discover -s tests -p chatgpt_bridge_stdio_tests.py
```

The full CLI includes a regression that runs `doctor` against a real private
Unix HTTP endpoint. `install-tunnel-client.sh --flavor full --test` runs its
affected Go packages before building. Repository fixtures do not attest to an
installed binary, account provisioning or ChatGPT tool discovery; record the
deployed binary/configuration identities and run the golden tests against the
chosen profile.

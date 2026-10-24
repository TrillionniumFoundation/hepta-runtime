# ChatGPT Secure MCP Tunnel deployment

This is the final local integration layer between ChatGPT and the existing
hepta-runtime operator deployment. It deliberately does not modify the
runtime listener, token, SSH configuration, host authority, or Desktop
Commander service.

## Architecture

~~~
ChatGPT custom MCP app (read/fetch on Pro)
  -> OpenAI Secure MCP Tunnel
  -> tunnel-client v0.0.16 on qian-qi
  -> stdio read-only MCP facade (child of tunnel-client)
  -> http://127.0.0.1:8790/mcp
  -> existing hepta-runtime
~~~

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

The tunnel profile launches the facade directly over stdio. This avoids a DNS/probe mismatch observed when tunnel-client doctor validated a logical HTTP hostname before honoring the Unix-socket dial override. The stdio facade still talks only to the existing loopback runtime and retains MCP session/protocol state inside that one child process.

The previously installed `hepta-chatgpt-bridge.service` remains available as a local acceptance/debug surface on an account-owned Unix socket, but it is no longer required by `hepta-openai-tunnel.service`. The tunnel service depends only on the existing `hepta-runtime-operator.service`.

## tunnel-client

The local deployment currently uses `tunnel-client 0.0.16+5f99daab`, whose embedded git SHA resolves to the public `openai/tunnel-client` repository. The locally installed binary SHA256 is recorded in qualification evidence. An attempted downgrade to the latest tagged v0.0.15 release was abandoned before replacement because the local download path produced an incomplete archive/CDN denial; the existing binary was left unchanged.

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

The long-lived service is hepta-openai-tunnel.service. It is enabled but has
two systemd ConditionPathExists gates, so it remains inactive without the real
account values:

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
prompt. It writes both local files mode 0600, runs:

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

On ChatGPT Pro, this deployment is intentionally read/fetch only. Full MCP
write/modify support currently requires Business or Enterprise/Edu.

## Golden tests

After creating the app:

1. Ask ChatGPT to use host_list and list the configured hosts. The current
   runtime should return six configured hosts.
2. Ask it to call stream_handoff_list with a small limit and summarize the
   retained sessions without changing anything.
3. Ask for stream_handoff_status or stream_handoff_read on one returned
   session.
4. Use file_info or document_read only on a known non-sensitive fixture.
5. Confirm no mutating tool appears in the tool picker. A direct JSON-RPC
   shell_start attempt against the facade must return -32601.

Do not use a production secret or sensitive document as the first golden test.

## Current qualification

Local acceptance has already verified:

- anonymous direct access to the private runtime is not the supported path;
- the installed facade can authenticate to the existing runtime while ignoring
  a caller-supplied Authorization header;
- initialization and initialized notification handling;
- discovery exposes exactly seven read-only tools;
- host_list traverses facade -> runtime and returns all six configured hosts;
- shell_start is rejected by the facade;
- stream_handoff_list reaches the installed persistent stream broker;
- seven hosted-safe facade unit tests pass.

The only intentionally incomplete steps are OpenAI-account provisioning,
tunnel-client doctor with a real runtime key/tunnel ID, ChatGPT Scan Tools,
and ChatGPT-originated golden tool calls.

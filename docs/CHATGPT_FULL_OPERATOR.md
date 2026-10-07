# Hepta Runtime Full Operator — private-workspace contract

This is the private full-operation candidate. It does not replace the execution engine, claim a public Cloud Gateway is already deployed, or mark a local test as a ChatGPT-originated request. The old seven-tool readonly facade and live tunnel remain separate until an explicit deployment to the selected workspace is qualified.

## One execution engine and one full catalog

`deploy/contracts/hepta-runtime-full-operator-v1.json` captures all 46 tools of the currently installed native runtime, including their exact names, descriptions, input schemas and annotations. Nineteen operations are marked read-only and twenty-seven permit changes. Shell, PTY input, arbitrary permitted executable invocation, identity-aware external-PID signalling, temporary sudo, binary/document writes and stream-handoff writes are included. None is disguised as a read action to get through a client restriction.

`deploy/mcp_tool_contract.py` is transport-independent. It verifies the explicit file digest and canonical catalog digest, rejects duplicate tools and incomplete annotations, and checks that the native catalog has not drifted. The same contract can later be consumed by a public gateway; no second shell/process/file implementation is introduced here.

`deploy/chatgpt_full_operator.py` is the private stdio adapter. It reads the existing account-owned token locally and calls only the existing IPv4-loopback HTTP `/mcp` endpoint. It opens no public listener and accepts no inbound credentials, upstream URL, policy or hidden tool names from model arguments. Startup requires both a pinned contract-file SHA256 and an explicit full-operator acknowledgement.

At initialization it authenticates to the native backend, completes the native initialization notification, reads the actual catalog and compares the entire contract before admitting any action. Later discovery rechecks the contract and preserves the original annotations instead of overwriting them. A changed name/schema/description/annotation requires review and a new pinned contract. This is an interface pin, not a claim that the native code's behavior cannot change without a version update.

All execution still uses the configured host account, its existing paths/SSH/sudoers/PAM rights and native recovery semantics. This adapter neither grants OS privilege nor disables ChatGPT action confirmations. Full operator shell authority is intentionally powerful: anyone allowed to call it can exercise the selected account's permitted commands. Do not attach it to an untrusted or broadly shared workspace.

## Transport and uncertainty

The stdio protocol keeps session and protocol headers internal and never accepts an account token from a caller. It supports the explicit tools-only MCP transport surface, not arbitrary discovery/execution dispatch. Single JSON-RPC requests need response identities; batch requests and side-effecting notifications are refused. Empty SSE data heartbeats are skipped, while multiline data events are parsed as one message.

Request and response sizes are separately bounded at 4 MiB and 16 MiB. The larger request budget allows the native 1 MiB binary payload to be encoded as base64 without the old facade's 1 MiB JSON ceiling rejecting it. Operations can wait up to 150 seconds for a native response. Native job/PTY tools remain the correct way to execute long-running work; this is not an unbounded synchronous shell.

A transport failure after submitting a write is reported as `outcome=unknown`, with `automatic_retry=false`. The adapter never silently sends the same write again. Reconcile using the native job/request/upload identity and actual target state. Error messages do not include token contents, arguments or response bodies.

## Current deployment and account boundary

The source candidate and the actual installed backend must be distinguished. A successful facade test from qian-qi proves local stdio → authenticated runtime → target behavior. It does not prove a request originated from ChatGPT, a custom app exists, or the linked workspace has Business full-MCP permissions.

The existing tunnel metadata names a workspace UUID but does not identify its plan, administrator role or membership. The current plugin search did not return a usable Hepta app; that search is not an exhaustive enumeration of all other workspaces. No signed-in browser automation endpoint was available for inspecting the workspace UI. Before activation, the target Business administrator must identify the correct workspace and confirm its custom-MCP/write permissions and intended user access. A tunnel association alone is not evidence of those settings.

A staging-installer source write was blocked during this continuation before file creation. It was not reapplied through another command or installed by an alternative route. Consequently this source candidate is **not** the currently running tunnel adapter, and no full-tunnel service is claimed started. The existing readonly tunnel, private runtime and DC remain unchanged. An uninstalled activation draft, if left in the local worktree, is not part of the shipped contract or qualification.

## Required private endpoint acceptance

The target Business app should be named **Hepta Runtime Full Operator**, not Readonly. Its scanned tool definitions must match the contract digest and all 46 approved tool names. The correct scan includes `shell_start`, `sudo_start`, `host_signal`, `pty_write`, `binary_write`, `document_write` and their native write/destructive annotations. It must not add unreviewed tools, omit write tools while claiming full mode, or relabel writes as reads.

After the actual workspace app is installed and available to this ChatGPT session, execute a fresh isolated scratch workflow from that app: real shell pipeline/environment/redirection; an interactive PTY with Ctrl-C; a write/read/hash cycle; identity-checked signal delivery to a disposable PID; temporary existing sudo UID 0; and native job reconciliation after a transport interruption. Keep separate evidence for model-origin calls, local calls and tunnel transport health. Do not count a DC-started Python MCP client as the final ChatGPT test.

## Executed local acceptance

`tests/full_operator_facade_tests.py` covers catalog integrity/drift, exact full annotations, hidden-tool rejection, no pre-initialization side effects, loopback/private-token restrictions, SSE framing, large/malformed requests, stdio launch opt-in and an injected lost write response with exactly one backend effect. It also checks that the separate old readonly facade still blocks shell tools.

`tests/full_operator_acceptance.py` uses the existing installed native runtime without restarting it, DC or the live tunnel. It exercises selected configured hosts with only unique scratch directories and self-expiring test processes. It checks all 46 tools, native shell idempotency, a >1 MiB JSON binary write, DOCX write/edit/read, real PTY/Ctrl-C, stale external PID identity refusal, actual signal delivery, existing sudo UID 0, and a facade-only restart with a once-only durable native job.

Two initial failures are retained rather than relabelled: the first native initialize revealed an empty SSE heartbeat the new parser did not yet handle; the first Mac binary test used symlink `/tmp` instead of canonical `/private/tmp`, correctly rejected by the native no-symlink path policy. The parser and test fixture path were corrected without weakening the runtime policy or removing checks.

## Public gateway sequencing

Do not publish a public endpoint or submit a directory app before the private ChatGPT-origin acceptance passes. The shared contract module/catalog are ready for reuse, but OAuth user identity, tenant isolation, per-user device routing, revocation and outbound agent channels remain a subsequent product layer. A private single-account runtime token is not a public multi-tenant credential. Tools' existing OS execution/recovery logic remains in hepta-runtime, not copied into the gateway.

## Current official references

- Business developer/admin and full-MCP requirements: https://help.openai.com/en/articles/12584461
- Private tunnel associations and transport: https://developers.openai.com/api/docs/guides/secure-mcp-tunnels
- Custom MCP creation and read/write tools: https://developers.openai.com/api/docs/guides/custom-mcp-server
- App connection and testing versus public publication: https://developers.openai.com/plugins/deploy/connect-chatgpt

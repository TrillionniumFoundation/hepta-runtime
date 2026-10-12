# Support case — Hepta Runtime Full Operator MCP execution gate

Status: **ACTION-GATE HOLD**, 2026-10-12. Reproduction is limited to authorized private devices and non-sensitive scratch actions. This is a support request, **not** evidence that complete shell access was approved.

## Copyable support summary

> In ChatGPT web using GPT-6, the private **Hepta Runtime Full Operator** MCP app is installed and lists 46 tools. The app-specific permission is **Allow all actions**, the same setting as the installed **Remote Desktop Commander** app. Hepta's actual `host_list`, `file_info` and `stream_handoff_list` work. A separate non-read-only, non-destructive Hepta `workdir(reset=true)` also returned `{"action":"reset","success":true}`; tunnel accepted/completed counters both increased 20→21. However, a user-authorized scratch `shell_start` and a separate scratch-DOCX `document_write` request produced a ChatGPT tool dispatch error: **“此工具调用被 OpenAI 的安全检查屏蔽。请仔细检查你发送的内容。”** (blocked by OpenAI security check). Both had no successful native tool execution receipt. By contrast, a safe Desktop Commander `start_process` request (`/usr/bin/id -u`) returned UID 1000. What specific client-side/workspace/app/tool safety rule is responsible for this difference? What officially supported correction, consent step, review, or admin control (if any) applies? We will not relabel write tools as read-only or attempt to bypass the safety decision.

### Environment and expected behavior

- Product surface: ChatGPT **web**, GPT-6, text conversation; exact browser build, account entitlement and selected workspace role should be verified through support's account-side diagnostics. Do not infer Business entitlement from tunnel metadata alone.
- App: `Hepta Runtime Full Operator` (private MCP). The MCP tunnel is associated to one workspace; ask the workspace admin to provide its exact ID to Support privately, not by posting browser cookies.
- The existing six-host native hepta-runtime supports 46 explicitly enumerated tools. All preserve accurate annotations: 19 read-only, 27 potentially state-changing; shell has `readOnlyHint=false`, `destructiveHint=true`, `openWorldHint=true`. A DOCX creation tool is also explicitly state-changing/destructive. The successful `workdir` reset is state-changing but not destructive.
- Original shell request was scoped to a unique `/tmp` test directory and used a normal user account; original DOCX request used `expected_sha256=absent` on a unique temporary output. Neither targeted business data, accounts or secrets.
- ChatGPT app-specific permissions independently inspected: **Allow all actions** for Hepta and **Allow all actions** for Remote Desktop Commander. The global default `Allow low-risk actions` is overridden at the individual app level.
- The Desktop Commander app has its own command blocklist covering `sudo`, `su`, `shutdown`, `reboot`, `poweroff`, disk formatting, firewall changes, etc. Its safe terminal success does **not** prove unrestricted privileged Desktop Commander execution.
- Approximate first action-denial window: **2026-10-12, around 17:19–17:30 UTC+08**, from this ChatGPT conversation. Ask Support to inspect the exact tool-dispatch timestamps / request IDs in internal tracing.

### Separate resolved backend issue (do not confuse with safety gate)

A native loopback MCP session expiry previously caused Hepta read-only calls to return `-32603`. That was independently reproduced with an expired `Mcp-Session-Id` and fixed by **bounded, authenticated read-only catalog-preflight reinitialization**. Post-fix, thirty local adapter tests passed; three injected native expired-session checks each recovered and returned six hosts and all 46 tools. The corrected immutable adapter release is installed, and three ChatGPT-originated reading operations succeeded with tunnel delivery counters increasing by three, with zero dispatcher failures. The runtime and Desktop Commander processes were not restarted. This fix **did not affect tool annotations, permissions or the client safety decision**.

### Independent tunnel observation

- The full-operator tunnel is active, `/readyz = 200`, with `control-plane = ok/polling`.
- Native tool discovery returns all 46 tools and correct schemas; official 2026-07-28 JSON Schema checks passed for `server/discover` and `tools/list`.
- A dispatched response receiving HTTP 200 means the tunnel delivery was accepted; it **does not** prove the client accepted or ran a particular action.
- The tunnel deliberately does not log caller identities, arguments, credentials or tool payloads. If a call is rejected before entering the MCP transport, the tunnel cannot identify the platform's exact safety rule.
- Earlier one-off `tools/list -32603` during a UI scan is also separate; repeated local discovery probes passed. Client-side tool approval should be checked independently.

### Requested investigation from OpenAI Support

1. Locate the ChatGPT tool-dispatch event for the Hepta `shell_start` and `document_write` calls and confirm whether either was rejected **before** MCP transport, and what user-visible review path or supported policy correction exists.
2. Identify whether the decision depends on tool safety annotations, high-risk general-purpose process/file capabilities, app review status, session context, workspace permissions, product plan, or a separate safety policy. Do not disclose undisclosable internal details; a supported next step is sufficient.
3. Explain why the same configured app-specific permission permits `workdir(reset=true)` but not the two specific scratch actions, and whether a reviewed app package or admin approval is required for this private tunnel use case.
4. Indicate any safe debugging identifiers users can provide (request ID / time / conversation link) to correlate platform-side decisions without sharing secrets.
5. Confirm whether a Business workspace administrator needs to refresh/review/publish the 46-tool snapshot again, even though all 46 appear in this ChatGPT session.

### Attachments and sensitive-data hygiene

- Safe attachment: `docs/qualification/chatgpt-action-gate-snapshot-20261012.json`, generated by a whitelist-only read-only telemetry script.
- Support can use the dated ChatGPT conversation URL, redacted screenshot of the blocked call and exact error message. Include full workspace and tunnel identifiers through the private Support form **only if requested**.
- **Never attach:** OpenAI API keys, the local hepta-runtime bearer token, Authorization/Cookie headers, browser HAR containing authenticated headers, SSH keys, shell output with business data, or raw journal dumps.
- Plugin server source and tests are maintained in a private GitHub repository; support cannot assume public repository access.

## Engineering release gate

**Passed:** model-origin read-only tool calls and one model-origin benign non-read-only `workdir` reset. **Not passed:** ChatGPT-origin `shell_start`, PTY creation/input, `sudo_start`, writes and external PID signals. Native six-host isolated-local acceptance is not a substitute. Keep the public multi-user Cloud Gateway on HOLD until a legitimate complete end-to-end qualification and separate OAuth/tenant isolation work.

## Official references

- App permissions: https://help.openai.com/en/articles/11487775-connected-apps-in-chatgpt
- App troubleshooting and Support checklist: https://help.openai.com/en/articles/20001497-troubleshooting-plugins-apps-in-chatgpt
- Tool annotations: https://developers.openai.com/plugins/plan/tools
- Plugin guidelines: https://developers.openai.com/plugins/plugin-guidelines

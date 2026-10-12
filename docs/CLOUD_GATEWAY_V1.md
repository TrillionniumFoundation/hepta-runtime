# Hepta Runtime — public Cloud Gateway policy core (candidate)

**Status: offline policy prototype only. NO public HTTPS server, OAuth authorization
server, user enrollment service, outbound device agent, public plugin, or production
deployment has been created.** This module cannot currently receive MCP requests
from the internet or impersonate a user on a computer.

## Why this work now

The private v4 runtime has a frozen **50-tool native catalog** (19 read-only and
31 non-read-only); bounded ChatGPT-origin receipts cover **29 non-read-only tool names
with successful bounded invocations** (some test operations do not actually
change state), plus a read-only `process_checkpoint inspect`. The existing public
Desktop Commander comparison reports nine qualified categories of ten; the
remaining `set_config_value` is vendor configuration mutation. No generic
runtime-policy writer should be added to inflate a parity count.

The existing Hepta private controller is single-account and may have
`controller_workspace_roots = ["/"]`. This scope must **never** be directly
exposed to public customers. A public product requires an isolated agent and
an explicitly enrolled private, non-root workspace per tenant/user/device.

## Shared contract and policy

- `deploy/cloud_gateway_policy.py` consumes the existing
  `deploy/mcp_tool_contract.py` loader and
  `deploy/contracts/hepta-runtime-full-operator-v4.json`. There is NO second
  implementation of shell, PTY, process, document or file execution.
- Reviewed v4 catalog SHA256 is hard-pinned:
  `63742708c287e8468d73f27ba85ecc6585afd4adcd76d06b618456730cfaf8ad`.
  An updated tool name, input schema, annotation or description requires an
  explicit release review and pin update.
- The future trusted OAuth ingress MUST verify token signature/JWKS, issuer,
  audience/resource, expiry, revocation, scopes and account consent on each
  request. The Python policy receives only an `AuthenticatedUser` returned
  by such a verifier callback. Tests use a deliberately fake verifier;
  **this module does not implement OAuth authentication**.
- The future outbound mTLS device channel MUST prove device certificate identity,
  connection generation, native catalog hash, configured host aliases, isolated
  tenant account and its workspace root. The policy requires an exact match
  between those verified agent attributes and administrator-enrolled binding.
  The agent attestation object in the current offline tests is NOT a signed
  identity document; it must never be accepted directly from client JSON.
- All tools need an exact per-tenant allowlist. There is no `*` tool, host or
  tenant wildcard, no automatic elevated rights and no hidden dynamic executor.
  The `hepta:connect`, `hepta:write`, `hepta:execute` and
  `hepta:privileged` OAuth scopes are independently required.
- `sudo_start`, `host_signal`, `process_checkpoint`, and
  `privileged_action` require an additional exact administrator enrollment.
  A scope alone is not authority; the underlying isolated agent still applies
  existing OS/sudoers and provider approval requirements.
- Ordinary local path tool parameters are restricted to an absolute tenant
  workspace prefix, disallow path traversal and arbitrary SSH/SFTP URLs.
  This is only a cheap gateway check: the real agent MUST recheck via its own
  fd-relative filesystem policy, refuse symlink escapes and hold an isolated
  OS security boundary. Arbitrary shell commands cannot be sandboxed by JSON
  path inspection.
- Do not return `host_list` information from a shared agent listing hosts
  beyond the tenant's authorization. The policy requires equality between
  enrolled and attested host aliases to avoid that information leak.

## Request replay / crash integrity

`OnceOnlyLedger` is a private SQLite reservation ledger with FULL synchronous
transactions. It stores only hashed tenant, subject and device keys, a bounded
opaque request ID, connection generation, immutable catalog/payload SHA256
digest and one of three states: `reserved`, `completed`, or `unknown`.

For non-read-only actions a transaction reserves the request **before** dispatch.
After a crash, an identical call ID is rejected even if the response was lost;
reconciliation must use the native job ID, upload ID, request receipt or target
state. It is never silently executed a second time. The unique deduplication
key intentionally excludes connection generation, so reconnect/rotation cannot
replay an uncertain action. No request body, command, OAuth token, document
contents, tool response or bearer secret is persisted.

Limitations: an independent NEW call ID can still represent the same desired
operation; model/tool identity discipline and backend idempotency are still
needed. This ledger currently does not proxy calls or return cached responses.
A real product must guarantee a durable datastore and correct ingress-to-agent
handoff, expose explicit uncertain-outcome reconciliation, enforce quotas and
revalidate revocation immediately before dispatch.

## Test receipts

`tests/cloud_gateway_policy_tests.py` is offline, does not start an endpoint,
does not touch production files and never calls an actual agent. It verifies
cross-tenant/subject/issuer denial, audience/expiry/scope validation, wrong
device certificate/generation/host/root/catalog rejection, default refusal of
privileged actions, unsupported tools, local path traversal, unknown argument
authority injection, oversized requests, private DB permissions, crash
reservations and concurrent duplicate writes. Includes a reconnect-regression
that reuses the same request ID with a NEW connection generation; it must fail
closed without another write reservation.

Source-level unit testing is **not** an OAuth compliance certificate, a public
network security penetration test, signed device manifest verification or
ChatGPT Plugin Directory review.

## Work required before internet exposure

1. Choose a verified organization, actual stable owned public HTTPS domain,
   trusted OAuth 2.1 authorization server, per-tool `securitySchemes`, verified
   scopes/redirect URIs and well-known protected-resource metadata.
2. Implement real streamable HTTP MCP `/mcp` with protocol
   `server/discover`, `tools/list`, and `tools/call` using the single v4
   catalog; return truthful read-only/destructive/open-world annotations.
3. Implement independently authenticated outbound agents, per-device mTLS
   certificate rotation, signed agent manifest, tenant-specific OS namespace/UID
   isolation, host allowlists, explicit filesystem roots and revocation.
4. Complete remote transport errors, resource/latency limits, replay/failover,
   streaming, version upgrades and security testing across two unrelated tenants.
5. Obtain organization identity verification and required app publishing
   permissions. Submit the actual endpoint and test account for review; public
   approval is NOT guaranteed, especially for generic shell/sudo capabilities.
6. Maintain existing private tunnel, runtime and Desktop Commander unchanged
   until an entirely separate gateway passes these gates.

Official product requirements:
- https://developers.openai.com/plugins/build/auth
- https://developers.openai.com/plugins/build/mcp-server
- https://developers.openai.com/plugins/deploy/app-review
- https://developers.openai.com/api/docs/guides/secure-mcp-tunnels

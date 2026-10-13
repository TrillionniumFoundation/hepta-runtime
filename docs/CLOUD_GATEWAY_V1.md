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

A separate two-tenant positive/negative regression verifies that two enrolled
accounts each retain their own reservation for the same opaque client call ID,
while a token from tenant A cannot select tenant B's agent or write paths.
These are still fake verifier identities, not real commercial customers.

## Offline tenant path-authority closure (2026-10-13)

Adversarial tests found that the pre-dispatch policy checked `path`,
`source`, `destination` and similar primary fields but did **not** reject
out-of-tenant execution `cwd`, secondary PDF `output_path` / password/trust
files, nested PDF page `source_path`, or rich-render assets' nested `path`.
Before this change those malformed requests could be *reserved* by the
replay ledger as if admitted. No internet endpoint was deployed and no native
execution occurred in these tests.

`GatewayPolicy.prepare` now applies the explicit enrolled tenant-root check
on each known primary and secondary path field. The four executable-start
operations (`shell_start`, `process_start`, `pty_start`, `sudo_start`) need an
explicit **absolute tenant-scoped `cwd`**; tools with a `host` input in the
execution category require an enrolled exact host alias. Structured
`pdf_edit.operations` and `document_render.assets` are checked for their
known file sources; malformed shapes are denied *before* write reservation.
Arbitrary user-authored document/form text is not searched or interpreted as a
path, and tool names, descriptions, schemas and honest risk annotations remain
unchanged.

**This is preflight defense, not runtime isolation.** A shell can change
its directory and refer to arbitrary absolute paths. Before public release,
the independent customer device agent must enforce an isolated non-root UID,
filesystem mount/namespace rules, no implicit sudo rights, fd-relative local
path validation and explicit host allowlists. The offline policy has no power
to contain native processes or to prove an OAuth signature or mTLS identity.

`tests/cloud_gateway_authenticated_catalog_tests.py` is a persistent,
synthetic two-tenant regression for modern `server/discover` and `tools/list`
using the same reviewed v4 contract and fake *trusted* verifier/device inputs.
It checks per-user scopes, administrator elevated grants, cross-tenant identity
confusion, device certificate/generation/catalog drift, expired enrollment,
revocation, unauthenticated failures and blank authorized catalogs. It is now
part of the exact-head CI. It does **not** represent completed OAuth 2.1,
a live public server, signed device attestation, or customer onboarding.

## Offline OAuth verifier claim-type hardening (2026-10-13)

A second adversarial test found that the policy's `AuthenticatedUser` and
`AuthenticatedAgent` dataclass type annotations were not enforced at runtime.
If a future token verifier accidentally returned an OAuth `scopes` string,
Python substring membership could wrongly satisfy `hepta:connect`,
`hepta:write`, `hepta:execute` or `hepta:privileged`. Non-integer expiry
and certificate connection-generation claims could likewise cause an
unhandled TypeError rather than a stable authorization denial.

The policy now requires a **frozenset of bounded strings** for scopes,
integer (not boolean or float) expirations and integer connection generations.
Malformed verifier results fail with `OAUTH_INVALID`; malformed authenticated
agent generations fail with `AGENT_IDENTITY_INVALID`. Malformed administrator
binding generation/expiry fields fail enrollment validation. This hardens the
future verifier integration boundary; it is **not** a replacement for
cryptographic JWT validation, OAuth token revocation, or real device mTLS.

## Live contract mutation is not a reviewed catalog (2026-10-13)

The v4 catalog is pinned by a verified SHA256 digest, but Python lists/dictionaries loaded
from that immutable JSON file are mutable. A tenant-aware policy that checks
only `contract.catalog_sha256` at constructor time could later read an
in-memory changed `readOnlyHint` or a shadow `by_name` entry, altering the
OAuth write-scope decision without any reviewed release. Adversarial tests
proved this failure mode before the fix.

The shared `ToolContract.verify_integrity()` now rehashes the current tool
list against its pinned SHA256 and compares all entries against its indexed
names. The private facade's catalog verification invokes this check, and the
offline public Gateway calls it before every caller-specific discovery and
tool admission. The public catalog builder checks it before publishing any
selected schema. Any mismatch is a closed `CATALOG_DRIFT` denial; it cannot
become a silently downgraded tool annotation or a successful write permit.

No frozen 50-tool v4 JSON, published tool schema, authorization scope or
native execution policy was changed. The updated shared Python source is
currently a **candidate in the developer worktree**, not an automatic update
of the running private Full Operator's immutable installed release. Validation
still needs exact-head CI, and neither private model-origin execution nor
public OAuth/mTLS deployment is inferred from these unit tests.

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

## Offline MCP discovery and OAuth metadata projection

`deploy/cloud_gateway_mcp_catalog.py` builds a **pure-data** modern MCP
`server/discover`, `tools/list` and OAuth protected-resource metadata/challenge
projection from exactly the same reviewed v4 native catalog. The tool names,
input schemas and read-only/destructive/open-world annotations remain bytewise
identical in the selected native tool definitions; only an accurate
`securitySchemes: [{"type": "oauth2", "scopes": [...]}]` entry is added per
tool. The scope list reflects the same connect/write/execute/privileged policy
as the offline Gateway decision core. There is no anonymous fallback for
customer-specific tools.

The catalog projection requires a nonempty explicit administrator-reviewed
allowlist and cannot silently expose newly introduced tools. A deliberately
provided full 50-name allowlist remains just a **test catalog**; it does not
publish all shell/sudo operations or grant a customer any new authority.
`tests/cloud_gateway_mcp_catalog_tests.py` verifies 10 additional behavior
properties. The local development schema validation of full v4 catalog MCP
`DiscoverResultResponse` and `ListToolsResultResponse` recorded **zero**
errors against the 2026-07-28 official JSON Schema. No network/OAuth login
or actual multi-tenant execution is tested by this projection.

**High-risk tool caveat:** A public ordinary-user execution agent must not
inherit the private controller's broad sudoers/account privileges. Otherwise
`shell_start` or `process_start` could evade a policy intended only to gate
`sudo_start`. A future signed OS sandbox attestation must prove an isolated
non-root UID, dropped capabilities and no implicit sudo rights; any privileged
lane needs its own explicit audited authorization boundary. This protection
is NOT implemented by the offline Python policy or a mere boolean claim.

## Caller-specific authenticated MCP discovery (offline candidate)

**Mandatory future public ingress flow:** verify an OAuth bearer token's
signature, issuer, audience, scopes, expiry and revocation using an independently
trusted verifier; authenticate an isolated device over real mutually authenticated
transport; then use `GatewayPolicy.authorized_tool_names(...)` to derive **each
caller's** subset of the approved native v4 tools. The new
`authenticated_tools_list_response(...)` only returns that derived subset.
The `authenticated_discover_response(...)` entrypoint enforces the same
user/device admission before returning public capability metadata.

`reviewed_public_tools(...)` and `tools_list_response(...)` are offline/admin
building blocks, **not HTTP handler entrypoints**. They must not be wired to
untrusted model-supplied tool names, a shared global token, or an anonymous
fallback. Each `tools/call` must separately invoke `GatewayPolicy.prepare`
with the current independently verified user/device. The policy and catalog
remain immutable until an explicit reviewed release.

A direct, **non-network** local verification of the existing code after the
identity-aware refactor (using the test fixture's fake OAuth verifier and
synthetic agent certificate identities) returned: 6 names for an enrolled
read+write+execute user, 2 for connect/read-only, 5 for connect+write without
execute, and an empty catalog for a caller with no enrolled tools. Invalid
bearer and cross-tenant agent cases were rejected. Every authenticated
`server/discover` and `tools/list` response tested against the local official
MCP 2026-07-28 JSON Schema returned zero errors. These ad-hoc checks have
not been promoted to a separate persistent CI test because the attempted
source-test edit was blocked by this ChatGPT session's safety check; no
alternative path was used to replay that rejected edit. This is **not** a
production readiness qualification.


## Public HTTPS resource and OAuth issuer syntax — 2026-10-13

An adversarial offline inspection reproduced that the former public URL checks accepted
`https://127.0.0.2/mcp`, RFC1918 IPv4 and private IPv6 literals, local DNS
suffixes, and a malformed nonnumeric port (e.g.
`https://gateway.example.test:bad/mcp`). The OAuth issuer metadata check had
the same gap. These were **candidate configuration inputs only**, not an
actual request accepted over the internet.

`deploy/cloud_gateway_https.py` now supplies **one shared syntax admission**
for `GatewayPolicy` public MCP audience URLs, enrolled OAuth issuer origins and
`cloud_gateway_mcp_catalog` metadata/challenges. It requires standard HTTPS
(default port or explicitly 443), a canonical multi-label ASCII DNS name, no
private IP literals/special-use local suffixes, no userinfo/controls, and an
exact `/mcp` resource path or origin-only issuer. The policy also checks the
admin-enrolled issuer rather than trusting any arbitrary future token verifier
string. Invalid/ambiguous strings fail before any tenant dispatch reservation.

This **does not prove the domain is owned, DNS resolves publicly, the TLS
certificate is valid, or the host cannot rebind to a private address**. The
future network ingress must perform real DNS/TLS/issuer validation, OAuth
resource verification and transport threat review. Isolated device mTLS, actual
agent enforcement and public app publication remain HOLD. The private 50-tool
contract, runtime, DC and private tunnel were not modified.

Source, adversarial regression and prepatch observations are frozen at
`docs/qualification/cloud-gateway-offline-https-origin-20261013.json`.

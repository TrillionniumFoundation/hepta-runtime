# REA 6.8.0 native Rust integration — scoped P0-P5 register

Controlling source: upstream Git commit 93b8b82db70279e40f484114cff9dc1958dc14ee,
whose package.json reports version 6.8.0. This is NOT a claim that the npm
registry tarball has the same content or that the complete REA catalog has
been captured. Runtime baseline: ba574f2a6a1b74e85191c58d7bec011720736bb9.

Sources: https://github.com/morluto/rea/blob/93b8b82db70279e40f484114cff9dc1958dc14ee/src/domain/evidence.ts
and https://github.com/morluto/rea/blob/93b8b82db70279e40f484114cff9dc1958dc14ee/src/contracts/toolFamilyIds.ts

## P0: AUTHENTIC PUBLISHED MCP SCHEMAS — PARTIAL / OPEN

UPSTREAM.json freezes 18 source family IDs and key Evidence fields.
PUBLISHED_6_8_0_ORACLE.json independently pins real npm 6.8.0 metadata:
229 distinct tool names, compact-input/full-output and full-input/off-output
MCP schemas captured in actual separate stdio sessions. The two runs have the
same tool-name identity and distinct profile-specific catalog digests.
REA's canonical Evidence id is ev_<digest>; it depends on the upstream
canonicalization and full record, including explicit relationship_coverage
and analysis_profile. The Rust-native preview remains a NON-REA Evidence record. A separate
policy-gated verifier checks source-derived REA ev_ semantic ID commitments
for JSON with exact safe integers. It rejects duplicate keys, tampering and
an omitted null relationship_coverage but cannot establish full Zod or
floating-number parity. The full
generated tool catalog, schemas, golden records, original unknown ledger,
errors and authentic differential fixtures still need collection from a
locked REA installation. Source inventory is not conformance acceptance.

## P1: NATIVE FOUNDATION — PARTIAL

The built-in read-only rea_inspect_artifact MCP tool runs on the controller
with --runtime-config, accepts only absolute regular-file paths traversed by descriptor-relative
opens beneath controller_workspace_roots and caps input at 32 MiB.
It returns SHA-256, bounded header observations and a versioned, deterministic
hepta_rea_preview_v1_ identity. It does not use Node.js, REA MCP or Python.
Supported preview header families: ELF, PE, Mach-O, WASM, GGUF, safetensors,
ZIP. Safetensors additionally validates bounded tensor shape products, file ranges, gaps, overlaps and known dtype storage lengths, and rejects duplicate JSON members (including nested tensor declarations). This is a deliberately partial implementation: no full format parsing,
decompilation, symbol extraction, code validation or signature verification.
The native preview identifier is NOT an REA ev_ identifier. Fail-closed
and symlink-escape tests are included. File-descriptor admission rejects symlink traversal and parent components,
including ordinary rename/symlink swaps between validation and open. Hostile
mutation of an already opened file's *contents*, compromised policy roots, and
untrusted parser process crashes still require isolated worker/quotas.

### P1 Evidence digest subset (still OPEN for full parity)

The Rust MCP tool rea_verify_evidence reads at most 8 MiB under the same
confined descriptor-relative file policy. It checks a source-derived REA
semantic projection (excluded display path, included null relationship
coverage) with UTF-16 key sorting and SHA-256. Node.js source-semantics
reference hashes cover ASCII and supplementary-plane key ordering.
Only exactly representable signed/unsigned safe integers are admitted;
fractional and exponent numbers fail closed. Complete upstream Zod
validation, authentic upstream generated Evidence E2E and production
semantics are still unqualified. Successful output says subset only.

## P2: FORMAT PARITY AND APPLICATIONS — OPEN

To close: real independent per-format differential fixtures (including
malformed and oversized cases), full provenance and unknown semantics,
Rust AST-based JS/Electron, APK manifests/signatures, model tensor-offset
validation, firmware extractors, retained Evidence and versioned projections.
The preview does not qualify any of these larger features.

## P3: REAL PROVIDER ADAPTERS — OPEN

Ghidra, IDA, Hopper and other external engines remain independent and
optional. Native Rust adapters must preserve exact target/profile identity,
read-only-by-default authority, provider lifecycle, cancellation, cleanup
retry, restart/reconnect, live engine fixtures and differing engine outputs.
Do not claim a native rewrite of the external proprietary or Java engines.

## P4: LIVE OBSERVATION — OPEN

Browser, Android, debugger, Frida and packet/firmware runtime tools require
host-side isolation, no ambient network/secrets, authority checks, lifecycle
ownership and complete cancellation/failure contracts. No real-provider,
device, browser or dynamic-observation run is claimed here.

## P5: RUNTIME ADMISSION — PARTIAL, PRODUCTION HOLD

The local read-only tool is wired directly into the Rust MCP tool router and
advertised only when a runtime policy is enabled. It has no external REA
process and returns explicitly partial results. Full P5 additionally requires
remote dedicated Rust worker binaries, host-bound capability scoping,
durable Evidence bundles, session and policy negatives, cold restart,
real cross-host E2E and rigorous differential parity with REA 6.8.0.

Current gate: EXPERIMENTAL ONLY. Do not deploy as a replacement for REA, a
binary scanner for hostile concurrent inputs, or a production reverse
engineering engine. HeptaRuntime's existing remote process/inspection helpers
also still run Python; zero-Python for the complete runtime is a separate
migration gate.

## Verification contract

CI must run fmt, check --locked, clippy -D warnings, tests and release build
on the exact integration commit. Tests must cover format markers, truncation,
unknown-state preservation, deterministic non-REA IDs, workspace allow/deny
and symlink escapes. CI success is not real-provider or production parity.

## Third-party attribution

This source experiment draws on the upstream MIT-licensed REA analysis
contracts and safetensors dtype table. The exact upstream MIT notice is
retained in LICENSES/REA-MIT.txt (included in source packages); proprietary external engines are not
embedded or relicensed by this contribution.

## P0 published-release oracle (development CI)

The separately triggered rea-reference.yml job uses Node.js only in GitHub CI,
installs exact rea-agents@6.8.0 from npm, records the downloaded tarball SHA-256,
starts the actual REA MCP over stdio and saves its compact-profile tools/list
catalog and negotiated protocol as a build artifact. Only an actual completed
run, with its artifact and package digest, qualifies this catalog capture.
This does not add a Node dependency to the shipped Rust binary and cannot
establish full tool-behavior parity, upstream source/tarball equivalence or real
provider/dynamic-E2E qualification. See Issue #79.

P0 published-reference fingerprint is pinned separately in
PUBLISHED_6_8_0_ORACLE.json. The reference workflow fails on npm archive or
MCP catalog drift, captures a true inspect_elf_notes Evidence record for
/usr/bin/true and runs an ignored-by-default Rust differential test against
the exact native subset implementation. That authentic record's hash is
host-image-specific; never use it as a universal constant across hosts.

The npm oracle also attempts a second real MCP session using full input
schemas and disabled output schemas, to retain both full input contracts and
full output contracts without exceeding a single MCP catalog frame. Success
is qualified only by that run's generated artifacts; it is not a declaration
that a simultaneous full/full catalog frame fits the client transport.

The two-profile published npm reference **passed** in CI run 41435221835.
Its complete input and output schemas are retained in artifact 13135513725.
The full-input/off-output catalog hash is
`1f37341b9b409b5f98ee3f69f7b81fff2306e5677bb863c2fa0fc92cb76d2eaf`;
compact-input/full-output hash remains `6d635f60ca666ef15ada8cae73b16e77c4d1ec3a8397aaa877b87b06605a845a`.
The shared 229-name digest is `d3da3dcd88936744d1c08f5d985625e6ee7ecc376581530e876c093f3b20f48c`.

## Synthetic policy-enabled MCP acceptance

CI adds an isolated test-process MCP client/server transport that enables a
synthetic non-privileged runtime config, proves the native REA tools are
advertised only in policy mode, invokes real read-only WASM inspection,
rejects a file outside workspace roots and refuses malformed REA Evidence.
This is a local mocked-host policy test; it does NOT prove remote Ghidra,
actual host identities, cold recovery or the production security gate.

The reference oracle now captures an actual invalid-relative-path MCP
`tools/call` negative result (or protocol error, with delivery type preserved).
This freezes one validation failure surface only; it does NOT close arbitrary
typed error or cancellation contracts, all 229 tools, or security review.

## Deterministic parser adversarial regressions

A fixed-seed mutation matrix probes eight binary/model signatures over
1,536 mutated specimens and asserts no panic, no accidental REA parity claim
and no complete-coverage promotion. Extreme safetensors header lengths are
negative probes. This is a bounded regression, **not** continuous libFuzzer
coverage nor independent unknown-generator qualification.

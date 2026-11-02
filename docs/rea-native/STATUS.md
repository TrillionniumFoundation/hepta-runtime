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

## Isolated Rust artifact parser (experimental)

The production `rea_inspect_artifact` handler reads admitted bytes using the
workspace-confined descriptor API and passes them over stdin to the same
shipped Rust binary in hidden `rea-worker` mode. The worker opens no artifact
paths, receives no controller runtime environment, has a 32 MiB read limit,
256 KiB response limit and 20-second controller deadline. On Unix it installs
CPU, address-space, file-descriptor, core-dump and output-size rlimits before
parsing. The Rust process boundary contains `panic = abort` failures.

Worker UID and network namespace remain inherited. Linux post-read syscall
denials are not a complete filesystem or credential sandbox; macOS has
resource limits only. Third-party provider execution remains unqualified. Worker
process startup and failure are exercised through a real compiled binary in
`tests/rea_worker.rs`; unit-only MCP smoke bypasses the process boundary under
`cfg(test)` and does not qualify the shipped MCP-to-worker E2E path.

### Linux post-read syscall restrictions

Linux x86_64/AArch64 workers now install no_new_privs plus a
process-thread-synchronized seccomp-BPF denylist *after* bounded stdin
receipt and *before* parsing. The filter returns EPERM for file opens,
socket creation/network sends, exec/fork/clone, ptrace, io_uring and
related operations. An actual compiled-binary test probes denied file
and network syscalls. If seccomp is unsupported or a Linux architecture
is not qualified, the worker refuses parsing. This is defense in depth
only: it does not establish a complete filesystem/namespace/credential
sandbox or third-party provider isolation. macOS remains rlimit-only.

### Full external MCP-to-worker smoke (in CI)

The separate `tests/rea_mcp_external.rs` integration executable launches
the shipped `hepta-runtime mcp --runtime-config` as a real child process,
uses newline-delimited MCP JSON-RPC, verifies that policy-gated REA tools
appear while `shell` is hidden, and exercises allowed WASM, denied
out-of-root files and malformed ELF. It then cold-restarts the controller
and repeats the workflow. The production handler thereby exercises the
isolated Rust worker, unlike the in-process unit MCP smoke. This remains
local-host E2E, not remote multi-host recovery or full REA parity.

## Native preview durable evidence (experimental local P5 increment)

The policy-gated `rea_retain_preview` MCP tool re-inspects an admitted artifact
through the real sandboxed Rust worker, then atomically publishes an immutable
by-protocol, content-addressed `hepta.rea.preview.v1` record under the private
controller `state_dir/rea-preview-v1`. `rea_read_preview` looks up only a
validated native ID and checks both complete-record SHA-256 and native identity.
An exclusive hard-link publication refuses overwrite, verifies existing entries
and permits idempotent replay with a distinct original display path. Dedicated
Rust unit tests verify simultaneous writers, damaged-record rejection, symlinked
store refusal and file mode constraints; the shipped MCP process E2E checks a
fresh controller can restore the same immutable record without rereading the
source artifact. **Not REA original Evidence, not a tamper-proof signed log.**
Trusted state directory ownership, total disk quotas, hostile inode mutation,
full remote signed worker, policy reconciliation and production OS isolation
remain OPEN. Do not promote P5 based only on local-state durability.

The retained-record readback now uses the shared duplicate-key-rejecting
JSON parser and refuses unknown envelope fields. Atomic staging filenames
include a high-resolution timestamp, PID and per-process sequence. The real
shipped MCP controller restart test temporarily removes the original artifact
before restoring retained Evidence, proving the read path does not reopen the
source. All validations are local host only; original REA Evidence semantics,
cross-host replay and tamper-resistant signing remain unqualified.

## Concurrent first-publication stress regression

A permanent local Rust regression repeats 24 fresh-store creations with four
simultaneous same-ID writers each (96 concurrent publication attempts in
separate rounds). It requires exactly one atomic new hard-link per round,
verified reusable content and private directory permissions established by
the directory creation syscall itself. Qualification depends on an exact-head
full CI pass; this exercises a single trusted Linux runner, not adversarial
cross-UID state-directory ownership or real distributed storage.

## Local Preview Store resource budget (partial P5)

The trusted local store now serializes cooperating Unix controller writers via
an exclusive directory `flock` before counting stored bytes and records.
A default budget of 2,048 published previews or 256 MiB of all store-file
sizes (including abandoned temporary files) rejects new unique identifiers
when exceeded, while allowing authenticated reuse of an existing ID.
Corrupt/non-regular entries fail closed; sparse abandoned-file and small-count
fixtures exercise the quota boundary. This is **not** a full quota system:
same-UID malicious writers can bypass the cooperative flock, inode/directory
usage, remote hosts, audit log growth and per-client fairness are not accounted.
Production adoption remains NO-GO until host-level storage responsibility and
multi-tenant policy are qualified.

## Worker output memory admission: real hostile subprocess regressions

The parser controller now streams stdout and stderr through independently capped
async readers **while the worker is still running**. It does not call
`wait_with_output`, which buffers unconstrained child output before a post-hoc
size check. The stdout cap is 256 KiB, stderr cap 64 KiB, and each reader
retains at most one byte over its cap before refusal. On I/O failure or excess
output the child is killed and reaped. Stdin, stdout, stderr, and process wait
are polled concurrently to avoid a child which writes before consuming input
stalling the controller. Real adversarial subprocess tests flood each stream.
These limits do not qualify a complete network/UID/mount namespace sandbox.

## Controller-to-worker record authenticity checks (limited)

The controller now computes SHA-256 of admitted input before sending it to
an isolated worker, then validates the worker's native semantic commitment,
source-byte count, selected display path and exact v1 envelope shape before
accepting output. Tampered normalized facts, substituted paths and hashes,
extra fields, and wrong input sizes are rejected in dedicated Rust tests.
This is not a cryptographic proof of a remote worker's identity: the local
controller and untrusted parser worker share a trust domain with no signed
host attestation; it also cannot independently prove parser classification.

## Controller-only selected-path disclosure (local worker)

The spawned parser now receives a fixed nonsecret selected-path placeholder
in its process arguments. The controller that admitted the bytes rebinds
its original path only after receiving a report with the expected placeholder,
then verifies digest, byte count and native semantic ID. Worker process
command-line inspection no longer discloses arbitrary caller-selected paths.
This does not hide input bytes from the worker or establish tenant isolation.

The full-duplex regression also launches an actual process that writes 200 KiB
of stdout **before** consuming 512 KiB of stdin. This passes only when the
controller polls both pipes simultaneously, avoiding writer/reader deadlock.

The same capture path now uses an explicit deadline wrapper that kills and
reaps the process on timeout, rather than depending solely on asynchronous
kill-on-drop. A real sleeping subprocess regression checks the deadline and
reaping behavior. This qualifies the LOCAL child deadline path only, not
remote provider cancellation or multi-host orphan recovery.

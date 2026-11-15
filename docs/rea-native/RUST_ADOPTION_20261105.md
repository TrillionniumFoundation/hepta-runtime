# REA capabilities inside HeptaRuntime: implementation and acceptance boundaries

## Decision

REA's own orchestration, contracts, evidence projections, bounded static readers,
session services, and engine adapters can be implemented in Rust inside the
existing HeptaRuntime. The integration should use the existing runtime as the
single admission, process, cancellation, recovery, and publication owner. A second
REA daemon or supervisor is unnecessary for those native routes.

Replacing an adapter does not replace its engine. Ghidra/JADX, Chromium/CDP,
GDB/LLDB, Frida, Android platform tools, and caller-provided commercial engines
have separate implementations, installation identities, and acceptance scopes.
Complete Rust replacement of those engines would be separate projects, not an
automatic consequence of porting REA's TypeScript.

## Freeze the behavior target

| Identity | Observed value |
| --- | --- |
| Project | [morluto/rea](https://github.com/morluto/rea), Reverse Engineer Anything |
| Behavior package | `rea-agents@6.8.0` |
| Published tarball SHA-256 | `8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb` |
| Original frozen Git source | `93b8b82db70279e40f484114cff9dc1958dc14ee` |
| Upstream Git observed during this review | `71f680d7c1aa7a45ba0325fe87b104744b0c105f` |
| Observed upstream commit time | `2026-11-04T20:30:52Z` |
| Git drift from frozen source | 142 commits ahead, 0 behind |
| Version in the later Git source | Still `6.8.0` |
| Captured npm inventory | 229 distinct tools, 18 source family IDs |
| Hepta starting publication | `310add6db47bcfbed3545432eb528a72f5eb6dcd`, PR #84 |
| Local continuation used for this work | `ce246a57cdc6299fb7291fa03fb8eca0f44b1716` |

The version string is insufficient to select an oracle. Preserve the npm archive,
the source checkout, complete catalog profiles, and their distinct fingerprints.
The later source must not silently change the acceptance target. The later commit
specifically adds pagination for retained instruction references; it is a useful
design input, not proof that the frozen npm package implements the same behavior.

Sources: [upstream commit](https://github.com/morluto/rea/commit/71f680d7c1aa7a45ba0325fe87b104744b0c105f),
[source comparison](https://github.com/morluto/rea/compare/93b8b82db70279e40f484114cff9dc1958dc14ee...71f680d7c1aa7a45ba0325fe87b104744b0c105f),
[package metadata](https://github.com/morluto/rea/blob/71f680d7c1aa7a45ba0325fe87b104744b0c105f/package.json),
and the existing [published package oracle](PUBLISHED_6_8_0_ORACLE.json).

## What Rust can own

| Layer | Rust responsibility | Independent acceptance |
| --- | --- | --- |
| Contract | Input defaults and errors, exact null/omission semantics, MCP envelope and tool mapping | Complete original/native wire comparisons, including unsuccessful requests |
| Evidence | Canonical ID, schema authentication, parent links, first-retention origin, projections and complete export | Tamper and duplicate rejection, exact identities, retained original bytes and readback |
| Static readers | ELF, PE, Mach-O, WASM, APK/ZIP, models, JavaScript/TypeScript/ASAR/source maps | Independent producers and malformed, compressed, large and unknown cases |
| Provider adapter | Fixed operations, pinned engine/source identities, bounded input/output and owned scratch | Actual selected engine, failure, timeout, cancellation, reconnect and cleanup |
| Runtime | Existing authorization, admission, durable job owner, quotas, recovery and rollback | Same source/binary/configuration across execution and refusal/recovery paths |
| Agent workflows | Compose evidence-backed operations and preserve partial/unknown states | Task outcomes under equal information and complete costs |

REA's MIT notice must be retained for copied or adapted source. That notice does
not grant rights to IDA, Hopper, JEB, or other separately licensed engines. Actual
third-party dependencies retain their own licenses and deployment requirements.
See [REA LICENSE](https://github.com/morluto/rea/blob/71f680d7c1aa7a45ba0325fe87b104744b0c105f/LICENSE)
and [third-party notices](https://github.com/morluto/rea/blob/71f680d7c1aa7a45ba0325fe87b104744b0c105f/THIRD_PARTY_NOTICES.md).

## Acceptance must follow callable behavior

A parsed tool catalog, a source file, an unregistered module, a successful build,
or a test command selecting zero tests cannot close an operation. The current
operation ledger must be generated from implementations and independently
validated receipts; historical inventory counts cannot describe newly added
routes without regeneration.

For each claimed operation, bind the source tree, toolchain, build logs, executed
binary, policy/profile, original npm bytes, input corpus, original wire transcript,
and independent comparison. A qualified helper is not automatically a qualified
MCP endpoint. A release binary and a test binary are separate identities.

In particular, an oversized-result response must leave a usable recovery path.
If it instructs the caller to inspect a retained view or export a bundle, those
operations must be registered, authorized for the original owner, bounded, and
verified against the same retained record. A frame check must measure the actual
SDK message, including the request ID, escaping, metadata and error form.

All three worker pipes belong to the operation deadline. Reaping the main child
does not imply stderr EOF. The private owner must join its stdout and stderr
readers before releasing the parser slot and effect admission, even after the
requester drops. Oversized stderr must terminate the worker promptly. A retained
external write descriptor must not cause an unbounded join or premature success.

## Recovery and dependency claims

The frozen npm Evidence session is in memory. A new stdio process has a new empty
registry. Automatically importing the previous process's records would violate
that compatibility contract. Hepta's separately named durable preview/model
stores have their own authenticated owner/policy and cold-recovery contract.

The native REA routes can remove the Node/TypeScript REA supervisor from deployed
execution. Node remains a development reference for differential testing.
Existing Hepta remote helpers and general model workers may still depend on
Python/PyTorch. Neither REA model metadata inspection nor native Rust transport
establishes general model inference, weight-space understanding, or model-quality
improvement.

Full replacement remains subject to per-operation behavior and lifecycle evidence,
actual external engines and devices, platform-specific authorization and recovery,
and complete resource/cost measurements. Narrow successful comparisons must not
be converted into all-229-tool or production qualification.

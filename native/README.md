# HIA native runtime

This directory holds the current HIA implementations, ABI contracts and
reproducible qualification inputs. The production target has **136 MCP
handlers**; no production handler is declared replaced. `whole_runtime_replaced`,
`production_activated` and `old_stack_removal_qualified` remain **false**.

## Source identities and coverage

| Input | Exact Git identity |
| --- | --- |
| Production target (`main` snapshot) | `737acf6f901e46c57b0b4374e323e0d1132e0d49` |
| Historical comparison baseline | `a0dcdda1991ec536d5e2d252c006a778993fa566` |
| Hepta compiler | `d3e2c90173cf733e42b299d0c4274df4b593a12f` |
| Native platform | Linux x86-64, LP64, SysV AMD64 |

[migration.json](migration.json) registers native sources, historical comparison
owners and remaining system owners. Its digest-bound
[migration_target.json](migration_target.json) separately records the target:
**474 files under `src/`, plus `Cargo.toml` and `Cargo.lock`**. Relative to the
historical source, **49 source files were added, 47 changed, and both Cargo
files changed**. The historical inventory has **125 handlers**; the target adds
11 across REA and weights. Old parity does not qualify these new or changed
owners.

The snapshot reconstructs the Git source tree and modes. An independent target
checkout verifies source bytes, Cargo declarations and handler names. This
identifies the target without qualifying its behavior.

## Component domains

ABI and composition manifests define each owner's scope:

| Domain | Native owners and compositions |
| --- | --- |
| Text and files | Byte/protocol primitives, line endpoints, text budgets, batch planning/application, atomic writes, exclusive local creation, filesystem parity, delta, editable content, history and locks |
| Read services | Path policy/canonicalization, stat/version, local I/O, multi-read, file-info, view parameters/calls/rendering/cache and literal/regex search |
| JSON and numbers | Locked serde-compatible JSON/number behavior, private RawValue expansion at typed boundaries, finite binary64 arithmetic, private Bellman numerical core and canonical commitment |
| Identity and requests | Caller authority, KDF/AEAD/nonce/records, entropy, operation/request scope, request context and result publication |
| Configuration and sessions | Configuration, regex syntax/HIR/NFA/matching, client/session context and workdir state |
| Shell and effects | Admission, terminal cleaning, execution composition, effect fences, prepared processes, foreground/output/background state and capture preparation |
| MCP composition | Catalog/admission/protocol, view/workdir gateways, static image packers and public exchange/reference fixtures |

The Bellman numerical core and its separate commitment owner cover typed
calculation, canonical serialization, and request/plan hashing. The commitment
owner accepts the implementation digest only through its trusted private
input. Public JSON admission, installed implementation authority, deadline and
async permit/cancellation ownership remain separate work. Each other owner or
public composition also retains its declared limits. Complete service closure still
requires production routing, persistence/restart and unknown-outcome recovery,
SSH/SFTP/HTTP/PTY, full editing/delta behavior, REA, documents/worksheets, model
workers, deployment ownership and additional platforms.

Both `serde_json.hepta` and the public frontend's `serde_json_span.hepta` include
private RawValue expansion. The frontend distinguishes generic Value positions,
the typed argument map, selected request IDs, typed string fields and ignored
struct fields. It retains the SDK's silent-discard and protocol-error routes,
including reuse of the connection by a following valid request. Complete
original public comparisons and the additional typed-boundary Rust replays
are independently required; the shared-parser comparison alone does not
qualify the frontend. [The public ABI](runtime_mcp_abi.md) records the exact
scope, capacity continuation and error precedence.

The private [Local Create owner](local_create_file_abi.md) preserves exclusive
pathname creation, 2 MiB write chunks, partial writes, interrupted syscalls,
WriteZero and one-close descriptor retirement. Three registered suites cover
its complete state, actual filesystem behavior, build provenance and evidence
refusals. Its seven recorded original processes freshly build the locked
Rust reference and replay all kernel, competing-create and file-size fault
inputs. Full create orchestration, asynchronous cancellation, cache publication
and public admission retain their separate qualification boundaries.

## Inventory and target checks

Run from this checkout:

```sh
python3 -B scripts/check_hia_native_inventory.py
python3 -B scripts/check_hia_native_target.py
python3 -B scripts/check_hia_native_target.py \
  --target-root /absolute/path/to/exact-target-checkout

python3 -B scripts/check_hia_native_inventory.py --require-complete
python3 -B scripts/check_hia_native_target.py --require-complete
```

Valid source checks return 0. Without `--target-root`, the snapshot check reports
`target_checkout_verified: false`. Both `--require-complete` commands currently
return **2 / INCOMPLETE**. Completion flags cannot substitute for implementation
and behavioral proof.

## Full qualification

The builder checks the pinned Hepta commit/tree, source bytes, compiler fixed
point and module provenance. Run qualification on the configured development
host per `AGENTS.md`, with a fresh output directory outside Git.

Build/test dependencies include Python 3.11+, a C toolchain, Rust **1.95.0**,
Cargo and that toolchain's rustfmt. Independent Python references use the locked
requirements below. Required Linux kernel controls and GNU assembler/linker
fixtures must be available; their suites do not silently skip them.

```sh
python3 -m venv /absolute/path/to/hia-reference-environment
/absolute/path/to/hia-reference-environment/bin/python -m pip install --only-binary=:all: \
  -r tests/hia_native/python-reference-requirements.txt

/absolute/path/to/hia-reference-environment/bin/python -B scripts/qualify_hia_runtime_native.py \
  --hepta /absolute/path/to/pinned/Hepta \
  --output /absolute/path/to/new-native-result

/absolute/path/to/hia-reference-environment/bin/python -B scripts/compare_hia_runtime_rust.py \
  --output /absolute/path/to/new-native-result \
  --rustc /absolute/path/to/rustc
```

Both phases are required. CI uses one fresh cold/build job, eight native
partitions, a native collector, seven original comparison partitions and the
final collector. The registry contains 73 component builds, 198 native suites,
67 original Rust recipes and 169 HIA sources. The ten independent rendering,
cache, history and session suites occupy `view_components`; the seventeen
read, parameter, caller and public MCP suites retain their producer order and
fixture retirement together in `view`. Each suite and original recipe still
executes exactly once under its existing process and job deadline.

Original receipts preserve shared process attribution and the two fresh typed
span reference builds, including their compiler version, materialized source,
executables and complete input/output bindings. Missing, failed, duplicated or
altered evidence cannot qualify the combined tree. Earlier branch results
cannot qualify new sources.

## Repository and evidence retention

Keep current HIA sources, ABI contracts, build tools and reproducible tests.
Retain original runtime owners until production replacement and removal gates
close. Preserve actual failure results, raw process output, regression inputs
and source/compiler/manifest identities. A rerun receives its own result
directory. Existing consumers of `docs/qualification` and `tools/x230` must stay
reproducible.

Authoring scratch, intermediate variants, compiler caches and local binaries
belong outside Git. Required executable fixtures and raw Unix filenames,
symlinks or FIFOs remain inside qualified evidence archives. Git history keeps
the former development narrative; this document describes the current layout
and its qualification requirements.

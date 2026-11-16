# HIA native runtime

This directory holds the current HIA implementations, ABI contracts and
reproducible qualification inputs. The production target has **136 MCP
handlers**; no production handler is declared replaced. `whole_runtime_replaced`,
`production_activated` and `old_stack_removal_qualified` remain **false**.

## Source identities and coverage

| Input | Exact Git identity |
| --- | --- |
| Production target (`main` snapshot) | `d3d75c30719db966b004756f610007a7c723729e` |
| Historical comparison baseline | `a0dcdda1991ec536d5e2d252c006a778993fa566` |
| Hepta compiler | `d3e2c90173cf733e42b299d0c4274df4b593a12f` |
| Native platform | Linux x86-64, LP64, SysV AMD64 |

[migration.json](migration.json) registers native sources, historical comparison
owners and remaining system owners. Its digest-bound
[migration_target.json](migration_target.json) separately records the target:
**474 files under `src/`, plus `Cargo.toml` and `Cargo.lock`**. Relative to the
historical source, **49 source files were added, 51 changed, and both Cargo
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
| Text and files | Byte/protocol primitives, line endpoints, text budgets, typed batch planning, application and annotated diff, atomic writes, exclusive local creation, filesystem parity, delta, editable content, history and locks |
| Read services | Path policy/canonicalization, stat/version, local I/O, multi-read, file-info, view parameters/calls/rendering/cache and literal/regex search |
| JSON and numbers | Locked serde-compatible JSON/number behavior, private RawValue expansion at typed boundaries, finite binary64 arithmetic, private Bellman numerical core and canonical commitment |
| Identity and requests | Caller authority, KDF/AEAD/nonce/records, entropy, operation/request scope, request context and result publication |
| Configuration and sessions | Configuration, regex syntax/HIR/NFA/matching, client/session context and workdir state |
| Shell and effects | Admission, terminal cleaning, execution composition, effect fences, prepared processes, foreground/output/background state and capture preparation |
| Retained results | Private safe DTO admission, typed record JSON, retention and validation, record I/O, directory leases, archive metadata, publication and store graphs |
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
WriteZero and one-close descriptor retirement. Seven registered suites cover
the blocking leaf, segmented poll continuation, held completion ordering,
actual filesystem behavior, build provenance and evidence refusals. Twelve
recorded original commands freshly build two locked Rust references and
replay the 357 ordinary and 43 held root processes. This retains the original
Tokio 1.53.1 reference profile; the target Tokio 1.53.3, full create
orchestration, cancellation, cache publication and public admission require
their separate qualification boundaries.

The [Text Editor parameter owner](text_editor_params_abi.md) projects all four
commands and six fields from the shared canonical map. Two native suites
retain 1,992 semantic inputs and complete capacity/continuation records. Its
separate fresh locked reference uses the unchanged target types and exact
serde 1.0.229 / serde_json 1.0.151 dependency profile. Typed projection does
not activate a filesystem handler or replace a public route.

## Current public stdio entry

The default `scripts/hia_native_runtime_mcp_build.py` API/CLI builds the current
91-image graph and its actual nine-tool routes. TextEditor owns the Local four
commands through the real caller/body/cache graph. The entry integrates current
G1 projection, G2 connection admission, fixed current get_info, shared text
result construction and serial transport/shutdown. Its full source closure is
`runtime_mcp_sources.json`; exact source and qualification limits are in
[runtime_mcp_current_qualification.md](runtime_mcp_current_qualification.md).

The ordinary current qualification freshly compiles 62 comparison members and
83 candidate members, freshly builds both current Rust 1.95.0 references, and
compares all 324 handshake responses, public90 and framing24. Codec EOF's four
observations remain a separate original-only domain. The actual default build
and launch commands are in the repository README.

## Historical public local filesystem composition

The retained [58-image public stdio test profile](filesystem_public_abi.md)
advertises eight tools: `host_list`, `effective_config`,
`execution_shadow_admit`, `view`, `workdir`, `directory_create`, `file_move` and
`directory_move`. The three local filesystem methods call the actual typed,
fence, shared Session, installed configuration, path-policy, request-scope,
canonical-key, descriptor-effect, cache and publication owners. JSON fields do
not select private state or internal child instances. The real fence permit is
held across each admitted method and released after its terminal completion.

A separately linked observer executable shares exactly the same 58 freshly
compiled images. It has two real Session/cache instances and one shared installed
configuration/fence owner. This private observer is never selected by public
stdin. The mandatory native producer runs 28 observed processes for all 323
public attempts plus nine explicit cache/filesystem controls. A separate 26
ordinary-stdio processes cover 317 public attempts and five filesystem controls,
including real EOF and BrokenPipe. These two domains overlap and their totals
must not be added as independent semantic cases.

Native admission reads complete source, compiler, linker/packer, both ELF images,
all 68 fixed patches, actual streams, state snapshots and syscall/continuation
records before the unchanged Rust reference runs. Only then are the owned test
files archived with their full bytes, raw Unix names, modes, attributes, hardlink
relationships, symbolic-link targets and FIFOs. The original stage reconstructs
the same absolute paths, runs the fresh fixed-Rust-1.95 reference and requires
complete response/state/filesystem comparison plus six groups of 42 physical
evidence refusals. Pure retained readers never restore paths or start HIA/Rust.

The configuration span owner also serves these public methods. Its remote-policy
op8 borrows the complete input and grows an error response before changing state;
it no longer expands unrelated work regions for a long path. Its legacy u32
success channel remains an explicit representability boundary. Configured-fence
focused observations and larger remote-policy errors are separate evidence from
the 323-attempt SDK domain. Remote filesystem execution, general concurrent HTTP
routing, unconstrained regex resources, the full 136-handler production target and production
activation remain unfinished. The original implementations stay in place.

## Inventory and target checks

The component registry and its original public tests run from an explicit
historical public source view. It restores the exact 58-image graph and leaves
all unrelated current qualification bytes unchanged; it never changes this
checkout's default 91-image entry.

```sh
python3 -I -B tests/hia_native/historical_public58/materialize.py \
  --source "$PWD" --output /absolute/path/to/new-historical-public-profile
cd /absolute/path/to/new-historical-public-profile
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

## Retained component and historical public qualification

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

Both phases are required and run inside the source view created above. CI uses
one fresh cold/build job, ten native partitions, a native collector, eight
original comparison partitions and the final collector. The retained registry
contains 87 component builds, 225 native suites, 81 original Rust recipes and
195 HIA sources. Current83 qualification is a separate mandatory job; these
historical public results do not qualify its current framing or SDK behavior. The ten independent rendering,
cache, history and session suites occupy `view_components`; the twenty
read, parameter, caller, public MCP and filesystem suites retain their producer order and
fixture retirement together in `view`. Each suite and original recipe still
executes exactly once under its existing process and job deadline.

The independent `storage` groups retain all thirteen native processes, nine
fresh original recipes, twenty-five retained evidence refusal controls and
five additional RawValue controls. Their thirty
images and six private graphs must be rebuilt against the current shared
owners; prior branch receipts do not qualify changed JSON or regex children.
Public admission, the global archive mutex and restart/cancellation behavior
remain outside the private storage contracts.

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


The private [complete Local Create composition](local_create_spec_abi.md) has a
separate target Tokio 1.53.3 reference. It joins the existing source/parent,
whole-worker mkdir, segmented exclusive-write, inline-close, canonical-key and
ViewCache owners in the original body order. Five registered suites retain
38 ordinary and 15 held-boundary native cases, complete response/file/cache
observations, 20,207 typed calls and strict build/evidence controls. Six actual
original processes freshly build and replay the unchanged selected source with
Rust 1.95.0. This qualification does not activate the public TextEditor gateway,
change the older leaf's Tokio provenance, or qualify removal of the old runtime.

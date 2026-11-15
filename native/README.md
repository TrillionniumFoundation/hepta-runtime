# HIA native runtime

This directory contains the current HIA implementation of deterministic runtime
components, local read/write descriptor owners and persistent native MCP stdio services. All implementation sources
in this directory use `.hepta` and are compiled by HIA to machine code. The Linux
executables have no Python, Rust, libc or dynamic-loader runtime dependency.

The complete existing runtime has **not** been replaced. Its 125 registered MCP
tool handlers and the durable/remote service owners remain in their original
implementation. The diagnostic native service advertises `runtime_native_info`
and `runtime_line_hash`. A separate, explicitly selected local read profile
provides `host_list`, `binary_read`, `read_multiple_files` and `file_info` through seven native HIA images. It has
partial original-tool coverage; configured remote hosts and complete original
authorization behavior remain outside that profile. Production activation and
deletion of the original runtime remain incomplete.

## Fixed source baseline

| Input | Exact Git identity |
| --- | --- |
| Runtime source | `a0dcdda1991ec536d5e2d252c006a778993fa566` |
| Runtime tree | `98d96c88d54082637c27f1cbfae61a66d0dd81e7` |
| Hepta compiler | `d3e2c90173cf733e42b299d0c4274df4b593a12f` |
| Hepta tree | `8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49` |
| Native target | Linux x86-64, LP64, SysV AMD64 |

The runtime baseline is the head of the existing #118 → #119 → #120 integration
stack. The older `hepta-runtime-base` default branch does not contain that
complete functionality. This work preserves the integration stack as its base.
Hepta already uses the `.hepta` suffix; protocol names such as `hia-asm.v1`
continue to identify the language and are not filename extensions.

## Shadow execution composition

The [three shadow owners](execution_shadow_abi.md) preserve exact original serde
admission, non-effectful validation, canonical SHA256 and parameter errors.
The composed controller calls typed JSON, installed exact-host lookup, then the
core; unknown hosts therefore retain their original priority over invalid record
fields. It cannot install configuration or grant execution.

The source-bound scoped run executes five actual native suites in 115.922 seconds:
73,349 core rows, 14,960 direct/Value JSON rows, all 7,480 canonical-Value error
outcomes, 963 controller calls with explicitly identified host dependency
fixtures, and one accepted evidence object plus 20 physical corruption refusals.
Actual standard-profile ELF tests are separate from wide composed-image profiles.
No complete installed-host or public MCP parity is claimed by these fixtures.

The portable original recipe freshly compiles the exact original owner and both
reference entries with 28 production-lock-verified dependencies, runs all five
original tests, and replays both full corpora. Its observed ai395 run
`1a1dbf15a2f-392-1b3a` passes all five subprocesses in 11.809 seconds. It compares
39,009,956 core output bytes and 41,226,842 normalized JSON output bytes, plus the
complete 58,230,252-byte original typed result/error stream. Historical receipts
do not replace the fresh mandatory original recipe in the aggregate.

Every new native suite retains 180 seconds, and the single original-recipe
process retains 180 seconds including compilation and full replay. The ordinary
builder, loader, compiler pin and all existing component gates remain unchanged.
The `execution_shadow` registry entry belongs to the JSON partition; no
production handler, activation or old-stack-removal state is advanced.

## Effect fence acquisition and lifetime

The [native effect fence](effect_fence_abi.md) combines the original admission
decision, descriptor custody and private asynchronous permit lifecycle in a
fixed static executable. It validates owner/state/predecessor identity, holds
the actual shared fence until release, and reclaims cancelled or failed workers.
The production profile has 512 workers. A separately source-pinned one-worker
packer exists only for queued-cancellation qualification.

The frozen scoped run `1a1dbed81b7-392-1b32` completed seven native suites and
eight actual original Rust checks in 91.395 seconds. Its 36 native groups include
128 real executable processes, 49,757 transport frames, 249 complete semantic
responses, 98 native packer calls, one valid cache admission with ten refusals,
and one accepted evidence object with 38 refusals. Both freshly built original
references pass the complete serial and paired-kernel domain, all five unchanged
acquisition test bodies and the real Mutex-poison control. Earlier failures,
including the observer's incorrect original task-count assumption, remain
identified in the retained observations.

The same seven suites and eight subprocess checks are mandatory in the aggregate.
The JSON partition executes the seven suites in dependency order; every process
retains 180 seconds. Trusted startup and private permit ownership do not yet
connect every production effect caller or install RuntimeConfig. The public
tool and old-stack-removal declarations therefore remain incomplete.

## Installed configuration and MCP composition

The [configuration scope](config_scope.md), [private owner contract](config_owner_abi.md)
and [regex ABI](regex_abi.md) bind the installed configuration to native Unicode
data/query, syntax, HIR, NFA, matching and continuation owners. The fixed
sixteen-image stdio profile provides `host_list`, `effective_config` and
`execution_shadow_admit`. Startup owns installation, retained lock descriptors
and immutable host identity. The eleven-image installed-owner profile and the
MCP profile both execute the configured regex dependencies through checked
source/image identities and fixed calls.

Fifteen mandatory native processes retain the original six configuration suites
and add nine complete regex suites. NFA construction is split into two fixed
halves covering all 3,584 cases; each process retains its existing 180-second
limit. Native evidence admission checks every actual process, source/image pair,
ELF stream and complete corpus before creating compatibility results.

Two fresh original processes run inside the existing configuration recipe.
The configuration process compiles four entries with 100 locked dependencies and
compares 13,460 typed, semantic, installed-owner, MCP and startup-refusal cases,
including 3,694 extended semantic inputs. The regex process compiles its locked
five-dependency reference and replays 6,560 Unicode, 18,976 AST, 34,130 HIR,
3,584 NFA and 65,440 matching cases: 128,690 complete inputs plus the capture-name
predicate projection. Original Rust 1.95 is selected explicitly. Both original
results and the unchanged native evidence are re-admitted after execution.

After every original recipe finishes, a separate check runs against the inactive
qualification directory. Its 14 altered-evidence cases cover missing or changed
actual processes, timeout/SIGKILL, source/ELF changes, duplicate NFA cases after
rehashing, incomplete original replay and missing startup-failure observations.
It restores all changed bytes and performs six complete baseline admissions.
These checks add no native or original semantic calls.

The frozen focused run passed all fifteen native processes and both fresh
original recipes, followed by the evidence controls. That observation belongs
to the exact preserved handoff; the repository integration requires a fresh
complete aggregate. Unconstrained regex arena/resource equivalence, original
meta-engine resource optimizations, complete configuration-owner parity and
public production routing remain unqualified. The complete-runtime and
old-stack-removal declarations remain false.

## Local write, directory, workdir and SDK connection chains

Four additional registered components bind the previously separate owners into
fixed private native services. Their 19 native suites and four fresh original
recipes are mandatory in the aggregate. Each service has its own source/image
manifest, complete process streams and domain-specific evidence admission.

| Component | Native behavior and qualification boundary |
| --- | --- |
| [Write chain](write_chain_abi.md) | Local write/append callers compose shared locks, history, cache transitions, descriptor reads and atomic replacement. Six suites include actual write, cancellation and concurrency processes; the fresh original recipe compares all 147 large-file requests and the complete kernel/concurrency domains. |
| [Directory service](directory_service_abi.md) | Typed caller ordering, installed configuration/regex policy, canonical paths, the actual effect permit and Linux directory creation are one fixed chain. Five suites retain functional, injected-fault, transport, build and regex observations; the original recipe includes paired actual kernel boundaries and evidence mutations. |
| [Workdir service](workdir_service_abi.md) | The fixed 21-image profile composes typed parameters, the trusted connection snapshot, session latch/state, installed regex policy and Linux canonicalization. Its three suites cover 680 parameter cases, 193 caller controls and installed-regex processes. The fresh original recipe additionally compares 1,537 complete public-method requests per side through the explicitly private test adapter. |
| [SDK connection](sdk_connection_abi.md) | Native message decoding, transport framing and session lifecycle reproduce the pinned rmcp 3.4.1 observations. Five suites include 2,215 real ELF processes, including controls. The original recipe freshly compiles the three locked SDK references and executes the full 11,789-case domain. |

The write chain keeps its declared 512 MiB input, 1 GiB output and 1,152 MiB
workspace profile. It does not claim arbitrary `usize` resource equivalence or
the separate batch-edit final response. Directory and workdir remote execution,
complete public connection dispatch, durable request admission/audit/results and
production activation remain outside these four private profiles. The workdir
startup snapshot does not itself implement repeated public initialization or
the expanded argument domain of a complete public SDK caller.

## Public installed-method registry

The [public registry profile](public_registry_scope.md) connects the persistent
SDK connection to exactly three installed methods: `host_list`, `effective_config`
and `execution_shadow_admit`. Its fixed 17-image executable accepts administrator
configuration only at startup, uses the original catalog and typed parameter
behavior, and preserves modern/legacy negotiation and repeated initialization.
It embeds the same configuration, execution and regex owners already qualified
above. The [private ABI](public_registry_abi.md) keeps calls and immutable startup
authority separate from ordinary tool arguments.

The aggregate registers three additional native suites and one fresh Rust 1.95
recipe, each with its unchanged 180-second process limit. The native suites run
164 actual ELF processes and 1,070 responses, plus 119 direct router entries with
explicitly synthetic child completions. The original recipe freshly builds the
locked 100-package reference, verifies all 175 rmcp crate files, and compares
152 native and 152 original sessions: 1,036 complete responses per side. It binds
ten exact original server blocks, the HIA catalog predicate and 54 original
configuration/execution blocks.

After all original recipe workers have terminated, an additional retained
process rejects 20 damaged-source, image, corpus and completion observations and
performs 22 full evidence admissions. Its stdout, stderr, exit status, duration
and exact immutable report input are checked before the aggregate can pass.
This control process adds no native or Rust semantic calls.

The original `server.rs::call_tool` caller binding, audit, cancellation completion
and durable result chain are still outside this composition. This profile does
not mark any of the 125 production handlers as replaced, advertise unimplemented
tools, or qualify old-stack removal. The SDK default-handler fixture and the
private workdir/directory profiles retain their separate qualification domains.

Admission rechecks the actual compiler/packer results, source closure, full raw
process streams, complete SDK source inventory and every original replay.
The directory's five aggregate wrappers also retain their actual child commands
and completed inner-process streams. No saved summary replaces a fresh original
invocation. Closed effect fixtures are removed only after their captured byte,
filesystem and trace evidence passes; receipts bind that evidence. The workdir
original probe, public-method and regex fixtures are three distinct domains,
and symlinks outside those exact fixture roots remain an admission error.

## Native components

Qualification covers 113 native HIA sources through 45 executable component
entries; the two scope profiles share their HIA scope owner. The shadow entry
qualifies its typed JSON, canonical core and ordered composition controller.
The source registry explicitly identifies the immutable one-worker fence packer
as qualification-only. The 19 test HIA fixtures are recorded separately.
These counts do not count migrated production MCP handlers.

| Source | Implemented behavior |
| --- | --- |
| [runtime_bytes.hepta](runtime_bytes.hepta) | Existing line hash/ID, strict and clamped line indices, log cursor/page arithmetic, name/digest/text predicates |
| [runtime_protocol.hepta](runtime_protocol.hepta) | Strict JSON, JSON-RPC IDs/errors, protocol negotiation, initialization lifecycle, native tool responses and line hashing |
| [text_budget.hepta](text_budget.hepta) | Original byte-based token estimate, binary64 boundary behavior, MiB formatting, line ranges and head/tail truncation |
| [line_endpoint.hepta](line_endpoint.hepta) | Original typed line-endpoint parsing, Unicode trim, integer boundaries, hash normalization and exact diagnostics |
| [batch_plan.hepta](batch_plan.hepta) | Original typed batch admission, operation parsing and endpoint planning, complete ordered diagnostics and full 50-operation / 5 MiB file domains |
| [batch_apply.hepta](batch_apply.hepta) | Original ordered batch conflicts, duplicate/noise diagnostics, full application through EditableContent, Rust Debug escaping and fixed plan-to-apply composition |
| [batch_render.hepta](batch_render.hepta) | Complete original Local batch diff/result rendering, original line IDs, clipping and removed markers |
| [batch_write.hepta](batch_write.hepta) | Complete private Local batch_edit_spec composition through validation, reads, locks, writes, history, cache and full result rendering |
| [batch_write_packer.hepta](batch_write_packer.hepta) | Fixed fourteen-image Local batch effect carrier with explicit wide byte bounds |
| [atomic_write.hepta](atomic_write.hepta) | Complete original Linux Local atomic-write policy, exact Unix temporary paths, metadata/permission behavior, retries, cleanup and cancellation ordering |
| [atomic_write_packer.hepta](atomic_write_packer.hepta) | Fixed native write syscall boundary, descriptor custody, owned worker, cancellation/drain and parent-death cleanup |
| [line_verify.hepta](line_verify.hepta) | Original stale line-ID verification, exact fresh context and nearest-three relocation hints, plus complete strict/clamped index results |
| [delta.hepta](delta.hepta) | Original bounded Myers line diff, exact hunk rendering and deletion markers, CRLF normalization and Rust line splitting |
| [editable_content.hepta](editable_content.hepta) | Original ordered text state, per-line endings, insertion, normalized-byte replacement and trailing-newline preservation |
| [view_render.hepta](view_render.hepta) | Original view range resolution, independent read snapshots, whole/ranged rendering, cache plan and result-size gate |
| [view_filter_packer.hepta](view_filter_packer.hepta) | Static filter for the explicit view-render capacity profile, with exact compiled-image binding |
| [view_cache.hepta](view_cache.hepta) | Persistent serial cache state, lifecycle, per-value limit, invalidation, poisoned-lock behavior and native view-plan application |
| [history.hepta](history.hepta) | Persistent serial original undo snapshots, ten-entry per-file eviction, 64 MiB global budget, stale queue events and exact push/pop/lifecycle behavior |
| [session_workdir.hepta](session_workdir.hepta) | Private per-session root/current path state, exact poisoned-lock behavior and the one-time first-tool atomic latch |
| [file_lock_state.hepta](file_lock_state.hepta) | Original shared lock registry, weak/strong references, fair pending leases, cancellation, sweep and arena growth |
| [file_lock_key.hepta](file_lock_key.hepta) | Exact local canonical path/failure fallback and remote host/port/path key formatting |
| [file_lock_service.hepta](file_lock_service.hepta) | Native canonical-key-to-state dispatch with actual cross-thread shared serialization and growth |
| [file_lock_state_packer.hepta](file_lock_state_packer.hepta), [file_lock_key_packer.hepta](file_lock_key_packer.hepta) | Required standalone state and key qualification executables |
| [file_lock_service_packer.hepta](file_lock_service_packer.hepta) | Fixed three-image static service, four native threads and private CAS/futex state boundary |
| [write_chain.hepta](write_chain.hepta), [atomic_write_shared.hepta](atomic_write_shared.hepta), [local_read.hepta](local_read.hepta) | Local write/append controller, shared atomic caller and descriptor reads through the qualified lock/history/cache chain |
| [write_chain_packer.hepta](write_chain_packer.hepta) | Fixed native write-chain executable and kernel boundary |
| [directory_caller.hepta](directory_caller.hepta), [directory_create.hepta](directory_create.hepta), [directory_errno.hepta](directory_errno.hepta) | Ordered directory caller, real creation state and exact errno results |
| [local_path_policy.hepta](local_path_policy.hepta), [canonical_path_policy.hepta](canonical_path_policy.hepta), [path_source.hepta](path_source.hepta) | Original local policy, canonicalization policy and path-source interpretation |
| [config_directory_owner.hepta](config_directory_owner.hepta), [client_context.hepta](client_context.hepta), [session_request_context.hepta](session_request_context.hepta) | Installed directory/workdir configuration, typed SDK context and per-call session context composition |
| [effect_fence_caller_owner.hepta](effect_fence_caller_owner.hepta), [effect_fence_caller_manager.hepta](effect_fence_caller_manager.hepta), [directory_fence_fs.hepta](directory_fence_fs.hepta) | Fixed permit ownership, caller lifecycle and descriptor operations for directory effects |
| [directory_fence_packer.hepta](directory_fence_packer.hepta), [directory_fence_queue_fixture_packer.hepta](directory_fence_queue_fixture_packer.hepta) | Source-pinned production-capacity and qualification-only one-worker fence executables |
| [directory_service_prefix.hepta](directory_service_prefix.hepta), [directory_service_packer.hepta](directory_service_packer.hepta) | Native directory adapter emission and fixed image packing |
| [workdir_params.hepta](workdir_params.hepta), [workdir_caller.hepta](workdir_caller.hepta), [local_canonical.hepta](local_canonical.hepta) | Exact parameter errors, private set/reset caller order and raw Linux path canonicalization |
| [workdir_service_prefix.hepta](workdir_service_prefix.hepta), [workdir_service_packer.hepta](workdir_service_packer.hepta) | Fixed 21-image private workdir executable |
| [sdk_message.hepta](sdk_message.hepta), [sdk_connection.hepta](sdk_connection.hepta) | Typed SDK message classification and native connection lifecycle |
| [sdk_default_fixture.hepta](sdk_default_fixture.hepta), [sdk_connection_packer.hepta](sdk_connection_packer.hepta) | Explicit default-handler test fixture and static SDK connection test executable |
| [fence_json.hepta](fence_json.hepta) | Exact original typed owner/job serde projection, duplicate-known rejection and IgnoredAny grammar |
| [serde_json.hepta](serde_json.hepta) | Locked Value ordering, integer/float classification and compact finite-number serialization |
| [serde_filter_packer.hepta](serde_filter_packer.hepta) | Static filter for the explicit serde-json.v1 16/64/256 MiB profile |
| [execution_shadow.hepta](execution_shadow.hepta) | Original typed intent validation, canonical struct serialization, domain-separated SHA256 and exact shadow-only result |
| [execution_json.hepta](execution_json.hepta) | Original execution serde types, direct and canonical Value admission, strict unknown-field rules and exact typed error messages |
| [execution_controller.hepta](execution_controller.hepta) | Fixed typed admission, installed-host lookup and core validation order, with checked private child continuations |
| [config_json.hepta](config_json.hepta) | Original typed configuration schemas and defaults |
| [config_validation.hepta](config_validation.hepta) | Original validation order and immutable configuration normalization, with fixed resumable calls into native regex syntax, HIR, NFA and matching. Unconstrained regex resource equivalence and complete production routing remain unqualified. |
| [config_identity.hepta](config_identity.hepta) | Effective configuration serialization and installed identity digest |
| [config_fs.hepta](config_fs.hepta) | Actual startup file/state operations and retained lock descriptors |
| [config_owner.hepta](config_owner.hepta) | Private installed configuration, exact host lookup and immutable cached responses |
| [config_mcp.hepta](config_mcp.hepta) | Persistent stdio controller for the three configured tools |
| [config_fs_packer.hepta](config_fs_packer.hepta) | Static filesystem qualification executable |
| [config_owner_packer.hepta](config_owner_packer.hepta) | Fixed eleven-image static startup owner, including six regex dependency images and preserving private configuration installation and actual descriptor lifetime. |
| [config_owner_fixture_packer.hepta](config_owner_fixture_packer.hepta) | Fixed eleven-image qualification-only startup reinstallation profile with the complete regex dependency chain; never enabled by public MCP input. |
| [config_mcp_packer.hepta](config_mcp_packer.hepta) | Fixed sixteen-image static MCP executable. Validation image 3 calls regex controller 15; syntax 10, HIR 12, NFA 13 and matcher 14 use immutable Unicode image 11 through checked call targets. Only the filesystem image owns OS effects. |
| [config_regex_packer.hepta](config_regex_packer.hepta) | Fixed native configuration-validation profile joining the original validation owner to all required regex children. |
| [regex_controller.hepta](regex_controller.hepta) | Native continuation controller composing syntax, HIR, NFA and matching with checked child receipts and resource/domain refusals. |
| [regex_hir.hepta](regex_hir.hepta) | Native regex HIR lowering, flags and class semantics through checked Unicode queries; complete 34,130-row original HIR domain. |
| [regex_hir_packer.hepta](regex_hir_packer.hepta) | Fixed static native HIR executable with checked Unicode data calls and retained framing/resource refusals. |
| [regex_match.hepta](regex_match.hepta) | Native regex matching through fixed NFA and Unicode dependencies, covering the complete 65,440 original pattern/haystack cases. |
| [regex_nfa.hepta](regex_nfa.hepta) | Native regex NFA construction and observed original budget boundaries; two unchanged halves cover all 3,584 original cases. Unconstrained resource equivalence remains unqualified. |
| [regex_pipeline_packer.hepta](regex_pipeline_packer.hepta) | Fixed static native regex pipeline joining syntax, HIR, NFA, matching and immutable Unicode data. |
| [regex_syntax.hepta](regex_syntax.hepta) | Native regex AST parsing, original diagnostics and typed continuation to immutable Unicode data; complete 18,976-row original syntax domain. |
| [regex_syntax_packer.hepta](regex_syntax_packer.hepta) | Fixed static native syntax executable with checked Unicode data calls and retained framing/receipt refusals. |
| [regex_unicode.hepta](regex_unicode.hepta) | Native Unicode class/property admission and range serialization, with complete 6,560-row original domain and Rust 1.95 capture-identifier predicate projection. |
| [regex_unicode_data.hepta](regex_unicode_data.hepta) | Immutable original Unicode tables encoded in native HIA, supplying checked private range queries to syntax, HIR and matching owners. |
| [regex_unicode_packer.hepta](regex_unicode_packer.hepta) | Fixed static native Unicode query executable generated by HIA; includes the immutable Unicode data dependency. |
| [effect_owner_fence.hepta](effect_owner_fence.hepta) | Original owner/state/predecessor admission and exact semantic results |
| [effect_fence_fs.hepta](effect_fence_fs.hepta) | Descriptor custody, filesystem validation and real Linux failure/race controls |
| [effect_fence_manager.hepta](effect_fence_manager.hepta) | Private asynchronous acquisition, worker cancellation and live permit lifetime |
| [effect_fence_async_packer.hepta](effect_fence_async_packer.hepta) | Fixed five-image static executable with the 512-worker startup profile |
| [effect_fence_async_queue_fixture_packer.hepta](effect_fence_async_queue_fixture_packer.hepta) | Immutable one-worker qualification fixture for queued cancellation |
| [binary_codec.hepta](binary_codec.hepta) | SHA256 raw/hex and resumable state; canonical Base64 encoding and explicit legacy, strict-padding and canonical decoding |
| [operation_kdf.hepta](operation_kdf.hepta) | Internal HMAC/HKDF-SHA256, original token-key derivation, private binding bytes and per-record key derivation with cleared workspace |
| [operation_aead.hepta](operation_aead.hepta) | Internal ChaCha20-Poly1305, full-tag authentication before plaintext output, exact refusal/capacity behavior and declared-workspace clearing |
| [operation_nonce.hepta](operation_nonce.hepta) | Internal serial nonce reservation, original 16,384-use scope budget, exact identity namespaces and persistent private-set lifecycle |
| [operation_record.hepta](operation_record.hepta) | Internal original binding/AAD and bounded result seal/open composition, complete u128 timestamps, authenticated inner-record validation and private staging cleanup |
| [entropy_policy.hepta](entropy_policy.hepta) | Serial Linux entropy fill for 0..128 bytes, default backend probe and descriptor caching, partial fills, retry/error rules and complete-output publication |
| [entropy_packer.hepta](entropy_packer.hepta) | Fixed entropy syscall boundary and static ELF transport with checked continuations, opaque device descriptors and EOF cleanup |
| [operation_scope.hepta](operation_scope.hepta) | Private serial scope construction, bindings, seal/open ordering, reference lifetime and joint key/nonce destruction in separately qualified fixture-entropy and real-OS-entropy profiles |
| [caller_authority.hepta](caller_authority.hepta) | Serial origin/token admission, private authenticated scope selection, first-call session ownership and distinct trusted startup/reconnect lifetimes |
| [authority_loader.hepta](authority_loader.hepta) | Account-owned private token admission and before/after descriptor checks, plus the original fixed-device stdio owner generation order |
| [authority_packer.hepta](authority_packer.hepta) | Exact nine-image authority profile, startup-only token-path effects, private capability boundaries and shutdown cleanup |
| [policy.hepta](policy.hepta) | Original deterministic permission/protection order, executable/environment policy, remote lexical paths and local path operations |
| [stat_version.hepta](stat_version.hepta) | Exact original five-field stat version text and canonical inverse over full integer/timestamp domains |
| [io_policy.hepta](io_policy.hepta) | Read-only descriptor custody, bounded chunk/full-file continuations, file versions, single-link/UTF-8/confirmation checks, complete fingerprint/Linux metadata capture and typed deadline/finalizer decisions |
| [io_packer.hepta](io_packer.hepta) | Static ELF construction with checked syscall records, opaque handles and persistent binary I/O framing |
| [local_service.hepta](local_service.hepta) | Persistent MCP controller for the explicit `native-local` profile, with `host_list`, `binary_read` and delegation to the batch and file-info owners |
| [multi_read_service.hepta](multi_read_service.hepta) | Exact original batch validation order, policy-before-effects, complete UTF-8 file results, MCP text-result budget and redacted failures |
| [file_info_service.hepta](file_info_service.hepta) | Original typed file-info admission and exact compact Linux fingerprint/metadata results, checked IO response and version formatting |
| [composition_packer.hepta](composition_packer.hepta) | Closed native image tables, fixed call authority, private workspaces and bounded child/OS continuations and fixed owned-worker inspection deadline in one static ELF |
| [stdio_packer.hepta](stdio_packer.hepta) | ELF construction and persistent newline-delimited input/output transport |
| [binary32_json.hepta](binary32_json.hepta) | Integer-only exact locked binary32 JSON formatting |
| [typed_result_json.hepta](typed_result_json.hepta) | Original typed Complete CallToolResult/ErrorData field order and scalar serialization |
| [request_result.hepta](request_result.hepta) | Original identity, ack, exact typed wire budget and completion-classification byte decisions |
| [filter_packer.hepta](filter_packer.hepta) | ELF construction for one complete binary input/output operation |

The byte ABI and all eight operations are specified in
[runtime_bytes_abi.md](runtime_bytes_abi.md). Text behavior is specified in
[text_budget_abi.md](text_budget_abi.md), and the typed endpoint boundary in
[line_endpoint_abi.json](line_endpoint_abi.json). Delta operations, exact ordering
and capacity rules are specified in [delta_abi.md](delta_abi.md). Hash/state layouts,
binary bounds and Base64 policies are specified in [binary_codec_abi.md](binary_codec_abi.md).
The internal key/binding frame and caller-owned secret boundary are specified in
[operation_kdf_abi.md](operation_kdf_abi.md). This primitive is not an MCP tool and
is not installed in the seven-image local read service. Its key outputs require a
trusted caller; the serial scope and caller-authority compositions below qualify
those owners separately from the local read service.
The AEAD byte frame and authentication-failure boundary are specified in
[operation_aead_abi.md](operation_aead_abi.md). It is also internal and is not
installed in the local read service. Nonce uniqueness, trusted scope state,
entropy and trusted scope lifetime remain separate requirements; the record byte owner below composes this primitive.
The serial nonce-set boundary is specified in [operation_nonce_abi.md](operation_nonce_abi.md).
It requires one private persistent workspace per trusted scope; all scope clones
must reach that same state. Its two-image hex transport is a qualification fixture
under `tests/hia_native`, separate from the seven-image local read service.
Entropy, production serialization and destruction of the corresponding key
capability remain caller-owned requirements.
The internal record frame is specified in [operation_record_abi.md](operation_record_abi.md).
Its fixed five-image fixture uses the already qualified KDF, codec and AEAD images.
Keys and reserved nonces come only from a trusted scope controller; preflight
admits payload/binding before that controller requests entropy or reserves a nonce.
Its hexadecimal transport is a test fixture and is not installed as a public MCP tool.
The 1,184-byte codec sanitation proof and record high-water cleanup are explicit;
a fatal child-contract failure requires destruction of the whole composition.
The native entropy boundary is specified in [entropy_abi.md](entropy_abi.md).
It supplies the original Linux default backend behavior for serial requests of
0..128 bytes. Its cached descriptor belongs to one private serial workspace;
scope cloning, cross-thread serialization and production crypto call sites
remain separate owners. It is not installed in the seven-image local read service.
The private scope owner is specified in [operation_scope_abi.md](operation_scope_abi.md).
Its eight-image fixture keeps keys behind the scope entry, shares a single nonce
set across serial references and destroys both on last release. It still uses
the deterministic entropy fixture; the standalone system entropy owner above
has not been connected to this frozen scope profile.
The separate [OS scope profile](scope_os_abi.md) connects that same scope owner
to the Linux entropy owner through a fixed eight-image table. Only the private
scope can call the entropy slot; the hex test controller cannot call raw entropy,
record or key primitives. The generic packer validates the complete profile and
actual compiled-image hashes before admitting this effect. The original fixture
profile remains mandatory for deterministic lifetime and fault comparisons.
The OS profile does not install bearer authentication, concurrent capability
sharing or a production MCP handler.
The separate [caller-authority profile](authority_abi.md) binds private token
loading and the original fixed-device stdio owner generation to trusted native
startup events. Its nine-image table admits only the specified controller, scope,
crypto, entropy and loader entries. Request data cannot select the token path or
create an authenticated extension. The serial controller preserves Origin-first
refusal, fixed-width token-digest comparison, first-call owner binding and refusal
of HTTP calls that lack the trusted extension. It does not install concurrent
HTTP transport, metadata annotations or the production handlers. Its exact test
and reference boundaries are in [authority_integration.md](authority_integration.md)
and [authority_original_rust_comparison.json](authority_original_rust_comparison.json).
The [history owner](history_abi.md) preserves the original snapshot and eviction
order, including stale queue entries and the exception that retains one snapshot
larger than the global budget. Its image profile admits complete 128 MiB request
frames, with 256 MiB of private state; the separate persistent ELF fixture has an
explicit smaller transport boundary. The full native corpus contains 6,198
original-owner rows and is replayed against the exact original Rust methods.
The retained observation is in
[history_original_rust_comparison.json](history_original_rust_comparison.json).
Shared file locks, canonical path keys, filesystem writes and production undo
routing remain separate owners; a serial snapshot store alone does not replace
the `undo_edit` handler.

The [private session owner](session_workdir_abi.md) retains an immutable root,
optional current path, original poisoned-lock behavior and the first-tool atomic
latch in one session-owned workspace. Its native suite replays all 4,914
original-owner rows, including complete 8 MiB path values, with 5,043 image
calls. Eight persistent ELF sessions separately replay 320 smaller wire frames;
that fixture domain does not stand in for the wide image corpus. The original
recipe freshly compiles the unchanged `SessionWorkdir` methods, genuinely
poisons nine original locks and checks the atomic latch with 64 Rust threads.
The native side admits 64 serialized entries against the same private state.
Fifteen evidence controls bind the complete streams, images, private call table,
compiler receipts and actual process commands. An independent invocation of the
three unified qualification entries passed in 18.807 seconds using verified
compiler artifacts; this is a focused run, not a fresh full compiler-cold claim.
First-capabilities policy/OS checks, the public `workdir` handler and concurrent
HTTP session ownership remain caller work. No production handler is activated
by this state component.

The [file-lock components](file_locks_abi.md) retain the original canonical-key
and registry semantics. Their standalone state/key executables are required
qualification dependencies of the [connected lock service](file_lock_service_abi.md),
which dispatches the actual HIA canonical owner into one shared state owner.
The service uses four native threads with explicit CAS/futex serialization and
retains 2,080 leases during shared arena growth. Its complete native domain has
237,424 ELF requests: 51,783 state operations, 179,431 canonical acquire/drop/statistics
requests and 6,210 concurrent operations. These overlap the standalone domains;
they are not additional unique owner cases to sum together.

All six suites run in one ordered partition. The aggregate checks the complete
state producer's actual stdout before admitting the service corpus, all image
and HIA pack receipts, 133 direct service calls, six packer calls, thirteen actual
transport/bad-child processes and 51 refusal controls across the two components.
Two mandatory original recipes each freshly build the locked Rust owners. The
service recipe compares 231,214 sequential result frames byte for byte, checks
6,210 original concurrent-property operations and runs 112 paired real kernel
controls. Concurrent interleavings and TIDs are checked by their properties;
they are not claimed to match byte for byte. Retained independent observations
are [file_locks_observation.json](file_locks_observation.json) and
[file_lock_service_observation.json](file_lock_service_observation.json).

Pending async waiting, cancellation/Drop ownership in an upper write caller,
atomic/history/batch ordering and SSH/SFTP effects still require integration.
Neither lock component activates a production handler or qualifies removal of
its original callers. The key/state standalone sources and tests remain active
dependencies, rather than abandoned versions of the composed service.

Policy operations and their caller boundaries are in [policy_abi.md](policy_abi.md).
The exact file-version boundary is specified in [stat_version_abi.md](stat_version_abi.md).
The read-only OS dependency, startup-root custody and exact wire records are
specified in [io.abi.json](io.abi.json).
The explicit local MCP profile is defined in [service_contract.md](service_contract.md),
and the closed native call boundary in [composition_abi.md](composition_abi.md).
The batch owner and its independently checked validation/reference domains are
defined in [multi_read_service_abi.md](multi_read_service_abi.md).
The file-info controller, metadata IO order and native watchdog are specified in
[file_info_service_abi.md](file_info_service_abi.md), [file_info_io_abi.md](file_info_io_abi.md)
and [file_info_deadline_abi.md](file_info_deadline_abi.md). Its normal filesystem
comparisons, synthetic native state controls and actual cancellation evidence
remain separate in [file_info_deadline_observation.json](file_info_deadline_observation.json).
No native component falls back to
a Rust or Python implementation of its calculations. Endpoint JSON number
classification and compact display bytes remain explicit caller inputs; the
component does not claim to replace the serde parser itself.

The packers contain explicit Linux syscall adapter bytes for memory allocation
and descriptor I/O. HIA code constructs the ELF, relocates the call and installs
the HIA component image. These adapters do not supply a general filesystem,
network, SSH, database or process-management standard library.

## Build and verify

Use an ordinary checkout of the exact Hepta commit shown above. The builder
checks both the commit/tree and the actual tracked source bytes; changing the
dependency checkout, a source file, or a cached compiler image is rejected.
Qualification clears inherited `HIA_*` development overrides before admitting
its own manifest, source, compiler and corpus inputs. Standalone suites retain
their explicit development overrides; these cannot silently substitute an
external loader or fault probe in the closed qualification.
Python 3.11+ and a C toolchain are build/test dependencies for the initial seed.
Independent comparison also requires Rust 1.95.0, Cargo and that toolchain's
`rustfmt`; endpoint, batch planning, codec, KDF, AEAD, nonce, record, entropy, scope and authority
reference dependencies are pinned in their Cargo.lock files.
The independent Python AEAD reference uses the exact packages in
`tests/hia_native/python-reference-requirements.txt`, installed in a test-only
virtual environment. Emitted HIA programs do not use those packages.
The read-only I/O fault tests also require Linux seccomp user notification for
their own test child. The suite does not skip these controls when unavailable.
They are not dependencies of the emitted executable. The observed empty-pipe
blocking fixture additionally uses GNU `as` and `ld` at test time, and its actual
ELF is retained with the qualification receipts.

From this runtime checkout:

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

CI executes the complete gate through one fresh prepare job, five native
partitions, seven original-reference groups and a final evidence collector. The
prepare job executes the full cold gate and builds every module once. Each
native partition admits that workflow-produced SHA256 and the full source,
compiler, build and invocation identity before running its complete suite list.
Batch, text/history/view, JSON, configuration/regex and system suites run on
separate runners. Configuration keeps all fifteen existing suites in their
original order; the three result byte owners remain in the JSON partition.
Each job retains 15 minutes, each native suite retains 180 seconds, and every
original recipe and compiler cold deadline remains unchanged.

A separate native collector admits all five completed partitions and seals the
whole native corpus. Every original group starts from those exact bytes. The
forty required recipes are assigned once to bytes, state, services, JSON,
configuration, system and batch groups. The two generic JSON recipes share one
fresh locked build; the three result recipes share another. Workdir and Write
stay together through their original fixture retirement, and the two independent
OS reference workers retain their separate concurrent process receipts.

Each successful original job publishes its own seal SHA256 through a dedicated
workflow output. The final collector requires all seven supplied identities,
every recipe, every actual completed process and all retained source, binary,
input/output and compiler bytes. A partial group cannot claim aggregate PASS.
The final mutation controls run only after every reference job has completed.
Both native and original shard reports remain retained and are rechecked at
later evidence admission. ZIP-lost executable modes are restored only after all
owned regular-file bytes pass; directory inventories preserve empty snapshots.

Failed jobs upload a separately captured diagnostic tree, including raw inputs,
outputs, original source and receipts. Active Cargo target/build trees and live
effect fixtures are excluded from that diagnostic subset, so a disappearing
compiler temporary cannot break the upload. This does not turn partial output
into complete evidence or qualify cleanup after an outer SIGKILL. Successful
shards retain their full artifact inventory. The original cancelled CI runs and
their exact failures remain separate observations.

Live effect fixtures are retired only after complete snapshots, full content
gzips, traces and actual process outputs pass their owner checks. Their receipts
bind that accepted evidence; no semantic call is reconstructed. The standalone
commands above remain available for the complete sequential gate.

The output directory must be new. Earlier reports are not overwritten. The
builder executes B0 → B1 → B2 → B3 and requires byte-identical B1, B2 and B3.
The declared gate has 133 native suite processes, one fresh compiler cold
process and 40 required original recipes. The CI groups additionally retain
seven actual Rust-version observations; the sequential entry retains one.
Each recipe may contain several actual compile/replay checks, all counted from
completed records. The configuration recipe retains both complete original
processes. Twelve result controls, twenty public-registry controls and fourteen
configuration/regex controls then re-admit the inactive evidence without adding
semantic calls. Each shared JSON build still performs every complete replay.
A component's retained historical
comparison is not a fresh aggregate invocation.
The OS-scope, authority-transport and file-info-guard suites run through two
independent worker slots. The JSON Value and JSON transport suites execute in
order through one additional worker, using their separate output directories;
the compiler cold gate finishes before these workers start. Large batch, view
and history suites remain sequential on the caller. The original OS-scope and authority Rust
recipes use two independent workers, while the two JSON references retain their
shared-build order. No suite or recipe is omitted, and all process results are
collected in declaration order. Each suite keeps its original 180-second process limit and private
execution receipt. The aggregate records every completed process, drains jobs
already launched when another suite fails, and checks the receipt hashes again
before accepting any original Rust replay. The file-info cancellation fixtures
retain both fixed 30-second deadlines.
The resulting B3 compiles the runtime sources and their HIA transport packers.
Every invocation also runs the complete upstream cold replay in a new source-only
export, retaining the upstream 180-second qualification and separate 3-second
cleanup budgets. The outer process has 240 seconds only to allow cleanup and
report writing; it cannot extend the inner qualification deadline. The result
must contain all 11 original outer checks and all 5,049 nested checks, matching
source hashes, a successful owned-process receipt and B1/B2/B3 images identical
to the compiler used for these runtime modules. Only then can
`matching_source_full_cold_qualified` become true.

The earlier `f33d8da` compiler cold run timed out at 180.309 seconds with 6/11
outer checks. It remains recorded as a failure in
[compiler_cold_observation.json](compiler_cold_observation.json). The current
`d3e2c901` compiler changes final evidence serialization while preserving the
HIA compiler image. Its observed 11/11 and 5,049/5,049 cold pass in 173.029 seconds
is retained with original report/source digests in
[compiler_compact_cold_observation.json](compiler_compact_cold_observation.json).
That historical observation never substitutes for the fresh replay above.

The main output files are:

```text
result.json
compiler-cold.json
compiler-cold.cold/qualification.json
compiler-cold.cold/process-owner.json
build/modules/runtime-protocol/runtime-protocol.elf
build/modules/runtime-protocol/manifest.json
build/modules/runtime-bytes/runtime-bytes.elf
build/modules/runtime-bytes/manifest.json
rust-oracle/input.bin.gz
rust-oracle/native-output.bin.gz
text-rust-oracle/native-corpus.json
endpoint-rust-oracle/native-corpus.json
delta-rust-oracle/native-corpus.json
codec-rust-oracle/native-corpus.json
codec-rust-oracle/codec_cases.jsonl.gz
operation-kdf-rust-oracle/native-corpus.json
operation-kdf-rust-oracle/kdf_cases.jsonl.gz
operation-aead-rust-oracle/native-corpus.json
operation-aead-rust-oracle/aead_cases.jsonl.gz
operation-nonce-rust-oracle/native-corpus.json
operation-nonce-rust-oracle/nonce_cases.jsonl.gz
operation-record-rust-oracle/native-corpus.json
operation-record-rust-oracle/record_cases.jsonl.gz
system-entropy-rust-oracle/native-corpus.json
system-entropy-rust-oracle/backend.json
system-entropy-rust-oracle/packer.json
system-entropy-rust-oracle/kernel-native.json
system-entropy-rust-oracle/transport.json
system-entropy-rust-oracle/kernel-original.json
system-entropy-rust-oracle/rust-comparison.json
operation-scope-rust-oracle/native-corpus.json
operation-scope-rust-oracle/scope_cases.jsonl.gz
operation-scope-rust-oracle/scope_fault_sessions.jsonl.gz
operation-scope-rust-oracle/scope_capacity_controls.jsonl.gz
operation-scope-rust-oracle/rust-comparison.json
caller-authority-rust-oracle/controller.json
caller-authority-rust-oracle/controller/authority_cases.jsonl.gz
caller-authority-rust-oracle/kernel/kernel-report.json
caller-authority-rust-oracle/transport/transport-report.json
caller-authority-rust-oracle/packer.json
caller-authority-rust-oracle/evidence.json
caller-authority-rust-oracle/rust-comparison.json
batch-plan-rust-oracle/native-corpus.json
batch-plan-rust-oracle/requests.bin.gz
batch-plan-rust-oracle/native-output.bin.gz
batch-plan-rust-oracle/history.jsonl.gz
batch-plan-rust-oracle/elf-observation.json
batch-plan-rust-oracle/original-build/build.json
batch-plan-rust-oracle/original-replay/comparison.json
batch-plan-rust-oracle/original-replay/original-output.bin.gz
batch-plan-rust-oracle/rust-comparison.json
policy-rust-oracle/native-corpus.json
stat-version-python-reference/native-corpus.json
stat-version-python-reference/stat-version-cases.jsonl.gz
local-service-python-reference.json
multi-service-python-reference.json
file-info-python-reference.json
file-info-controller.json
file-info-io-state.json
file-info-deadline-state.json
file-info-io-faults.json
file-info-guard.json
file-info-blocking-probe.json
file-info-blocking-probe.elf
multi-read-rust-oracle/native-corpus.json
multi-read-rust-oracle/requests.hex.gz
multi-read-rust-oracle/native-output.txt.gz
build/composition/<source-key>/manifest.json
build/composition/<source-key>/native-local-read.elf
```

The test driver runs actual native images and the standalone ELF. It retains
test stdout/stderr, source identities, compiler receipts and exact output
corpora. The CI workflow compiles original Rust function bodies and independent
locked Rust reference crates, then compares their results with the retained
native corpus. The aggregate
result is `NATIVE_COMPONENTS_PASS` after the fresh full compiler cold gate,
native tests and retained-Python chunk/full-file, file-version and MCP comparisons. It becomes `PASS` only
after all 40 required original Rust recipes succeed. The Python reference domain
is accounted separately and is never represented by a dummy Rust recipe. Timeouts retain partial
stdout/stderr and the failing check; they cannot be recorded as a pass.

The local-service receipt records live comparisons on temporary files whose
inode and timestamp values vary on each run. The original Python read helper
runs against those same fixtures, and the test compares the native MCP result
text byte for byte. This reference domain has no synthetic Rust recipe. The
closed image table and its generic continuation controls are reported separately
as new native adapter behavior. Qualification rechecks all seven source/image
pairs, the HIA packer, exact call masks and capacities, packed-frame digest and
final executable identity before accepting this evidence. Each packed child is
also matched to the native image independently exercised by its component suite.

The record receipt independently binds its fixed five-image call table, every
source/image pair, the compiler, packer, packed frame and executable. Its three
crypto leaves must match the native images exercised by their individual suites.
The live corpus also binds the test and build driver source hashes. Qualification
counts 823 replay rows separately from 702 rows reaching original semantic
owners and 817 observed original-owner calls; the 121 malformed-frame rows are
adapter coverage. Capacity, extra byte-domain and child-contract controls are
not relabelled as original interface comparisons.

## Explicit native local read service

Build the seven-image service using the same pinned compiler:

```sh
python3 -I -B scripts/hia_native_composition_build.py \
  --hepta /absolute/path/to/pinned/Hepta \
  --build-root /absolute/path/to/native-build
```

The command returns a manifest path. Its directory contains the executable:

```sh
/absolute/path/to/native-build/composition/<source-key>/native-local-read.elf \
  --local-read-profile /administrator/selected/root
```

The explicit profile argument is required. The root is supplied by the operator
at startup and retained as an open directory capability. Client JSON cannot
change it or reinterpret an existing SSH alias. `host_list` returns one host
named `native-local`, with reads enabled and execution, PTY and writes disabled.
After initialization, `binary_read` accepts that host and an absolute path under
the selected root. It preserves the original read response fields, default and
clamped limits, Base64 bytes, SHA256, exact version text and successful MCP text
envelope on the tested shared domain. A noncanonical expected-version string
becomes a version mismatch after file/path/type admission and before cursor
checks, preserving the original error order.

`read_multiple_files` accepts one to sixteen distinct absolute paths. It defaults
to 16,384 bytes per file and a 65,536-byte result budget; explicit bounds must be
1..65,536 and 1,024..262,144. It checks every path before opening any source,
reads complete regular single-link files, verifies versions and path identity,
and requires strict UTF-8. Its result states `atomic_snapshot: false` and
`snapshot_scope: "independent_file"`. A failed file produces a redacted error
without publishing earlier file content. The result limit covers the complete
MCP text result, including nested escaping, and excludes the JSON-RPC envelope.

`file_info` requires string `host` and `path` only. It hashes the complete held
regular file to EOF, then captures Linux xattr/ACL metadata through a retained
parent descriptor and separate version intervals. It preserves original compact
text, metadata ordering and last-finalizer error precedence on the declared
local domain. Its native watchdog has a fixed 30-second duration: only an owned
worker performs target effects, and the parent imports a complete result after
root, counter, descriptor-generation and deadline checks. Timeout discards partial
state and cancels that worker. At most one not-yet-reaped worker can remain;
subsequent inspection returns `EBUSY` until a nonblocking reap succeeds.

The current normal suites observe 415 actual service responses. Separate actual
metadata-fault and guard controls add 30 and 34 responses. The guard controls
include blocked read/xattr deadlines, five setup failures with same-process
recovery, resource custody, root replacement and a closed-stderr launch retaining
its root as raw fd 2. HIA fixture acknowledgements and the separate 200 ms actual
pipe-block probe are never counted as production filesystem results.

The controller calls fixed HIA owners for policy, binary codec, read-only I/O,
stat version and batch orchestration. The batch owner may call the same four
leaves; it cannot call the main controller. The executable contains all seven images and the native
continuation adapter; it invokes no Python semantic dispatcher or dynamic module
loader. Call masks and region bounds constrain child calls. Private mappings,
an eight-level depth bound and a 262,144-entry per-frame continuation budget constrain the
adapter. This is a closed set of trusted compiled HIA images, not a sandbox for
arbitrary uploaded machine code.

This profile deliberately retains root inode custody across requests, while the
original Python helper reopens pathnames. It also has explicit native path and
frame bounds. Binary-read paths are bounded to 4,095 UTF-8 bytes, while batch
paths preserve the original 4,096-byte component-walk boundary. It does not replace configured host loading, SSH, remote platforms
or the complete original authorization model. Those differences keep the 125
production-handler migration rows and all completion/removal flags unchanged.

## Diagnostic MCP stdio service

Launch `runtime-protocol.elf` directly with no arguments. It reads one JSON
message per LF-delimited frame and writes one LF-delimited response. A final
nonempty frame at EOF is processed once. Notifications produce no response.
The process retains its own initialization state and supports multiple calls
before stdin closes. Separate processes/sessions have separate state.

The supported protocol version is **2025-06-18**. An older or unknown client
proposal receives that supported version. The client decides whether it can
proceed. Batch requests are outside this profile. The service implements:

- `initialize`, followed by `notifications/initialized`;
- `ping` during and after initialization;
- `tools/list` and `tools/call` after initialization;
- `notifications/cancelled`, with no outstanding asynchronous tool to cancel;
- malformed-input, invalid-request, unknown-method, invalid-parameter and
  uninitialized-session responses.

`runtime_line_hash` accepts `{"text":"hello"}` and computes the original
runtime's FNV-1a32/XOR-fold8 hash over decoded UTF-8 bytes. Its result for this
example is `57`. Unicode and escape-equivalent JSON strings retain the same
underlying byte semantics as the original Rust `str` implementation.

Frames and outputs are bounded to 8 MiB; the native service has a 32 MiB private
workspace. JSON depth and node limits are 128 and 262,144. Buffer exhaustion is
an explicit refusal. Initialization state advances only after a complete
successful initialize response can be constructed. A closed output pipe may
terminate through inherited SIGPIPE; callers must observe the process exit.

## Verified behavior

The byte kernel has passed **22,509 direct native calls**, including **21,863
cases in the original Rust text/integer domain** and 646 extra byte-domain
controls. A separate Rust 1.95.0 execution of the unchanged original function
bodies produced exactly the same 601,173 output bytes for all 21,863 original
domain cases. The source and output identities are retained in
[original_rust_comparison.json](original_rust_comparison.json). That independent
recheck is not added to the native count as new functional coverage.

The text component has passed **26,869 valid native cases**, including full-u64
floating-point rounding boundaries, Unicode, line ranges and release-profile
integer wraparound. The unchanged original Rust functions produced identical
1,531,374 output bytes for those cases; see
[text_original_rust_comparison.json](text_original_rust_comparison.json). Invalid
UTF-8/frame controls, capacity atomicity, independent VM cases and direct static
ELF execution are checked separately.

The endpoint component has passed **6,366 native calls**, including 930 retained
Rust-generated vectors, 5,224 generated reference cases, invalid UTF-8, capacity
atomicity and an 8 MiB boundary. A separate execution of the original, included
`src/utils/line_hash.rs` with pinned serde dependencies matched **6,155 actual
native calls**. See [endpoint_original_rust_comparison.json](endpoint_original_rust_comparison.json).

The delta component has passed **9,101 valid native cases**, including exhaustive
short repeated-line inputs, independently checked minimum edit distances, exact
Myers tie ordering, context merging, Unicode, CRLF and distances 499/500/501.
The unchanged original Rust functions produced the same **2,530,734 output
bytes**; see [delta_original_rust_comparison.json](delta_original_rust_comparison.json).
It also passed 90 malformed-record controls, capacity and semantic-`None`
distinction, five VM cases and three standalone ELF calls. File access and
per-session view-cache state remain original caller owners.

The codec component has passed **22,517 direct native calls**, including SHA256
padding/block boundaries, portable state partitions and forks, a 9 MiB stream,
Base64 grammar/pad-bit controls and the exact binary payload bounds. The SHA
compression helpers are imported unchanged from the pinned upstream HIA source,
with function-index relocation checked by structural hashes. Independent locked
Rust `sha2`/`base64` crates matched **16,965 captured cases**. Actual desktop
CPython 3.12.3 matched **5,380 legacy-decode cases**; actual scratch CPython
3.12.14 matched **5,381 strict-padding cases**, including an additional input
bound control. Each run tests only its observed Python policy directly. Both
policies remain explicitly selectable in native code; the canonical profile
also rejects nonzero pad bits. See
[binary_codec_independent_comparison.json](binary_codec_independent_comparison.json).
These comparisons replay existing native calls and do not add new native
coverage. Filesystem publication, file-version checks and upload state remain
with their existing owners.

The operation KDF component has passed **1,378 direct native calls** and **five
standalone ELF executions**. Its independent Python comparisons comprise 867
standard HMAC/HKDF cases, 388 original-binding projections and seven additional
exact-capacity successes; 14 capacity refusals are checked separately. The
captured 1,364-row corpus includes 102 other admission refusals. Native success
clears the full 2,048-byte used workspace; refusal leaves mutable buffers intact.
All nine imported SHA helper functions are checked against the codec source
after reversing call relocation.

A separate locked Rust execution matched all **1,364 captured rows**, including
**405 calls into the complete unchanged original operation crypto module** and
**28 comparisons through its opaque record-key AEAD result**. Those original
owner calls include rejection cases. All inputs are synthetic keys/tokens, and
replaying the corpus adds no native test coverage. The retained proof is
[operation_kdf_original_rust_comparison.json](operation_kdf_original_rust_comparison.json).
The current qualification repeats this recipe. It qualifies deterministic key
and binding bytes; bearer verification, trusted context construction, AEAD
scope integration, entropy, nonce custody, scope lifecycle, replay and ledger persistence
remain unfinished original owners. There is no public MCP key-output interface
or constant-time/whole-process erasure qualification.

The operation AEAD component has passed **1,856 direct native calls** and **six
standalone ELF executions**. The independent `cryptography` reference checks
671 encryptions and 671 decryptions, including the published RFC 8439 known
answer, padding/counter boundaries and maximum inputs. Separate domains cover
354 authentication refusals, 119 malformed/over-bound refusals, 15 capacity
refusals, four exact-capacity successes and 33 original record projections.
The latter projections include both payload kinds, full 128-bit timestamps,
empty through 1 MiB original payloads and corrupted tags. These domains overlap
where a record projection is an authentication refusal; the total direct-call
count is independent and exact.

The locked Rust recipe must match all **1,841 exported rows**, including
33 calls each to the complete unchanged original seal and open owners, with
11 original authentication refusals. Deterministic synthetic entropy makes the
original packets directly comparable with native output. The recipe adds no
native-call coverage and cannot qualify aggregate PASS until actual execution
matches every output and the recorded domain counts. Authentication failure
leaves the entire output unchanged. Successful operations and authentication
refusals wipe the declared 512-byte workspace. CPU register/stack erasure,
constant-time behavior, nonce uniqueness and complete crypto scope ownership
are not certified by these byte tests.

The operation nonce component has passed **17,830 direct native calls** and
**16,401 requests across four actual static ELF processes**. The latter comprises
16,399 requests through the persistent two-image test fixture and two standalone
lifecycle requests. Direct controls cover exact exhaustion at 16,384 reservations,
namespace separation, all nonce bytes, collision chains that wrap the table,
duplicate refusal without state loss, nine capacity refusals and ten private-state
fault controls. A trusted controller must retain the same workspace for every
clone of a scope and destroy its key capability when clearing that workspace.

The original Rust execution matched all **17,811 captured session rows**,
including **17,611 original binding calls**, **17,470 actual NonceLedger
reservations**, **17,183 accepted reservations** and **287 nonce refusals** across
eight sessions. The retained observation is
[operation_nonce_original_rust_comparison.json](operation_nonce_original_rust_comparison.json).
Every qualification must execute that tenth Rust recipe again; the historical
observation cannot advance an aggregate result. The checker binds the corpus and
output digests, exact counts, original source, direct native image, both packed
fixture images and their fixed authority table. The fixture does not qualify
entropy, production concurrency, rollback resistance or complete crypto-scope
replacement, and introduces no public MCP crypto tool.

The entropy component has four mandatory suites, with exactly **11 backend,
5 packer/cache, 8 kernel and 6 transport groups** and no skips, expected failures
or unexpected successes. The backend suite performs **1,929 actual HIA calls**
with **1,609 synthetic effect completions**; these are state-machine controls.
The packer/cache suite makes **42 actual HIA packer calls**, executes **19 native
images**, and verifies one admission plus two refusals against a copy of the
real compiler/artifact cache when the top-level compiler pin is missing or wrong.
The transport suite runs **13 native processes** for framing, CLI, output-error
and invalid-kernel-success controls.

The separate kernel suite executes **25 actual native processes and 56 request
frames**. The same eight groups were replayed against the complete unchanged
original `SystemEntropy`, making **56 original owner calls**. Each side produced
46 successful fills and 10 entropy refusals. It covers real default Linux
`getrandom` and device-fallback selection, cached probes/descriptors, interrupted
and partial reads, failures and recovery. Native and original normalized syscall
traces match. Normal random bytes are not compared for equality. The only
normalization removes actual descriptor numbers and the native explicit cached
descriptor close at EOF; the original cache is closed by process exit. See
[entropy_original_rust_comparison.json](entropy_original_rust_comparison.json).

Every qualification rebuilds and executes this twelfth Rust recipe. The gate
binds all four complete suite receipts and streams, all kernel events and their
provenance, current source bytes, compiled flat images, full compilation/packing
receipts and the final static ELF. It verifies the unchanged original module
inside the generated Rust source, locked dependencies, empty `getrandom` features
and rustflags, actual original binary bytes, and all 25 paired traces. It never
counts replayed cases as new native cases. A host unable to perform the owned
child kernel controls fails the gate. The reference lock uses `libc 0.2.191`,
while the pinned runtime lock uses `libc 0.2.189`; the ABI documents this
difference. These results do not claim a rebuild of the complete original lock,
thread-safe workspace sharing, production adoption or complete runtime replacement.

The private scope component has passed **12 native groups** covering construction,
all private binding methods, seal/open ordering, serial clone lifetime, the full
16,384-reservation budget and joint destruction. It retains **17,021 direct
requests**: 588 scope requests, 16,384 nonce-preparation requests and 49 fixture
controls. A separate eight-image executable runs **27 requests in four processes**,
producing 26 responses plus one deliberate fatal child-contract exit.

The actual original Rust replay contains **16,944 rows across 24 complete sessions**.
These include 16,384 nonce-preparation rows, 423 original scope rows and 137
adapter-only rows. Original calls total 33,191: 32,768 nonce/binding preparation
calls and 423 scope calls. This preserves four clones, 22 releases, 18 last
releases and 92 synthetic entropy fills requesting 1,704 bytes. See
[operation_scope_original_rust_comparison.json](operation_scope_original_rust_comparison.json).

The gate retains all **74 rows from 25 predefined fault sessions**, including
their 47 earlier rows and later release/refusal rows, plus **three capacity
controls**. These domains are disjoint from Rust replay and reconstruct every
direct native request in order. Installing a named fault selects its entire
session before the result is observed. The checker binds each reason, ordinal,
mutated completion record and resulting state to its complete retained history.
Its dedicated Rust recipe keeps real original scopes, clones and nonce sets
alive across the admitted session histories and compares statuses, output bytes,
reference counts, entropy-call counts and nonce counts. This frozen fixture does
not establish an operating-system entropy connection, concurrent capability
admission or production replacement.

The real OS scope profile separately passes **11 native kernel groups**, with
**37 native processes and 238 responses**, plus four no-response contract or
transport requests. Its paired original comparison retains **31 original
processes and 226 responses**: 220 calls reach original owners and six are
adapter-only state refusals. It compares 114 deterministic responses byte for
byte and performs two real-random cross-owner decryptions. All 31 standard
library `RandomState` seed calls remain in the trace with actual libc/vDSO
identity, instruction position and event order; they are not counted as
`SystemEntropy` calls or hidden by output filtering. Every native exit is checked
for declared workspace/output clearing and cached-descriptor retirement.
The packer suite performs 103 native calls and refuses 37 rehashed altered ELFs.
The receipt suite rejects 33 damaged evidence cases without adding native calls.
See [scope_os_original_rust_comparison.json](scope_os_original_rust_comparison.json).
The paired comparison executes a fresh 37-process native side again; those
additional 238 responses are reported separately from the native phase.

The serial caller-authority profile has five mandatory suites and **30 native
groups**: eight controller groups, five loader groups, six transport groups,
four packer groups and seven evidence groups. Their retained domains include
786 controller/leaf entries, 110 actual loader processes and 48 actual transport
processes carrying 144 frames. All five require zero skips, failures and errors.
The evidence suite rejects 37 changed receipts or artifacts, including two
consistently rehashed substitutions of directly loaded leaf images. Production
entropy and deterministic controller-fixture entropy remain separate evidence
domains; the latter cannot establish OS behavior.

Its mandatory original Rust recipe checks formatting with the selected
toolchain, compiles the unchanged original owners with locked dependencies,
replays 122 captured controller rows, and executes 110 original loader
processes. The four completed subprocess checks retain their own streams and
exact source/binary identities. Historical comparison receipts in
[authority_original_rust_comparison.json](authority_original_rust_comparison.json)
cannot substitute for that new execution or increase native coverage counts.

The line-verification component compares **4,346 complete responses** with the
unchanged original `verify_line_id`, relocation and strict/clamped index
functions. It preserves the complete diagnostic text, two context lines on
each side, nearest-three ordering with stable ties, full LP64 totals and
`i64::MIN` behavior. Its compact typed line-slice frame covers a complete
5 MiB file with **5,242,880 empty lines** and a full-size UTF-8 line. The actual
original Rust replay matched all **12,105,180 captured output bytes**. Another
92 malformed packets, four capacity refusals and one exact-capacity acceptance
bring the direct native count to **4,443**; four static ELF calls are separate.
The [ABI](line_verify_abi.json) and
[original comparison](line_verify_original_rust_comparison.json) describe this
internal owner. JSON parsing, file effects, edit locking and the public edit
handlers remain separate.

The batch-planning component has **3,339 direct requests**: **3,174 original
reference rows** and 165 adapter, frame, child-contract and capacity controls.
Those requests enter the HIA controller 53,301 times, the native endpoint owner
40,630 times and the native verification owner 9,332 times. They preserve the
original preflight and operation-error order, null/end/insert behavior, both
endpoints and duplicated diagnostic text. A separate fixed four-image ELF
executes 21 requests, including 20 original-compatible responses and one
declared adapter-capacity refusal; it has no Python semantic dispatcher.

The maximum cases use all 50 operations against a full 5 MiB line. One hundred
plain diagnostics produce **524,298,089 bytes**; one hundred stale-ID diagnostics
produce **524,301,763 bytes**. Pure repeated endpoint verification is memoized,
while every original error copy remains in the output. The full corpus retains
**1,066,976,665 output bytes** as complete compressed streams and compares every
byte with the unchanged original Rust blocks. The named image-only
`batch-plan.v1` capacity profile supports these tests without changing the
standard or view transport limits. The static four-image fixture has its own
smaller 2 MiB result boundary; it does not claim that large-result coverage.

Qualification requires both native suites, 44 evidence-mutation refusals,
source-checked imported HIA functions, actual compiler receipts and complete
ELF/image-table binding. The independent recipe performs a fresh locked Cargo
build and then streams all 3,174 rows through that newly built binary. Its
build and replay each keep the 180-second budget. The
[ABI](batch_plan_abi.md) and [captured original comparison](batch_plan_original_rust_comparison.json)
describe the internal boundary. Public JSON/MCP admission, path authorization,
conflict checks, edit application, history/cache effects and production routing
remain separate owners.

The [batch application owner](batch_apply_abi.md) covers 14,412 complete original
requests plus 140 invalid frames and six capacity refusals. The maximum case
retains all fifty five-MiB contents and its complete 267,387,010-byte result.
Its 102 contract faults and exact-capacity success verify child calls, private
state cleanup and publication atomicity. A fixed six-image ELF serves eight
requests, including eight complete native plan-to-apply joins. Unicode Debug
formatting is checked against the complete Rust scalar domain. The mandatory
original recipe freshly compiles and executes both the unchanged original
batch owner and the Debug probe, preserving complete output bytes and actual
stderr. Seventeen evidence-corruption controls do not add semantic calls.
The EditableContent LF scan and bulk operations have changed f3/f5/f8; all other
twenty functions retain their exact source and the complete original Editable
recipe remains mandatory. Canonical locks, file writes, history/cache updates,
configuration, authorization and production routing remain separate owners.

The [local atomic-write owner](atomic_write_abi.md) runs the complete original
Linux Local `atomic_write` ordering through a fixed syscall-only native boundary.
It preserves raw Unix parent bytes, lossy temporary names, followed metadata,
all original permission bits, open/write/chmod retry behavior, partial writes,
write-failure temporary files and chmod/rename cleanup precedence. The native
worker preserves cancellation acknowledgements, blocking-stage drain, persistent
statx fallback state and parent-death custody. The complete batch-derived
**505 MiB write** uses the existing named adapter capacity profile; it does not
introduce a new file-size policy.

Four mandatory suites cover **170,947 direct HIA entries**, including **88,807
path requests** and synthetic effect/error histories; **151 real-kernel cases
with 171 actual write requests**; **28 actual boundary processes**; and **34
evidence-corruption refusals**. Synthetic transitions, filesystem requests and
refusal checks remain separately counted. All four processes keep the original
180-second deadline. They run sequentially in the batch partition, preserving
the complete large-memory domain.

The required original recipe uses Rust **1.95.0**, the complete unchanged
`text_editing.rs` atomic function and locked original dependencies. It freshly
builds the oracle, compares all 88,807 path responses and 4,095 errno properties
plus two NUL/WriteZero properties, then runs both writers against fresh kernel
fixtures: 151 state/trace comparisons and 171 requests per writer. The new paired
native calls do not increase the native-phase count. The
[captured original comparison](atomic_write_original_rust_comparison.json)
retains the final actual remote execution and earlier failures, including the
statx fallback correction. That observation does not substitute for the required
fresh CI recipe. Canonical file locks, shared caller lifetimes, authorization,
history/cache updates, Remote/SSH and production tool routing remain unported.

The editable-content component compares **8,749 complete ordered responses**
with the unchanged original `EditableContent` methods. This includes mixed
line endings, UTF-8 byte boundaries, full-u64 method errors, an empty final
unterminated line, 1,400 deterministic operation sequences and complete 5 MiB
files. Its 5,242,880-line case executes both in-process HIA and the standalone
ELF. Another 65 malformed frames, four capacity refusals and one exact-capacity
acceptance are native-only controls. The final locked original Rust recipe was
also executed directly and matched every captured byte. The
[ABI](editable_content_abi.md) and [original comparison](editable_content_original_rust_comparison.json)
describe the boundary: no file reads/writes, locks, history or production edit
handler has been installed by this component.

The view-render component compares **3,125 captured requests** with unchanged
original range, file-render, cache, delta and result-gate methods: 2,721 render
requests and 404 preparation requests. Its 237,318,931 request bytes and
139,202,296 response bytes are retained in compressed corpora and checked as
streams. It covers the complete 5 MiB file domain, 8 MiB result boundaries,
different first/second read snapshots, cache updates before oversized-result
refusal, full refresh and worst-case line counts. The explicit `view-render.v1`
transport provides 16 MiB input/output and 256 MiB workspace; the existing
standard profile remains 8/8/32 MiB. A 32 MiB workspace refusal is kept distinct
from the original semantic decision to omit a delta. Its 135 malformed frames,
capacity controls, three standalone executions and six VM/native/reference
comparisons are separate domains. See [view_render_abi.md](view_render_abi.md)
and [view_original_rust_comparison.json](view_original_rust_comparison.json).
This component returns a cache plan; actual cache storage, file effects,
directory/search routing and a complete public view response remain separate.

The cache component implements the original serial `ViewCache` state machine,
including the **1 MiB per-value** limit, missing versus empty values, selective
invalidation, poisoned-lock results, write/create normalization and cache plans
produced by the actual view image. It compares **13,907 captured rows** with the
unchanged original Rust owners: 13,875 state operations, 22 lifecycle operations,
two real mutex-poison fixtures and eight view-plan adapters. The native domain
executes **13,873 direct cache-image calls**, **66 persistent ELF requests** and
**13 calls to the view image**. The 32 malformed, capacity and state refusals
are separate from the original comparison rows. An exhausted native workspace
refuses without mutating state; it does not introduce an eviction policy or an
original total-cache limit. Dynamic allocation, concurrent `Arc`/`Mutex`
ownership, lock-key canonicalization and the public file operations still need
their own integration. See [view_cache_abi.md](view_cache_abi.md) and the
[original comparison](view_cache_original_rust_comparison.json).

The policy component has passed **11,655 valid native cases** covering first-error
order, permission/protection precedence, environment checks, executable denial,
Unicode whitespace, arbitrary Unix path bytes and exact lexical normalization.
The unchanged original Rust policy functions produced the same **1,550,158
output bytes**. Its 188 malformed controls, buffer-capacity checks, independent
VM cases and actual static ELF calls are separate. See
[policy_original_rust_comparison.json](policy_original_rust_comparison.json).
This component does not load host configuration or resolve filesystem paths.

The file-version component has passed **10,624 native calls**. It directly
compares **5,236 formatting results** with the unchanged original Python
`binary_file.py:version` function, extracted from its pinned source through the
Python AST. Its new inverse has **5,236 canonical roundtrip cases**, with a
separate arbitrary-precision reference and exact reformatting through the
original function. Negative timestamps and signed-seconds extrema preserve
the original mathematical nanosecond value without fixed-width multiplication
overflow. The suite also checks 66 noncanonical inputs, 78 malformed frames,
five capacity controls, eight HIA VM cases and three static ELF executions.
The live Python-reference corpus captures 10,620 calls; one exact-capacity
success and three native comparison inputs for the ELF checks are separately
asserted. See [stat_version_original_python_comparison.json](stat_version_original_python_comparison.json).
This is a representation boundary; it does not open files or replace a tool.

The read-only I/O dependency has passed **21 test groups and 242 actual ELF
requests**. The existing chunk domain has **119 requests and 8 direct original
Python comparisons**. The complete-file domain adds **123 requests and 63
original comparisons**, comprising 41 successful complete reads and 22 strict
UTF-8 rejections. `multi_read_host.py`, `binary_file.py` and `file_metadata.py`
are bound to their original Git blobs. Tests exercise real short
reads, injected EINTR/EIO, version changes during reads, close failures, empty
PATH execution, broken output pipes, descriptor reuse and rejection of malformed
effect records. Its startup root inode remains in custody across requests;
the old helper reopens pathnames on every request. That distinction is tested
explicitly and prevents a claim of complete original authorization or tool
parity. The current observation is in
[io_reference_proof.json](../tests/hia_native/io_reference_proof.json). Complete-file
tests also cover an exact 4,096-byte path, one byte beyond the file ceiling,
growth/hard-link changes during real reads, replacement before confirmation,
strict UTF-8 before confirmation, and persistent mixed-request cleanup.
[full_read_boundary_observation.json](full_read_boundary_observation.json) records
the current adapter bounds. The earlier five-image/119-request observation in
[composition_observation.json](composition_observation.json) is historical.

The local service has passed **11 suites with 342 actual ELF responses**.
The existing suite has 234 responses, **118 live original Python chunk-read
comparisons**, 20 protocol refusals and 21 tool-domain refusals. The batch suite
adds 108 actual responses, including 101 batch calls, **57 original successful
batch comparisons**, **13 original failure comparisons**, four exact shared
budget-boundary pairs, 11 parameter refusals and 33 domain refusals.
Eight direct native controller calls separately
exercise response capacity and continuation acknowledgement. Their synthetic
startup acknowledgements isolate lifecycle state and are never counted as a
filesystem read. All real service processes execute with an empty `PATH`.
The frozen identities and counts are retained in
[local_service_observation.json](local_service_observation.json); the current
aggregate gate repeats them from its own source snapshot.

The batch-controller suite separately runs **1,747 requests, 1,946 actual HIA
controller calls and 137 native leaf calls** with **53 explicitly synthetic IO
completions**. It directly checks the original Python `_wire_size` function
once and captures **1,689 original Rust validation cases**. These fixtures add
zero actual filesystem observations. The unchanged original Rust `validate`
body produced the same 198,934 output bytes for all 1,689 cases; see
[multi_read_original_rust_comparison.json](multi_read_original_rust_comparison.json).
That retained proof predates the additional setup-only parser-provenance check;
its historical test hash is preserved. The current suite verifies every imported
parser function after call-index relocation and checks the original Rust body
byte for byte. Neither structural check adds a native case or fixture IO count.

The internal record owner has passed **978 logical native requests**, comprising
**3,071 direct controller entries**, **2,093 direct crypto leaf entries**, and
separately **9 actual composed ELF requests**. Its suite includes 140 fatal
child-contract controls, 9 capacity refusals, 5 exact-capacity successes and a
non-UTF-8 input outside the original Rust String domain. The known-secret SHA
cleanup fixture compares every codec workspace byte and preserves untouched
tail/canaries. A real locked Rust execution matched all **823 retained rows**,
including **817 actual original-owner calls**, against the complete unchanged
`operation_crypto.rs`. See
[operation_record_original_rust_comparison.json](operation_record_original_rust_comparison.json).
Each reference row uses a fresh synthetic scope; persistent scope cloning,
concurrency, entropy and nonce lifetime remain separate qualification owners.

The generic composition suite adds **10 groups, 26 actual ELF executions and
39 frames**. It checks call-mask and depth refusal, recursion, overlapping
borrows, footer protection, nonprogressing continuations, exact maximum framing,
broken stdout, malformed packer inputs and cache-image mutation. It also packs
and runs an actual executable larger than 1 MiB. Its generic controller/leaf
fixtures remain under `tests/hia_native`; they are not production native owners.

The protocol tests cover randomized JSON formatting and field order, strict
Unicode, duplicate decoded keys, ID echo, invalid envelopes, initialization
ordering, response-capacity failure and recovery, concurrent isolated calls,
and actual fragmented pipe input. The transport tests check exact maximum
frames, plus-one refusal, final EOF framing, real descriptor failure, empty-PATH
execution, sealed RX code mappings and source/image/compiler drift refusal.

The native source profile and its limitations are recorded in the build
manifest and `result.json`. A passing component result is not a passing full
runtime migration result.

## Locked serde JSON owners

`fence_json.hepta` implements the retained `OwnerDocument` and `LegacyJobKey`
derived structures directly, including duplicate-known-field rejection,
map/sequence differences, nullable fields, and the original `IgnoredAny` byte
grammar. `serde_json.hepta` implements the separately declared `Value` and
finite-number contract: last duplicate selection, BTree key order, exact
integer/float classification, `float_roundtrip`, and the locked `zmij` output.
The reference uses the original 11 registry dependency versions/checksums and
unchanged derived definitions. The original serializer is `zmij`, not an
assumed substitute.

The complete eight-MiB JSON domain is retained. Its named `serde-json.v1`
profile supplies 16/64/256 MiB input/output/workspace and a source-owned static
filter; the maximum expansion fixture produces 31,876,700 bytes. The typed
owner uses the ordinary profile. Neither component grants authority, performs
OS effects, registers another MCP handler, or replaces a production call site.
Raw lexical `RawValue` identity and arbitrary derived structures are outside
these two declared ABIs.

The three actual native suites execute **22,918 direct native calls and 13
static ELF processes**, retaining **5,087 typed and 17,778 generic reference
frames**. A fourth suite checks completed-process, source, compile/pack,
rehashed-ELF, corpus, and transport receipt mutations; these synthetic evidence
controls add no native cases. Aggregate admission binds each completed stdout
and stderr, current source map, actual compiler and packer receipts, exact ELF
prefix/embedded image, and complete corpus bytes. The two original-reference
recipes share one actual locked Cargo build and independently execute every
retained frame through that binary. The existing historical Rust comparisons
remain historical; each aggregate run must perform its own two replays.

See [fence_json_abi.md](fence_json_abi.md),
[serde_json_abi.md](serde_json_abi.md),
[serde_json_composition.json](serde_json_composition.json), and the retained
[native](serde_json_native_proof.json) and
[original Rust](serde_json_original_rust_comparison.json) observations.

## Remaining migration work and cleanup

[migration.json](migration.json) is the single current source coverage inventory.
It enumerates every existing registered tool and the remaining system owners.
The native sources currently have no substituted production call sites.

| Existing tool family | Registered handlers still owned by the original runtime |
| --- | ---: |
| Filesystem and control | 28 |
| Hosts and processes | 24 |
| Durable requests | 10 |
| HIA Agent integration | 11 |
| REA analysis | 34 |
| Weights | 9 |
| Documents and worksheets | 9 |
| **Total** | **125** |

The remaining service work includes persistence/restart and unknown-outcome
recovery; identity and effect ownership; SSH/SFTP/HTTP/PTY; file editing and
delta state; REA parsers; documents and worksheets; model workers; deployment
gateways; and non-Linux-x86-64 targets. Those are implementation dependencies,
not tasks that can be closed by renaming Rust or Python files.

Check the inventory with:

```sh
python3 -B scripts/check_hia_native_inventory.py
python3 -B scripts/check_hia_native_inventory.py --require-complete
```

The second command currently returns 2 and reports `INCOMPLETE`. It cannot be
made successful by changing a JSON completion flag. Existing code, call sites
and their behavioral tests need actual replacements first.

Only the current native sources, ABI documentation, build tools and reproducible
tests are added to the repository. Development authoring scratch, intermediate
versions and local build outputs stay outside the tracked tree. The original
runtime and historical regression inputs remain: active workflows and tests
still read files under `docs/qualification` and `tools/x230`. Their cleanup must
follow replacement of those dependencies; their historical Git identities and
original failure results must remain traceable.

## Typed result serialization and final wire budgets

The `binary32_json`, `typed_result_json`, and `request_result` image-only owners
cover the original typed serialization and result metadata byte seam. Their
complete native domains and three fresh, ordered Rust replay recipes are
documented in [result_values_qualification.md](result_values_qualification.md).
The one-hundred-package Cargo reference build is shared, while every domain
executes its full original input set. Typed results preserve original field
order and f32 formatting; canonical Value bytes are not substituted for typed
result bytes when calculating the final wire budget.

These private owners do not complete public caller binding, request admission,
audit durability, result storage or acknowledgement ordering. No existing
production handler is replaced by this registration.


## Complete private Local batch write

The [batch-write integration contract](batch_write_integration.md) registers one
component, eight native suites and one required fresh original recipe. Its
fourteen-image executable composes the existing Local write foundation with
exact batch admission, line resolution, conflict/application and complete diff
rendering. The wide domain retains every byte of the 50-by-5-MiB response and
filesystem result. The locked original recipe builds both unchanged body and
renderer references and executes all 7,909 calls in 84 processes.

The explicit `batch-write.v1` borrowed profile provides 512 MiB input, 2 GiB
output and 3 GiB workspace, and cannot be packaged as an automatic standalone
filter. Existing profiles retain their capacities. Dependent owners that bind
the common build/loader source need actual source-matched refreshes; historical
proofs keep their prior hashes. This component does not migrate public
`batch_edit` parameters, authorization, remote SFTP, audit or durable results.
All 125 production handler records and removal flags remain unchanged.

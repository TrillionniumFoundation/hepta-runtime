# Administrator configuration and the sixteen-image MCP profile

This profile is an actual static Linux x86-64 executable. It reads an
administrator-selected configuration at startup, retains the original two
controller locks, installs one immutable configuration, and serves
`host_list`, `effective_config`, and `execution_shadow_admit` through native HIA.
It contains no interpreter, Rust runtime, dynamic linker, libc, or semantic
fallback. Python and the assembler are build/test tools only.

**The complete original configuration and runtime domains are not closed.**
Administrator `extra_arg_patterns` now execute the pinned HIA syntax, Unicode, HIR and forward/reverse NFA owners. Valid patterns are accepted and original syntax/10 MiB compiled-size failures preserve the first-error order. The finite native AST/HIR resource profile and serial installation entry still differ from the unrestricted original API. None of the 125 existing
handler owners may be removed on this evidence. The profile does not grant a
local filesystem capability for an SSH alias or expose a public config setter.

## Source and authority boundaries

The executable accepts exactly `--runtime-config FILE`. Its fixed adapter
reads the initial process environment; the HIA owner implements the original
`HEPTA_RUNTIME_STATE_DIR`, `XDG_STATE_HOME`, `HOME`, and temporary-directory
default precedence. Environment/pathname bytes remain Unix bytes, including
non-UTF-8 defaults. Configuration is not read from MCP stdin.

Startup preserves load/initialize order: actual configuration read, typed
deserialization, first validation, second validation, directory preparation,
canonicalization, both retained lock acquisitions, then immutable publication.
The private typed arena is never replaced by an MCP request. Later edits or
renames of the config/state pathname do not reload or transfer its authority.
Successful public summaries are cached. The first policy digest result, including
the deferred non-UTF-8 path serialization error, is cached separately. EOF
releases all retained handles.

The production adapter has one startup event. The separate owner fixture ELF
has an explicitly named trusted reinstall event for comparison with `OnceLock`;
its failed second installation preserves the old config and locks. This fixture
route is absent from the MCP executable.

The internal query, exact host lookup, alias lookup, and state-dir contracts are
in `config_owner_abi.md`. An opaque host node is not a bearer capability. This
revision does not export a general workspace-root or host-policy accessor.
The execution handler only uses successful exact configured-name lookup before
record validation, matching the original first-error order.

## Fixed image table

| ID | HIA source | Callable children | Effect authority |
|---:|---|---|---|
| 0 | `config_owner.hepta` | 1, 2, 3, 4 | None |
| 1 | `config_fs.hepta` | None | Enumerated configuration filesystem effects |
| 2 | `config_json.hepta` | None | None |
| 3 | `config_validation.hepta` | 15 | None |
| 4 | `config_identity.hepta` | None | None |
| 5 | `config_mcp.hepta` | 0, 6, 9 | None |
| 6 | `execution_controller.hepta` | 0, 7, 8 | None |
| 7 | `execution_json.hepta` | None | None |
| 8 | `execution_shadow.hepta` | None | None |
| 9 | `serde_json.hepta` | None | None |
| 10 | `regex_syntax.hepta` | 11 | None |
| 11 | `regex_unicode_data.hepta` | None | None |
| 12 | `regex_hir.hepta` | 11 | None |
| 13 | `regex_nfa.hepta` | None | None |
| 14 | `regex_match.hepta` | 11 | None |
| 15 | `regex_controller.hepta` | 10, 12, 13, 14 | None |

The builder verifies every actual embedded image, the immutable adapter prefix,
relative call displacements, native HIA packer output, compiler identity, and
declared buffer profile. Unknown call targets, changed spans, incorrect sequence
receipts and unauthorized effects fail closed. The nested execution-to-owner
route retains the current caller context and separate monotonic call sequences.
Only image 1 may yield a syscall effect. The fixed boundary is not a general
foreign function interface.

The executable lazily maps 3,707,834,368 bytes of virtual address space. It does
not clear all image workspaces eagerly. Regions above 2 GiB use zero-extended
register arithmetic. All borrowed child buffers, persistent configuration,
controller workspaces and call footers have disjoint fixed spans. The standard,
`history.v1` and `serde-json.v1` buffer profiles retain their existing definitions;
the profile names do not grant authority.

## Configuration data contracts

All wire integers below are little-endian u64. Every length is exact; these are
internal component records and are not accepted as tool arguments.

| Owner | Request | Result |
|---|---|---|
| Typed JSON | `HRCFGJ01`, op, schema, default-path length, JSON length, then default bytes and JSON | op 1: exact typed serialization; op 2: owned `HRCFGA01` relative arena |
| Validation | `HRCFGV01`, op, arena length, arena | `HRCFGR01`, status, diagnostic, payload length, payload |
| Identity | `HRCFGI01`, op, arena length, arena | op 1: raw 32-byte policy SHA-256; op 2: exact typed serialization used by that digest |
| Filesystem | `HRCFSQ01`, op, payload length, payload | `HRCFSR01`, stage, errno, first/second opaque handles, payload length, detail, reserved zero, payload |
| Installed owner | `HRCFGQ01`, op, payload length, payload | `HRCFGM01`, status, diagnostic, payload length, payload |

Typed schema 100 is `RuntimeConfig`. Schemas 101–108 cover HostConfig,
PrivilegedAction, Weight worker/native-client profiles, REA static/Java/Ghidra
profiles, and HIA worker profiles. Enums and primitive schemas are retained for
the complete original type corpus. Required/default/Option/sequence behavior,
known duplicate-field rejection, strict nested unknown fields and original
`IgnoredAny` tolerance are distinct. Unknown values are not incorrectly passed
through a strict `Value` decoder. JSON key strings remain strict.

The relative arena starts with `HRCFGA01`, byte length, root offset and schema.
Every node is 64 bytes: type, next sibling, first child, child count, value
offset/length and key offset/length. Offsets refer to owned bytes in the arena,
never a caller pointer. Validation and identity independently validate its
structure before use. Failed admission or output capacity does not publish a
partial result.

Validation op 1 validates, op 2 renders host_list, and op 3 renders effective
config. The validation owner calls child 15 for each pattern in original map/vector order. Syntax and original NFA size-limit errors become the original ACTION_REGEX diagnostic and public error text. A private arena/output refusal remains a distinct native capacity failure. All four former dependency-refusal cases now require exact original results. Identity refuses non-UTF-8 PathBuf serialization with `0xfffffffd`; installation
does not eagerly convert that deferred digest failure into startup failure.

Filesystem op 1 prepares/canonicalizes state and returns both retained locks;
op 2 releases the exact opaque handle pair; op 3 reads the config file. The HIA
owner handles mkdir order, mode/ownership/link checks, symlinks, `LOCK_EX | LOCK_NB`
acquisition, jobs/audit directory handling and cleanup. The adapter supplies only
fixed syscall argument shapes and a private descriptor registry. Raw OS fds
0, 1 and 2 remain valid descriptor values behind nonzero opaque handles.

## Actual MCP behavior

The transport is a persistent newline stream with an 8 MiB request limit and
supports final EOF without a trailing newline. It negotiates 2025-06-18 and
enforces initialize/initialized ordering. Only the three implemented tools are
listed. Execution schema bytes were obtained from the exact locked original
schemars schema.

For a known tool, the complete arguments subtree first goes through the real
native serde_json `Value` owner: duplicate keys use last-wins, object order uses
BTree order, and every number is classified before duplicate removal. The
resulting canonical bytes go to the original typed parameters owner. Unknown
empty-struct fields produce the exact SDK error prefix and tool-error envelope.
The execution controller calls typed JSON, installed host lookup and core
validation in that order. Canonical arguments may exceed 8 MiB even when the
input frame does not, so this call chain uses the existing larger profiles.

The actual 2025-06-18 SDK transport removes `resultType`. The wire serializer
therefore emits `content` and `isError` without `resultType`. The original
effective_config byte-budget calculation uses its distinct direct Serialize
representation, including its original overhead; that calculation is unchanged.
All text and IDs are escaped with the qualified native serializer.

This is a declared MCP subset, not a claim of complete SDK parsing/concurrency.
Outside arguments it retains the existing strict protocol duplicate policy.
Unknown tool names are refused before argument Value conversion. Batch arrays,
unadvertised handlers, general asynchronous cancellation and arbitrary resource
methods are not implemented by this transport.

## Finite resource profile

The configuration-file read is at most 8,388,544 bytes, allowing its internal
startup header within the fixed 8 MiB source span. The installed arena has a
64 MiB region. Canonical path processing has an 8,192-byte workspace bound and
a 40-symlink traversal bound. These limits are explicit native resource refusals;
they are not described as original unlimited-domain equivalence. Public summary
limits retain the original 256 host entries and 262,144-byte effective_config
wire budget.

No finite native profile alone proves complete handling of all administrator
regex programs, unconstrained source sizes, or the original general concurrent
installation API. Those remain follow-up owners.

## Reproduction and original comparison

`scripts/build_hia_config_service.py` compiles 18 distinct components (19 manifest names including the unchanged validation alias), and packs nine executables: the filesystem probe, eleven-image installed owner and trusted fixture, sixteen-image MCP service, and five fixed dependency probes. `run_config_native.py` executes six original configuration suites plus nine dependency suites, each with its unchanged 180-second process limit and three-second cleanup bound. It retains actual stdout, complete corpus bytes and embedded-image bindings. This does not replace the repository compiler cold gate.

The original configuration recipe prepares the existing four-bin project, verifies 54 unchanged original source blocks and exactly 100 locked registry packages, and shares one Cargo build across complete typed, semantic, installed-owner and actual rmcp domains. The additional configuration/regex domain contains 3,694 cases; the former four regex refusals are exact comparisons. All 62 baseline owner scenarios and 1,119 baseline SDK responses remain, plus three regex owner profiles/42 response pairs, four MCP profiles/24 response pairs, and four startup-failure pairs.

The separate regex recipe compiles the exact five-package original dependency closure once, then executes every one of 128,690 Unicode/AST/HIR/NFA/match requests and the full Rust 1.95 identifier-predicate projection. Full original output is retained, including parser diagnostics that the component ABI intentionally represents only by error class. AST/HIR success bytes, original forward/reverse NFA minimum allocation limits, capture counts and Boolean match results compare exactly.

Original Rust runs only on ai395 or CI. The runtime compiler pin and all process deadlines remain unchanged. Completed historical original comparisons and the fresh portable execution are separate records; no prior compilation is relabeled as a new build. See `regex_abi.md` for exact component records, limits and remaining resource gaps.

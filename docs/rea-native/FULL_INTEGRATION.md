# REA native integration on #84

Source baseline: `f9756508462ebc72e814a12f5dbba1b067edabe4`, branch
`feature/rea-runtime-unified-20261103`. The preview publication fix from
#83 (`d875438db6d20f2c0218fde7a47f79a42d66b088`) is incorporated.
This document describes implementation scope; exact test receipts must be
bound to their source and binary identities.

## One runtime owner

Native artifact tools, retained model sessions, static providers and the
weight workbench share the existing runtime admission and file policies.
Static analysis uses the existing durable job, request digest, host binding,
output witness and cancellation interfaces. There is no separate REA daemon.
Absent optional engine/native-client fields preserve old profile identities.

On Unix, runtime initialization now creates missing controller-state directories
with mode `0700` in the creation syscall, including missing ancestors. It then
checks the current effective UID and exact private mode before claiming state
locks. An existing nonprivate or foreign root is refused without changing its
permissions. This closes the first-use mismatch between an ordinary `0022`
umask and the request auditor's existing private-root requirement. The source
and paired pre-fix MCP evidence are recorded in the
[state-root qualification](../qualification/rea-state-root-umask-20261103-r1/README.md).

## Implemented routes and boundaries

| Area | Route | Actual scope |
| --- | --- | --- |
| Models | GGUF/safetensors reader and snapshot open/list/query/read | Supported directory and tensor extents, immutable retained bytes; no general model inference |
| Build artifacts | Bounded native ELF structures | ELF32/64, byte order, program/section tables, symbols, selected notes and build IDs |
| GPU metadata | ELF machine, flags and bounded notes | Declarations only; no kernel execution, driver or hardware compatibility verdict |
| Application packages | Checked ZIP plus fixed manifest decoding | APK binary XML and JAR main attributes, stored/deflate and CRC; no signature or installability verdict |
| Mature engines | Optional JADX and Ghidra providers | JADX class/source observations; legacy Ghidra ELF inventory or explicit revision 2 inventory/function analysis/xrefs/decompilation, under the original job owner; partial coverage and no verified reconstructed-source claim |
| JS/Electron | package.json declarations and bounded native Oxc AST analysis | Explicit JS/TS sources, imports/exports, lexical bindings, Electron callsites and IPC candidates; no source execution, whole-application resolution or runtime-delivery proof |
| Browser evidence | Existing durable process owner → native Rust private Chrome capture → saved HAR inspection, comparison and selected body replay | Bounded same-host owned HTTP-resource capture; saved-representation replay; no application-script execution or complete browser-state replay |
| Weights | Existing native transport, patch/restore and F32 Linear | General model execution remains with its selected backend |

Details: [models](MODEL_SESSIONS.md), [ELF and Java](ELF_AND_JAVA.md),
[bounded Ghidra analysis](GHIDRA_ANALYSIS.md),
[applications](APPLICATION_MANIFESTS.md), [JavaScript AST](JAVASCRIPT_AST.md), [web](WEB_OBSERVATIONS.md),
and [original convergence](UNIFIED_RUNTIME.md).

## Added MCP interfaces

The continuation adds nine policy-gated interfaces to the existing MCP server:

| Interfaces | Behavior |
| --- | --- |
| `rea_model_session_open` | Admit and atomically publish an immutable model snapshot and directory indexes |
| `rea_model_session_list`, `rea_model_session_query`, `rea_model_session_read` | Recover the current authenticated owner/policy inventory, query stored indexes and verify bounded snapshot ranges |
| `rea_inspect_application` | Read supported APK/JAR manifests from the admitted archive descriptor |
| `rea_inspect_javascript_package` | Read literal package declarations and their JSON locations |
| `rea_inspect_web_capture`, `rea_compare_web_captures`, `rea_replay_web_entry` | Inspect saved HAR observations, preserve repeated-request identity, and read a selected saved response representation |

Model-session creation owns an actual effect admission through final commit.
Read interfaces use the existing file and owner policies. Callers cannot
supply a model-session owner in their arguments.

## Cache and retention

Explicit model-session creation verifies the complete source SHA-256 while
copying it, builds its directory once, and retains the snapshot, chunk
commitments, paged indexes and manifest together. Repeated queries verify
selected stored pages without parsing the original directory or hashing the
complete payload again. Range reads verify the touched 1 MiB chunks and
return at most 64 KiB.

Limits are 32 sessions, 64 GiB total store bytes, 32 GiB per snapshot, 64 rows
per index page, a 4 MiB manifest and 128 MiB of index data. Incomplete staging
consumes the same bounded storage budget. Short one-off inspections can retain
their stateless behavior without paying for a snapshot.

Sessions bind the authenticated owner, current policy, parser schema and
source identity. The original file may change or disappear without changing
the retained snapshot. Stable authenticated HTTP identity, unchanged policy
and retained private state define the tested cold-recovery path. A new stdio
connection does not implicitly inherit the previous stdio owner's sessions.

The session list exposes only the current owner and policy's admitted
manifests. It reads no source payload. Listing is not a claim that every
unread index page or chunk is intact; those checks occur on actual access.
Missing or damaged committed manifests are errors, not an empty inventory.

Final publication owns both the store lock and effect-owner admission until
exclusive directory rename and parent-directory fsync actually complete.
Cancelling the waiting request cannot release these guards prematurely.
Rename and fsync use the same held directory descriptor. Cancellation or
interruption produces an unconfirmed result until reconciliation, never a
successful durability receipt.

| Result | Restart boundary |
| --- | --- |
| Retained native preview | Verified ID under the existing preview-store policy; source unnecessary |
| Model session | Snapshot and indexes retained; current authenticated owner and policy required |
| Static-provider output | Original host/job/request identity and current authorization; status/read do not resubmit |
| HAR/package/application inspection | Stateless committed observations; these reads create no separate result database |
| Resident model work | Existing weight-worker/session/job contracts |

The model cache is not presented as a universal cache for stateless
archive/application inspection. Native IDs are not relabeled as upstream
REA `ev_` evidence.

## External engines and offline web operations

External engines are administrator-configured optional providers. Callers
choose fixed operations and content-pinned inputs, not scripts, shell text,
plugins or arbitrary flags. Engine-specific versions and exact coverage are
recorded separately.

For JADX, the JAR, fixed bridge and input are sealed Linux snapshots. Selected
installed Java/JRE files are hashed and their path/inode observations checked
around execution. This is not a sealed installation or dynamic-library closure.
Scratch permissions are private in the creation syscall. Aggregate scratch
usage is monitored, not a hard filesystem quota. Normal completion cleans it;
after cancellation, observe the original job terminal before reconciling its
own residual scratch. The inspected program is never executed.

Legacy Ghidra profiles omit `ghidra_engine.bridge_revision` and retain the
original inventory bridge bytes and serialized identity. This route keeps
automatic analysis disabled and returns bounded imported memory-block and symbol
observations. Explicit revision `2` profiles can admit `inventory`, `functions`,
`function`, `xrefs` and `decompile`; the analysis operations run a fixed, partial
analyzer profile and the selected-function decompiler operation invokes Ghidra's
native decompiler. Neither route executes the inspected program or saves a
project. These bounded observations do not establish full Ghidra coverage, REA
behavioral parity or general source equivalence. The versioned bridges and
qualification boundary are documented in
[GHIDRA_ANALYSIS.md](GHIDRA_ANALYSIS.md).

The complete admitted `Ghidra/` file set is manifest-pinned and checked before
and after execution. Ghidra and its JDK remain external engine dependencies,
rather than a Rust rewrite or sealed memory image. The qualified 12.2
installation uses its required JDK 25 and is read-only to the actual
non-privileged Java identity.
That uses the engine's supported precompiled-Sleigh path without generating
lock files or recompiling processor definitions. The qualification binds this
installation preparation rather than weakening file-set or identity checks.

HAR comparison preserves repeated request occurrences. Replay reads the
selected saved body representation; missing, empty and base64-encoded bodies
retain distinct meanings. package.json reports JSON locations and literal
declarations without evaluating conditional exports or npm scripts. The native
Oxc graph route accepts an explicit bounded source-file set and observes AST
imports/exports, lexical bindings and Electron callsites. Static IPC channel
matches are candidates. Collection pages recompute against the same full source
hashes and an expected graph hash; they do not claim retained upstream Evidence
views, complete Node/Chromium resolution or dynamic message delivery. See
[JAVASCRIPT_AST.md](JAVASCRIPT_AST.md) for the exact selectors and limits.

The [bounded local capture helper](LOCAL_BROWSER_CAPTURE.md) runs as a native
Rust command through the existing durable process owner. It owns its fixed CDP
transport, private Chrome process group and temporary profile. Python helpers
remain for reference capture and PDF workflows. The native helper admits a
content-pinned resource manifest and uses a fixed, owned loopback harness;
supplied HTML/JavaScript is fetched as data. It does not
attach to a user's browser, run an application's scripts, or establish a new
REA execution service. The actual qualification covers capture, repeated-resource
comparison, retained HAR reads after controller restart, same-key reuse,
representation replay and cancellation cleanup. Missing response bodies stay
missing. Replay observed no connections or HTTP requests at two known,
positive-controlled origins; that is not a process-wide network-isolation claim.

## Workload-driven replacement and qualification

The weight-client comparison separates client process startup, direct
resident-worker exchange and complete MCP submit-to-retained-result latency.
Hashing, admission, remote transport and polling remain part of the last
measurement. A transport microbenchmark cannot establish that end-to-end win.

Python remains in general PyTorch workers and existing remote helpers not
yet replaced and qualified. Development fixture and differential scripts are
not shipped runtime implementations. These changes do not establish complete
REA tool parity, a zero-Python runtime, full browser replay or production
cutover.

The earlier development and release comparisons each retain 210 measurements
and their original mixed results in the
[development report](../weight-runtime/BENCHMARK_CLIENTS_DEV_20261103.md) and
[release report](../weight-runtime/BENCHMARK_CLIENTS_RELEASE_20261103.md).
The [client closure comparison](../weight-runtime/BENCHMARK_CLIENTS_CLOSURE_20261103.md)
adds 240 fixed ABBA identity/large-frame measurements and 300 real-worker/MCP
measurements after the full-byte hashing and duplicate-response-parse changes.
The principal native-client paths used about 40% less median client CPU than
the pinned earlier native release. On the three measured real-worker cold-helper
operations, mean client CPU was 16–18% lower than the Python compatibility client.

Native transport remains opt-in: complete MCP latency was mixed, and the
lifetime-RSS measurements do not establish a memory advantage. Both transports
use the same Python/PyTorch backend. Both native revisions already used a
current-thread WeightClient runtime; the gain is not attributed to removing
a host-sized Tokio pool. Full input hashing, exact response bytes, error
semantics and no-resend behavior remain part of the contract.

## Source-bound qualification

The [qualification index](QUALIFICATION_20261103.md) binds the complete functional
gates, actual operator engines, storage environments and workload measurements.
The complete on-host test matrix uses explicitly recorded tmpfs fixture storage.
The original ext4 audit-statistics query-budget failure and its diagnostic
remain preserved. The [blocker closure report](BLOCKER_CLOSURE_20261103.md)
records the later warm-admission fix and its separate physical-ext4 qualification
with the unchanged three-second budget. It also binds the client and real-browser
results to their actual source and executable identities. GitHub validates the
publication commit and prospective merge independently; earlier green CI does
not stand in for either new gate.

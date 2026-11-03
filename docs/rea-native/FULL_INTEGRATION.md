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
| Mature engines | Optional JADX and Ghidra providers | JADX class/source observations and Ghidra ELF import inventory, under the original job owner; no verified reconstructed-source claim |
| JS/Electron | package.json declarations | Entrypoints, dependencies and scripts; no script execution, Node resolution or IPC reconstruction |
| Browser evidence | Saved HAR inspection, comparison and selected body replay | Offline observations; no live request or complete browser-state replay |
| Weights | Existing native transport, patch/restore and F32 Linear | General model execution remains with its selected backend |

Details: [models](MODEL_SESSIONS.md), [ELF and Java](ELF_AND_JAVA.md),
[applications](APPLICATION_MANIFESTS.md), [web](WEB_OBSERVATIONS.md),
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

Ghidra uses a fixed ELF importer with automatic analysis disabled. It reports
bounded imported memory-block and symbol observations; it does not invoke
the decompiler or save a project. Its complete admitted `Ghidra/` file set is
manifest-pinned and checked before and after execution. This is an installed
engine, not a sealed memory image. The qualified 12.2 installation uses its
required JDK 25 and is read-only to the actual non-privileged Java identity.
That uses the engine's supported precompiled-Sleigh path without generating
lock files or recompiling processor definitions. The qualification binds this
installation preparation rather than weakening file-set or identity checks.

HAR comparison preserves repeated request occurrences. Replay reads the
selected saved body representation; missing, empty and base64-encoded bodies
retain distinct meanings. package.json reports JSON locations and literal
declarations without evaluating conditional exports or npm scripts. Existing
browser execution remains with Hepta's existing browser/task capabilities.

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

The completed development and release comparisons each retain 210 measurements
and the same five semantic checks. The current decision is to keep the native
client opt-in: the release cohort did not establish a general latency or memory
advantage. Its cold helper CPU cost was higher, full MCP medians were mixed,
and the per-client lifetime RSS measurement did not distinguish the paths.
Both transports used the same Python/PyTorch backend. Exact sample counts,
resource definitions, host-pressure observations and original failure records
are retained in the [development report](../weight-runtime/BENCHMARK_CLIENTS_DEV_20261103.md)
and [release report](../weight-runtime/BENCHMARK_CLIENTS_RELEASE_20261103.md).

## Source-bound qualification

The [qualification index](QUALIFICATION_20261103.md) binds the complete functional
gates, actual operator engines, storage environments and workload measurements.
The complete on-host test matrix uses explicitly recorded tmpfs fixture storage.
An ext4 audit-statistics query-budget failure and its single traced reproduction
remain separate, visible limitations; no production deadline or lock was relaxed.
GitHub validates the publication commit and prospective merge independently.

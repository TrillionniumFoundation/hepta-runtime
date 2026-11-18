# Finite session transport ownership graphs

This intake makes four existing, independently qualified ownership domains part
of the repository's executable native and original-reference gates. It adds 52
HIA source files: 34 semantic sources and 18 fixed packers. Four semantic sources
already in the repository are reused byte-for-byte. The resulting source set has
38 unique semantic images and produces four separate static Linux executables.
The selected public 114-image server is a separate graph.

The authoritative source, image, prefix, export and relocation tables are in
[`graph.json`](../tests/hia_native/session_transport/graph.json). The native
builder compiles every selected source, reconstructs every fixed prefix and
rel32 target, runs all 18 HIA pack calls, and requires each final ELF to equal
the previously qualified artifact. No semantic policy is implemented by the
Python builder or the assembly callback broker.

## Graphs and actual methods

| Graph | Semantic images | HIA pack calls | Included finite behavior |
| --- | ---: | ---: | --- |
| Server message | 15, including five ServerMessage policies | 3 | Typed `ServerJsonRpcMessage` normalization, complete wire serialization, immutable `ValueLease` construction and type-12 Drop |
| Worker owners | 32 | 5 | Actual `WorkerSendRequest<LocalSessionWorker>` with `cancellation=None`, direct and MPSC movement, oneshot unit result, request Take and typed cleanup |
| Handle initialization | 36 | 5 | Actual `LocalSessionHandle::initialize`, real client and server messages, MPSC/oneshot Pending, success, cancellation and capacity handoff |
| Local worker error | 38 | 5 | Actual variants 1–6, nested SessionError and SessionEvent ownership, `WorkerResult::Err`, oneshot return, Take and Drop |

Each larger graph keeps the shared scheduler, budget, channel and `ValueLease`
owners selected by its frozen parent. An owner is identified by its actual
descriptor address **and generation**. The verifiers require identical full
descriptor and payload bytes throughout that identity's lifetime. An address
may be reused only after the preceding identity has been consumed or retired.
Typed callback order, child movement and endpoint retirement are reconstructed
from the retained physical call and resource streams.

The fixed callable contracts are retained without rewriting their history:

- [ServerMessage owner ABI](../tests/hia_native/session_transport/evidence/SERVER-MESSAGE-ABI.md)
- [Worker request and result ABI](../tests/hia_native/session_transport/evidence/WORKER-OWNERS-ABI.md)
- [Handle initialize paired protocol](../tests/hia_native/session_transport/evidence/HANDLE-INITIALIZE-PROTOCOL.md)
- [Local worker error ABI](../tests/hia_native/session_transport/evidence/LOCAL-WORKER-ERROR-ABI.md)

Observer type 12 belongs to ServerMessage. Worker request Drop/Take use 11/13,
worker result Drop/Take use 14/15, and LocalWorkerError uses 16. These observation
identities do not replace the actual typed callbacks. The native assembly stays
in [`scripts/session_transport`](../scripts/session_transport); the policies
and bounded packers stay in [`native/session_transport`](session_transport).

## Mandatory fresh gate

The `session` native partition executes three complete subprocesses:

1. `test_session_transport_owned.py` builds its invocation from the registered
   graph and runs the Worker72, Initialize40 and LocalError140 corpora in both
   scheduler modes: six actual native processes and 504 programs.
2. `test_session_transport_server.py` runs the ServerMessage factory corpus in
   both modes: two actual native processes, 616 owned programs and 180 complete
   message projections.
3. `test_session_transport_receipts.py` performs 27 coordinated compiler-record
   damage controls. Every refusal is followed by a complete restoration and
   re-admission. These are data controls with zero new semantic calls.

The `session` original group freshly builds four independent Rust binaries in
one Cargo project. Its complete source archive preserves the original runtime
blocks, complete rmcp 3.4.1 source, 139 locked registry dependencies, four exact
original mains, and three module-local qualification appendices. The appendices
do not replace production method bodies. The builder checks the complete
project inverse, all dependency archive members and checksums, metadata source
identity, the exact Rust 1.95 tool set and sysroot artifacts before and after
compilation, full compiler output, and each actual Cargo target artifact.

The paired replay starts four actual original processes and no native process.
It executes 342 programs: 90 ServerMessage wire requests, 72 Worker owners,
40 Handle initialize flows and 140 LocalError flows. Each program is compared
with both already admitted native modes, yielding 684 comparison rows. The
server's 90 original requests prove typed wire equality; they do not independently
prove the native factory's physical allocation lifecycle. The other 252
original programs exercise their actual Rust ownership and channel APIs.

Each native suite and original build/replay process retains its 180-second
outer limit. The fresh Cargo subprocess keeps its existing bounded deadline;
individual original replay processes retain their 30-second limit. Native and
original workflow jobs keep 15 minutes. Source registration, actual completed
commands, PIDs, complete stdout/stderr, full raw streams and canonical
reconstruction are required before aggregate PASS. A captured or built-only
status cannot satisfy the gate.

The independent qualification produced the exact four ELF bytes and passed
the complete native capture, compiler refusal and four-bin original replay.
[The intake record](../tests/hia_native/session_transport/evidence/canonical-intake-v1.json)
binds those completed jobs to their external receipts. It is evidence for that
focused invocation; the current commit still requires its own complete CI run.

## Preserved larger domains and limits

The independent ServerMessage seal also retains 6,441 complete codec pairs,
25,211 HIA entries, the exact 8 MiB input boundary and its 31,876,198-byte
serialized wire, 698 private HIA calls, 601 immutable refusals and the complete
historical failures. The source and fixed ABI do not change during this intake.
Those larger historical domains remain explicitly separate from the mandatory
616-program factory gate and 90-request fresh wire replay.

[The ServerMessage handoff](../tests/hia_native/session_transport/evidence/server-message-handoff.json)
and [the three ownership-domain handoff](../tests/hia_native/session_transport/evidence/worker-domains-handoff.json)
pin their complete external archives. The latter retains the 252 actual
original programs, both native modes and all private continuation controls.
The complete archives include unsuccessful attempted versions; this repository
contains the selected source and executable gate inputs rather than duplicate
Cargo build trees or historical executable artifacts.

This intake does not qualify a complete `LocalSessionWorker::run`, worker
transport send future, Join failure, QuitReason, HTTP SessionManager, socket,
cross-thread scheduler or arbitrary unwind. The ServerMessage factory's physical
ownership remains a native finite domain with separately paired typed wire.
Guarded-map and FD retirement in its historical seal is tied to the completed
fixture assertions; no missing raw map or FD snapshot is invented. All 125
top-level handlers and all 10 production owner categories remain `not_ported`.
Production activation, whole-runtime replacement and deletion of the original
implementation remain false.

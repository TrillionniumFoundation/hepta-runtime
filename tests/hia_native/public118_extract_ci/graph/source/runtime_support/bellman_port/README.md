# Shared Bellman port

This package contains the fixed slot57 capability, its narrow extra-engine
overlay, complete-buffer qualification drivers and strictly readonly readers.
The runtime remains eight HIA images. Four images retain the qualified
baseline exactly; four are fixed-byte-access successors. Only fourteen
checked eight-byte load/store helpers change. Their full ordered symbolic
accesses, bounds failures, partial writes and return values match the
retained baseline; every other function AST is exact. The native
mechanical adapter owns memory, capability bindings, journal writes and export
dispatch. Numerical solving, deadlines, commitment, rendering, caller states
and the two-permit pool remain in their existing HIA owners.

`PORT_ABI.md` is the frozen interface. Its historical worker source reference
is retained as baseline history. The checked-byte successor dependency pin is
`6b5983d351b380b53f5838dc7ca8adac523d6c95ac12df51c3f975faf60d53c2`.
No ABI field, clock checkpoint, scheduling rule or mathematical algorithm
changes. Successor image identities require their own complete replay; the
prior qualification is not reassigned to these new images.
`source/native/bellman_port_component.json` records the current fixed images,
exports, source identity and shared-engine slots.

## Runtime integration

Create one port context per runtime process and explicitly attach each engine
that can issue Bellman work. The engine table remains at `engine + 8192`; the
engine allocation remains 16384 bytes. The host owns `engine + 440` and
`engine + 448` for this port. Preserve authority fields including `+432` and
`+488`, and Batch fields `+416` and `+424`.

The overlay preserves frontend child12 to authority slot56, reserves child13
to Batch slot47, and adds child14 to Bellman slot57. Reserving Batch's selector
does not install that capability. The package does not replace its separate
Batch tables or production owners.

Install the checked packed ELF address in slot57. The fixed engine dispatch
adds the identity-bound `runtime_bellman_owned` offset 2469. Allocate a private
tag through `HBLTAG01`; do not derive a tag from an MCP request ID. A caller
request uses the complete `HBLCLQ01` frame. Start, poll and cancel return the
complete `HBLCLR01` frame, retaining a pending request's private tag and job.

Treat result status3 as a real yield. Retain the exact frontend slot18 input,
output, workspace and generation until completion or cancellation. A pending
frontend result is exactly 64 bytes: `HRCMFR02`, kind4, zero close/prefix/body/
error/reserved fields and the ordinary sequence at48. Read the private
`HBLFRS01` record at workspace1280; write its matching `HBLFRQ01` poll/cancel
control at1344. The separate host scheduler owns public SDK request-task and
generation tracking.

Service the persistent worker context on its actual wake descriptor. Copy
every complete READY event before releasing its exact borrow token. Retain
all events, including completion after caller cancellation. Never replay a
control or TAKE when the HIA caller requests delivery-only continuation.
Retiring caller buffers does not release a running worker's permit. Shutdown
drops caller interest and continues service/reap/READY retirement. Detach each
engine explicitly; destroy returns busy while actual workers or borrows remain.

## Portable build

The readonly `worker-source` directory is the complete 90-file successor
dependency. Its source pin and build reader admit its actual five-image
build, with two unchanged and three checked-byte successor images. It does not create another runtime pool or implementation.

Use immutable Hepta commit `d3e2c90173cf733e42b299d0c4274df4b593a12f` and
supply a complete admitted worker build:

```sh
python -I -S -B recipe/build_capability.py \
  --package PACKAGE --package-sha256 PACKAGE_SHA256 \
  --hepta HEPTA --worker-build WORKER_BUILD --output NEW_BUILD
```

The helper verifies the worker build, copies its verified bootstrap and
compiler evidence into its own output, compiles all three caller members,
assembles the adapter and actually compiles/invokes the HIA packer. Generated
authoring files stay in the build directory and must equal the frozen packer
bytes. `port-build.json` names the packed ELF, component and packer receipt.
It does not claim a new cold qualification.

The Python entry is `build_bellman_port(hepta, build_root, worker_build, *,
package, package_sha256) -> Path`. All paths are explicit; the source package
is unchanged. CI can freshly make the dependency using the unchanged
`worker-source/tests/hia_native/blocking_worker/worker_build.py`.

## Qualification and reading

`recipe/qualify_port.py --phase all` runs the portable build and both complete
native cohorts. Every actual native cohort retains its 60-second process
deadline. The outer supervisor adds only cleanup-recording time. The lifecycle
keeps both 4096-state jobs, actual first-CLOCK stop/continue observations,
cancelled completion without TAKE, two engines, global private tags, complete
READY FIFO and shutdown/reap. Every complete input, output, workspace, owned
state and journal is recorded. The engine cohort keeps all 426 paired frames,
all 1003 target pairs and its actual slot57 worker job.

Seven physical port evidence refusals and four engine evidence refusals use
independent full copies. They include cancelled no-TAKE CLOCK deletion and
delivery-only/source/state/FIFO controls. `--phase verify` rereads those bytes
and existing process receipts; it neither writes nor executes HIA/Rust.
`recipe/verify_readonly.py` additionally rejects writes, processes, ctypes/mmap
execution and fallback to recorded original paths after relocation. It checks
complete tree bytes and metadata before and after. This guard covers these
fixed Python readers, not arbitrary Python code. An optional guard report must
be written outside all protected trees.

This port recipe preserves the full private worker and caller contracts.
Its port-only gate does not replace the separate full successor worker/Rust
reference replay. It does not itself run Rust or qualify public SDK request
scheduling, cancellation delivery, a complete public handler or the whole
runtime. Those flags remain false until the combined public gate completes.

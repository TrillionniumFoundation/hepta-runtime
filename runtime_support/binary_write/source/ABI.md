# Private same-process binary write composition

This candidate composes the exact adapter source from runtime PR137 with the
qualified R3 parent owner. The parent contains the unchanged nine-image body.
No public route is registered. Existing runtime files and their thirteen routes
are outside this isolated source tree.

## Fixed owners

The adapter controls every request decision. It receives an `HBWAQ001` start,
retains the entire planner request and expected ready result, asks the exact
HIA planner for its actual result, and either emits a complete `HBPWQ001` packet
or a complete `HBWAR001` mismatch result. A fixed mechanical connection calls
the real parent only for the adapter's kind-2 parent request. No JSON is parsed
or reconstructed by assembly, Python, or the carrier.

Parent source manifest:
`b674d9c033dd43350a2d5f38039df469c8983149c0e568ab9c51ca614411d612`.
Adapter source manifest:
`1c38b08d610c2440ae2e246bc06519f416591bbca590850f758ea8eef5848d4a`.
Both complete source trees are preserved under `parent/` and `adapter/`.
The compiler remains d3e2c90173cf733e42b299d0c4274df4b593a12f with B3
`bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`.

## Callable lifetime

The private SysV exports are:

- `binary_write_composition_create(callback, opaque, process_pool, entropy)`;
- `binary_write_composition_invoke(context, request, length)`;
- `binary_write_composition_release(context)`;
- `binary_write_composition_destroy(context)`.

Construction creates the real parent through its unchanged constructor. The
single process orphan pool and entropy context are borrowed. The parent checks
their concrete types, creator PID and association; the composition also binds
its actual creator PID. Callback identity is a trusted graph binding, never a
field in an application request.

Invoke retains input before entering the HIA continuation and uses fixed image
entries for adapter and planner. Only actual child results are returned to HIA.
Workspace growth copies every prior byte and zeroes only the extension. Input
and output retain the original 128 MiB limit; workspace retains 256 MiB.

A terminal result is borrowed until explicit release. Parent results keep the
actual parent result borrowed for that entire interval. The adapter also keeps
its terminal continuation until release. Busy invoke and destroy fail without
replacing the held result. Release invokes the unchanged child release and the
actual HIA adapter release; a private failed release does not pretend ownership
was retired. Shared process pool and entropy are never destroyed by this owner.

Private failure is a retained failure state. Destruction does not fabricate file
cleanup: the unchanged parent destructor decides whether its ownership is safe
to retire. In particular, its second-close and pending-orphan flags retain their
original meanings. All parent/body errors and override order remain in HIA.

## Result framing

The result is the exact complete `HBPWR001` parent frame, or the exact complete
`HBWAR001` adapter mismatch frame. No additional envelope consumes the original
128 MiB output allowance. The two existing magics distinguish the fixed result
owners. The composition's private context records the actual child return and
borrowed extent; the callback journals preserve the entire actual child call.

An admitted terminal invoke returns 64. Physical invalid, busy and private
resource failures use the existing `0xffffffff`, `0xfffffffd` and `0xfffffffc`
codes. This boundary does not translate application errors or claim a public
API. The future public response owner remains separate.

## Full validation boundaries

The existing complete 433 planner, 196 typed-write and 256 parent-interface
domains remain required. The parent R3 domain remains all 256 inputs, 992
natural-termination lanes and six actual EINTR/SIGTERM controls. Its two absent
version inputs are legitimate private parent inputs but remain the original
typed String rejections on the planned public input path; the composition must
record that distinction instead of silently supplying an absent version.

The new composition must additionally prove the actual parent request equals
the complete packet produced by the real adapter, and preserve complete parent
effect/error/FD/filesystem evidence. All new adapter/planner calls, full buffers,
growth, retained result and release boundaries are attributed. No application
result, syscall result, deadline, original input or existing workflow is changed.
The historical parent receipt and build are retained with their desktop origin;
new construction uses fresh local source-bound compiler/linker/packer outputs.

The composed effect intersection is 254 String-version inputs and all 985
originally eligible natural lanes. The independent reader derives those inputs
and the two actual typed-`None` refusals (seven original lanes: four for input217 and three for faulted input244) from the complete unchanged 256-input
parent domain. All six original permanent-EINTR/SIGTERM controls remain.
Additional observed boundary processes exercise both real planner mismatch
branches and a physically invalid header, with complete parent context, kernel,
file, descriptor, busy, release and destruction evidence. The original minimum
48-byte qualification transport remains unchanged; a shorter transport packet
is not represented as an executed HIA input.

The entire 433/196/256 pure-owner regression is freshly executed separately.
The complete composition DATA reader has the original 600-second limit and
retained eleven-capability denial guard, with whole file bytes and metadata
snapshotted before and after. The producer's 60-second exchange, 180-second
case and 1800+5-second whole-process-group limits are unchanged.

The new wrapper's partial release and failed result-allocation ownership paths
have source review but do not yet have dedicated dynamic failure controls.
Those controls and public host/audit/SSH/response lifecycle remain explicit
requirements before public registration; the bounded private evidence must not
be used as a claim that those remaining domains have been exercised.

`public_binary_write_registered`, `host_audit_ssh_lifecycle_qualified` and
`whole_runtime_replaced` remain false.

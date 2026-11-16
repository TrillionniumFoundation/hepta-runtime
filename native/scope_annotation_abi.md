# Private current-target scope annotation

`scope_annotation.hepta` implements `OwnerScope::annotate` from runtime commit
`d3d75c30719db966b004756f610007a7c723729e`. The independently retained original
function and `kind` are compiled unchanged against the target Cargo lock and
RMCP 3.9.0. The existing Value and diagnostic HIA owners remain the only JSON
parsers. No public handler, credential verification, owner binding, backend
query, timeout, cancellation, or production routing is claimed by this module.

## Input and trust boundary

`HSCANQ01` is a private 48-byte header followed by UTF-8 JSON text. The little
endian u64 fields are operation 1 at byte 8, the already verified authenticated
observation at 16, search flag at 24, text byte count at 32, and zero at 40.
Both flags must be 0 or 1. The authenticated observation is provided only by
the trusted caller after scope resolution; it is not a public request option.

The inherited Value profile admits at most 8 MiB of text. The output loan is
at least 64 bytes; the private workspace loan is 256 MiB. Original semantics
outside that declared input profile remain unqualified. Invalid UTF-8 is a
private framing refusal because the Rust method receives a valid `String`.

## Native child loans

The owner returns `0xffffffe0` with a 96-byte `HSCAA001` descriptor at workspace
byte 256. Its fields after the magic are sequence, child, zero, request offset,
request length, reply offset, reply capacity, acknowledgment sequence, returned
code, zero, and zero. Child 1 is the existing `HSJVAL01` Value owner; child 2
is the existing `HSJERQ01` diagnostic owner, called only after an actual Value
refusal. Child 3 is the shared `HRTCRQ01` target SDK text-result constructor,
always with policy 0 and `is_error` 0. The transport executes exactly that owner and writes its complete
result and matching acknowledgment. It does not parse JSON or apply scope rules.

The exact original input, output/workspace capacities, query bytes, descriptor,
sequence and acknowledgment are validated before resumption. A completed or
capacity-refused request returns to phase zero. Sequence wrap is refused.
`0xffffffff` means private input refusal, `0xfffffffe` means capacity refusal,
and `0xfffffff8` means an invalid continuation contract. No partial final output
is published during a child loan or refusal.

## Transformation and actual SDK wire

Value parsing occurs once. The owner performs a sorted merge of complete
canonical JSON spans to insert or overwrite the original fields. In the
non-search branch it transforms `retention.per_session` only when retention is
an object and the key is present, including null, replacing `per_owner` exactly.
It preserves unrelated fields and the opposite branch's existing fields.
It never reparses the transformed object; this preserves non-first RawValue
keys which canonical sorting may move to the first position.

The owner sends its complete annotated text to the shared constructor implementing
`CallToolResult::success(vec![ContentBlock::text(&text)])`. It reads the complete
`HRTCRS01` extent: the entry return is 64, while the payload length is at byte 40.
The constructor owns the `resultType`, `content`, `isError` field order and exact
string escaping. There is one constructor source for annotation and public
publication; annotation contains no second serializer or contracted mutable loan.
Both source authors reproduce their exact imported AST closures during the build.

A real constructor `HGRWS002` request propagates as a private capacity refusal;
it cannot become a success or budget observation. The final result descriptor
must state policy 0 and `isError` 0. Complete request bytes and acknowledgments
remain checked across this third phase. This budget precedes negotiated-version
field projection, as in the unchanged current-target Rust function.

The complete emitted wire length is compared with 65,536, inclusively. The
implementation does not substitute an estimated JSON size. The independent
target-qualified typed serializer checks all representable test projections;
the unchanged original method and actual RMCP constructor compare every case,
including the one projection beyond that serializer's separate 8 MiB profile.

Workspace regions are control below 16 KiB, error text at 16 KiB, immutable
input at 1 MiB, child request at 16 MiB, canonical reply at 32 MiB, annotated
text at 96 MiB, and constructor reply at 160 MiB. The complete SDK wire starts
64 bytes after that reply. Annotation and wire each admit 64 MiB. The complete
constructor query may reuse retired canonical-reply storage after the merge;
its source annotation span and destination are disjoint. The constructor has
its own mutable workspace and disjoint output loan.

## Result and evidence

`HSCANR01` has a 64-byte header: original result kind at 8 (0 success, 1 error),
message bytes at 16, complete wire bytes at 24, category at 32 (0 success,
1 parse error, 2 non-object, 3 wire budget), annotation bytes at 40, and zeros
at 48/56. The complete original success text or error display follows.
The private annotation and complete SDK wire remain observable for qualification.

The focused corpus has 444 complete inputs and 48 wire-boundary cases. It retains all
27 original lifecycle/refusal controls and adds 12 actual constructor continuation,
capacity and recovery controls. The new graph performs 2,484 actual native calls,
including 331 shared-constructor calls and 330 independent typed comparisons. The native transport retains every full
input, the entire annotation output capacity and control/action span for each
call, complete child request/result spans, and the complete final annotation
and SDK wire. It does not claim full capture of the already-qualified child
workspaces. Refusal controls hash every declared workspace byte before and
after; full base arrays plus explicit pre-call patches give a lossless retained
representation of unchanged buffers. No native execution occurs in readers.

Fresh original evidence distinguishes the unchanged complete method from a
separate, exact source-prefix observer which exposes the actual complete wire
even when the original budget rejects. Both are executed for every input.
The native and original complete framed streams must match byte for byte.

## Focused gate

`qualify_hia_scope_annotation.py --phase all` builds all five pinned HIA modules,
executes the native corpus and controls in separate owned processes, then builds
and replays the unchanged reference on CI. Compilation heaps retire before the
semantic process starts. Each semantic or reader process retains its original
180-second deadline. The exact target dev profile, Rust 1.95, offline locked
build, actual compiler commands and complete registry source archives are bound
in the reference evidence. `--phase verify` rereads retained evidence without
executing HIA or Rust. Native-only results remain explicitly reference-pending.

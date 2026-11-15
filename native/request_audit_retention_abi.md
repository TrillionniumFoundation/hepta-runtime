# Audit retention caller ABI

This HIA owner implements the control flow of the unchanged original
`retained_record`, `archived_copy_matches`, `archive_replacement`, and
`retain_for_batch` functions. It is a callable native image with explicit child
effects. Qualification compares the original Rust policy and HIA against the
same predeclared child results. It does not qualify the actual archive,
activity registry, hot filesystem, public dispatch, or complete audit storage.

## Borrowed buffers

The entry function uses the pinned runtime borrowed-buffer ABI. Its immutable
input is at most 1 MiB; its private workspace is at least 4 MiB. Output capacity
must be at least 576 bytes for operations 1–3, or `64 + record_count * 520` for
operation 4. Each caller owns a distinct workspace until the operation completes.

Requests begin with the 64-byte `HRAKQ001` header. Every number is a little-endian
unsigned 64-bit word.

| Offset | Field |
| --- | --- |
| 8 | Operation: 1 retained record, 2 archive compatibility, 3 replacement, 4 retention |
| 16 | Sync-directory flag, 0 or 1; operation 4 only |
| 24 | Primary record projection length; operations 2 and 3 only |
| 32 | Record count; operation 4 only, at most 512 |
| 40 | Pending request ID count; operation 4 only, at most 512 |
| 48 | Owner UTF-8 byte length; operation 4 only, at most 256 |
| 56 | Request ID UTF-8 byte length; operation 1 only, at most 256 |

Payload order is the primary projection, each record as `u64 length + bytes`,
each pending ID as `u64 length + UTF-8`, the owner, and the request ID. Unused
header fields are zero. Record projections use the canonical `HRAJJ001` audit
record format, have length 256–512, preserve the full u128 timestamp and
`None` versus `Some(0)` elapsed time, and require canonical string offsets,
valid UTF-8, valid state/option tags, and zero reserved words. Public ID/tool
validation belongs to the actual record reader. This private typed policy ABI
does not replace that validation.

The current admitted domain is a record vector and pending-ID vector each of
at most 512 elements, strings of at most 256 bytes for owner/ID/pending input,
and projections of at most 512 bytes. Public-call integration must establish
these bounds. The output preflight is deliberately conservative, allowing
every admitted record slot to hold the maximum projection.

## Child effects and resumption

`0xfffffff0` means that the owner yielded a child effect. The 96-byte action at
workspace offset 256 is `HRAKA001`, followed by sequence, kind, flags, argument
offset, argument byte length, reply offset, reply capacity, acknowledged
sequence, returned reply byte length, transport errno, and reserved word.

| Kind | Contract | Argument | Flags |
| --- | --- | --- | --- |
| 100 | Hot `read_record` | UTF-8 request ID with `.json` suffix | 0 |
| 101 | Actual future `Archive::read_record` | UTF-8 request ID with `.json` suffix | 0 |
| 102 | Actual future `is_active` | UTF-8 request ID | 0 |
| 103 | Hot `remove_record` | Complete canonical record projection | Sync-directory flag |

The argument is at workspace offset 8192, at most 512 bytes. The reply is at
offset 4096, capacity 560. The carrier may write the reply bytes and the
acknowledged sequence/returned length at action offsets 64/72. All other
action fields and the argument must remain unchanged. Transport errno and
the reserved action word remain zero. A result error is represented in the
typed reply, not by changing the transport errno.

The reply is `HRAKC001` and five words: diagnostic, errno, error-kind tag,
value, and zero reserved word. A read success appends a record projection and
sets value to its byte length. An activity success has value 0 or 1 and no
payload. A removal success has value 0 and no payload. An error has nonzero
diagnostic, zero value, no payload, and exactly 48 bytes. Only diagnostic 23
(I/O) permits a nonzero errno or error-kind tag; errno is at most 4095 and the
kind tag is 0 or 1. Kind 1 means `std::io::ErrorKind::NotFound`. Absence uses
this semantic tag, independently of the raw errno. Other diagnostics are
opaque values in 1–65535 propagated according to original policy.

The caller resumes with the same input bytes and buffer capacities. The HIA
owner verifies the immutable input snapshot, action sequence, receipt,
argument, effect kind versus current phase, span limits, response type,
canonical projection, and reserved fields before accepting the result.
Malformed input/receipt returns `0xffffffff`; insufficient admitted buffer
capacity returns `0xfffffffe`. Neither result is a completed operation.
Malformed sessions must be discarded. Completion resets the phase to zero;
the same private workspace may then execute another request.

An actual kind-101 adapter must hold an Archive lease and execute the full
original `fence_record` before the frozen audit record reader. A direct call
to the hot reader does not satisfy this child contract. The qualification
driver deliberately implements only scripted results and cannot substitute
for this adapter.

## Completed results and preserved policy

Completed results start with the 64-byte `HRAKR001` header: diagnostic at 8,
errno at 16, error-kind at 24, decision at 32, remaining record count at 40,
selected projection length at 48, and zero at 56. Operation 1 returns decision
0 for no record or 1 plus a selected projection. Operation 2 returns a boolean.
Operation 3 returns 0 for no change, 1 for create (`Some(false)`), or 2 for
replace (`Some(true)`). Operation 4 returns a boolean and the remaining record
vector as length-prefixed projections, including on error.

Diagnostic 35 denotes retained-record binding disagreement; 36 denotes an
archive identity disagreement; 37 denotes changing an immutable terminal
outcome. Child errors otherwise propagate or are suppressed exactly where
the original policy suppresses them.

The owner preserves these observable behaviors:

- Hot read errors fall back only for NotFound. An archived record is preferred
  over a compatible hot record; a hot unknown state or absent elapsed value
  may lag the archive. Terminal state and a present elapsed value must match.
- Archive matching suppresses child read failures and returns false.
- Replacement checks owner/tool/timestamp identity before ignoring stale
  unknown records. Terminal outcomes and elapsed times are immutable. Equal
  state and elapsed time are no-ops; only archive NotFound permits create.
- Retention enforces the owner bound of 128 before the global bound of 512.
  It preserves vector order and skips non-owner or pending records before
  querying activity. Activity errors propagate. Incompatible or unreadable
  archived records are ineligible. Removal receives the complete record and
  sync flag, and vector removal occurs only after child success. Earlier
  successful evictions remain observable if a later child fails.

The native machine executes all these decisions. Python in the qualification
driver transports predeclared replies and records the resulting transcript;
it does not select records, classify policy outcomes, or implement fallback.

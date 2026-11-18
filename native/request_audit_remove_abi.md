# HIA audit record removal

`request_audit_remove.hepta` implements the Unix `remove_record` operation from
`src/mcp/runtime/request_audit.rs`. It invokes the complete qualified audit
read graph, compares every field of the expected record, unlinks the record
name only after equality succeeds, and optionally synchronizes the directory.
Its composition manifest pins the owner, exact scalar imports and unchanged
read child. The read child invokes the unchanged typed audit JSON decoder.

The static Linux x86-64 executable is packed by HIA from those three execution
images and the descriptor boundary frozen in the layout manifest. It has no
runtime Rust, Python, libc or dynamic-loader dependency. The caller supplies
the root directory authority and the original surrounding store lock. This
operation adds no private-directory check that the original function did not
perform; directory acquisition and authority validation belong to its caller.

## Wire format

Integers are little-endian. The carrier accepts a sequence of requests framed
by eight-byte lengths and returns a four-byte code followed by that many
response bytes. Each request is at most one MiB.

| Request offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 8 | `HRAXQ001` |
| 8 | 8 | Directory synchronization flag, exactly zero or one |
| 16 | 8 | Following projection length |
| 24 | variable | Complete expected `HRAJJ001` audit record projection |

The projection has the same 256-byte header and three contiguous UTF-8 string
spans as `request_audit_json`'s record kind. Kind, flags, state, reserved bytes,
all span bounds and UTF-8 are checked before any effect. It retains the full
128-bit acceptance time and distinguishes absent elapsed time from present
zero. Strings are compared by their complete UTF-8 bytes, without Unicode
normalization or added public admission rules.

| Response offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 8 | `HRAXR001` |
| 8 | 8 | Diagnostic |
| 16 | 8 | Positive errno only for operating-system diagnostic `23` |
| 24 | 8 | Reserved zero |

Normal responses are exactly 32 bytes. Diagnostic zero means the requested
removal and any requested directory barrier completed. Diagnostic `31`
means the complete read record differs from the expected record. Read and
recovery diagnostics are forwarded unchanged: `8` size, `17` private file,
`18` staging inode, `19` staging link binding, `23` OS error, `24` JSON,
`25` record identity, `26` filename, `27` staging identity and `28` directory
entry UTF-8. These codes are composition diagnostics, not exact public error
strings.

Malformed frames, projections or suspended receipts return `0xffffffff`
without an output body. Insufficient borrowed output or workspace returns
`0xfffffffe`. The owner requires at least 32 output bytes and four MiB of
workspace. Its read child has an independent four MiB workspace and the JSON
child has an independent one MiB workspace; an inaccessible final page guards
the executable's mapped workspaces.

## Equality, order and effects

The complete audit read operation runs first, including deterministic and
legacy random staging recovery, private-file checks and record/filename
binding. An absent or invalid record therefore returns its original read
error before an expected-record mismatch can be reported.

Equality includes request ID, owner, tool name, durable state, complete
acceptance time and the optional elapsed-time value. The canonical projection
representation permits an exact complete-byte comparison after both sides
have been validated. In particular, unknown and completed states differ,
and absent elapsed time differs from present zero. No mismatch can unlink a
record.

After a matching read returns and releases its files, the owner unlinks the
derived `.json` filename relative to the retained directory descriptor. It
preserves the original ordering when the pathname changes between reading
and unlinking; it introduces neither an additional inode fence nor a replay.
Unlink errors, including interruption, return immediately. If synchronization
was requested, the subsequent directory barrier retries interruption.
A barrier failure reports the error even though the unlink has already
occurred. No rollback recreates the removed name.

The root directory remains held between framed requests. All read, staging
and scan descriptors are released before a normal response. The remove owner
itself owns no extra file descriptor.

## Borrowed protocol

An effect returns `0xfffffff0` with a 96-byte action descriptor at workspace
offset 256. The descriptor records action magic, a persistent increasing
sequence, kind, slot, span, count, argument, child capacity, acknowledgement,
result, errno and a reserved word. The owner independently retains the action
words, suspended request and child request. Resume checks those bindings,
buffer lengths and result ranges before advancing.

| Action | Meaning |
| ---: | --- |
| 100 | Complete audit read child call |
| 8 | Descriptor-relative unlink of the exact derived record name |
| 5 | Directory synchronization |

Child input starts at workspace offset 1,048,576; its response has 512 bytes
at offset 16,384. The caller request snapshot starts at 2,097,152 and its
projection at snapshot offset 24. A second immutable child-input copy starts
at 3,145,728. The derived filename is at offset 65,536. The boundary checks
the original request ID against the unlink component, its 64 lowercase
hexadecimal bytes, the suffix, descriptor ownership and exact argument spans.

## Actual qualification

The fresh ai395 run builds 18 unchanged original source blocks with Rust
1.95.0 and 13 exact registry packages from the runtime lock file. It compares
208 baseline cases / 446 requests per side, 27 real kernel-fault and race
cases / 79 requests per side, and two owned-child death/recovery cases /
six requests per side. The two death boundaries are before unlink and before
the subsequent directory barrier. Complete responses, contents, modes,
ownership, links, inode changes and selected live descriptor sets match.
Nonfatal requests also check that only the root directory remains held at
each response. Inputs, original blocks, registry members and executables are
rechecked after execution.

Another 25 borrowed controls comprise 24 rejections and one synthetic child
completion. They execute no filesystem operation or original Rust and are
reported separately from actual storage equivalence.

This component does not qualify store locking, hot-cache enumeration and
retention, archive anchoring/indexes, active-request and read-pin registries,
admission/cohort coordination, async cancellation, public dispatch or
non-Linux execution. Audit/result storage closure, production activation,
whole-runtime replacement and legacy removal remain false.

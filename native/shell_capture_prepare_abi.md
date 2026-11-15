# Shell capture preparation continuation ABI

This private HIA owner implements the capture-creation continuation of
src/mcp/fs/background.rs, after duplicate admission and before construction of
the Job value. The pinned production source is 9434 bytes, SHA-256
826394f843a0891dfbe8b0b6986dad40d85b53e20a497cb4ddb04838a185f065.
The relevant source begins with jobs_dir() and create_dir_all, allocates the
sequence only after directory creation succeeds, creates stdout and stderr in
that order, and closes and removes stdout if stderr creation fails.

The result is an owned capture tuple or a typed original error. It does not
claim to execute the entire async prepare function. Registry duplicate locking,
concurrent global JOB_SEQ behavior, ambient TMPDIR/PID/time observation,
Tokio await cancellation and into_std scheduling, construction of Job/Arc/Mutex,
and io::Error Display/anyhow error text remain separate qualifications.
The caller supplies typed TMPDIR/PID/cache observations and must have already
performed any required duplicate admission. No public handler is activated.

The target is Linux x86-64 and pinned Hepta
d3e2c90173cf733e42b299d0c4274df4b593a12f. The HIA schema is v8.
The entry is f0(readbuf input, mutbuf output, mutbuf workspace) -> u32.
All three complete borrowed buffers are owned, disjoint, and stable throughout
a call. Integer fields are little-endian u64.

## Request

The request is exactly 64 bytes plus the complete raw TMPDIR bytes.

| Offset | Field |
| --- | --- |
| 0 | Eight bytes HSHPPQ01 |
| 8 | Operation: 1 START or 2 RESUME |
| 16 | TMPDIR presence: 0 or 1 |
| 24 | Observed PID, any u32 including zero |
| 32 | Raw TMPDIR byte length N |
| 40 | Initial serial statx cache: 0 unknown, 1 present, 2 unavailable |
| 48, 56 | Reserved zero |
| 64 | N raw TMPDIR bytes |

Absent TMPDIR requires N=0 and uses the original Linux /tmp fallback.
Present empty TMPDIR is distinct. Raw bytes, including non-UTF-8 and typed NUL,
are preserved. Real environment observations cannot contain an embedded NUL;
that expanded typed domain is explicitly a projection. A NUL then causes the
original mkdir leaf's local InvalidInput before a syscall or sequence request.

START requires an uninitialized workspace. RESUME repeats every original field
and byte except operation. It never supplies an FD, token, sequence result, or
child-module completion in the request. Completion is accepted only through the
private owned capability interface described below. Cancellation and restarting
an initialized continuation are not operations of this ABI.

## Return values and publication

| Scalar return | Meaning |
| --- | --- |
| 128 | A complete response is published |
| 4294967293 | PENDING: the HIA-issued private capability has not yet been consumed |
| 4294967294 | CAPACITY: private storage is insufficient or its complete extent cannot be represented |
| 4294967295 | INVALID: malformed request, state, or private completion |

The success scalar is a fixed descriptor size, not a payload length. All
complete extents and loops use u64. There is no fixed path or response byte
quota. Private capacity arithmetic is checked before mutation.

INVALID and CAPACITY preserve the entire output and workspace. PENDING
preserves the entire output. A ready-zero continuation call preserves the whole
workspace as well. Input and bilateral guards are always unchanged. Publication
preserves every output byte beyond the complete response extent.

For this private ABI, the caller supplies workspace of at least 1792+4*N bytes
and output of at least 384+3*N bytes. These conservative bounds include the
longest decimal PID/sequence and all response variants, so no filesystem effect
is started only to discover inadequate publication capacity later. They are
transport/workspace requirements, not semantic truncation or public quotas.
The fixed capabilities allocate path output 512+3*N, mkdir workspace 1152+10*N,
three file workspaces each 640+N, and input staging 256+N. Unrepresentable bounds
return CAPACITY before the first write or effect.

An actual failure to allocate these private child buffers is an infrastructure
result, separate from an original filesystem error. The INIT primitive must
roll back all of its partial private allocations before reporting such failure.

## Response

The complete response is 128 bytes plus jobs_dir, id, stdout_path and
stderr_path in that order.

| Offset | Field |
| --- | --- |
| 0 | Eight bytes HSHPPR01 |
| 8 | Complete response extent |
| 16 | Outcome: 0 prepared tuple, 1 original error, 2 private infrastructure error |
| 24 | Error stage: 0 none, 1 mkdir, 2 stdout create, 3 stderr create, 4 INIT |
| 32 | Error kind: 0 none, 1 raw Linux errno, 2 original local NUL InvalidInput |
| 40 | Error value: errno 1..4095 for kind 1; zero otherwise |
| 48 | Sequence observed flag: exactly 0 or 1 |
| 56 | Observed pre-increment sequence, or zero when unobserved |
| 64 | Sequence+1 with u64 wrap, or zero when unobserved |
| 72 | Final serial statx cache: 0, 1 or 2 |
| 80 | Owned stdout token, nonzero only on prepared success |
| 88 | Owned stderr token, nonzero only on prepared success |
| 96 | jobs_dir byte length |
| 104 | ID byte length |
| 112 | stdout_path byte length |
| 120 | stderr_path byte length |
| 128 | Complete raw segments in the order above |

The response magic in hexadecimal is 48 53 48 50 50 52 30 31.
A successful tuple has two distinct live tokens and zero error fields.
All failures have zero public tokens. Directory and INIT failure retain only
jobs_dir and have no observed sequence, ID, or log paths. File failure retains
the already allocated sequence and all path metadata. Sequence is never rolled
back after stdout/stderr failure.

For stderr failure, the exact original stderr error kind/value is saved before
cleanup. HIA then issues one close of the received stdout token, retires its
custody regardless of close errno, and calls the original file unlink leaf on
stdout_path. Every unlink errno is ignored. It does not remove stderr_path or
the directory. The saved stderr error is the terminal result.

There is no implicit cleanup on a caller abandoning this private continuation.
That requires the later asynchronous owner/cancellation composition.

## Unchanged HIA components

Directory creation invokes the frozen shell_capture_mkdir entry; file
CREATE/TAKE/UNLINK invoke the frozen shell_capture_file entry. Their HIA sources
and ABIs are unchanged. Statx choices, ancestor traversal, NUL rejection, open
flags, EINTR retry, and unlink behavior stay in those owners.

Before mkdir, this owner uses complete frozen capture_path helper bodies for
decimal formatting, exact literals and byte copying to construct only jobs_dir.
No sequence is allocated or formatted in that stage. After successful mkdir,
HIA requests the sequence observation and calls the full frozen
shell_capture_path entry with capture operation 3. The actual returned
jobs_dir/id/stdout/stderr tuple is validated and retained. The native
composition contains four unchanged compiled entries: this owner and the
path, mkdir and file leaves; three independent file arenas share the file image.

The helper proof records complete original/local bodies and permits only
function declaration and call-target ID relocation. The private authoring
generator is not a build or runtime dependency.

## Workspace

The owned control prefix is 1024 bytes. Fields not described here are zero.
The request staging span starts at 1024 and has capacity 256+N.
The path response span starts at P=1280+N and has capacity 512+3*N.
Its body starts at P+80, matching the frozen HSHCPR01 header. Before sequence
observation its header is zero and only the jobs_dir body is present.
All unused staging/data bytes through 1792+4*N are zero. Bytes beyond that
required workspace extent are untouched.

| Offset | Owned control field |
| --- | --- |
| 0 | HSHPPW01 |
| 8 | Phase, as listed below |
| 16 | Effect sequence, wrapping u64; zero after wrap is valid |
| 24 | Original N |
| 32 | Required workspace extent |
| 40 | Required private output capacity |
| 48 | Original TMPDIR presence |
| 56 | Original observed PID |
| 64 | Current serial statx cache |
| 72 | Sequence observed flag |
| 80, 88 | Observed sequence and next sequence |
| 96, 104 | stdout/stderr token retained by the relevant owner phase |
| 112 | Child request operation, or zero when no child request is staged |
| 120 | Terminal outcome tag, or zero before any saved failure |
| 128..223 | Private effect slot |
| 224, 232, 240 | Saved error stage, kind and value |
| 248 | P |
| 256, 264, 272, 280 | Directory, ID, stdout and stderr lengths |
| 288 | Complete staged child request length |
| 296, 304 | Mkdir and per-file workspace capacities |
| 312 | Immutable initial statx cache, equal to the original request field at 40 |
| 320..511 | Reserved zero |
| 512..559 | Complete short child result; 32 bytes plus 16 zero for mkdir |
| 560..1023 | Reserved zero |

Before every short child CALL, HIA zeroes all 48 result bytes. The adapter
copies the child's complete fixed output allocation back, including refusal
tails. It does not infer a stage from the child result.

## Phases

| Phase | Next private operation |
| --- | --- |
| 1 | INIT |
| 2 | CALL_MKDIR |
| 3 | DISPATCH_MKDIR |
| 4 | OBSERVE_SEQUENCE |
| 5 | CALL_PATH |
| 6 | CALL_FILE stdout CREATE |
| 7 | DISPATCH_FILE stdout |
| 8 | CALL_FILE stdout TAKE |
| 9 | ADOPT_FILE_TOKEN stdout |
| 10 | CALL_FILE stderr CREATE |
| 11 | DISPATCH_FILE stderr |
| 12 | CALL_FILE stderr TAKE |
| 13 | ADOPT_FILE_TOKEN stderr |
| 14 | CLOSE_OWNED stdout after stderr failure |
| 15 | CALL_FILE stdout-path UNLINK |
| 16 | DISPATCH_FILE unlink |
| 17 | Terminal publication |

The controller alone selects phases. A CALL returning a leaf PENDING selects
its corresponding DISPATCH. A DISPATCH completion selects a RESUME call to that
same leaf with unchanged semantic input. CREATE success selects TAKE, followed
by explicit receiver adoption. No adapter branch chooses an error, retry,
cleanup, path, output, or subsequent phase.

The order stdout CREATE -> TAKE -> receiver adoption -> stderr CREATE is
intentional. After TAKE, the frozen file arena no longer owns the token and
must not be forged back into a held state to use DROP. This controller is the
receiver. It requests CLOSE_OWNED on its own adopted capability when cleanup is
required.

## Private fixed capability interface

The slot at offset 128 is exactly 96 bytes.

| Relative offset | Field |
| --- | --- |
| 0 | HSHPPFX1 |
| 8 | Current effect sequence |
| 16 | Action |
| 24, 32, 40, 48 | a0, a1, a2, a3 |
| 56 | Ready: 0 or 1 |
| 64 | Result |
| 72 | Infrastructure/syscall errno where specified |
| 80 | Auxiliary result, zero for these actions |
| 88 | Reserved zero |

Only bytes +56..87 are completion fields. A ready-zero slot has zero completion
values. An action is dispatched at most once for its current owned slot.
No public caller can supply arbitrary raw pointers, FDs or PIDs.

Child arena roles are fixed: 1 path, 2 mkdir, 3 stdout, 4 stderr, 5 cleanup
unlink. Roles 3/4/5 have independent arenas and share the frozen file image.
The ledger mints opaque tokens from actual successful openat calls. It keeps
physical FD custody across TAKE; HIA decides when to adopt or close them.

| Action | Arguments | Fixed result |
| --- | --- | --- |
| 1 INIT | path output cap, mkdir work cap, per-file work cap, input staging cap | 0 on success; -errno/errno on complete allocation rollback |
| 2 CALL_MKDIR | 1024, staged input extent, 512, 0 | actual f0 scalar; full 32-byte output and 16 zero bytes at 512 |
| 3 DISPATCH_MKDIR | 0,0,0,0 | 0 after one issued mkdir/statx/newfstatat primitive writes that leaf's completion |
| 4 OBSERVE_SEQUENCE | 0,0,0,0 | observed old u64; errno/aux zero |
| 5 CALL_FILE | role 3/4/5, 1024, staged input extent, 512 | actual f0 scalar; full 48-byte output at 512 |
| 6 DISPATCH_FILE | role 3/4/5,0,0,0 | 0 after one issued openat/unlink/close primitive writes that leaf's completion |
| 7 ADOPT_FILE_TOKEN | role 3/4, token,0,0 | 0 after validating completed TAKE/held=0 and transferring ledger custody to this receiver |
| 8 CLOSE_OWNED | adopted token,0,0,0 | one actual close raw result and positive errno, then ledger retirement on every return |
| 9 CALL_PATH | 1024, staged input extent, P, 512+3*N | actual f0 scalar; opaque copy of the entire output-capacity span |

All results not explicitly carrying errno require errno=0 and aux=0.
CALLs are fixed borrowed-buffer forwarding. Input is copied from the exact
owned span chosen by HIA, output is initialized from the exact destination
span, and the whole output allocation is copied back regardless of the scalar
return. Path workspace has the original 128-byte private capacity. Full guarded
before/after arrays and actual scalar returns are retained for every child CALL.
No child semantic function is executed by a Python implementation.

A CALL_PATH result must be 80 and its complete HSHCPR01 envelope/body must match
the admitted request/sequence. A short child return is its fixed success size
or PENDING. Other returns or malformed completions are private contract
INVALID, preserve complete output/state, and are never relabeled filesystem
errors.

OBSERVE_SEQUENCE may be supplied by a fixture's private AtomicU64 fetch_add;
such a fixture must retain the actual before/after observation and label it as
private serial qualification. It is not proof of production JOB_SEQ identity
or registry concurrency.

ADOPT and CLOSE validate actual ledger ownership and never signal or close a
caller-provided raw FD. A CLOSE result is accepted only in the saved stderr
failure cleanup phase. The adapter performs no close retry. Linux close errno
does not restore ownership of a potentially reused descriptor.

## Qualification scope

Native state tests use actual compiled HIA entries for the controller and all
three leaves, while deterministic kernel observations remain typed plans.
The independent OS fixture replaces those observation plans with fixed real
syscalls and records actual ownership, sequence observations, file contents,
and cleanup. These two evidence domains must remain distinct.

Neither domain alone qualifies original Tokio scheduling/cancellation,
production duplicate admission, ambient observations, error Display formatting,
Job construction, production activation, complete prepare, whole-runtime
replacement, or removal of the previous stack.

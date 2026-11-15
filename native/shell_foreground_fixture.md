# Shell foreground native fixture

This private Linux x86-64 fixture composes four separately compiled HIA owners:
the unchanged process graph, unchanged foreground IO graph, unchanged owned-buffer
outcome object, and the foreground controller. The adapter supplies fixed kernel
operations, owned-buffer transport, and audit records. It does not choose command
environment/PATH, deadline promotion, error priority, cleaning, text limits, or
result formatting. Python is used only to build and qualify retained artifacts.

This is a prepared-capture boundary. It does not close request/MCP admission,
background preparation or registry, spawn-error discard/text, promotion text,
resource callbacks, production activation, or whole-runtime replacement. The
scope flags remain false. The unchanged process foreground deadline is
10,000,000,000 monotonic nanoseconds; frames cannot alter it.

## Invocation and capture custody

Run the linked executable with exactly:
`--foreground-fixture OWNED_CAPTURE_DIRECTORY`.
The directory already exists. Native startup exclusively creates stdout.log,
stderr.log, process-effects.bin, io-effects.bin, controller-effects.bin, and
controller-child.bin, using private CLOEXEC descriptors normalized above 2.
The capture token is 1. Frames never grant raw FD, PID, pointer, or syscall access.
The two writer FDs remain owned independently of later path replacements.
The IO owner opens the current full stdout/stderr paths. It does not read the
writer FD's old inode as a substitute for the original filesystem operation.

The bridge additionally requires pidfd_open and pidfd_send_signal. Immediately
after a successful parent fork, before any wait, it retains a separate CLOEXEC
pidfd to that exact child until overall retirement. This descriptor is used only
for infrastructure/contract failure containment. Ordinary HIA SIGNAL/WAIT effects
are unchanged. A custody acquisition failure is an infrastructure failure,
never an invented command spawn error; an unavailable pidfd never authorizes
signaling a numeric PID. HIA's semantic ABORT_SELF bypasses containment and keeps
its separate fatal allocation behavior.

The linked HIA outcome object imports only the pinned allocator's calloc/free.
The native startup is raw _start. The actual ELF interpreter, libc, linker,
assembler, object relocations, source bytes, and entry are independently pinned
by the build reader. No dynamic module choice is taken from ordinary input.

## Framing and borrowed output

Startup emits 64 bytes: eight Q words HSHFGRD1, token, PID, stdout writer FD,
stderr writer FD, stdout inode, stderr inode, zero. Numeric descriptors and PID
are audit observations, not input capabilities.

Input is u64 byte length followed by the exact HSHFGQ01 request in the controller
ABI. The initial request contains command/cwd. Later control frames are exactly
40 bytes, including the magic, and retain the bound token. Partial control
frames are kept until complete. EOF or a broken reply sink is a trusted shutdown
event, not a fabricated owner completion.

Every publication is u64 return=64, u64 extent, the complete 64-byte HSHFGD01
descriptor, then its complete loan. Extent is 64 plus the loan's u64 length.
The bridge only maps source token 1 to controller workspace or source token 2
to its owned outcome output and validates the range. It does not branch on the
business event kind. It copies the entire publication into its private queue
before advancing the controller. Thus output backpressure cannot retain a
borrow that the next HIA call may overwrite. A final pair of zero Q words means
retirement after custody and jobs have completed.

Initial framing/queue allocation is private storage, with checked extents and
actual allocation failure. There is no fixed command/log semantic quota or raw
8 MiB admission limit. Actual HIA refusals and infrastructure failures terminate
qualification with retained raw diagnostics; they are not converted to read
Results. Exit 64 is usage, 74 transport/audit/infrastructure, 75 private storage,
78 private contract; successful result errors still exit 0.

## Scheduling and private effects

Only the HIA controller issues its thirteen fixed capabilities. INIT uses HIA's
selected arena capacities. CONTEXT_EXTENT measures the held raw inherited
environment encoding; the fixture never changes environ. The process owner alone
parses, filters, sorts, overrides, and searches those bytes.

FORK executes on main; both branches receive their own completed private job.
The child continues the same HIA graph to exec. Blocking process handshake,
wait/wakeup and IO operations use distinct raw clone workers. A worker invokes
only fixed syscall primitives, never HIA or libc. No worker is created before
fork. Workers retain separate result/errno/aux fields. Main POLL checks the exact
job and unchanged emitted mailbox before publishing ready=1. Workers can write
only the admitted IO data span while HIA latches cancellation in disjoint state.
The memory GROW operation runs on main with no outstanding borrower.

Process controls are queued by HIA until the pending job completes: the original
process graph requires ready=1. The bridge never patches the process cancellation
word. Its dedicated wake eventfd lets WAIT_WAKEUP complete when a control frame
arrives. IO cancellation can be latched with ready=0; an already-started file
task continues to its real EOF/error and close, while HIA skips later awaits.
The controller decides when to acknowledge cancellation and when to advance each
owner. Outcome runs synchronously with the exact borrowed HSHOUT01 loan.

SEED_IO_CACHE copies only the HIA-specified 0/1/2 to IO workspace240 at its first
ADMIT phase1/sequence1/ready0. SNAPSHOT copies the field back. The one-invocation
fixture does not claim cache sharing across separate controllers/processes.

## Exact audit streams

process-effects.bin retains the frozen HSHPRTR1/HSHPAUD1 process records.
io-effects.bin retains HSHOITR1 records, including complete path, metadata and
read payloads, and HSHOIAU1 footer. Their syscalls can now run on worker TIDs;
each issued/completed pair must bind the same actual thread. Initial capture
fstat observations run on main.

controller-effects.bin holds parent/main records; controller-child.bin holds
post-fork child records. Each record is 128 bytes, sixteen Q words:
HSHFGTR1, per-stream inherited sequence, record type, process role, PID, TID,
CLOCK_MONOTONIC nanoseconds, controller capability sequence, capability action,
raw return, chunk byte count, process job token, IO job token, chunk offset,
total payload bytes, zero. The exact chunk follows. A complete logical payload
is split into at most 1 MiB chunks, with contiguous offsets; this is audit
framing, not a semantic byte limit. Header and chunk are one O_APPEND writev.
Sequence, chunk inventory, full bytes, and raw process streams are all retained.

Types are 0 controller input before call; 1 actual 64-byte descriptor with its
two 16-byte guards after call; 2/3 issued/completed capability slot; 4/14 process
input before/after call; 5 complete process output; 6/15 IO input before/after;
7 complete IO descriptor; 8/19 outcome input before/after; 16/9 outcome output
before/after including guards; 17/18 outcome workspace before/after including
guards; 10/11 process job submit/join mailbox; 12/13 IO job submit/join mailbox;
20 READY; 21 actual child pidfd acquisition; 22 accepted control; 23/24 worker
start/join; 25 pidfd close; 255 final audit footer.

The final type255 payload is sixteen Q words: HSHFGAU1, PID, actual parent
record count including this footer, last capability sequence, publication count,
exit status, transport error, custody pidfd after close, process-owned flag,
IO read FD, process worker TID after join, IO worker TID after join, IO statx
cache, process cached-wait state, zero, zero. A failed infrastructure boundary
may instead append HSHFGAB1 with exit/custody/raw failure data. It cannot be read
as a successful footer or a command Result.

All final evidence readers are read-only: source/ELF/receipt pins, complete
requests and controls, exact command and six shared specs, full call loans,
actual syscall/job ordering, descriptor/output framing, and owned fixture
retirement must be reconstructed. They do not run a native image, query current
/proc as historical evidence, or trust a stored PASS. A real ECHILD case may
prove IO starts before process arena0; it must not be mislabeled as a live
orphan. Live-orphan continuation remains a separately declared synthetic domain
until a justified real kernel case is observed.

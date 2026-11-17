# Private persistent audit legacy anchor

This is a new isolated successor to the closed native record-I/O pump. It implements
the unchanged target PinnedAnchor::open, record, fence/fence_with and File-drop
lifecycle with one retained file descriptor, complete inode stamp and original bytes.
The HIA owner selects every continuation and compares every inode field and reread byte.
The native transport performs its requested real open/stat/geteuid/read/pread/close.
The qualified audit JSON owner remains the only Anchor decoder.

The source-preparation checkpoint afed829e completed fresh source authoring and HIA
compilation in CI 44069399673. It made no anchor semantic calls and ran no Rust.
This package was written for the first complete semantic qualification; its source
STATUS.json deliberately remains pending. Actual successful GATE.json is evidence,
not a source declaration.

The fixed source corpus has 132 cases and 212 command operations. Both native
cohorts and the unchanged Rust reference execute every case: ordinary/empty/maximal
Anchor values, sequence decoding, all source-owned file types and modes, unknown,
duplicate and missing fields, whole size boundaries through 65536 input bytes, and
changes between calls while the original descriptor remains pinned. Retained-file
changes include replacement, unlink, chmod, hard links, positional rereads, and
drop/repair/reopen. Full original errors remain in stderr; the private output
projects their OS/source/Serde/UnexpectedEOF class and does not claim to replace
the exact Serde diagnostic text.

The observed native cohort retains every HIA input, output and workspace byte,
every libc return/errno and complete stat, every descriptor capability before and
after, complete outer context buffers and destructor close records. The independent
observer-free cohort uses the same packed image and complete ordinary corpus,
with actual strace boundaries and all full external results/owned file trees.
The original reference includes the exact target source spans without editing the
function bodies and builds with the unchanged locked dependency versions and Rust
1.95.0. All new Rust execution belongs to the frozen CI recipe.

The old 45 native admission/refusal/recovery groups are retained for the extended
18-word capability table and real missing-anchor recovery. Additional direct HIA
controls use fixed distinct actual checkpoints, retain all physical pre/post buffers,
and reject malformed headers/ACKs/workspaces and insufficient capacities before
testing exact replay/recovery. They issue no filesystem operations. They are separate
from the actual filesystem corpus and do not imply race or crash-injection coverage.

The strict readers validate fresh B1/B2/B3, all three image compile receipts, complete
GAS/packer buffers, locked crate archives and every vendored implementation file,
all actual process receipts, source manifest, complete native/original streams, and
file/descriptor lifetimes. Fifteen rehashed physical mutations and two independently
relocated full captures are retained. Each read-only pass is guarded against writes,
process execution and native mappings and compares every file byte and metadata
before and after. Prepare reader imports before entering the guard.

Budgets remain 60 seconds per native/original ordinary replay, 180 seconds per
control/reader phase, 900 seconds for each compiler process, and 15 minutes per CI
job. Failures and partial observations are archived without reclassification.
A reader command with --receipt explicitly writes its report after leaving the
read-only boundary; reader_cli.run and read_capture.verify are pure readers.

This private component does not qualify the complete archive store, namespace
versioning, HOT_CACHE, begin/finish callers, public handlers or the whole runtime.
It does not change the main branch or any previous frozen qualification package.

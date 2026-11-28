# Root and legacy-store directory ownership

`request_store_directory.hepta` owns the original descriptor-relative
`open_root`, `open_store`, `private_directory`, and `directory_identity`
decisions, including the existing anchor-presence fence. It retains a real
open directory until the caller releases its lease or the process exits.
This is one private directory owner, with one live lease at a time; callers
may instantiate separate owners for independent retained descriptors.

The resulting Linux x86-64 static ELF embeds the HIA owner and a fixed syscall
adapter. The HIA packer emits and relocates the ELF. Rust, Python, libc, and a
dynamic interpreter are not required when running this executable. The caller
must establish authorization for the explicit root before entering this
component. The component does not implement archive initialization, anchor
content validation, audit policy, per-record locking, or public dispatch.

## Private frames

All words are little-endian `u64`. The owner requires 4 MiB of private workspace,
at least 64 output bytes, and an input frame no larger than 1 MiB. Return codes
`0xffffffff`, `0xfffffffe`, and `0xfffffff0` denote invalid input, capacity, and
a pending descriptor action. A normal response is exactly 64 bytes. The
standalone executable reads `u64 length + frame` from stdin and writes
`u32 code + response` to stdout; private error codes have no response bytes.
It accepts no command-line arguments beyond the executable name.

| Request offset | Meaning |
| --- | --- |
| 0 | `HRSDQ001` |
| 8 | 1 open root, 2 open legacy store, 3 inspect lease, 4 release lease |
| 16 | Private-directory check: 0 or 1 for operation 3; otherwise zero |
| 24 | Current lease for operations 3 and 4; otherwise zero |
| 32 | Root path byte length; zero for operations 3 and 4 |
| 40 | Zero |
| 48 | Root path bytes |

| Response offset | Meaning |
| --- | --- |
| 0 | `HRSDR001` |
| 8 | Diagnostic class |
| 16 | Raw errno when diagnostic is 23; otherwise zero |
| 24 | Current lease, or zero when no lease is held |
| 32, 40 | Actual device and inode on successful acquisition or inspection |
| 48, 56 | Zero |

Diagnostic classes are 0 success, 1 root is not UTF-8, 2 invalid absolute root,
3 invalid CString component, 16 private-directory metadata refusal, and
23 an OS error. A failed inspection preserves the existing lease. Releasing
the lease drops the actual descriptor once. New acquisitions are refused while
a lease is live. Lease generations increase after successful acquisitions;
stale generations and generation exhaustion are refused.

## Path and lifetime behavior

The owner checks the complete path's UTF-8 and absolute-path rules before
opening anything, including the original refusal of any `.` or `..`
component. Repeated and trailing separators remain accepted. It opens `/`,
then each nonempty component with directory, no-follow, and close-on-exec
flags. The preceding descriptor is released after the next descriptor opens.
Embedded NUL is refused when that component is reached, preserving the
original error order when an earlier component does not exist. Each component
is passed separately to the kernel, allowing a complete path longer than the
single-syscall path limit.

Legacy-store opening probes `.request-results-v2-anchor.json` using the
original read-only, nonblocking, no-follow flags. An existing anchor means
the legacy directory must already exist: it is never recreated as empty
history. When the anchor is absent, the owner creates `request-results` with
mode 0700, accepts an existing entry only through the original `EEXIST` path,
synchronizes the parent after a successful creation, opens the directory, and
requires its effective UID and exact 0700 mode. Errors remain errors even when
an earlier filesystem effect succeeded.

Successful acquisition moves the actual descriptor into the held slot; it
does not reduce ownership to a device/inode pair. Subsequent inspection calls
`fstat` on that descriptor, even if the pathname has been renamed, replaced, or
unlinked. A private inspection performs the original metadata check followed
by the original identity observation. Descriptor lifetime and identity are
separate from path identity.

At workspace offset 256, `HRDSA001` actions have twelve words: magic,
sequence, kind, slot, span, count, argument, capacity, acknowledgement,
result, errno, and zero. Kinds 1 through 8 are open slash, open component,
metadata/effective UID, create legacy directory, synchronize, close, transfer
descriptor ownership, and probe the anchor. Slots 1 and 2 are temporary walk
descriptors; slot 3 holds the successful lease. The adapter checks roles,
bounded component spans, root/request-component binding, exact store/anchor
names, and vacant/live slots before effects. The HIA owner checks retained
request bytes, immutable action fields, acknowledgement sequence, and reserved
words before resuming. Sequence numbers cannot wrap.

## Actual qualification

The final v3 qualification on ai395 used Rust 1.95.0, eight unchanged original
function bodies, the original DirectoryIdentity body, and two unchanged
constants. Serialization derives are outside this IO fixture. The two
original-version locked packages, `anyhow` and `libc`, were verified against
their package archives, including all 458 packaged source files, before and
after the run. The HIA owner and HIA packer were freshly compiled.

The comparison executed 121 cases and 347 requests in 121 processes per
implementation, with 359 observations per implementation including external
fixture mutations. It covered ordinary and Unicode paths, invalid UTF-8,
embedded NUL error order, dotted components, every tested symlink position,
directory/file/FIFO/socket substitutions, permissions and umasks, absent and
present anchors, missing legacy history, stale leases, and paths longer than
4,096 bytes. Real rename, unlink/recreation, and permission changes occurred
while the child process kept its directory descriptor open.

The harness inspected the owned live child's descriptor table and checked
each returned device/inode against that actual descriptor. A lease retained
the same descriptor and identity across all of its inspections. Separate
original/native fixture directories naturally have different inode numbers:
the comparison zeroed only those two identity words after verifying each
against its own actual descriptor. All remaining response bytes, reported
lease generations, descriptor targets, and observed filesystem state matched.
This is not a claim that unrelated fixture inode numbers were byte-identical.

The native ELF is 84,949 bytes with SHA256
`7103e606c00471003e84d61250953bfc892fd72bd636fa20d9d94df35bcdbdec`.
The complete v1–v3 evidence archive is 1,098,924 bytes, SHA256
`9106768ddcc9d6950b98f536d679c66a123ef6e02f100c8b728e82cb5faa1e22`.
All 1,477 archive members were verified after retrieval. Four deliberately
unreadable ordinary fixture files and two inaccessible fixture directories
are explicitly retained as metadata and read/enumeration refusals; their
contents were not claimed to have been read. Input case definitions preserve
the original fixture construction data. Nonregular objects are metadata only.

The first original fixture failed to compile because an include fragment used
an inner doc comment. The second attempt failed before semantic comparison
when `/tmp` exhausted its free inodes. Those failures remain preserved. The
successful run used its own output/temporary directory, with the same HIA and
original function bodies and the same case corpus. A failed archival attempt
that tried to read an intentionally unreadable fixture is also retained.

Archive anchoring, result storage as a whole, audit storage, public dispatch,
whole-runtime replacement, production activation, and old-stack removal
remain unqualified. The acquisition/inspection corpus does not claim general
future cancellation or a full syscall-fault domain.

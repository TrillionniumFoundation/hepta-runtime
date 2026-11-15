# Native audit record reads and staging recovery

`request_audit_read.hepta` owns descriptor-relative audit record reads and both
deterministic and legacy random staging recovery. It composes the separately
qualified `request_audit_json.hepta` typed decoder. Neither runtime semantics nor
filesystem decisions are implemented by Python or Rust in the executable.

The caller supplies an already held directory capability. This component covers
the original `read_record`, `cleanup_staging`, and directory scanning helpers in
`src/mcp/runtime/request_audit.rs`. Root acquisition, the global store lock,
archive layout and fencing, admissions, mutations, tracing, and public dispatch
are separate components or remain unqualified. Error categories below are a
private qualification ABI; exact original public error strings are not claimed.

## Request and response

All integer fields are little-endian `u64`. A request is at most 1 MiB.

| Request offset | Field |
| --- | --- |
| 0 | Eight bytes `HRARQ001` |
| 8 | Operation: 1 read record, 2 clean one staging name |
| 16 | UTF-8 filename byte length |
| 24 | Exactly the declared filename bytes |

Names are checked in HIA. Record reads require 64 lowercase hexadecimal digits
followed by `.json`. Cleanup requires `.` + 64 lowercase hexadecimal digits +
`-` + 64 lowercase hexadecimal digits + `.tmp`. No path lookup occurs for a
rejected name. Invalid UTF-8 cannot represent the original function's `&str`
argument and is an ABI rejection.

| Response offset | Field |
| --- | --- |
| 0 | Eight bytes `HRARR001` |
| 8 | Diagnostic |
| 16 | Original positive OS errno for diagnostic 23, otherwise zero |
| 24 | Typed projection length |
| 32 | `HRAJJ001` audit-record projection, only after a successful read |

Successful cleanup has no projection. Successful reads retain all typed record
fields, including the full `u128` acceptance time, state, optional elapsed time,
request ID, owner, and tool name. Projection offsets are relative to the embedded
projection; see `request_audit_json_abi.md`.

| Diagnostic | Meaning |
| --- | --- |
| 0 | Success |
| 8 | Actual read exceeded 2,048 bytes |
| 17 | Published inode is not a private regular record |
| 18 | Staging inode failed its original metadata checks |
| 19 | Staging hard link does not bind to the published inode |
| 23 | OS error |
| 24 | Original typed Record JSON rejected |
| 25 | Decoded request ID, owner, tool, or filename binding rejected |
| 26 | Invalid record filename |
| 27 | Invalid staging filename or identity |
| 28 | A scanned directory name is not UTF-8 |

The native return value is the full response size. `0xffffffff` is an invalid
request/state/receipt contract; `0xfffffffe` is insufficient output or workspace;
`0xfffffff0` requests one explicit effect. Rejections leave the output buffer
unchanged. Filesystem effects already completed before an output capacity
rejection are not rolled back. The standalone driver provisions 512 output
bytes, enough for every successfully identity-validated record.

## Original ordering and held files

For a read, the deterministic staging name is probed first. A present probe
remains held throughout the separate cleanup call, matching the lifetime of the
original Rust match scrutinee. The probe is dropped after cleanup returns and
before opening the published record. An absent probe is ignored only for ENOENT.

The published file is opened without following symlinks and with nonblocking
access. Its initial metadata is inspected before private-file validation. Two
links trigger the old random-staging recovery scan. The scan opens a fresh `.`
description, duplicates it with `F_DUPFD_CLOEXEC`, checks its status and directory
metadata, then obtains real kernel directory entries. Both directory handles are
held through scanning. Every nonempty inode entry is checked for UTF-8 before a
matching staging prefix/suffix is considered. Matching malformed staging names
are refused; unrelated valid names remain untouched.

Cleanup checks a regular file, effective UID, exact mode 0600, one or two links,
and length at most 2,048. For two links, the named published target must have the
same device and inode. That target handle is dropped before unlinking staging.
The staging file remains held through directory fsync. Only fsync retries EINTR.

After recovery, published validation performs a separate metadata read and
requires exactly one link, a regular file, the effective UID, exact mode 0600,
and length at most 2,048. Reading is bounded to 2,049 actual bytes and retries
EINTR. The original typed JSON contract is applied, followed by request/owner
lowercase hexadecimal checks, the 1–64 lowercase/underscore tool rule, and the
request ID's filename binding. All operation-owned descriptors close before
returning a response, including on errors.

The Linux boundary uses actual `openat`, `fstat`, `geteuid`, `read`, `unlinkat`,
`fsync`, `close`, `fcntl`, and `getdents64`. It admits only the fixed action types,
slots, and spans. It interprets neither JSON nor audit identity policy. The
getdents capacity is the observed directory block size clamped to 32 KiB–1 MiB;
the Linux readdir EOF treatment for ENOENT is preserved.

## Private workspace and effect receipts

The owner requires 4 MiB of private mutable memory. The typed JSON child has
separate 1 MiB memory. The driver maps 7 MiB plus a guard page, makes each input
read-only while executing, and preserves owner state between requests.

The workspace magic is `HRARW001`. The effect descriptor at offset 256 starts
with `HRARA001`, then sequence, kind, descriptor slot, span, count, argument,
child capacity, acknowledged sequence, result, errno, and reserved zero. A
suspended call must receive the identical input, capacities, and action fields.
The acknowledged sequence must match; sequence exhaustion is rejected.

| Slot | Capability |
| --- | --- |
| 0 | Caller-held directory; never closed by the owner |
| 1 | Published record being read |
| 2 | Staging inode being cleaned |
| 3 | Fresh scan description |
| 4 | Duplicated scan stream |
| 5 | Published target used for hard-link verification |
| 6 | Deterministic probe held through cleanup |

Action kinds are 1 metadata, 2 nonblocking named open, 3 bounded record read,
5 directory sync, 8 staging unlink, 9 close, 10 fresh scan open, 11 scan duplicate,
12 scan status flags, 13 getdents, and 100 the typed JSON child call. Metadata
argument 1 omits the effective-UID report when the original operation only reads
metadata; argument 0 includes it for the original private-inode check.

The final program consists of the read-owner and typed-JSON images. The HIA
packer embeds the exact descriptor-only boundary and fixes its two call sites;
there is no dynamic linker, libc, interpreter, or hosted runtime dependency.

## Verification scope

Fresh remote qualification rebuilds the three native images with the pinned
compiler, verifies all original source blocks and all locked package contents,
and compiles the actual original Rust functions with Rust 1.95.0.

The final actual comparison covers 182 baseline cases, 503 requests and 503
per-response filesystem/descriptor observations per implementation. It includes
the full acceptance-time range, all durable states, elapsed presence/limits,
typed map and sequence forms, 2,048/2,049-byte files, identity refusals, inode
types/modes, deterministic and random recovery, wrong bindings, malformed names,
invalid UTF-8 entries, repeated calls, and a 1,802-entry scan over multiple
getdents pages.

The 53 additional real kernel cases execute 159 requests per implementation.
They inject selected EIO/EINTR, test getdents ENOENT, replace a pathname while its
old inode is held, grow a file after metadata validation, remove a staging name
before unlink, and add staging before scanning. The observer continues ordinary
operations in the kernel and does not implement filesystem semantics. Complete
responses, effects, stable inode relationships, per-response live descriptors,
and held files at each selected fault must agree.

There are also 24 rejection controls and one synthetic completion control for
buffer capacities, immutable inputs, action fields, sequence binding, and output
atomicity. These explicitly do not execute original Rust or filesystem effects.

The initial baseline passed but the first strengthened kernel comparison caught
the prematurely closed probe described above. Its source bundle, failed run,
and exact observation remain in the evidence. The final correction retains a
separate probe slot and reruns the complete baseline and kernel corpus.

Whole audit storage, result storage, production activation, public dispatch,
concurrent store locking, and removal of the old runtime remain false.

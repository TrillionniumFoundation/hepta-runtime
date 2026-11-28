# Native HIA REA file components

These Linux x86-64 components implement the original confined file admission,
bounded read, private-inode read, and eleven-field same-descriptor identity
policies. They are a qualified component boundary. Public REA method routing,
parser-worker cancellation, end-to-end installed runtime delivery, and legacy
retirement are separate gates.

## Source and construction authority

The reference is hepta-runtime commit
`abc9ecb95ee9538518ec3f36c47b881974107021`.
The original `src/mcp/rea_files.rs` is 8,671 bytes with SHA256
`a4c920dd16647f3a61cbf1f9e68b9510ae123d2d7b2a8fd6b72f13ec147f0d11`.
The four original test functions retain the exact 5,385-byte test source,
SHA256 `4eb7e89b386f493bd8feb38f9072e485abb14c8e38dc0204274c4998033b7ee1`.

| HIA source | Functions | Instructions | SHA256 |
| --- | ---: | ---: | --- |
| rea_file_policy.hepta | 10 | 419 | 93c4841f65904ba025de02ee3bb0c79fdc9f014552c2b02f204eed6a17f39a8d |
| rea_file_actor.hepta | 20 | 1233 | 24182c6e5b12c5e47b415366956cd3c36f74cd1d6c357dc95cd2617aaeb569ee |
| rea_descriptor_packer.hepta | 8 | 867 | 04764472d0557881c8740b722757c4550cb450690e7f3707fbcbb215a507146c |

Construction uses pinned Hepta
`d3e2c90173cf733e42b299d0c4274df4b593a12f`, B3 SHA256
`bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`.
The actor imports all ten already qualified policy functions through a
mechanical function-name relocation; their instructions are unchanged.
The development author asserts exact imported IR equality.

The HIA packer consumes exactly 24 bytes:
`HREAPQ01`, version u64 1, reserved u64 0.
It emits a 2,115-byte typed `HREAPK01` engine containing a 64-byte header
and 2,051 native mechanical syscall bytes. Header words are total extent,
flat extent, create offset 0, step offset 154, take offset 1744, destroy
offset 1831, and zero. The whole output SHA256 is
`04398f038a64471a5b6dad3774ba03f469c5d8a3e41a4f8191d5c60dc7a8ea68`;
the flat code SHA256 is
`14e65f19b70579d0f3d028687283209440dde7d52613385ed7038c8a8de39f2e`.

The independent development assembly is retained as a byte oracle. Actual
HIA output was compared with every independently assembled byte, every export
offset, and ELF relocation-section absence. An assembler is not required to
construct the delivered engine. `scripts/build_rea_file_component.py`
performs the complete reproducible HIA construction and validates all source,
compiler, image, and engine pins.

## Private byte ABI

All integers below are little-endian unsigned 64-bit words unless stated
otherwise. The ordinary borrowed-byte entry ABI returns u32 in the low word.

The path request starts with `HREAFPL1`, operation 1, path byte length, and
root count. Raw Unix path bytes follow. Each root is encoded by its length
word and raw bytes. The whole input must be consumed. Paths do not need to
be UTF-8.

The policy returns `HRFPLAN1`, status, error, configured-root byte length,
relative component count, and total component bytes including terminating
NULs. A successful response continues with the exact configured root spelling
plus NUL and each Normal relative component plus NUL.

Policy operation 2 consumes exactly 192 bytes: magic, operation, eleven
before words, and eleven after words. Operation 3 consumes 112 bytes:
magic, operation, effective UID, and eleven metadata words. Metadata order is
device, inode, length, mode, UID, GID, link count, mtime seconds, mtime
nanoseconds, ctime seconds, ctime nanoseconds. Access time is excluded.

The actor owns an exclusive stable workspace and output throughout its
continuation. Workspace byte offset 144 selects admission mode 0, bounded-read
mode 1, or private-read mode 2; byte offset 152 holds the maximum byte count.
All other initial state is zero. The private caller allocates at least
69,632 workspace bytes and enough output for the path plan and captured
payload. The workspace, descriptor context, slots, and pointers are never
public request values.

The actor returns `0xfffffff0` for a pending effect, `0xffffffff` for an
invalid private frame/state, and `0xfffffffe` for insufficient owned capacity.
A terminal `HRFDRS01` response has a 128-byte header: magic, status, error,
errno, eleven metadata words, and payload byte count, followed by captured
payload. The returned extent is 128 plus that count. Error responses have
a zero payload and exactly 128 bytes. Public text/JSON formatting is outside
this component ABI.

## Descriptor owner

The twelve-word action at workspace offset 256 is:

1. `HRFDAC01` magic.
2. Strictly increasing sequence.
3. Operation.
4. Owned descriptor slot.
5. Workspace span.
6. Byte length.
7. Operation argument.
8. Parent slot.
9. Acknowledged sequence.
10. Result.
11. Positive errno.
12. Reserved zero.

The last four words must initially be zero. The mechanical owner captures
the first eight words before acting and validates ownership, flags, spans,
and operation-specific arguments. It acknowledges the actual syscall result.
The actor checks the phase, sequence, operation, slot, result, and errno.

| Operation | Effect |
| ---: | --- |
| 1 | Open the exact configured absolute root into parent slot 0 |
| 2 | Open one Normal directory component into the alternate parent slot |
| 3 | Open the final component into file slot 2 |
| 4 | fstat the same file slot into the eleven-word metadata span |
| 5 | Read the real effective UID |
| 6 | pread from the same file slot without changing its stream cursor |
| 7 | Read from the same file slot |
| 8 | Close and consume an owned slot |

Root and directory flags are `0xb0000`; final-file flags are `0xa0800`.
These are the original Linux flags. The administrator-controlled root
spelling is preserved, including its original treatment of ancestor links
and dot components. Relative children are single Normal components, opened
with the held parent descriptor and NOFOLLOW. No selected child pathname is
reopened.

The new parent is acquired before the old parent is released. The first file
stat and regular-file check occur while the parent is held; the second stat
occurs after the parent is released. Bounded and private reads retain the
same file descriptor through their reads and final metadata checks.
Private checks use effective UID, single link, and permission mode 0600,
both before and after the read. The original maximum-plus-one behavior and
error ordering are retained.

`take` transfers the file descriptor exactly once, only after both parents
are released. Destruction closes the owned file before parents and releases
its temporary path and context mappings. Actual close errors are preserved.
Separate sessions have separate contexts, owned slots, and mutable memory.

## Executed qualification

- 1,961 comparisons against the original Rust Path/CString statements:
  zero differences.
- 768 metadata controls, 160 private-inode controls, 63 malformed controls,
  and 30 output-capacity controls: 2,982 policy invocations in total.
- Nineteen actual HIA emitter controls, full independent code-byte and export
  comparisons, and no ELF relocations.
- Three actual file-admission/read modes, including retained descriptor
  transfer, followed by 150 real filesystem, mutation, ownership, cancellation,
  and invalid-action/ACK controls. All 2,335 full native state records remain.
- The four unchanged original Rust test functions pass against both the
  original implementation and the HIA implementation. Native actor execution
  records contain 77 actor calls and 63 syscall effects; the original metadata
  test additionally invokes the actual HIA metadata policy.
- Original Cargo.toml, Cargo.lock, dependency features, and profiles are retained.
  The exact lock contains 362 total packages: 360 registry packages and two
  local packages. All 360 registry archives were checked against the lock;
  315 compiled registry packages and their 12,271 actual source files were
  checked byte-for-byte against those archives. The record also hashes all
  631 Cargo artifact records and 1,197 output files.
- A second actual HIA construction reproduces all three qualified images and
  the complete typed descriptor engine byte-for-byte.

The initial build observer's `full_lock_packages: 360` field referred to
registry packages; the complete provenance report records the exact 362/360
counts. The original observer report is retained unchanged.

Qualification archives preserve the initial unsupported author operation,
the u32/u64 author type failure, the readelf locale observer failure, the
missing test-folder setup failure, and the Unix socket fixture pathname
failure. The successful successors correct those concrete causes without
changing original test functions, product limits, source pins, or deadlines.
They do not claim public REA routing or whole-runtime replacement.

## Remaining product boundary

The parser workers and public REA parents must retain this descriptor
ownership through parsing, selected-byte commitment checks, cancellation,
and final same-descriptor metadata verification. The public process owner,
worker deadlines and resource limits, exact public diagnostic formatting,
and complete installed MCP tests still require their own qualification.
The Python and Rust files under development/qualification paths are
observers and original references; they are not native execution fallbacks.

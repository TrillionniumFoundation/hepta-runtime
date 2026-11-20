# Independent binary parent owner

This candidate implements the `parent(root, path)` operation and the final
`close(parent_fd)` surrounding the unchanged binary-write body. The authoritative
original is the complete `reference/binary_file.py`, SHA-256
`c15e8900b0ab867b221ff08d5a10401c8b656c87676f57b478b9a21219f7fe12`.
The existing body, its nine HIA members and process-level primitives remain
byte-identical copied inputs. This candidate does not register a public writer,
modify the runtime graph, or inherit the previous body-only 101-case result.

## Application ownership

`native/binary_parent_owner.hepta` owns UTF-8 validation, `PurePosixPath`-compatible
normalization for the frozen string domain, absolute path and ancestry decisions,
the `.hepta-` target rule, traversal order, EINTR retries, original cleanup and
error precedence. The native assembly supplies fixed Linux open/close operations,
bounded guarded buffers, the already admitted body continuation and immutable
process-orphan recording. No application packet can choose an FD, callback, code
address, syscall or effect order.

The public C-shaped exports are `binary_parent_owner_create(callback, opaque,
process_pool, entropy)`, `binary_parent_owner_invoke(context, request, length)`,
`binary_parent_owner_release(context)`, and `binary_parent_owner_destroy(context)`.
The callback is an optional read-only observer. Pool and entropy must be the
existing `HPORP001` and `HENTCI01` objects for this actual process. They are borrowed
and outlive the owner. The create operation first creates the byte-identical body
child, which checks those capabilities and their actual creator PID.

## Input and result

`HBPWQ001` is a 96-byte header followed by root, path, expected-version and base64
UTF-8 bytes. All integer words are little endian u64. Start fields are command 1
at offset 8, zero sequence at 16, mode 1 at 24, four lengths at 32–56,
expected-version-present at 64, zero words at 72 and 80, and total trailing bytes
at 88. A missing expected version has a zero present word and zero bytes. A start
contains no descriptor. Resume command 2 is private to the fixed mechanical
adapter and returns the actual kernel or fixed body response to HIA.

`HBPWR001` has a 64-byte header. Kind 0 is the complete original success JSON;
kind 3 is a complete retained nested error frame. The whole returned buffer is
borrowed until release. Kinds 1 and 2 are private fixed effect/body requests;
kinds 4 and 5 request bounded storage growth. Application code never receives a
partially finished request. Input/output remain bounded by 128 MiB and workspace
by 256 MiB; none of the existing image compiler limits are increased.

## Descriptor and exception order

The root is actually opened at `/` using `O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
O_CLOEXEC` (720896), with the original `os.open` default mode 511. Each child is
opened relative to the actual current FD. The original current FD is closed
before assignment to the child. An initial close failure leaves the original
numeric FD selected for one second cleanup close. The second error, if any,
overrides the first. The newly opened but unassigned child is recorded in the
one process orphan pool and is retired by OS exit. It is not silently closed.

After the body returns, the parent performs exactly the original outer close.
Its error overrides either a body result or a body error. A failing close does
not prove that an FD has closed; actual final FD inventories are retained.
Constructor, release and destroy do not invent application cleanup. Unresolved
ownership, second-close permission or pending-orphan state refuses destruction.

Repeated slashes and `.` normalize as `PurePosixPath` does, including the special
double-slash anchor. `..` is rejected before opening. A NUL in a parent component
fails at that component's attempted conversion point, after previous effects;
a NUL basename reaches the unchanged body. Backslashes are ordinary characters.
No blanket early NUL check substitutes for the original error/effect order.

## Frozen qualification scope

`DOMAIN.json` fixes 256 inputs: a 12 × 16 lexical product and 64 additional
filesystem, error, FD-zero, close-error, regular-file and descriptor-limit cases.
Every input runs through the complete unchanged original twice and the actual
observed native image once. All 224 inputs without kernel fault plans,
descriptor actor or descriptor-limit intervention additionally use the callback
disabled native lane. These are 992 natural-termination case runs.

Six additional resource controls run root/child permanent kernel EINTR through
the original twice and native once. The observer records eight actual -EINTR
returns, sends actual SIGTERM and proves process termination. These controls do
not claim application success or arbitrary signal equivalence. All 998 runs
share the original 1800-second whole-capture limit; ordinary exchanges remain
60 seconds, ordinary cases 180 seconds, and cleanup 5 seconds. Retry controls
have a 60-second bound. A timeout is a retained HOLD, never a smaller passing set.

The descriptor actor is explicitly a qualification-only fixed FD-table actor:
it actually closes the old descriptor before the first close, then actually
opens `/` before the second close to reuse the same numeric FD. This yields a
real first-close EBADF and real second-close success. All actor syscalls and
`HBPWAC01` records remain in evidence. No return value is replaced. Two private
ABI controls set only idle ownership flag 272 or 280, require actual destroy to
refuse, then restore that same word; whole contexts must match before/after.

The independent reader retains and checks full raw system-call records, complete
memory spans, zero acknowledgements, whole HIA input/output/workspace journals,
complete results and error chains, actual inode/version binding, file contents,
FD state and orphan records. Device/inode and time values remain raw witnesses;
cross-run comparison binds each returned version to its own complete actual
stat instead of demanding equal newly allocated inode numbers. Python and
carrier pipe FDs are distinguished from target directory ownership explicitly.

Compilation uses the exact development B3 image
`bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`, with all 1080
compiler input files checked at commit `d3e2c90173cf733e42b299d0c4274df4b593a12f`.
It compiles twelve actual HIA sources, uses the actual HIA static linker and
packer, and links ten runtime images. It does not execute a new seed or assert
a new Hepta cold bootstrap qualification.

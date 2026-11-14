# Native caller authority and private startup loader

This serial native component implements the authority decisions from original
runtime baseline a0dcdda1991ec536d5e2d252c006a778993fa566, with real Linux
x86-64 startup effects. Its integration base is
be1b871ce482fec97e65664866731c0b145e79c3. The compiler remains
d3e2c90173cf733e42b299d0c4274df4b593a12f. Earlier base fields in the fixed
profile and provenance record historical authoring origin and remain unchanged.

This is an internal qualification executable. It does not replace the HTTP
listener, concurrent sessions, the full MCP server or metadata annotation.

## Source and authority ownership

caller_authority.hepta owns credential hashing, the fixed 32-byte digest
comparison, HTTP/stdio authority selection, first-call owner binding and private
crypto selection. authority_loader.hepta owns private-file admission and
ordered read/stat/error decisions. authority_packer.hepta emits the static ELF
and its fixed syscall adapter. Python builds and qualifies the images; it is
absent from the executable.

The token pathname comes from the administrator's original argv bytes. The
adapter preserves it in a separate read-only configuration region. Loader slot
8 is admitted only from root 0 during trusted startup, at depth 1, with that
exact pathname. Ordinary frames cannot select a new path, reload the token,
reinitialize the session or create an authenticated owner. Serialized owner
hashes and authenticated fields confer no authority.

Successful middleware verification permits use of private credential scope
state. The original non-serialized extension is represented by private native
state and protected lifecycle entry points. This serial representation does not
implement concurrent axum extensions, Arc reference lifetimes or mutex poison
semantics. HTTP without the trusted extension never falls back to stdio.

The first admitted tool resolution freezes the session owner; later resolutions
must match. A private controller fixture separately tests trusted reconnection:
global credential scope/nonce state persists and per-session state is replaced.
Ordinary input cannot invoke that lifecycle event. The emitted CLI exposes a
single session.

## Exact image profile

Every image has the actual HIA ABI
f0(readbuf, mutbuf, mutbuf) -> u32. The composition imposes these additional
fixed capacities and child capabilities:

| ID | Owner | Flags | Child mask | Input | Output | Workspace |
|---:|---|---:|---:|---:|---:|---:|
| 0 | caller authority | 1 | 456 | 8388608 | 8388608 | 16777216 |
| 1 | operation record | 1 | 28 | 8388608 | 2097152 | 3145728 |
| 2 | KDF | 0 | 0 | 8388608 | 128 | 2048 |
| 3 | binary codec | 0 | 0 | 8388608 | 128 | 1184 |
| 4 | AEAD | 0 | 0 | 8388608 | 1048640 | 512 |
| 5 | nonce owner | 0 | 0 | 164 | 64 | 1576960 |
| 6 | operation scope | 1 | 166 | 8388608 | 2097152 | 3145728 |
| 7 | SystemEntropy | 4 | 0 | 24 | 128 | 1024 |
| 8 | authority loader | 8 | 0 | 131095 | 4096 | 262144 |

Sizes are bytes. The packer checks the exact sources and actual image bytes
pinned in authority_profile.json. Flag 8 is legal only for slot 8 in this exact
nine-image table. Entropy slot 7 admits scope 6, plus root 0 during trusted
startup only. Root mask 456 selects precisely modules 3, 6, 7 and 8.

Codec output capacity 128 permits incremental SHA state across the 1 MiB chunk
boundary. The older eight-image OS-scope profile retains capacity 32 and its
existing source/image. Supplying the old capacity to this packer is a tested
refusal.

The bridge checks child identity, exact-u32 results, continuation sequence,
active recursion/depth, disjoint spans and buffer bounds. External frames never
contain native addresses. A 256-byte footer carries the protected continuation
and lifecycle fields; caller input cannot write those fields.

## Private token and owner loader

Input is HRLOAD01, little-endian u64 operation, zero reserved u64, and tail
bytes. Operation 1 receives the original startup pathname, at most 131071
non-NUL bytes, once in HTTP-token startup. Operation 2 has no tail and gets the
independent 32-byte stdio owner seed from fixed /dev/urandom.

Token operation order matches the original owner:

1. Open read-only with O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, target flags 0xa0800.
2. Obtain initial descriptor metadata. Require regular file, effective-account
   ownership, exact 0600 including special permission bits, and one link.
   geteuid follows regular-file admission.
3. Read until EOF or the original take(4098) bound, handling short reads.
4. Obtain final descriptor metadata and check the original uid, mode, nlink,
   length, mtime and ctime conditions, including nanoseconds.
5. Remove at most one LF. Require 32..4096 bytes, each ASCII 33..126.
6. Retire the private descriptor slot before close.

Final symlinks are refused; parent symlinks follow the original behavior. There
is no pathname reopen or added inode/device/gid fence. Descriptor mutation and
pathname replacement remain different cases. Open/read EINTR retries preserve
the original contract; metadata errors propagate. Original Drop-close failures
do not replace the earlier result. No new wall-clock timeout is added.

Owner operation 2 preserves original File::open("/dev/urandom"),
read_exact(32) and Drop-close behavior, using flags 0x80000. This is distinct
from the crypto SystemEntropy implementation.

The loader's ten-u64 effect record begins at workspace byte 256:
HIALOD01, sequence, span offset, span length, reserved, action, result, errno,
acknowledged sequence and done. Pending return is 0xfffffff0. Actions are
1 token open, 2 effective uid, 3 initial stat, 4 read, 5 final stat, 6 close and
7 fixed owner-device open. Stat spans are 144 bytes on this Linux ABI. The
adapter validates actions and registered workspace spans; it makes no
file-admission decision.

The module returns a produced length or a refusal. The isolated probe emits
u32 result followed by owned fixture bytes. Production never publishes loader
bytes.

| Result | Meaning |
|---|---|
| 0xffffffff | Invalid typed input |
| 0xfffffffe | Output/workspace capacity |
| 0xfffffffd | Private token unavailable |
| 0xfffffffc | Private-file admission failed |
| 0xfffffffb | Token changed while reading |
| 0xfffffffa | Token format refused |
| 0xfffffff9 | Independent owner entropy unavailable |
| 0xfffffff6 | Loader lifecycle refused |
| 0xffffd000 OR errno | Descriptor metadata/read error |
| 0xffffffe8 | Fatal state or continuation |

## Credential and entropy order

HTTP-token startup reads the credential and initializes the credential-derived
global scope. Its owner hash uses the original domain
hepta-runtime/private-operator-credential/v1\0 followed by the token.
Request middleware hashes the complete candidate header and compares all 32
digest bytes without a first-difference exit. This is not a claim of complete
constant-time or compiler stack-erasure qualification.

In authenticated HTTP mode, Origin presence yields the 403 domain result before
candidate-token processing. Missing or incorrect token yields 401. Header names
are case-insensitive; selection follows original HeaderMap::get behavior.

Original server creation also attempts the independent random stdio owner and
then four ordered 32-byte crypto fills, even when HTTP never selects stdio
crypto. A separate private 128-byte region represents that unused HTTP object.
Failure clears partial crypto bytes and records absence without overwriting
global credential scope. Owner failure does not suppress crypto initialization,
and crypto failure does not fabricate an owner.

The direct controller fixture deliberately replaces slot 7 with the frozen
deterministic entropy image and records all nine actual loaded identities.
The actual composed ELF uses OS entropy. Its supervised startup, failure and
fallback processes provide separate evidence.

## Qualification CLI and wire

    native-authority.elf --authority-http-token PATH
    native-authority.elf --authority-stdio
    native-authority.elf --authority-http-optional

--authority-http-required without a token exercises missing required credential
refusal. It never constructs an unauthenticated HTTP authority.

Each stdin line contains lower-case hexadecimal for HRAUTR01, then three
little-endian u64 words: operation, header count and payload length. Each header
contains u64 name/value lengths followed by those bytes; payload follows all
headers. The line bound is 8 MiB, hence 4 MiB decoded. This typed qualification
transport is not an HTTP parser or a registered MCP tool.

| Operation | Success payload |
|---:|---|
| 0 | Empty: middleware admission only |
| 1 | One byte: 0 stdio or 1 authenticated credential |
| 2 | Original request binding: 64 lowercase ASCII hex bytes |

Binding input retains the original nonempty, at-most-1-MiB domain. Candidate
header hashing is incremental over every admitted byte, with no chunk-prefix
substitution.

Controller output is hex for a little-endian u32 semantic status and payload.
Its HIA entry returns output length; the adapter appends LF. EOF processes a
final unterminated line. Malformed frames refuse and permit later frames;
oversized lines fail closed.

Semantic statuses include forbidden 0xffffffdf, unauthorized 0xffffffde,
missing verified extension 0xffffffdd, owner entropy unavailable 0xffffffdc,
changed authority 0xffffffdb, unavailable crypto 0xffffffda, binding input
0xffffffd9, and required credential 0xffffffed. CLI exits are 64 bad argv,
2 startup/domain/oversized input, 3 response capacity, and 74 transport I/O.

The ELF has no dynamic interpreter, libc/Python dependency or RWX segment.
Exit retires private descriptors and clears all nine workspaces and transport
buffers. The 17 supervised processes inspect 41689784 cleanup bytes each.
Read-only configuration holds a pathname, not credential bytes.

## Qualification and unported owners

Five mandatory suites have 8, 5, 6, 4 and 7 groups respectively. All require exact
counts and zero failures, errors, skips, expected failures and unexpected
successes. The actual original recipe compiles complete unchanged caller/crypto
modules and exact main authentication/owner-generation segments, then executes
the original axum middleware and rmcp context owners.

Historical captures do not substitute for new aggregate Rust execution. Missing
owners include HTTP socket/transport integration, concurrency and Arc/mutex
lifetimes, metadata annotate/annotate_search_effect, full MCP dispatch and
other still-unported runtime owners. Production activation, old-stack removal,
complete runtime replacement and concurrent HTTP qualification remain false.

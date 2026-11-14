# Native local file-info controller

`file_info_service.hepta` is the HIA continuation owner for the explicit
`native-local` profile's `file_info` tool. It exports
`f0(readbuf input, mutbuf output, mutbuf workspace) -> u32`; input and output
are bounded at 8 MiB and its private workspace is 32 MiB. The fixed composition
places it at module 6, callable by module 0, with child permissions for the
policy, codec, IO and stat-version images at IDs 1 through 4.

The first nested invocation receives the unchanged administrator root from
immutable bridge region 3. A valid UTF-8, NUL-free, absolute root of 1..4095
bytes is retained; successful initialization returns zero. Later invocations
receive the entire unchanged MCP request and return a complete JSON-RPC
response. All nested entries have bridge invocation kind 3. The retained state
distinguishes initialization from later requests. Only module 0 initializes
and closes the shared IO owner.

## Parameters and ordering

The tool accepts exactly `host: string` and `path: string`. Both are required;
nulls and unknown fields refuse typed admission with JSON-RPC `-32602`.
Configured host lookup follows complete parameter decoding. Only the immutable
`native-local` host exists in this profile. The original native policy owner
then checks the decoded path against its administrator root. This controller
does not accept a root, target, interpreter or command in tool arguments.

The local path domain is valid UTF-8 of at most 4096 bytes. The controller
performs that byte bound after host lookup to admit its fixed child buffer;
original `FileInfoParams` has no such byte bound. The descriptor IO owner
normalizes dot and repeated-slash components consistently with its declared
ordinary-read profile and refuses NUL, traversal, symlinks, special files,
the capability root itself and reserved final names. Ordinary hard links and
special permission bits remain readable, as in the original info helper.

## Child sequence and retained spans

The `HIACAL01` footer and acknowledgement rules are the same as the local
service bridge. Every continuation validates magic, monotonically increasing
sequence, completed sequence, completed flag and zero bridge status before
accepting a child result.

| Stage | Child | Operation |
|---|---|---|
| 1 | Policy, ID 1 | Original configured read-path check, operation 6 |
| 2 | IO, ID 3 | Complete fingerprint and metadata capture, operation 3 |
| 3 | Stat version, ID 4 | Exact original five-field version formatting |

The decoded JSON arena ends before workspace offset 25165824. Child input is
workspace `[25165824, 25296896)`, child output `[25296896, 25427968)`, and the
retained complete IO response `[25427968, 25559040)`. Version text uses at most
122 bytes at 25583616. The root is retained at 26214400. The final 4096 bytes
hold private state and the bridge footer; 256 checked record pointers occupy
private offsets 1024..3071. None of these spans overlaps a live decoded node.

## IO operation 3

The request is the existing 112-byte `HIARD001` header followed by exact path
bytes. Its request ID is bound to the controller continuation. Operation is 3;
offset, limit, expected-version flag and all seven expected-version words are
zero. The IO owner carries administrator root custody independently.

The response starts with the 128-byte `HIARR001` header. On success, the original
fingerprint's seven stat words occupy bytes 64..119 and its POSIX mode occupies
120..127. Header field 32 is the exact payload length; fields 40, 48 and 56 are
zero. Errors retain the 128-byte header with no metadata payload.

The success payload starts at response byte 128:

| Payload offset | Value |
|---|---|
| 0 | ASCII `HIAINF01` |
| 8, 16, 24, 32 | Capture UID, GID, mode and link count, little-endian u64 |
| 40 | Attribute count, 0..256 |
| 48, 56 | Reserved zero |
| 64..95 | Raw 32-byte complete-file SHA256 |
| 96..127 | Raw 32-byte Linux ACL SHA256 |
| 128 onward | Sorted attribute records |

Each record contains little-endian u64 name length, the exact name bytes, then
the raw 32-byte value SHA256. Names must contain 1..255 valid UTF-8 bytes with
no NUL, in strictly increasing byte order. UTF-8 byte ordering agrees with
Unicode scalar ordering for valid strings. Record boundaries and the entire
payload extent must close exactly. Mode values are at most 07777; UID and GID
fit unsigned 32-bit words. Raw xattr values never enter the controller output.

The controller validates and retains the complete response before calling the
stat-version formatter, so that child scratch reuse cannot corrupt metadata.
It emits lowercase hexadecimal digests and the exact compact original key
order. Top-level mode and metadata mode remain separate observations. The
original string result is one MCP text item with `isError: false`; local tool
refusals use the corresponding text error envelope. Partial response bytes
are never published on capacity or continuation failure.

The controller handles the IO owner's declared operation-3 domain statuses:

| Status | Meaning |
|---|---|
| 1, 2 | Invalid/reserved target or target outside the admitted root |
| 3, 4 | Open failure with errno, or non-regular target |
| 7, 8, 9 | Fingerprint version changed, stat/read failure, or close failure |
| 13 | Reopened descriptor version differs from the fingerprint |
| 14 | An xattr name is outside the valid Unicode scalar domain |
| 15 | Inspection deadline expired |
| 16, 17 | Attribute syscall failed, or metadata count/value budget exceeded |
| 18 | Capture's final version differs from capture's first version |
| 19 | Deadline/clock setup failed |

Errno-bearing native messages are explicitly local diagnostics. Original
domain messages are preserved for hashing changes, metadata inspection
changes, metadata budgets and capture changes. Malformed IO-contract status
10 and statuses unreachable for this fixed operation refuse the continuation.
An error frame must have extent 128 and zero payload/metadata fields; a success
frame must have errno zero. The capture-first stat is compared only with
capture-final, preserving the original gap after the separate reopened
descriptor/fingerprint comparison.

## Reference and scope

Original source identities are pinned to runtime commit
`a0dcdda1991ec536d5e2d252c006a778993fa566`. The semantic source is `info()` in
`binary.rs`, `main(op=info)` and `fingerprint()` in `binary_file.py`, and capture
and summary functions in `file_metadata.py`. Parser reuse is checked by exact
assembled function-graph comparison after call relocation.

`test_file_info_controller.py` uses real HIA policy/stat images and explicitly
synthetic IO completion frames to test admission, continuation and formatting.
These are not filesystem observations. The separate `test_info_service.py`
must run the actual static ELF and compare exact result text against the
unchanged original helpers on the same owned temporary files. The composition
continues to declare its local-root profile, root-inode lifetime and local OS
diagnostics separately from original SSH transport behavior. This owner does
not establish complete runtime migration or remote-host parity.

The direct controller suite uses `HIA_FILE_INFO_MANIFEST`,
`HIA_POLICY_MANIFEST`, `HIA_STAT_VERSION_MANIFEST` and `HIA_HEPTA_DIR`.
`HIA_INFO_SERVICE_SOURCE` may select an isolated development source; the final
repository default is `native/file_info_service.hepta`. Optional
`HIA_FILE_INFO_RESULT` records the admitted source and image hashes, observed
counts and explicit fixture scope. The actual ELF suite consumes the common
`HIA_SERVICE_MANIFEST` and records optional `HIA_INFO_SERVICE_RESULT`.

# Bounded multi-file body HIA ABI

This is the private body corresponding to the exact target's multi_read_host.py,
not a registered public route or permission to read arbitrary local paths.
The original Rust operator-host validation, per-path Remote policy, SSH transport
and 30-second transport deadline remain separate required composition gates.

## Packet and result

All integer fields are little-endian u64. f0 has (readbuf, mutbuf, mutbuf) -> u32.
HMRDQ001 is 96 bytes: command at 8 (1 start, 2 actual effect/child reply), sequence
at 16, start presence flags at 24 (bit 0 max_file_bytes, bit 1 max_response_bytes),
file count at 32, optional file limit at 40, optional response limit at 48,
zero 56 through 80, total payload bytes at 88. Every start payload entry is
root-byte-length, path-byte-length, root UTF-8 bytes, path UTF-8 bytes. Missing
limits use exactly 16,384 and 65,536. An absent limit's numeric field is zero.
Count outside 1..16 and invalid numeric limits produce the original bounded
request ValueError before any entry access. Valid-count entries require complete
bounded framing and valid Unicode; malformed private packets return INVALID.

Reply command has current sequence at 16, actual signed result at 24, all
32..80 zero, actual reply bytes after 96. An outstanding reply is accepted once;
capacity continuation accepts only the same complete reply bytes/result/sequence.
Framing errors return ffffffff; output under 64 bytes returns fffffffe.
Before start mutation, the controller requests complete workspace and at least
8,352 output bytes. Workspace is 4,096 + input payload length + 1,048,576.
Output-capacity requests are kind 5; workspace requests are kind 4 with needed
extent at 32. Both have HMRDS001/64-byte headers.

HMRDS001 has kind at 8, sequence at 16, op at 24, args at 32/40/48 and payload
length at 56. Returned u32 is 64: actual complete output extent is 64+length.
Kind 0 completes with exact compact sorted result JSON. Kind 3 completes with
an entire HBRDS001 structured exception or HUTFD001 UTF-8 diagnostic frame.
No partial file contents form an error response.

## Fixed capabilities

Kind 1 requests OS actions: op 1 readonly nofollow/nonblock/cloexec openat
(parent FD at 32, nul-terminated basename payload), op 2 fstat (owned FD at 32),
op 3 close (owned FD), op 4 ORPHAN_OWNED (owned FD), op 5 raw read (owned FD at
32, maximum byte count at 40). No caller-selected flags or addresses exist.
OS errors are raw negative errno, no payload; fstat success is the complete
144-byte Linux stat; raw read success has exactly its returned bytes.

Kind 2 fixed children: op 1 binary_codec, op 2 stat_version, op 3 parent acquire
(parent slot 0 or 1 at 32), op 4 parent close (slot at 32), op 5 UTF8 diagnostic.
All child output bytes are returned unchanged to HIA. There are two contexts
of the same unchanged parent_directory image. Acquired parents remain held until
the HIA controller explicitly closes that slot; neither parent is duplicated.
The second parent rewalks the original complete root/path while the first remains
open. Their error responses are copied before child release.

The regular() helper's first non-EINTR fstat failure transfers the actual opened
FD to the shared c811 process-orphan pool, then retires its operable owner token.
Both source and confirmation regular() roles follow this rule. Other errors and
all normal cleanup close the relevant descriptors in the original nested-finally
order: confirmation file, confirmation parent, source file, source parent.
A later close error overrides an earlier error exactly at its original position.
The pool is shared by all contexts and never closes orphans at release/EOF/destroy.

## Result and budget

HIA validates all entry paths before opening the first file. Per file it retains
the two regular checks and three explicit fstats, bounded raw-read loop, strict
UTF-8 decode, actual independent parent rewalk, identity verification, digest,
JSON escaping and complete nested MCP serialized byte budget in original order.
The fixed result region holds a previously accepted prefix plus the maximum next
file, including sixfold JSON escaping. There is no cross-file atomic snapshot.
This source-author package makes no application or public qualification claim.

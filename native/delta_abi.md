# Native line delta owner

`delta.hepta` implements the deterministic line-diff owner from the original runtime: `diff_lines`, its `backtrack`, `render_delta`, `removed_marker`, and CRLF normalization. It also exposes the exact `str::lines()` split used by the original whole-file view path. The compiled image executes HIA integer and buffer operations; its standalone Linux x86-64 filter uses the repository's fixed syscall transport.

This component does not own file access, path authorization, file locks, per-session cache entries, cache invalidation, or MCP routing. Those callers still need migration. A semantic `None` result from the diff must remain distinct from insufficient native memory. `render_whole_file`'s full-file fallback and its unchanged/empty-file messages belong to that caller and are not synthesized here.

## Original source identity

The source owner is [src/mcp/fs/delta.rs at a0dcdda1991ec536d5e2d252c006a778993fa566](https://github.com/TrillionniumFoundation/hepta-runtime/blob/a0dcdda1991ec536d5e2d252c006a778993fa566/src/mcp/fs/delta.rs). Its SHA-256 is `a21e86bc959ce79f35cb7695e908fa37d5fd5fb56e00673ecf4a8cd291c080e1`.

Line IDs preserve [src/utils/line_hash.rs at the same commit](https://github.com/TrillionniumFoundation/hepta-runtime/blob/a0dcdda1991ec536d5e2d252c006a778993fa566/src/utils/line_hash.rs), SHA-256 `904bc9a70e1ade3802213cd067ab7b75bce4dd075e4ab4965f32e9964293ba57`. The hash is the original FNV-1a 32-bit recurrence over UTF-8 bytes, XOR-folded to 8 bits and rendered as two lower-case hexadecimal characters. The composite ID is `N:hh`.

The retained Rust oracle contains the unchanged original function bodies, enum, and line-ID helpers under their original Apache-2.0 notice. The test verifies that the checked-in oracle matches an extraction from the original repository source before it exports a native comparison corpus.

## Function ABI

The first function is `f0(readbuf, mutbuf, mutbuf) -> u32`. The input, output and workspace are three borrowed byte buffers represented as pointer/length pairs by the Linux x86-64 ABI. No raw pointers, file descriptors, or host objects appear in the data frame.

The return value is the number of output bytes, including zero where the operation permits empty output. `0xffffffff` means invalid input. `0xfffffffe` means insufficient output or workspace capacity. The output remains unchanged on either refusal. Workspace contents are scratch state; callers may reuse a workspace between requests.

The native profile accepts at most 8 MiB input, with up to 8 MiB output and 32 MiB workspace supplied by the standard filter. Smaller caller-provided buffers are supported when sufficient for the actual operation.

## Input frame

All numbers are unsigned 64-bit little-endian words. The header is exactly 64 bytes.

| Byte offset | Field | Meaning |
| --- | --- | --- |
| 0 | Magic | Eight literal bytes `HRTDLT01` |
| 8 | Operation | One of 1 through 5 |
| 16 | `a` | Operation-specific argument |
| 24 | `b` | Operation-specific argument |
| 32 | `n` | Number of old/input strings |
| 40 | `m` | Number of new strings |
| 48 | Reserved | Must be zero |
| 56 | Reserved | Must be zero |

The header is followed by `n + m` string records: first all old/input strings, then all new strings. Each record is its UTF-8 byte length as one little-endian word, followed by exactly those bytes. Empty strings are permitted. Every record must be valid UTF-8. No trailing bytes are permitted.

## Operations and results

| Operation | Arguments and input | Output |
| --- | --- | --- |
| 1: `diff_lines` | `a = max_d`, `b = 0`; arbitrary old/new line arrays | `found` word. If zero, no further bytes. If one, an operation-count word and that many 24-byte operation records. |
| 2: `render_delta` | `a = b = 0`; arbitrary old/new line arrays | `found` word. If zero, no further bytes. If one, the exact original UTF-8 delta text follows. |
| 3: `removed_marker` | `a = first`, `b = last`, zero-based inclusive indices into old lines; `m = 0`; require `first <= last < n` | Exact UTF-8 removal marker, without a status prefix. |
| 4: `normalize` | `a = b = 0`, `n = 1`, `m = 0`; one complete text string | Exact text with each `CR LF` pair replaced by `LF`. |
| 5: `lines` | `a = b = 0`, `n = 1`, `m = 0`; one complete text string | A line-count word followed by length-prefixed UTF-8 line records. |

An operation-1 record contains three words: `kind`, `old_index`, `new_index`.

| Kind | Meaning | Indices |
| --- | --- | --- |
| 0 | Equal | Both old and new zero-based indices |
| 1 | Delete | Old index; unused new index is `0xffffffffffffffff` |
| 2 | Insert | Unused old index is `0xffffffffffffffff`; new index |

The operation list is in forward traversal order. For example, diffing `['a']` against `['b']` with bound 2 returns `Delete(0)` followed by `Insert(0)`. With bound 1 it returns the eight-byte zero `found` word. Returning `None` preserves the original distance-bound decision, including bound 0; it is not used for memory refusal.

The renderer uses the original distance ceiling of 500, two operations of context on each side, original hunk merging when context ranges touch, fresh IDs for equal/inserted lines, and grouped old-ID ranges for consecutive deletions. It emits no terminal newline. The unchanged array case produces the original zero-hunk header; the session cache caller decides whether to instead produce its separate unchanged-file message.

Line arrays are already split inputs. Their strings may contain embedded LF, CR, NUL, or other valid Unicode; the diff compares and hashes their exact bytes. Operation 5 performs Rust's line splitting: LF terminates a line, a preceding CR is removed, and a final LF does not add a trailing empty line. A final lone CR remains. Unicode line separators such as U+2028 are ordinary content, as in `str::lines()`.

## Memory and algorithm fidelity

The implementation preserves the original Myers frontier traversal, strict `<` tie comparison, snapshot before each edit depth, and reverse backtracking decisions. It emits the reversed backtracking buffer in forward order. It does not substitute a heuristic or a different shortest-edit-script ordering.

Let `T = n + m`, `D = min(max_d, T)`, and `V = 8 * (2 * D + 3)`. Rendering fixes `max_d = 500`. The input string table occupies `16 * T` bytes after a 256-byte control region. Operations reserve `24 * T` bytes. Rendering reserves `16 * D` bytes for hunks. The current frontier uses `V` bytes. A full `V`-byte snapshot is added only for each depth actually visited.

At depth `d`, diff workspace demand is therefore `256 + 40*T + (d+2)*V`; rendering adds `16*D`. Capacity is checked before each frontier snapshot. This preserves the original lazy trace growth while returning a finite capacity refusal instead of writing past the caller's buffers. Output rendering uses a count pass followed by a write pass, so an output shortage cannot expose a partial result.

## Verification and reuse

`tests/hia_native/test_delta.py` accepts `HIA_DELTA_MANIFEST`, `HIA_HEPTA_DIR`, and `HIA_DELTA_CORPUS_DIR`, with command-line overrides for the source, loader, repository, and manifest. The corpus environment variable causes it to export the actual tested native request/output pairs and `native-corpus.json`. `tests/hia_native/oracle_delta.rs` reads hexadecimal requests from stdin and writes `OK ` followed by hexadecimal output per line; it takes no arguments.

The native corpus contains 9,101 valid cases. It includes every pair of binary-alphabet line sequences through length four at several bounds, repeated-line tie cases, independent LCS dynamic-programming checks of minimum edit distance, Unicode and embedded delimiters, hunk merging, and distances 499/500/501. The suite also checks 90 malformed records, four capacity refusals, exact capacity, semantic `None`, five HIA VM cases, and three standalone ELF invocations with an unusable `PATH`.

The original Rust oracle was actually compiled with `rustc 1.95.0`, `--edition=2021 -O -C overflow-checks=off`, then run against the same 9,101 native requests. All outputs matched byte-for-byte. Source, requests, and native output hashes were checked before and after the run. The observed job succeeded with exit code 0, complete output, and confirmed terminal publication. Detailed identities are retained in `delta_original_rust_comparison.json`.

| Artifact | SHA-256 |
| --- | --- |
| HIA source | `433e4f389a59fa05b4cf7f18df9f730a5a02b8049517b281b56ac520246e25f3` |
| Native image | `a5bb83531e1661737d3645f7cb0ec874070658b2f780e165b2cd711f37870423` |
| Rust oracle source | `ad9ee4e6caef683206fd9c44d8e79f03f86bc27d951ccac9b6502a7b897a7d32` |
| Requests | `0862c69da84cb8433b06ce5cf92d4a234996c73db24922176a6422c80115e45a` |
| Native and Rust outputs | `76d5f6a9c50ee13d1735020a5802a70501966b85d2a20fa252aeec61e90e074b` |

These are component-parity results under the pinned development compiler fixed point. They do not establish completion of the production runtime migration or replace the compiler's full cold qualification gate.

# Native shell admission and stash detection

`shell_gate.hepta` implements the deterministic shell admission and stash
classification from `src/mcp/fs/shell.rs` at runtime baseline
`5b54cdf879b157b997cbff89f2847bd9044cf4a3`. Its semantic implementation is HIA
`hepta.hia.program.v8`, compiled with the repository's pinned Hepta compiler
`d3e2c90173cf733e42b299d0c4274df4b593a12f`. It uses byte buffer operations and
does not require HIA v9 word operations.

The original Rust functions remain independent comparison inputs. This
component does not launch a shell, check authority, install a dispatcher,
own a process group, or replace the production `shell` handler. Component
qualification alone does not qualify any of those effects or removal of the
existing runtime.

## Borrowed buffers and return value

The entry is `f0(readbuf input, mutbuf output, mutbuf workspace) -> u32`.
The caller supplies valid, nonoverlapping input, output and workspace borrows.
There are no host callbacks, external function imports or retained state
between calls. The input remains unchanged.

All integer fields are unsigned 64-bit little-endian values. A successful
return is the exact number of output bytes written; there is no terminating
NUL. Bytes beyond that extent retain their previous values.

| Return | Meaning |
| --- | --- |
| `0x00000008` through `0xfffffffd` | Successful output extent |
| `0xfffffffe` | Insufficient output/workspace capacity, or an output extent that cannot be represented without colliding with a reserved return |
| `0xffffffff` | Invalid request frame, operation, presence flag or command UTF-8 |

Both refusal returns leave **every output byte unchanged**. Workspace bytes
are private scratch and may change on a capacity refusal reached after frame
admission. Malformed requests are rejected before workspace mutation.

## Request

| Offset | Field |
| --- | --- |
| 0 | Eight literal bytes `HSHGATE1` |
| 8 | Operation, 1 through 6 |
| 16 | Workdir present: 0 or 1 |
| 24 | Command byte length `C` |
| 32 | Workdir byte length `D` |
| 40 | Exactly `C` command bytes |
| `40 + C` | Exactly `D` workdir bytes |

The frame length must be exactly `40 + C + D`, checked with subtraction before
addition. A missing workdir requires `D = 0`. A present empty workdir is valid
and differs from a missing workdir. Workdir fields retain the same frame
validation rules for operations which do not consult them.

The command must be a complete valid UTF-8 string, including embedded NUL when
present. The workdir is a **Unix `OsStr` byte sequence**, not a UTF-8 string;
non-UTF-8 bytes and NUL are retained. The original path operation is lexical
and performs no filesystem call. Rejecting those workdir bytes would narrow
the original Rust domain.

There is no semantic total-command-length threshold. The caller's actual
buffers and execution budget bound transport and execution. Output capacity
refusals and workspace capacity refusals are not shell-admission decisions.

## Operations

| Operation | Original behavior | Output |
| --- | --- | --- |
| 1 | `detect_shell_misuse(command, workdir)` | One tag word, then the complete original message bytes |
| 2 | `stashes_changes(command)` | One word: 0 for false, 1 for true |
| 3 | `split_shell_segments(command)` | Count word followed by `(start, end)` word pairs |
| 4 | `shell_token_spans(command)` | Count word followed by `(start, end)` word pairs |
| 5 | `redirect_targets(command)` | Count word followed by `(start, end)` word pairs |
| 6 | `ssh_remote_command(command)` | Presence word; when present, one `(start, end)` word pair follows |

Operation 1 tags are 0 for `None`, 1 for `Reject`, and 2 for `Hint`. Tag 0 has
exactly eight output bytes. Tags 1 and 2 append the original UTF-8 message
without an additional length field, escaping, newline or NUL. The entry return
supplies its extent. A later rejection supersedes an earlier hint; when no
rejection occurs, the first hint in original traversal order is retained.

Operations 3 through 6 expose the original helper's returned slices for exact
comparison. Every offset is a byte offset **relative to the command**, with an
exclusive end. Empty segments and empty redirect targets remain observable.
Operation 6 returns eight bytes for `None` and 24 bytes for `Some`, including
`Some("")`. Helper operations are literal calls to those helper semantics;
operation 6 does not first verify that the command's first program is `ssh`.

The list operations count the complete result before writing any output. They
then repeat the same scan over immutable input to emit spans. They do not
return a truncated list when the output buffer is short.

## Workspace and recursive SSH bodies

Every operation requires at least 128 workspace bytes. Operations 2 through 6
need no additional workspace. Operation 1 uses an explicit stack in the
remaining workspace: each currently active nested SSH command requires
another 32 bytes, in addition to the root's 128-byte scratch area.

For maximum encountered remote nesting depth `N`, `128 + 32*N` bytes are
sufficient. There is no fixed nesting-count cutoff and no recursive native
function call for remote bodies. A short workspace returns `0xfffffffe`; it
does not turn the remaining remote command into an allowed command. Each frame
retains the parent scan cursor, end, loop depth and end-of-segments state.
Only the root uses the caller's workdir; remote bodies use the original `None`
workdir behavior. A new call reinitializes all state it relies on, regardless
of previous scratch contents.

| Workspace offset | Private use |
| --- | --- |
| 0, 8 | Iterator cursor and final-segment flag |
| 16, 24 | Current token or path component endpoints |
| 56, 64 | Selected remote-body endpoints |
| 80, 88 | Program bytes for the selected result |
| 96, 104, 112 | First-hint flag and program endpoints |
| 128 onward | Active parent frames, 32 bytes each |

These offsets document the implementation; callers must not treat prior
workspace contents as authority or an externally resumable protocol.

## Preserved distinctions

The implementation follows the existing helper behavior, including its
different parsing rules:

- Program extraction, segment trimming, `sed` option splitting and redirect
  target termination use Rust character whitespace. The Unicode White_Space
  set is explicitly implemented, including vertical tab, NEL and nonbreaking
  spaces.
- Shell token spans use Rust `u8::is_ascii_whitespace`: tab, LF, form feed,
  CR and space. Vertical tab and Unicode whitespace remain token bytes here.
- Segment splitting preserves quote and backslash rules and splits unquoted
  `;`, LF, `&&`, `||`, `$(` and backticks. A single pipe remains inside its
  segment, so a later pipeline stage retains its existing treatment.
- Misuse program extraction removes leading `(` and trailing `)` from each
  whitespace token. SSH and stash token selection remove leading `(` only.
  Environment assignments, the exact `{` token and path basenames keep their
  original handling.
- Redirect parsing skips only literal ASCII spaces after `>` or `>>`.
  Descriptor duplication is excluded. Target termination, quote trimming and
  the treatment of empty targets retain the original order.
- Absolute redirect paths are compared against workdir using Unix components:
  repeated separators and interior `.` components normalize, while `..`
  remains a component. The implementation never resolves symlinks or changes
  `..` into a parent-directory traversal. An empty workdir is a prefix of
  every path; a nonempty relative workdir is not a prefix of an absolute
  target.
- The `do`/`done` counter and sleep exemption are local to each recursive
  command. `do sleep` keeps the original segment-level treatment.
- SSH option clusters consume the next token only under the original
  ASCII-letter and final-argument-option rule. The remote body is cut at the
  first unquoted local pipe and loses at most one whole-string quote layer.
- Git global `-C`/`-c` argument consumption and the first stash subcommand
  retain their exact original token tests. The implementation does not
  interpret additional shell or Git syntax.

All seven fixed rejection-hint strings and the blocked-command prefix are
stored as their original UTF-8 bytes. The scratch-redirect hint uses the
original selected program spelling.

## Source reading map

| HIA function | Responsibility |
| --- | --- |
| `f0` | Complete frame validation, operation dispatch and publication boundary |
| `f1` | Ordered gate evaluation with explicit SSH parent frames |
| `f2` | One segment's original admission order |
| `f3` | Complete original result-message construction |
| `f4`–`f7` | Program extraction, first shell token, basename and byte search |
| `f8`–`f11` | Redirect decisions and Unix component prefix comparison |
| `f12` | Original `sed` in-place option detection |
| `f13`–`f14` | Whole-command and segment stash classification |
| `f15`–`f17` | SSH body, option argument rule and unquoted local pipe |
| `f18`–`f21` | Segment, token and redirect iterators |
| `f22` | Complete helper-span counting and publication |
| `f23`–`f28` | Unicode token/trim/width/whitespace and ASCII whitespace |
| `f29`–`f59` | Exact keyword comparisons |
| `f60`–`f61` | Fixed message byte extents and byte publication |
| `f62` | Complete UTF-8 validation |
| `f63`–`f65` | Little-endian word reads/writes using byte operations |

`f62`–`f65` are exact relocated copies of `f2`, `f14`, `f15` and `f16` in
`native/text_budget.hepta` (SHA-256
`89df7b4320fdbd3525450e9446267ae3d54a5b62660d8904fe8f09be36a7fbf9`).
Their byte-access implementation is retained, rather than importing a newer
compiler instruction set.

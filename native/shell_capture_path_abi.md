# Shell capture path projection ABI

This private component implements deterministic Unix path and capture-name
operations in HIA. It performs no filesystem access, environment lookup, process
lookup, atomic operation, registry access, or scheduling. The input supplies typed
observations of TMPDIR, process ID, and the sequence value. Actual observation,
atomic ordering, allocation failure, concurrency, and capture creation remain
separate owners and qualifications.

The target is Linux x86-64 with Rust 1.95.0 Unix Path semantics and the pinned
Hepta compiler d3e2c90173cf733e42b299d0c4274df4b593a12f. The source uses HIA v8.
Its entry is f0(readbuf input, mutbuf output, mutbuf workspace) -> u32.

## Wire conventions

All integers are unsigned little-endian u64 values unless specified otherwise.
Paths are complete raw Unix OsStr bytes, including invalid UTF-8 and NUL.
No path is converted to text, lossily decoded, made absolute, or resolved through
the filesystem. NUL-containing TMPDIR inputs are typed projections; a real
environment observation cannot contain an embedded C-string NUL.

The three borrowed buffers obey the existing borrowed-bytes ABI. They are owned
and disjoint for the duration of a call. The input is immutable.

### Request

The header is exactly 64 bytes, followed by first and second, with no padding or
trailing data.

| Offset | Field |
| --- | --- |
| 0 | Eight bytes HSHCPQ01 |
| 8 | Operation: 1 equality, 2 parent, 3 capture paths |
| 16 | TMPDIR presence, used only by operation 3 |
| 24 | Observed process ID, used only by operation 3 |
| 32 | Observed sequence, used only by operation 3 |
| 40 | First byte length |
| 48 | Second byte length |
| 56 | Reserved zero |
| 64 | First bytes, then second bytes |

Operation 1 compares Path(first) and Path(second). Presence, process ID, and
sequence must be zero.

Operation 2 returns Path(first).parent(). Second length, presence, process ID,
and sequence must be zero.

Operation 3 receives the raw TMPDIR value as first. Presence must be 0 or 1.
Presence 0 requires first length zero and selects the original Linux fallback
/tmp. Presence 1 permits an empty value. Second length must be zero. Process ID
must fit u32, including 0; sequence accepts every u64. The sequence is the value
observed before the original AtomicU64 fetch_add, rather than a requested global
counter mutation.

All unused fields are canonical zero. Unknown operations, invalid scalar fields,
inconsistent extents, extra bytes, or a malformed magic return INVALID.

### Response

Successful calls return the fixed scalar 80. The response itself can be longer;
its complete extent is the u64 at offset 16. Consumers must not treat the scalar
return as the total payload length.

| Offset | Field |
| --- | --- |
| 0 | Eight bytes HSHCPR01 |
| 8 | Request operation |
| 16 | Complete response extent, including this 80-byte header |
| 24 | Equality result or parent presence; zero for operation 3 |
| 32 | Next sequence for operation 3; zero otherwise |
| 40 | Path byte length |
| 48 | ID byte length |
| 56 | Stdout path byte length |
| 64 | Stderr path byte length |
| 72 | Reserved zero |
| 80 | Path, ID, stdout path, stderr path bytes in that order |

The complete extent equals 80 plus the four lengths.

For equality, offset 24 is exactly 0 or 1 and all lengths are zero.

For parent, offset 24 distinguishes None (0) from Some (1). A None response has
path length zero. Some(empty) also has length zero, but presence 1. All other
lengths and next sequence are zero. A present path preserves the exact bytes
returned by Rust Components::as_path after consuming the final component.

For capture paths, flag is zero. Path is jobs_dir, ID is the decimal job ID, and
the two remaining segments are the full stdout/stderr paths. Next sequence is
the supplied sequence plus one with u64 wraparound. No atomic or global state is
changed.

## Exact operation semantics

Unix Path equality compares components. Repeated separators and internal dot
components are ignored, while a leading CurDir component remains significant.
ParentDir components are retained; this is not filesystem canonicalization.
The raw bytes of normal components are compared exactly.

Parent follows the pinned Path::parent sequence: consume the last component from
the back, accept Normal, CurDir, or ParentDir, then return the remaining
Components::as_path bytes. The remaining suffix is trimmed of ignored separators
and dot components; its internal raw bytes are retained. Examples:

| Input | Parent |
| --- | --- |
| Empty | None |
| / or ///./ | None |
| . or ././ | Some(empty) |
| a | Some(empty) |
| ./a | Some(.) |
| //a | Some(/) |
| a//b/c | Some(a//b) |
| a//b | Some(a) |
| ../.. | Some(..) |

For operation 3, the original Linux temp_dir choice is followed by the original
relative PathBuf joins:

- jobs_dir = temp_dir.join(format!("octofs-jobs-{}", pid))
- id = format!("{}-{}", pid, observed_sequence)
- stdout_path = jobs_dir.join(format!("{id}.stdout.log"))
- stderr_path = jobs_dir.join(format!("{id}.stderr.log"))

A separator is appended to a nonempty base only when its final raw byte is not
/. Existing bytes, including repeated separators, dots, and backslashes, remain
unchanged. Empty TMPDIR therefore produces relative capture paths. Decimal
formatting is performed in HIA over the complete u32/u64 domains.

These operations project original behavior but do not execute the whole original
prepare function. They do not select duplicates, advance JOB_SEQ, create or
remove directories/files, or register jobs.

## Capacities and refusal behavior

| Scalar return | Meaning |
| --- | --- |
| 80 | Complete response published |
| 4294967295 | INVALID: malformed or noncanonical request |
| 4294967294 | CAPACITY: insufficient private buffers or unrepresentable complete extent |

Workspace must contain at least 128 bytes. Its initial contents may be arbitrary
and it can be reused between requests. Bytes at offsets 128 and above are
unchanged. The first 128 bytes are private scratch and have no output meaning.

Output must hold the complete response. There is no fixed command, path, TMPDIR,
response, or input byte quota. Header extents and all loops use u64. Checked
capacity arithmetic refuses an extent that cannot be represented or held by the
provided buffer; it does not truncate a response or convert the condition into
a semantic path error. An outer transport may grow its owned buffers and retry.

Every refusal preserves the entire output buffer. Successful calls preserve
every output byte after the complete response extent. Input and bilateral guard
bytes are unchanged for all returns. No partial response is published.

Request validation precedes the private workspace capacity check. The workspace
may change after successful request validation, even if output capacity is
insufficient. Complete output capacity is established before its first write.

## Pinned sources and body reuse

Original behavior is drawn from src/mcp/fs/background.rs: jobs_dir, next_id, and
the untouched stdout_path/stderr_path join statements in prepare.

Rust source references:

- https://github.com/rust-lang/rust/blob/1.95.0/library/std/src/path.rs
  Git blob bf27df7b0428169a4308ebf413e732f3479754fe;
  SHA-256 2c41294523392663a73fa3da08864427a05bdd8ff0fff0bd157c0236680593bf.
  Path::parent, Path::components, Components iteration/as_path/equality, and
  PathBuf::_push define the Unix operations.
- https://github.com/rust-lang/rust/blob/1.95.0/library/std/src/sys/pal/unix/os.rs
  Git blob 494d94433db34c5fafcd8aad6dad2e948acad642.
  temp_dir selects var_os("TMPDIR") or the Linux fallback /tmp.

Five existing native/shell_gate.hepta function bodies are reused. Its complete
source SHA-256 is
52682cdf9e13a3eaf3ad8f168112531b2f918ed6139f06b769665a2ddaec05d1.

| Existing function | New function | Responsibility |
| --- | --- | --- |
| f10 | f14 | Following components, skipping slash and internal dot |
| f11 | f15 | Exact byte-span comparison |
| f63 | f16 | Read input u64 |
| f64 | f17 | Read scratch u64 |
| f65 | f18 | Write u64 |

native/shell_capture_path_reuse.json records the complete original and relocated
bodies and their hashes. Only function declaration IDs and call target IDs may
differ. New HIA explicitly handles the leading RootDir/CurDir distinction and
the reverse-parent iterator semantics. Shell-specific quote or redirect logic
is not imported. The private authoring generator is not a build or runtime
dependency: the authoritative product is the checked-in HIA source.

## Qualification boundaries

The native suite records complete request/response streams and the actual six
guarded buffers for each call, with capacity/malformed controls reported
separately from semantic cases. Its pure reader reconstructs the registered
inputs and validates immutable input, guards, refusal outputs, response framing,
and success tails without executing native code.

Original-Rust comparison separately binds direct std Path equality/parent and a
typed-observation projection of the original capture expressions. It must label
primitive observation substitution explicitly. An initialized real AtomicU64 can
verify fetch_add value and wrapping behavior without claiming production global
atomic ordering or concurrency.

No evidence here authorizes production Shell activation, whole-runtime
replacement, or old-stack removal.

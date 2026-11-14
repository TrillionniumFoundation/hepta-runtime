# Native JSON Value and number owner

`serde_json.hepta` implements three explicit byte operations for the retained
runtime's `serde_json::Value` and finite `serde_json::Number` behavior. The entry
is `f0(source: readbuf, output: mutbuf, workspace: mutbuf) -> u32`.

The component has no filesystem, process or network effects. It does not expose
public MCP tools, replace arbitrary Rust `Serialize`/`Deserialize` implementations,
implement `RawValue` identity, or grant caller authority. Original typed derives
with duplicate-field and unknown-field rules require their own projection; the
effect-fence projection is documented in `fence_json_abi.md`.

## Frame and operations

All words are unsigned 64-bit little-endian values. Every frame has the eight
bytes `HSJVAL01`, an operation word at offset 8, an exact payload-length word at
offset 16, and the payload at offset 24. The frame has no trailing bytes or
terminator. The payload limit is 8,388,608 bytes, including JSON whitespace.

| Operation | Input payload | Successful output |
| --- | --- | --- |
| 1 | Complete raw JSON document | Exact compact `serde_json::Value` serialization |
| 2 | Complete JSON number, with optional JSON whitespace | Two words: number tag and raw value bits |
| 3 | One eight-byte finite binary64 bit pattern | Exact finite-number JSON text |

Operation 2 tags are `3` for `u64`, `4` for `i64` represented as a two's-complement
word, and `5` for the IEEE-754 binary64 bits. Positive integer syntax within
`u64` stays unsigned. Negative nonzero integer syntax within `i64` stays signed.
`-0`, decimal syntax, exponent syntax and integer overflow use finite binary64.
Malformed numbers and overflow to a nonfinite value are refused. Underflow and
negative zero retain their original bits.

Operation 3 deliberately accepts only finite numbers representable by the
JSON `Number` domain. It is not the separate generic Rust serialization rule
that can map a nonfinite primitive `f64` to JSON `null`.

## Locked original semantics

The original runtime commit is
`a0dcdda1991ec536d5e2d252c006a778993fa566`. Its Cargo lock has SHA-256
`7f39704b92d5fc762a98a5313949034db464ca9485827b19b5dde7aa69902d43`.
The actual dependency is `serde_json` 1.0.151 with `float_roundtrip` and
`raw_value`; its float serializer is **zmij 1.0.23**. `preserve_order` and
`arbitrary_precision` are not enabled. The independent Cargo oracle retains
the exact registry versions, checksums and selected features.

Operation 1 therefore preserves these behaviors:

- Object keys are decoded strict Unicode strings, ordered by the original
  `BTreeMap<String, Value>` comparison. Later duplicate keys replace earlier
  values, including equivalent escaped key spellings.
- Every input value is parsed and every number is admitted before duplicate
  replacement. An overflowing or malformed value does not become valid merely
  because a later occurrence would replace its key.
- A complete single document is required. Container depth 127 is accepted;
  depth 128 is refused, matching the original generic `Value` recursion gate.
- Strings preserve Unicode scalar content, including embedded NUL. JSON output
  uses the original short control escapes and lowercase `\u00xx` escapes,
  preserves ordinary non-ASCII UTF-8 and does not escape `/` unnecessarily.
- Number parsing uses correctly rounded binary64 with the original
  `float_roundtrip` behavior. Serialization uses shortest roundtrip text,
  signed zero, fixed notation for decimal exponents -5 through 15, and the
  zmij exponent spelling without a padded leading zero.

Examples include `-0` becoming `-0.0`, `1e-5` becoming `0.00001`,
`1e15` becoming `1000000000000000.0`, and `1e16` remaining scientific as
`1e+16`. These examples and the numerical boundary corpus were executed by
the actual locked Rust dependency; Python floating-point formatting is not
used as a compatibility oracle.

## Native organization and output atomicity

The integer decimal/binary64 math, Unicode helpers and stable merge-sort
structure derive from hash-pinned Hepta sources at compiler commit
`d3e2c90173cf733e42b299d0c4274df4b593a12f`. The composition record lists the
source identities and the explicit serde adaptations. The checked-in HIA
source is the executable semantic owner; the Python files run only during
authoring, building or testing.

The 8,192-byte numerical scratch, parser state and node arena occupy disjoint
workspace spans. The arena starts at byte 16,384. It contains a 64-byte header,
56 bytes per admitted value node, decoded strings and canonical float text.
The complete 8 MiB domain includes 4,194,304 total value nodes; there is no
one-million-node shortcut. Internal arena records are private scratch, not a
public tree API or retained session state.

After complete admission and decoding, all numeric nodes are classified.
Objects then use a stable sort followed by final-duplicate selection. A first
serialization traversal measures the complete result and materializes every
reachable float spelling into private scratch. Only after the complete
output capacity check does the second traversal publish bytes. Neither pass
uses a host JSON encoder or host float conversion.

Within a single invocation, the last successfully classified numeric token
may be reused only after comparing its entire byte length and contents.
The last formatted float text may be reused only when all 64 bits match.
The cache is reset for each invocation; it neither merges positive and
negative zero nor skips an invalid overwritten value. Cached text spans are
immutable until the current invocation completes.

`0xffffffff` means invalid frame or a value outside the declared JSON domain.
`0xfffffffe` means insufficient output or workspace. Both leave all output
bytes unchanged. Scratch may change after admission and carries no semantic
state to the next request. Smaller caller-supplied buffers are supported and
fail explicitly when necessary.

## Explicit buffer and ELF profile

The named `serde-json.v1` profile admits 16 MiB of framed input, 64 MiB of
output and 256 MiB of workspace. The HIA component retains its stricter
8 MiB payload limit. The other profiles remain unchanged. The wider output
is necessary: an admitted 8 MiB array of `1e15` values serializes to
31,876,700 bytes under the original formatter.

`serde_filter_packer.hepta` emits a fixed Linux x86-64 static ELF carrying the
exact compiled image. Its boundary only reads standard input to EOF, allocates
the declared buffers, calls the fixed image and writes the returned output.
It has no dynamic loader, libc or Python dependency. A malformed component
frame exits 2, transport/capacity refusal exits 3, IO failure exits 4 and an
unexpected argument exits 64. No partial semantic output is published on a
component refusal. This profile has no persistent stdio transport.

The actual kernel test includes the 31,876,700-byte response, closed CLI,
nonfinite-number refusal, the component's 8 MiB payload bound and the
transport's 16 MiB bound. Direct native tests independently check output and
workspace canaries, mutation of neither source nor output on refusal, and
recovery when scratch is reused after an invalid request.

## Qualification contract

`test_serde_json.py` receives `HIA_SERDE_JSON_MANIFEST` and optionally exports
its actual corpus to a new `HIA_SERDE_JSON_CORPUS_DIR`. The actual filter suite
can write `HIA_SERDE_JSON_TRANSPORT_REPORT`. `test_fence_json.py` uses its
separate manifest and corpus variables. The JSON qualification helper binds
current HIA/image/ELF bytes, packers, native harness files, exact original
derive source, Cargo versions/features and reference oracle source. Its
`check_corpus` entry is available to the aggregate comparator.

The standalone Rust oracle in `tests/hia_native/serde_json_oracle` reads
hexadecimal ABI frames and emits `status_hex:output_hex` lines. It accepts both
generic and typed frames. Each exported corpus must be replayed by that actual
locked reference, and its complete stdout must equal the native output file.
Historical comparison evidence does not substitute for a fresh aggregate
reference replay or the compiler's full cold gate.

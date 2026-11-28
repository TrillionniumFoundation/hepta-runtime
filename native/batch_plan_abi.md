# Native batch admission and endpoint planning

This owner implements the pure admission, input parsing, endpoint resolution and
error aggregation blocks in `src/mcp/fs/text_editing.rs::batch_edit_spec`, together
with its complete `parse_line_range` and `resolve_unresolved_line_range` behavior.
The original source is pinned to runtime commit
`a0dcdda1991ec536d5e2d252c006a778993fa566` and exact Git blob/SHA256 identities.

The input is the typed projection of already decoded `serde_json::Value` fields
and the post-read normalized line slice. The upstream `BatchEditParams`
deserializer, content-array joining, path hoisting, JSON parsing, path resolution,
file existence/read/lock effects, `EditableContent` normalization, conflict and
duplicate detection, mutation, history and rendered edit result remain separate
owners. A resolved plan is not an applied edit. No public MCP tool replacement,
shared lock or concurrent-session guarantee follows from this component.

## Request

The entry has the standard borrowed-byte signature
`f0(readbuf, mutbuf, mutbuf) -> u32`. All fixed integers are little-endian u64.

| Offset | Meaning |
|---|---|
| 0 | `HBPLAN01` |
| 8 | Mode: 0 admission before filesystem effects; 1 full post-read planning |
| 16 | Path is a string: 0 or 1 |
| 24 | Number of normalized lines |
| 32 | Number of operations |
| 40 | Path UTF-8 byte length |
| 48 | Encoded line byte length |
| 56 | Encoded operation byte length |
| 64, 72 | Reserved zero |

The 80-byte header is followed by the path, encoded lines and operation records.
Each line is canonical ULEB128 byte length followed by valid UTF-8. The final
decoded cursor must equal the declared line-region end. No Unicode normalization
is introduced. Mode 0 has no lines. A missing or non-string path has flag zero and
no path bytes; these source values share the original missing-path result.

Each operation starts with nine u64 words, followed by four byte spans:

| Word | Meaning |
|---|---|
| 0 | Source value is an object |
| 1 | `operation` exists and is a string |
| 2 | `start` exists and is non-null |
| 3 | `end` exists and is non-null |
| 4 | `content` exists and is a string |
| 5–8 | Byte lengths of operation name, start packet, end packet, content |

The four payloads occur in that order. Absent flags require an empty associated
span. A non-object operation has all remaining words zero. A present endpoint is
the exact `HIAEP001` typed packet of the independently qualified line-endpoint
owner. Its `Other` payload is the original value's compact `Display` string,
provided by the trusted serde projection; it is not a second JSON parser. JSON
null is projected to absent before constructing the packet. Missing and wrongly
typed string fields share their original error domain. This quotient preserves
the original decisions; it does not turn arbitrary bytes into authenticated
serde values.

## Original ordering and plans

After complete transport admission, missing path wins, then an empty operation
array, then the unchanged maximum of 50. Mode 0 returns admission success at
that point. A caller must run this phase before original filesystem effects.

Mode 1 parses every operation in original order. The first malformed field in
each operation wins: object, operation string, supported operation, non-null
start, parsed start/end and permitted target kind, then content string. Insert
ignores end semantics. Replace parses an explicit end before applying its
plain-number rule; an omitted/null end clones start. Both numeric hints occur in
start/end order, including two identical hints. Insert with empty content
becomes one LF; empty replace remains deletion content.

Any malformed operation prevents all line verification. The complete malformed
aggregate retains its original indentation, index, text and newlines. Otherwise
the owner verifies all boundaries in operation order. Both replacement endpoints
are verified before their operation is rejected; both diagnostics remain in the
result. Reversed-range checking follows two successful verifications. Stale
operation errors are joined with the original `\n---\n` separator. Content is
returned unchanged after the one empty-insert rule.

The owner memoizes exact `(line number, lower-case hash)` verification results
within one immutable request. Repeated results still produce repeated original
text in the original order. Numeric hint lookup similarly caches full-content
hash and exact Unicode-trimmed byte span. The cache contains at most the 100
boundaries admitted by the original 50-operation maximum; it adds no independent
operation limit or semantic eviction behavior. Every cache is cleared on return.

The result has a 48-byte header: `HBPLR001`, status, operation count, body byte
length, and two zero words. Status 1 is an exact original UTF-8 error body and
has count zero. Status 2 is mode-0 admission success with an empty body. Status 0
contains plans in original order. Each plan is six words followed by content:
original index, operation kind (1 insert / 2 replace), range kind (1 single /
2 inclusive range), first, last (zero for insert), content byte length.

## Native child protocol and cleanup

The fixed module identities are 1 planner, 2 original endpoint owner and 3
original line-verification owner. The planner has call mask 12. It uses the
existing `HIACAL01` footer, child invocation kind 3 and its own module ID 1.
It checks matching sequence, completion, bridge status, target, regions, offsets,
lengths, capacities, reserved word and complete child return width before using
results. Endpoint and verify result headers, tags and exact produced lengths are
checked independently. No Python decision dispatcher is included in the ELF.

`0xffffffff` is malformed typed transport, `0xfffffffe` is actual caller capacity,
`0xfffffff8` is an invalid child/continuation contract, and `0xffffffe0` requests a
fixed native child. Original semantic errors remain status-1 byte strings, not
these adapter statuses. Public output is unchanged on every adapter refusal;
successful output leaves its unused tail unchanged.

The planner reserves 24,576 metadata bytes, an error arena sized by the actual
output capacity, a request arena and a result arena, then the 256-byte footer.
Before calling a leaf it marks the entire declared result arena as owned. Thus
even a contradictory short child return cannot leave the previously written
result tail outside cleanup. Terminal paths clear the complete owned private
prefix; unowned workspace tail and the adapter-owned footer remain distinct.
These are text buffers, not a key-custody claim. The caller must retain the
immutable original input and disjoint capacities across a continuation.

## Full file domain and finite adapters

The separate image-only `batch-plan.v1` capacity declaration admits up to 512 MiB
input, 1 GiB output and 1,152 MiB private workspace. It changes neither the
standard nor view-render profile, and has no automatic standalone transport.
These are caller/adapter capacities, not new limits in the original batch edit
semantics. Actual invocations use actual small buffers. The workspace requirement
is derived from those buffers and the largest endpoint, line and prefix spans;
an insufficient buffer produces `CAPACITY` without truncation or a changed
original error.

For the complete 5 MiB file domain, one stale-boundary diagnostic contains at
most the file's bytes once plus bounded context IDs, up to three relocation IDs
and original fixed text. A conservative bound is `B + 1024` bytes for file byte
count `B`. A plain-number hint contains at most `B + 128`. Fifty replacements
can repeat either diagnostic twice, so the aggregate is bounded by
`100 * (B + 1024) + P + 1024`, with path length `P`. The qualification corpus
includes actual 50-operation, two-endpoint repetitions of a full 5 MiB line for
both malformed numeric hints and stale IDs. The result is about 500 MiB, not a
truncated summary. The exact sizes and complete stream digests are measured in
the native corpus. The same input is also tested with a small output buffer,
which must refuse capacity atomically.

The full corpus also covers 5,242,880 empty normalized lines, a 5 MiB UTF-8
content body, a 5 MiB endpoint value and a 5 MiB unsupported operation name.
Large results are retained and compared as bounded gzip streams; neither native
qualification nor the original Rust comparator creates another whole output
copy solely to hash or compare it.

The separate four-image hexadecimal ELF uses the existing standard composition
capacities and is a test fixture. Its smaller output allowance is explicitly an
adapter boundary. It does not establish a 500 MiB standalone service transport.
The wide image tests and the small ELF tests are reported as different domains.

## Evidence

The pinned compiler is `d3e2c90173cf733e42b299d0c4274df4b593a12f`.
Source composition records exact imported function graphs and relocations for
UTF-8, FNV hashing, Unicode whitespace, scalar decoding and canonical ULEB128.
Endpoint and verification leaves are independently pinned and their actual
compiled images are compared between direct and ELF profiles.

The locked Cargo oracle includes the unchanged original line-hash module and
unchanged batch types, range helpers and owned parsing/aggregation blocks. Its
test envelope supplies the admitted path, serde values and normalized line slice;
it uses an error carrier that preserves the original display string. It does not
call filesystem or conflict/mutation code. A source reconstruction check binds
all copied blocks before compiling and before replaying the actual Rust binary.
Only actually replayed complete native rows establish original parity. Frame,
capacity and injected child-contract controls remain explicitly native-only.
All eleven registry packages in the oracle lockfile have the original runtime
baseline's exact version, registry identity and checksum. The reference recipe
has a smaller feature closure; it does not claim an identical application
lockfile or build unrelated filesystem/transport dependencies.

## Qualification interface and measured domain

Build with `scripts/hia_native_batch_plan_build.py --hepta <pinned-checkout>
--build-root <new-or-validated-build-root>`. The returned `bundle.json` binds three
wide direct images, their actual compiler input/output receipts and the four-image
ELF. `HIA_BATCH_PLAN_BUNDLE` supplies this bundle to both native suites;
`HIA_BATCH_PLAN_CORPUS_DIR` names an absent capture directory. The source checkout
is located from each script, so no neighboring repository name is assumed.
An explicit `--reference-root`/`HIA_REFERENCE_RUNTIME` is development-only for an
isolated candidate; aggregate qualification supplies its own frozen root.

The complete suite records 3,339 direct requests: 3,174 original-compatible rows
and 165 adapter/control refusals. Its continuations execute 53,301 planner,
40,630 endpoint and 9,332 verification entries. Those entry counts are derived
again from the complete captured histories. The static ELF separately executes
21 requests in one process: 20 original-compatible results and one declared
2 MiB output-capacity refusal. Those 20 complete results are also bound to exact
inputs and outputs in the Rust corpus; repeated inputs are counted separately
as actual requests, not invented independent semantic cases.

The two maximum repeated-diagnostic outputs are respectively 524,298,089 bytes
(plain numeric targets) and 524,301,763 bytes (stale line IDs), including the
48-byte result header. The complete Rust stream contains 36,628,387 input bytes
and 1,066,976,665 output bytes including each u64 framing length. Native and
original output SHA256 is
`5a054d4b59f92bf1d836b144e94552d10b1a1c0d747d81a6f857fee66f421d96`.
The locked original oracle has actually reproduced all 3,174 rows, including
both maximum diagnostics, rather than a smaller proxy corpus.

`scripts/hia_native_batch_plan_qualification.py` validates complete capture
streams, native call histories, exact imported function graphs, actual sealed
images and the complete ELF prefix/table/image layout. Evidence mutation tests
perform no additional native semantic or original Rust calls. The required Rust
recipe calls `compare_original(...)`, which really builds and runs the locked
oracle and retains its full compressed output, compiler and process receipts.
Historical observations remain separate from fresh qualification invocations.

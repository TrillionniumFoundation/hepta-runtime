# ELF notes and complete Evidence readback

This continuation keeps the frozen `rea-agents@6.8.0` operations unchanged and
adds an explicitly native complete-byte readback profile:
`hepta.evidence-bundle-readback.v1`. It is not a claim that upstream accepts ELF
notes as an `inspect_analysis_view` parent; the frozen operation rejects that
combination.

## Complete operation sequence

1. Identify the original npm tarball, installed files and Node executable, the
   actual native executable and its selected source, and the input ELF bytes.
2. Run `rea_inspect_elf_notes`. Read retained metadata with
   `rea_get_evidence_bundle` and `detail: summary`.
3. Read the complete canonical bundle with `rea_read_evidence_bundle`.
   The initial request omits `snapshot_id` and starts at byte offset zero.
   Every continuation supplies its returned ID and `next_offset`.
4. Decode `bytes_hex`, verify each `chunk_sha256`, concatenate in byte-offset
   order, and verify the final `sha256` and `total_bytes`. These bytes must equal
   an export of the same immutable Evidence selection, including manifests,
   records, display metadata and unknown revisions.
5. Release the readback handle with `rea_close_evidence_snapshot` and export
   the session's retained Evidence to an authorized path before closing the
   session normally.
6. Start a new MCP session, observe its empty registry, explicitly import the
   exported bundle, then read and export it again. Compare complete objects
   and canonical bytes; do not infer durable recovery from explicit import.

For example, the first native read uses:

```json
{"length":262144}
```

Continuation uses the actual returned values, without recomputing or guessing
an offset:

```json
{"snapshot_id":"ebs1_<64 lowercase hexadecimal digits>","offset":262144,"length":262144}
```

The response's `result` contains `profile`, `snapshot_id`, full `sha256`,
`total_bytes`, record/unknown counts, `encoding: "hex"`, `bytes_hex`,
`chunk_sha256`, `offset`, actual `length`, `next_offset`, `eof` and
`persistence: "session-only"`. A byte page can split a UTF-8 code point; decode
hex and reassemble the bytes before decoding the complete JSON. The EOF page
has no next offset. Reading exactly at EOF returns an empty final page;
reading beyond EOF is an error.

## Ownership and resource limits

Each MCP session owns its readback registry. Clones handling the same session
share it; other sessions do not. New Evidence and imports do not mutate a
previously selected snapshot. Handles bind the complete canonical bytes and
are usable only while retained in their original session. No filesystem,
network, external engine or Python helper participates in native readback.

Pages are 1–262,144 bytes (default 65,536). Each snapshot is at most 64 MiB;
a session retains at most four snapshots and 128 MiB of encoded payloads.
There is at most one active encoder per session. These are payload bounds,
not a whole-process RSS guarantee or a global admission budget across all
clients. The encoder checks cancellation while writing and owns its admission
permit until it stops, even if the request future is dropped. A failed,
over-budget or cancelled encoding publishes no partial snapshot.

There is no implicit eviction. A full cache refuses a new snapshot and points
the caller to explicit release or file export. An existing ID continues to
read at the cache limit. Release is idempotent and does not remove Evidence
records. A read admitted before release may finish from its own immutable
reference. Closing the session releases its cache; handles are not recovery
tokens in a new process. An oversized bundle beyond the snapshot cap can
still use the separately authorized export operation and file-reading path.

## Qualification and comparison boundaries

`scripts/rea_elf_evidence_family_qualification.py` executes the original npm and
native MCP on a pinned real ELF and independently encoded edge fixtures. It
keeps the original-compatible comparison separate from native extension
checks. The original-compatible path compares complete `CallToolResult`
objects, including opaque `content.text`; raw JSON-RPC bytes and their ordering
remain separate observations. It preserves the original 10 MiB response bound
and exercises the advertised retained-Evidence export path after a real
oversized result.

The native-only checks reconstruct a frozen snapshot across a subsequent
registry mutation, compare its bytes with the matching export, reject bad
continuations, release handles and reject their use in a new session. They
do not count as original Node API equivalence.

The operation consumer now records retention and cold-session isolation as
observations. Neither proves pagination. The old v1 operation receipt cannot
close `stable-pagination-and-complete-byte-readback` by supplying a PASS label,
an invented cursor or a successful build. Historical artifacts retain their
original content and their original execution scope. Complete P0–P5 and
229-tool replacement qualification remain separate gates.

## Replaying the retained family evidence

`scripts/rea_elf_evidence_family_evidence.py` is a read-only consumer for the
finite family receipt. Give it the original receipt's SHA-256 and the exact
source checkout:

```sh
python3 -B scripts/rea_elf_evidence_family_evidence.py \
  --repo /absolute/exact-source-checkout \
  --report /absolute/elf-family/qualification.json \
  --sha256 ORIGINAL_RECEIPT_SHA256
```

The consumer authenticates bounded compressed artifacts, reconstructs the full
wire index and binds each actual request to its response and recorded case.
It derives 40 public-operation comparisons, three schema comparisons and seven
canonical export-byte comparisons, verifies eight independently closed owners,
and reconstructs the native immutable snapshot from its original page bytes.
It also checks release, subsequent mutation, cross-session isolation, source
stability and the original build bundle. Producer-supplied PASS flags and
comparison counts do not establish those facts.

A successful finite replay retains `status: OPEN` and `qualified: false` for
whole-operation qualification. Active cancellation, the native deadline,
additional formats and platform/deployment requirements have separate receipts
and boundaries.

Actual execution counts, failures and source/binary identities belong in the
dated continuation receipt. This contract alone supplies no execution pass.

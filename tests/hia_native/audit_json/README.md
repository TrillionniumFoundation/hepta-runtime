# Native HIA audit JSON codec qualification

The runtime implementation is `native/audit_json.hepta`. Its typed boundary is
specified in `ABI.md`. The exact original `Record<S>`, `DurableState`, and Unix
`ArchiveAnchor` definitions are retained as reference material from target
`d3d75c30719db966b004756f610007a7c723729e`.

Source authoring passed CI 43995910414 at b128b8d27285fb3b077119c01cdeae4e508fde69.
It generated 46 functions, 739 blocks and 2102 HIA instructions. Imported JSON
integer, Unicode and decimal-format functions preserve their complete ASTs,
with only function/call names relocated. Source generation executes no HIA,
emitted native code, or Rust. Reference formatting passed CI 43996339337.

`CASES.jsonl.gz.b64` contains 3511 concrete inputs, fully pinned by `DOMAIN.json`.
They include all 720 audit-record field permutations in both owned and borrowed
forms, all 24 anchor field permutations, map/sequence representations, the full
u128/u64 boundaries, null/omitted option behavior, Unicode, escapes, invalid
typed values, exact declaration-order serialization, canonical binary projection
validation, storage read bounds and output/workspace capacity refusal. The
input author emits no expected semantic output.

`run_gate.py` runs only in the authorized CI environment. It freshly builds
B1=B2=B3 from the exact compiler, compiles the frozen codec, fetches the locked
original reference dependencies, verifies and retains their original crate
archives and complete vendored bytes, then builds the unchanged original types
using Rust 1.95.0 and the fixed development profile. Original and native
processes receive byte-identical complete inputs. Each has its own 60-second
budget; builds have 900 seconds, and each independent reader has 180 seconds.

The native fixture calls the admitted flat HIA entry directly and retains the
complete before/after source, output and workspace bytes, including all guard
tails. It has no host-side JSON parser or semantic fallback. The artifact is
compressed losslessly; its logical physical-byte count is independently read.

The fixed pure reader verifies all source/dependency/compiler identities,
actual process custody and complete streams, each original/native result,
contract admissions, refusal preservation and all output/workspace suffixes.
Twelve physical mutations must be rejected under twelve execution/write
guards. Two complete relocations and two post-refusal admissions must retain
the original evidence. A separate final reader verifies the entire capture and
all control proofs; it does not replay native or Rust semantics.

All success and failure evidence is exported. Temporary Cargo compilation
intermediates remain outside the capture; the exact original ELF, source,
dependency archives, complete vendored input and process streams are retained.
The archive deduplicates identical file bytes and modes without dropping any
logical path and re-reads every unique object and every logical file.

Qualification applies to the private codec only. Actual audit persistence,
authorization, retention, archive publication, public SDK callers and whole
runtime replacement require their own complete composition. They are not
declared qualified by this package.

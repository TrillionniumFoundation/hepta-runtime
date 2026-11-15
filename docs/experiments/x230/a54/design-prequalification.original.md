# A54 proposal: borrowed compact rows inside the existing serial full-record join

Status: **design and unqualified local candidate only**. A53 source, ELF,
qualification, measurements and frozen acceptance packages remain unchanged.
No Rust build, native workload or performance result belongs to this proposal.

## Evidence and exact parent

The parent is actual A53 r02 qualification
`ab3a37ceb97667694c201d9b62556398e04e805010c8492af6a8f6f51486a72b`,
whose 175-file tested/after map has compact SHA256
`91962e89b203621686cfa0d77567b13bd246092a99345681674bbafd46388c35`.
`design-inputs.json` pins eleven local source bodies against that map. The three
previously absent codec/cold/store files were read from the known Git commit
`17d01dda7bd75b9bb9c0c5f1f90f84bddbfb54cb`; each complete body independently
matches the actual A53 map. This analysis makes no X230 read or execution call.

The relevant inherited production sources are:

| Source | Matching local original | SHA256 |
|---|---|---|
| `request_archive_content.rs` | `runtime-a52-qualified/src/mcp/runtime/request_archive_content.rs` | `0939fdea0386da12114f469b06596b8a5f3d738f387dca1b68ae6853feb0d300` |
| `request_archive_codec.rs` | `multihost-review/a53-archive-analysis/source/request_archive_codec.rs` | `9096085b42b5e5ba2b074ae158f615044dc1e0df40382d7248e5a388728e68a5` |
| `request_archive_cold.rs` | `multihost-review/a53-archive-analysis/source/request_archive_cold.rs` | `819be525ee6bed14e55c9fd9c060263286750a43e7599461bda9da74549a03d8` |
| `request_archive_index.rs` | `runtime-a51-qualified/src/mcp/runtime/request_archive_index.rs` | `f7d1de279c473a5df75778a5baa0ff048c4b86d6afa2b53208a5ba4f37185389` |
| `request_archive_store.rs` | `multihost-review/a53-archive-analysis/source/request_archive_store.rs` | `d9869c388682b71f16887c8342c89b5d6f6a3e3a1fdcbfe4b50406b32fbadb26` |

A51's original trace, SHA256
`0cfec2026463cbd7669ac63e5d60641f609e574d31266025f6e613e910faee28`,
contains eight complete measured observations: four singleton and four
four-member cohorts. The complete verification spans 1,806,035–2,746,619 µs;
projection spans 334–6,499 µs, final fences 22–42 µs. Those eight verification
spans account for approximately 99.49–99.88% of their leader API-to-result time.
All twenty measured calls passed; initial index kickoff did not. The trace did
not reproduce the earlier C4 failure and does not establish its cause.

**A51 used parallel page readers. A53 already inherits A52's serial page kernel.**
These A51 numbers locate a prior cost category; they are not A53 timings or an
estimate of A54 benefit. Root's current A53 large result remains decisive.

## The concrete repeated work

In `verify_members_in_mode`, every original filename performs the same ROWS and
ORDER identity join. A compact ROW currently passes through `codec::decode`,
which constructs owned request-id, owner and tool `String`s. The two binary IDs
are expanded to canonical lowercase hex. `cold::order_value`, the explicit
identity check and `order_key` then parse the request-id three times, while
`order_key` parses the owner once. These operations use immutable already-read
ROW bytes within one redb transaction.

`codec::view` already validates the complete compact representation and returns
binary IDs, numeric fields, a complete `FileStamp`, and a borrowed tool string.
The cold table scanner already uses that API. The proposed change is restricted
to the serial complete-content join's interpretation of its expected ROW.
Original JSON parsing, all filesystem observations and the parallel usage worker
implementation remain unchanged in the first candidate.

## Proposed internal API and ownership

Add a narrow codec helper with the semantic shape:

```rust
fn view_if_compact(raw: &[u8]) -> Result<Option<View<'_>>>
```

It checks the exact existing `HAR1` marker. For a compact row it calls the
existing complete `view` parser and propagates any error. For a noncompact row
it returns `None`; the caller invokes the unchanged `codec::decode` legacy JSON
path. A malformed compact row can never fall back to legacy parsing.

Inside the serial callback, retain the original `ROWS.get` access guard, then
represent the expected base as either a borrowed `codec::View` or an owned legacy
`Entry`. The enum and access guard remain on the stack for one member, inside the
same immutable transaction. Nothing borrowed enters a task, channel, cache,
pending map, returned page or retained cohort. No extra observation owner exists.

Preserve error ordering: parse the base and validate its ROW/ORDER binding before
choosing a pending replacement. A valid pending record must not conceal a broken
base key, malformed base encoding or corrupted ORDER value. Preserve the existing
missing-base error before opening an unrelated original.

## Exact ORDER and record equivalence

For a compact view `v`, the existing owned decode produces:
`request_id = hex(v.identity)` and `owner = hex(v.owner)`. Both are exactly the
canonical lowercase encoding accepted by `id`. Therefore:

| Existing expression | Borrowed construction | Size |
|---|---|---:|
| `id(decoded.record.request_id)` | `v.identity` | 32 bytes |
| `cold::order_value(decoded)` | `v.identity` | 32 bytes |
| `order_key(decoded.record)` | `v.owner || v.accepted.to_be_bytes() || v.identity` | 80 bytes |

ORDER keys and values are already fixed arrays. This proposal does not claim to
remove a `Vec` allocation from those operations. It removes the three expected
record strings and their unnecessary binary-to-hex-to-binary round trips for
compact base rows only.

The original still passes through the exact existing `read_original`. Compare
all six fields and the full stamp: parsed request identity, parsed owner,
tool bytes, durable state, accepted `u128`, optional elapsed `u64`, and every
`FileStamp` field. Keep the actual identity parse explicit; no omitted-field
argument substitutes for a full comparison. `None`, `Some(0)` and `Some(u64::MAX)`
remain distinct. Pending overrides still use the existing complete `Entry`
comparison and bounded effective-view accounting.

## Parser and refusal behavior

- Compact length remains exactly `167 + tool_length`. Truncated records,
  appended bytes, zero/oversized tool lengths, invalid UTF-8, invalid tool bytes,
  invalid state tags, invalid elapsed tags and a nonzero unused elapsed word are
  rejected by the same `codec::view` implementation. Do not manually parse a
  selected subset of offsets or replace parser errors with absence.
- The original record remains bounded by 2,048 bytes and parsed completely with
  the existing `Record` deserializer, including `deny_unknown_fields`. All bytes
  through actual EOF are read. Unknown/duplicate fields, type errors and trailing
  non-whitespace JSON retain the existing behavior.
- Valid noncanonical JSON is still valid: field ordering, legal whitespace,
  trailing whitespace, and escaped strings that decode to valid lowercase IDs or
  tool names must not be rejected by a raw-byte/canonical-serialization shortcut.
- Noncompact derived rows retain the existing full `Entry` JSON parser, with its
  `Record` and `FileStamp` rules. Do not force legacy data through the compact
  parser, rewrite it, mark a format upgrade, or silently normalize malformed data.
- Do not invent a new relationship between state and elapsed fields. Preserve
  the existing parser domain, and compare each field exactly.

## Invariants kept intact

The observation remains one complete read of every effective original, including
records outside requested pages and owners. ROWS/ORDER share the same immutable
transaction; their row counts, every ROW identity, exact ORDER key/value,
pending-new-member count, pending deduplication and final observed count remain
mandatory. Staging entries are refused without removal.

Keep both `fence_record` calls, both pathname stamps, both descriptor checks,
private UID/0600/single-link/regular-file/length policy, no-follow opens, complete
original reads, per-read deadline checks, and all complete before/after flat/shard
layout and cross-namespace checks. Watches remain invalidation fences. No mtime,
digest, prior-result or content lease replaces an original observation.

The store/state guards, eight query slots, fixed one-millisecond cohort cutoff,
minimum original three-second deadline, final namespace fences, original work
custody, cancellation semantics and no-late-success checks stay unchanged.
The two-lane usage-reader path and cold recovery's complete post-apply validation
are not replaced or weakened. Reusing stat/fstat observations is out of scope.

## Meaningful regression plan before any qualification

1. Compare compact borrowed and legacy-owned ORDER construction across boundary
   IDs, accepted timestamps, tool lengths, all state values and elapsed variants;
   assert all 80 key and 32 value bytes equal the existing functions.
2. Exercise the real serial verifier with a different original or base field,
   including off-page content and each stamp component; it must refuse and leave
   original/cache bytes unchanged. Include a wrong base identity under a valid
   ROW key and a corrupted ORDER value.
3. Preserve parser refusal for compact truncation, extra bytes and each malformed
   tag/length/tool case. Legacy errors must remain errors; valid JSON whitespace,
   reordered fields and escapes must preserve success.
4. Cover a pending terminal replacement and new member; a corrupt base ORDER
   binding must still refuse even when the effective pending record is valid.
5. Retain the existing complete-content, staging, missing-member, expired-budget,
   cold-epoch, same-stamp recovery and original-reader lifecycle tests. No test
   timeout, ignored set, contract, fixture cardinality or qualification gate is
   relaxed.

Tests and a minimal candidate may be prepared in `runtime-a54/` only. No Rust
compile or X230 execution occurs until root selects this candidate and creates
its own immutable qualification. The first candidate is deliberately limited to
this expected-row conversion; buffer reuse and C-string reuse are separate later
possibilities that must not obscure its measured effect.

## Decision after A53 large

If A53 passes, assess whole-life CPU, original latency and complete comparison
coverage before deciding whether another candidate is justified. A source-level
allocation reduction alone is not a performance adoption.

If A53 fails, preserve that attempt and first distinguish a true product deadline
from a transport/unknown outcome, failed source/namespace fence, startup failure,
or incomplete cleanup. Existing public generic errors do not identify the
underlying cause. A new diagnostic, if root chooses one, stays separate from the
fixed comparison and binds the actual current source/ELF.

A split C4 cohort is a possible code path, not an established cause: registration
after the immutable one-millisecond cutoff creates a later group, while the
global store guard serializes full observations. The proof needed is actual
cohort membership and store-wait/full-validation timing. Do not widen the cutoff,
join an already observed group, reuse its result, retry, release permits early,
or extend the three-second deadline to turn that possibility into a pass.

# Persistent native view cache

`view_cache.hepta` owns serial, persistent state transitions from the complete
`ViewCache` methods and mutation helpers in `src/mcp/fs/delta.rs`. It runs as
native HIA with a private retained workspace. The accompanying two-image ELF
is a test transport, not an installed MCP service or a replacement for session
admission, filesystem path resolution, or shared synchronization.

## Original contract and remaining owners

The original cache has an inclusive **1,048,576 UTF-8 byte limit per value**.
It has **no total entry limit, no LRU, and no eviction of unrelated entries**.
An oversized `set` removes only its target key. `get` clones exact contents;
a present empty string differs from a missing entry. Raw `set` never changes
line endings. `note_create` and `note_write` replace each `CR LF` with `LF`
once. In particular, `CR CR LF` becomes `CR LF`, which must not be normalized
again when a prepared view result is stored.

`note_write` retains the entry only when the cached string equals the
once-normalized `before`. It then stores once-normalized `after`, subject to
the original per-entry limit. A stale or missing prior value is forgotten.
The original method takes separate locks for its `get` and subsequent
`set`/`forget`. This component qualifies serial histories; it does not claim
an atomic concurrent `note_write` transaction.

`forget_subtree(key)` removes exact `key` and every name starting with
`key.trim_end_matches('/') + '/'`. This is a byte-exact separator rule. It
does not case-fold, normalize Unicode, collapse internal slashes, or treat
backslash as a separator. Empty and all-slash keys follow that same rule.
Owned `forget_all` works without a request context and affects only its cache.

Original mutex poison makes every `get` return missing and every ordinary
mutation a no-op. The native trusted poison notification preserves stored
entries and never unpoisons an active instance. A test-only injection into
the original Rust `Mutex` is part of the actual reference replay.

The following boundaries remain separate:

* **Path keys.** Input keys are the already produced `String` from
  `lock_key_for_source`. Local canonicalization, canonical-parent fallback,
  lossy conversion of non-UTF-8 OS paths, and remote host/port identity remain
  with path/effect owners. Arbitrary valid UTF-8 keys here do not authorize
  filesystem access.
* **Storage.** The original session map is unbounded. This owner stores a
  variable number of entries in its supplied private arena and imposes no
  count quota. Exhaustion returns a distinct resource `CAPACITY` code without
  modifying state. It is not a miss, semantic eviction, or claimed substitute
  for the original allocator's unbounded domain. A trusted growing storage
  owner is still required for that domain. Offsets are relocatable; a tested
  trusted relocation to a larger zero-extended workspace continues the same
  state, but this module does not allocate, relocate, or share memory itself.
* **Session ownership and concurrency.** Session selection, `Arc` lifetime,
  Tokio task-local context, native mutex/poison production, publication
  coordination, and safe sharing across concurrent clones are not supplied.
  Exactly one trusted caller may use a workspace at a time. Different
  workspaces are different sessions.
* **View orchestration.** The typed plan input consumes the frozen native
  `view_render` result directly. Tests execute both actual images. It does
  not perform file reads, choose paths, or install a public `view` tool.

## Three-buffer entry point

`f0(readbuf input, mutbuf output, mutbuf workspace) -> u32` uses disjoint
borrowed buffers. Output length is the successful result. Reserved failures:

| Code | Meaning | State and output |
|---|---|---|
| `0xffffffff` | Invalid typed frame, UTF-8, or view-plan shape | Unchanged |
| `0xfffffffe` | Insufficient output/workspace capacity | Unchanged |
| `0xfffffffd` | Invalid private state or non-fresh initialization | Unchanged |

No source semantic fallback executes. The standard image profile admits up
to 8 MiB input/output and 32 MiB workspace; the test composition supplies an
8 MiB cache workspace and `1,048,608` output bytes. Those are declared execution
resources, not new original cache limits. The source checks lengths against
the actual borrowed buffers rather than defining a fixed slot count.

### Input

The fixed header is 48 bytes, followed immediately by `key`, `a`, and `b`.
Every integer is unsigned little-endian `u64`.

| Offset | Field |
|---:|---|
| 0 | Eight bytes `HVCACH01` |
| 8 | Operation |
| 16 | Context selector |
| 24 | Key byte length |
| 32 | `a` byte length |
| 40 | `b` byte length |

The frame must end exactly after the declared spans. All string spans must
be valid UTF-8, including embedded NUL and otherwise valid control characters.
Only the plan span for operation 8 is binary. Its text and cached string spans
are separately UTF-8 checked.

Context selector `0` means a direct owned-cache method, `1` means the test
adapter has a request context bound to this cache, and `2` means no request
context. Selector 2 returns missing for get and ignores contextual mutations.
It does not clear or replace the underlying session.

| Operation | Meaning | Key / a / b | Allowed selector |
|---:|---|---|---|
| 0 | Initialize fresh private storage | All empty | 0 |
| 1 | Get exact stored value | Key / empty / empty | 0, 1, 2 |
| 2 | Set exact value | Key / content / empty | 0, 1, 2 |
| 3 | Forget exact key | Key / empty / empty | 0, 1, 2 |
| 4 | Forget subtree | Key / empty / empty | 0, 1, 2 |
| 5 | Owned `forget_all` | All empty | 0 |
| 6 | `note_create` | Key / content / empty | 1, 2 |
| 7 | `note_write` | Key / before / after | 1, 2 |
| 8 | Apply native view cache plan | Key / complete `HVIEWR01` output / empty | 0 |
| 9 | Trusted poison notification | All empty | 0 |
| 10 | Destroy the private instance | All empty | 0 |

Initialization requires every supplied workspace byte to be zero. Repeating
it on an active instance is a `STATE` refusal. Destroy wipes the entire supplied
workspace, including a poisoned cache, and allows a later fresh initialization.
Initialization, destruction, contextual raw-set adaptation, and poison
notification are explicit integration/test operations rather than newly
claimed original public methods.

### Output

Every success starts with a 32-byte header:

| Offset | Field |
|---:|---|
| 0 | Eight bytes `HVCAR001` |
| 8 | Present, exactly 0 or 1 |
| 16 | Content byte length |
| 24 | Reserved zero |
| 32 | Exact content bytes, if present |

Only a successful get can set `present=1`. Present empty returns 32 bytes
with `present=1`; missing and successful mutations return 32 bytes with
`present=0`. Returned content is copied into the output buffer. Bytes beyond
the returned length are caller-owned tail and are not part of the result or
subject to a successful-call wipe guarantee. Every refusal preserves that
entire output buffer and the entire private workspace.

### Private storage

The 64-byte private header is `HVCSTA01`, version 1, used extent, entry count,
poison bit, then three zero words. The arena begins at offset 64. Each record
is `key_length:u64`, `value_length:u64`, exact key bytes, exact value bytes.
Offsets rather than pointers make trusted relocation possible. Replacing a
record uses final required size; it does not require room for both old and
new copies. Removal compacts retained records and clears the retired tail.
There is no implicit age or access-order eviction.

Structural metadata is validated before every active operation. This is
private trusted state, not an authenticated storage format or a general
deserializer for caller-provided snapshots. Tests inspect the full arena,
zeroed retired tail, and refusal snapshots. HIA's exclusive loans and the
packed table keep its workspace separate from other active modules.

## Applying the native view plan

Operation 8 accepts the complete 128-byte `HVIEWR01` header and its declared
text/cache payload. It validates exact framing, reserved words, supported
status/action/kind/hint fields and UTF-8. Cache action 0 does nothing, action 1
stores the exact cache payload without another normalization pass, and action
2 forgets the target. The already normalized payload may be an empty present
string. No unrelated key is affected.

The caller must preserve the view contract: capture the prior cache snapshot,
run prepare, **apply its cache action before render**, then render using that
prior snapshot. A later semantic result-size refusal or native output-capacity
refusal must not roll back the prepared cache update. The suite executes this
ordering, including a 900,000-newline cacheable input whose actual rendered
result exceeds the original 8 MiB response limit.

## Executed qualification and reference domains

The frozen source is `d363c2d3b06bf6d3de0ab20ad40ea3a090baf5d02fef9d280e54e6ef78c6cb01`.
Actual native image is `2c4841bcf5af5d931bd2f66fddf59ed9858a01090001812cceb05928db644602`.
The compiler remains the pinned `d3e2c90173cf733e42b299d0c4274df4b593a12f`.
Four qualified HIA byte/UTF-8/word helpers are imported with checked whole
function relocation; original source blobs and helper hashes are in
`view_cache_composition.json`.

Eight native test groups execute 13,873 cache image calls, 66 requests through
the actual persistent two-image ELF, and 13 calls to the actual frozen view
image. They cover empty/present distinction, exact raw contents, single CRLF
normalization, stale writes, normalized and raw 1 MiB boundaries, multiple
large entries, 1,500 retained small entries, subtree separators, Unicode keys,
independent sessions, context absence, real poison equivalence, relocation,
retired-tail wiping, and complete buffer preservation on refusal.

The Rust replay uses unchanged original `ViewCache` and mutation method
bodies, with declared admitted-key/context/lifecycle adapters. The actual
Rust compilation and complete 13,907-row replay succeeded on `ai395`:

| Domain | Rows |
|---|---:|
| Original cache operations, including contextual wrappers | 13,875 |
| Explicit initialization/destruction adapters | 22 |
| Actual original mutex-poison injections | 2 |
| Application of a native view plan through original set/forget | 8 |

13,841 replay rows came from cache image execution and 66 from the persistent
ELF. The 32 explicitly declared native-only refusals (17 frame, 6 capacity,
9 state) remain separate; none is counted as an original Rust operation.
Both outputs contain exactly 12,790,132 bytes with SHA-256
`78ee60da25ae71ce9982e812b51168ac93fb8b68b97c9a5efe4d110ced423fbc`.
The matching original result is a state-owner comparison, not a claim that the
Rust oracle reimplemented the native view renderer or all OS/session behavior.

The composition check admits both actual child images, compares their source
and compiler identities, and verifies the complete fixed ELF prefix, pointed-to
table, descriptors, workspace offsets, image bytes, hashes, and padding.
`view_cache_hex_transport.hepta` is a test-only root allowed to call only slot
1, with no syscall-effect privilege. The composition uses the unchanged frozen
OS8 packer; no packer modification or full cold qualification was needed for
this isolated component.

### View dependency update

The cache plan dependency is the bulk-rendering `view_render.hepta` source
`d7012a796fd83744bcfb4951d01a95d3bab63f9a7ed185ad035c4665989066a3`,
with actual image
`a1e5bc7cf485dd0d91521a3018c6e67e8fda5c85fcdbe1dfbb27fa37dca6e9c6`.
Its manifest SHA-256 is
`357356bf90e8a90dc025a8ee815e5d990e08e066a0e81dba9f14cd8f78f71144`.
The cache HIA source, cache image, transport and test inputs did not change.

After updating that dependency, both test processes actually ran again:
the eight-group native suite completed in 11.428 seconds, and the four-group
evidence suite completed in 1.377 seconds, each under its unchanged 180-second
process budget. All 13,873 direct cache calls, 66 persistent ELF requests,
13 actual view calls and ten evidence refusals passed. The selected compiler
and compile receipts were checked against 42 actual artifact identities. The
cache image was freshly compiled; the current view image had been compiled
and fully exercised in the same increment. This run reused the verified
compiler bootstrap and did not invoke the full cold gate.

All 13,907 exported rows, their complete request/output bytes and ordered domain
history are byte-identical to the earlier original-Rust comparison. The new
native capture is bound to that actual earlier replay by those identities.
This is explicitly not a new Rust invocation. The original replay receipt,
prior native observation and both earlier failed harness attempts remain
retained separately. Aggregate qualification must still perform its fresh
Rust compilation and complete replay.

### Reproduction interface

The native suite uses `HIA_CACHE_MANIFEST`, `HIA_CACHE_ELF_MANIFEST`,
`HIA_VIEW_MANIFEST`, and `HIA_HEPTA_DIR`. Optional development
`HIA_REFERENCE_RUNTIME` defaults to the containing repository, never to a
neighboring checkout name. `HIA_CACHE_CORPUS_DIR` creates a new gzip corpus
directory. `scripts/hia_native_view_cache_build.py` builds the two-image test
composition with the normal pinned builder and the exact source profile.

Compile the reference with
`rustc -O --edition=2024 tests/hia_native/oracle_view_cache.rs -o <binary>`, then
run `tests/hia_native/compare_view_cache_original.py --corpus <directory>
--binary <binary> --result <new-result>`. The replay driver verifies all input,
native-output and domain hashes, exact counts, ordered session lifetimes,
complete output equality, and the binary before/after digest. The enclosing
qualification recipe must bind its actual compiler invocation and source to
the supplied binary; accepting a precompiled path alone does not establish
that build provenance.

### Aggregate integration

`scripts/hia_native_view_cache_qualification.py` provides the required
verification and replay entries:

* `qualification_evidence(root, output, report, completed_test_summary)` checks
  the actual two test process receipts, complete native corpus, original and
  imported sources, pinned compiler, native compile receipts, independent
  view image, exact two-image table and ELF. The report uses module keys
  `view_cache` and `view_render`, plus a separate `cache_composition` fixture
  manifest. It requires the four-group, ten-refusal evidence-control suite;
  those controls add no native requests.
* `compare_original(root, output, report, rustc, completed_test_summary,
  record_check, env)` recompiles the original Rust oracle, runs the complete
  captured corpus, verifies actual process output and binary identity, and
  rechecks the native evidence. It never consumes the historical comparison
  JSON as a substitute for a fresh invocation.

Add `view_cache` to the ordinary borrowed-byte module registry with
`native/view_cache.hepta`, `HIA_CACHE_MANIFEST`, `test_view_cache.py`, and
additional test `test_view_cache_evidence.py`. Build the two-image fixture
with `build_cache`, store its relative manifest and SHA under
`report['cache_composition']` with builder `composition_fixture`, and set
`HIA_CACHE_ELF_MANIFEST`. Set `HIA_CACHE_CORPUS_DIR` to
`output / 'view-cache-rust-oracle'`. The verifier-control test reads this actual
output through `HIA_CACHE_QUALIFICATION_OUTPUT`, defaulting to
`Path(HIA_BUILD_ROOT).parent`. Qualifier-owned environment sanitation must
precede all of these assignments. The existing view module remains independently
qualified and supplies `HIA_VIEW_MANIFEST`.

Keep returned `artifact_sha256` and `corpus_sha256` maps in the aggregate's
retained input closure. Add the helper, builder, two tests, Rust oracle,
oracle-source adapter, comparison driver, transport HIA, cache HIA and source
composition to the normal strict source inventory. The Rust recipe is
standard-library only and is distinct from the view-render Rust recipe.

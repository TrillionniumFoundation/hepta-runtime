# Explicit native Evidence checkpoints

`rea_evidence_session_checkpoint`, `rea_evidence_session_resume`, and
`rea_evidence_session_list` add explicit durable retention to the native runtime.
They are separate native routes. The frozen REA session still starts empty, and
the existing import, export, projection, and Unknown contracts keep their current
behavior. A checkpoint does not enable automatic recovery or automatically save
subsequent observations.

## Authority and session behavior

All three routes require an authenticated HTTP operator credential. The existing
trusted caller-scope resolver supplies the stable credential owner; a session ID,
checkpoint ID, tool argument, or untrusted header cannot select another owner.
The stored owner digest is domain separated for this format. The existing runtime
policy binding must also match. Changing the credential or admitted policy hides
old checkpoints from listing and refuses resume. Returning to the same credential
and policy can authorize them again.

This is private operator credential scope. Separate MCP sessions using the same
credential can explicitly select its checkpoints; they do not automatically share
their live Evidence registries. This does not establish authenticated ChatGPT
end-user isolation. Checkpoint receipts state that distinction. Stdio refuses
checkpoint, resume, and list because its ephemeral transport scope provides no
persistent authenticated credential authority. Storage is implemented on Linux.

Resume requires an empty registry, including its Unknown revision history. It
first authenticates a complete candidate without changing the live session. The
last cancellation and empty-state checks run under the same session mutex as the
single state replacement. A concurrent import or observation makes resume fail
without overwriting that work. A repeated resume into an already populated
session fails explicitly. The caller can inspect that session after a lost resume
response or open another empty session and resume there.

## Routes

| Route | Arguments | Result |
| --- | --- | --- |
| `rea_evidence_session_checkpoint` | `{}` | Immutable `checkpoint_id`, full record and Unknown revision counts, payload sizes, whether identical content was reused, and confirmed file/directory durability. |
| `rea_evidence_session_resume` | `{"checkpoint_id":"ecp1_<64 lowercase hex>"}` | Complete counts and `restored:true` after atomic publication into this empty session. |
| `rea_evidence_session_list` | `offset` (default 0), `limit` (default 16, range 1–32), optional `expected_catalog_sha256` | Sorted checkpoint rows, counts, `next_offset`, `exhausted`, and the complete catalog identity. |

All parameter objects reject unknown fields. For list continuations, every
`offset > 0` requires `expected_catalog_sha256` from the first page. That identity
binds the owner, current policy, catalog format, and complete sorted set of
immutable checkpoint IDs. Creation, removal, corruption, or authority changes
cannot silently shift a continuation. A caller can supply the expected identity
at offset zero as well. Listing authenticates every visible complete checkpoint,
including payloads and retention metadata, before returning a page; it does not
only check the selected rows. Incomplete `.stage-*` directories are never listed
as checkpoints.

## Complete immutable format

The administrator's configured state directory contains
`rea-evidence-checkpoints-v1/<checkpoint_id>/` with exactly three private files:

| File | Contents |
| --- | --- |
| `manifest.json` | Required version/profile fields, owner and policy digests, both payload hashes and lengths, record count, and Unknown revision count. |
| `bundle.json` | The complete existing canonical Evidence bundle, including all retained records, manifests, and every Unknown revision. |
| `retention.json` | Versioned, complete per-record first origin and imported object-order authority. |

The checkpoint ID is `ecp1_` followed by SHA-256 of the exact canonical manifest.
The manifest binds the canonical bundle and retention hashes and lengths, owner,
policy, counts, and all format/profile versions. There is no fresh timestamp in
this identity: repeating exactly the same snapshot and authority selects exactly
the same create-only destination. Sidecar changes cannot keep an old ID merely by
updating its hash in the manifest.

Manifest and sidecar structs reject unknown fields and require every declared
field. The sidecar covers each record ID once, with no missing or extra records.
Imported object-order metadata is a flat list of paths, so its representation does
not double the original JSON nesting depth. Every actual object has one complete,
duplicate-free key sequence. Array shape, numeric index ordering, ordinary key
order, and duplicate-key replacement follow the existing admitted `ObjectOrder`
semantics. Metadata discarded by fixed-schema authentication is not resurrected.
An imported order cannot claim a native producing entry point.

Native origins are validated by traversing the existing response encoder over the
entire record into a bounded counting sink. Valid root field names alone cannot
authorize an unsupported nested producer order. Resume also runs the existing
bundle authentication, Evidence identities, Unknown history and relationship
checks; JSON syntax and file hashes alone are insufficient.

## Admission budgets

| Resource | Limit |
| --- | --- |
| Retained records | 2,048 |
| Retained Unknown revisions | 8,192 |
| Canonical bundle file | 128 MiB |
| Retention file and conservative order-building budget | 16 MiB |
| Manifest file | 4 KiB |
| Existing native parser materialization / token / depth | 128 MiB / 16 MiB / 120 |
| Checkpoint and staging directory entries in the store | 32 total |
| Store payload bytes, including incomplete staging | 256 MiB total |
| Concurrent blocking checkpoint owners in one process | 2 |
| Store-lock admission | 10 seconds, cancellation aware |

Record and Unknown revision counts are checked while holding the session mutex,
before cloning its retention maps. Snapshot payloads remain shared through `Arc`.
Serialization is bounded, and the exact serialized files must pass the same
parser and complete resume authentication **before staging begins**. A legal live
state that exceeds a checkpoint-specific budget therefore receives an explicit
gap and no successful checkpoint. No payload or Unknown history is truncated.
Recovery also checks the store byte budget before reading payloads; oversized
orphan staging cannot evade quota after a restart. Quota exhaustion requires
administrator inspection of durable state; these routes do not silently evict
checkpoints or delete unrecognized inodes.

## Commit, cancellation, and reconciliation

The blocking storage owner holds the existing runtime admission permit, its
bounded execution slot, and a descriptor-backed cross-process store lock until
the real work ends. Dropping the awaiting task cancels its child token but does
not release those owners while blocking filesystem work is still in progress.

Every create or reconcile admission confirms the complete configured state
directory parent chain with real directory synchronization, including parents
left by a failed earlier attempt. A newly created state path therefore cannot
receive a durability receipt merely because its internal checkpoint directory
was synced. The configured final state path is reopened without following a
final symlink and matched to its retained owner, mode, device and inode before
and after this step. Parent traversal keeps the trusted administrator path
policy.

New commits write all three files into an exclusive private staging directory,
sync each file, explicitly close it, and sync the staging directory. Immediately
before create-only `renameat2(RENAME_NOREPLACE)`, the store revalidates the staged
directory name, complete member set, file metadata/inodes, and actual file hashes.
It then syncs the parent directory and rechecks the final named directory and
members. A successful receipt requires all of those steps.

Before the rename, cancellation refuses publication and attempts to remove only
proven owned staging inodes. If the stage or a member was replaced, cleanup leaves
the foreign inode in place and returns an explicit incomplete-cleanup error.
After the rename, cancellation does not undo or relabel the committed observation;
the blocking owner continues through real parent synchronization. A late sync,
binding, or response failure returns no confirmed receipt and preserves the
visible content for reconciliation. Repeating the identical checkpoint validates
the complete existing content and confirms parent durability before returning
`reused:true`. List and resume also confirm parent durability for a valid visible
commit left by an interrupted prior owner.

The store opens private directories and regular files relative to retained
descriptors, rejects symlinks, hard links, foreign ownership and wrong modes, and
rechecks the configured state-directory name, checkpoint directory, and member
identity after complete reads and at every existing commit binding fence. Retained file
metadata binds manifest, bundle and sidecar observations together; replacing an
already read manifest cannot be combined with later payload reads. Catalog
responses retain those observations until their final binding checks.

The configured administrator state path and account are trusted. These checks
cover explicit directory/file replacement and commit boundaries; they do not
claim protection against arbitrary malicious code already controlling the same
Unix account. Files are private, not encrypted, and SHA-256 is content identity,
not a signature against an administrator capable of rewriting the entire store.

## Verification artifacts

`tests/fixtures/rea_evidence_checkpoint/unknown-verified.json` was independently
generated by the pinned `rea-agents` 6.8.0 original package using the existing
producer script and Node v22.23.4. Its SHA-256 is
`97e4e75d4e56c9c7eca22c91a0b0309be475141d22724027e96b3f1049c96215`.
The adjacent provenance and exact controller stdout bind package/tarball/Node
identity, producer/source input hashes, and the successful durable terminal
observation. Three Unknown revisions are retained. Native origin fixtures reuse
the independently generated APK service reference already in the repository.

Sibling unit tests exercise private filesystem admission, actual directory and
member swaps before and after publication, hash-consistent corrupted sidecars,
the native nested-order gap, all Unknown history, numeric/duplicate key order,
create-only retries, count/byte/token/depth budgets, stable catalog continuation,
and cancellation while the real commit lock and admission permit remain held.

The external `rea_evidence_checkpoint_external` test invokes
`tests/rea_evidence_checkpoint_http.py` against the shipping binary with fresh
generated credentials. It kills and waits for real HTTP server processes,
deletes the original import/APK inputs, verifies default empty sessions and
explicit same-credential recovery, compares complete content text and structured
object order, rejects changed credentials/policy and nonempty restore, exercises
catalog continuation and sidecar damage, and verifies all three stdio refusals.
It uses no production credential and contacts no configured remote host.

The separate [checkpoint upgrade runner](../../scripts/rea_evidence_checkpoint_upgrade.py)
requires explicit old/new executable and build-binding paths and SHA-256 values,
the selected checkout's `tests` directory and a new private output directory.
It also requires both original observations:

- `--original-public-observation` selects the pinned original REA cold-complete
  response that establishes the public Unknown member order.
- `--original-public-record-observation` selects the pinned original
  `reference-main/call-026-unknown-verified-complete.json`, together with its
  sibling `wire.jsonl`, `wire-0055-sent.json.gz` and `wire-0056-received.json.gz`.
  The exact original request/response bytes establish the observed sixteen-field
  record envelopes and this fixture's seventeen-field envelope containing
  `caller_input_path`. Current fixture values, paths and generic JSON child
  order remain intact when building the expected public response.

Each HTTP channel has its own expected serialization. Public content text
retains the original tool's observed member order; HTTP `structuredContent`
uses the fixed recursive object order of the bound Rust transport. Actual
responses are never reordered. Both channels retain exact within-version and
cross-version comparisons, including complete values and text bytes.

The old source is consumed from its historical Git objects and original matrix;
the new source must be the current clean, monitored, exact candidate. The
default entrypoint must be the selected checkout's script. An explicitly
reviewed external entrypoint additionally binds its real path, complete bytes
and SHA-256, and the replaced repository script's complete bytes and SHA-256.
Both sources are checked again at the end of the run.

Its finite Linux profile runs A → B → A → B using four real private HTTP servers.
It compares complete public values and text/order, adds two native records to the
three-record imported history, checkpoints all five records and three Unknown
revisions, waits for real termination before deleting source inputs, checks that
rollback leaves every checkpoint file byte and inode unchanged, then explicitly
resumes under B. Launch registration and owned shutdown defer soft cancellation
until process ownership and cleanup are established. A cancellation during final
verification also fails qualification. Raw responses, process identities, logs,
file observations and terminal receipts remain distinct from the final summary.
The profile does not establish automatic recovery, arbitrary version migration,
production deployment or whole-product cost benefits.

These are implementation and verification artifacts. Compilation, the focused
unit suite, the real HTTP run, and the next fixed-candidate full regression must
be recorded by the qualification controller; the presence of this document or
the fixture producer's success does not establish that those candidate checks
have run or passed.

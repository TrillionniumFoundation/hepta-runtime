# Retained model snapshot sessions

The native tools **rea_model_session_open**, **rea_model_session_query** and
**rea_model_session_read** remove repeated model-directory parsing from artifact
queries by capturing an explicit snapshot. A pathname, inode or modification
timestamp is never treated as immutable model content.

## Open once

~~~json
{
  "path": "/approved/models/model.safetensors",
  "expected_sha256": "COMPLETE_LOWERCASE_SOURCE_SHA256"
}
~~~

Open admits a read-only descriptor beneath controller workspace roots. Paths
within runtime state are refused even when a workspace root covers that state.
It streams the exact admitted length into a private snapshot while calculating
the complete digest and 1 MiB chunk digests. The required full digest and
ordinary concurrent source changes are checked. The source stays unchanged.

The isolated Rust model worker parses that snapshot once. Its internal complete
directory response has a separate 64 MiB ceiling and is never returned directly
over MCP. The controller validates the structure hash on the same descriptor.
Tensor/metadata rows become individually hashed 64-row files. A 256-bucket
tensor-name index supports selection without scanning the full tensor directory.

The manifest binds the full source digest, selected path, size, chunks, pages,
parser schema, actual authenticated owner and complete current runtime policy.
Its canonical SHA-256 becomes the **rms1_...** ID. The synchronized snapshot,
index and manifest are atomically published together with Linux
**renameat2(RENAME_NOREPLACE)**. Snapshot publication is currently qualified on
Linux only.

An identical open locates the previous manifest, verifies the current source's
complete digest and verifies all saved chunks/indexes before returning the same
ID. It does not parse the model again or require a new storage reservation.
Original-request reconciliation therefore works when the store is full.

## Query and read

~~~json
{
  "session_id": "rms1_MANIFEST_DIGEST",
  "collection": "tensors",
  "offset": 64,
  "limit": 64
}
~~~

Collections are tensors, metadata and summary. Each query verifies the manifest
identity and only selected index pages. It does not reopen the source, parse
its format, load the entire directory, scan the store, or read payload bytes.
At most 256 requested rows touch at most five 64-row pages. Summary returns
provenance, coverage and resource capabilities without reading payload or pages.

~~~json
{
  "session_id": "rms1_MANIFEST_DIGEST",
  "tensor_name": "weight",
  "offset": 0,
  "length": 64
}
~~~

Omitting tensor_name selects an absolute snapshot-file range. Named reads resolve
one name bucket and one tensor page. Unknown storage layouts cannot establish
verified tensor extents. Reads are limited to 64 KiB and verify each touched
1 MiB chunk, therefore at most two payload chunks. Private ownership, single
link, size and ordinary concurrent modifications are checked on the open file.

The result explicitly sets complete_snapshot_rehashed_this_read to false.
Capture hashed the complete file; subsequent reads verify only touched chunks.
Damage to an unrelated unread chunk is not represented as detected. Index
queries verify index contents, not the entire model payload. Hashes are integrity
commitments, not signatures authenticating a model author.

Query/read results include a deterministic result_sha256 over their response
before that field is inserted. The retained snapshot/index reproduces results
after restart. This does not extend the generic request-result archive to every
REA operation.

## Identity and recovery

The server supplies owner identity from its established authenticated binding.
There is no caller-controlled owner parameter. Open uses ordinary effect-owner
admission; query/read are observations. The scope is the runtime's authenticated
credential/principal: clients sharing one credential share that owner. This does
not introduce a distinct identity for each person using the same credential.

Every call checks that owner, exact current policy digest, parser schema and
recorded source-root membership. Different owners, changed policies or unknown
schemas refuse reuse. Possessing an ID does not grant access. Internal state
paths cannot substitute for session IDs.

Recovery requires the retained directory and the same authorized owner/policy.
The source can be absent or changed: queries return the captured bytes and never
silently switch to a newer file. A new model needs its new full digest.

A fresh anonymous stdio identity may change across controller restarts and must
not gain access to its predecessor's sessions. Cross-process recovery requires
an established stable authenticated identity, such as an existing HTTP principal
or a trusted native caller preserving its authorized owner. Identity checks are
not weakened for anonymous stdio.

## Budgets

| Resource | Limit |
| --- | --- |
| One snapshot / complete store | 32 GiB / 64 GiB |
| Published and staging directories | 32 |
| Index and manifest reservation per new snapshot | 128 MiB |
| Manifest | 4 MiB |
| Parsed header | Existing model-parser 16 MiB limit |
| Tensor / metadata rows | 100,000 each |
| Stored page / name bucket | 64 rows and 2 MiB / 8 MiB |
| Query | 1–256 rows; existing 1 MiB MCP output cap |
| Read / verified chunk | 1–65,536 bytes / 1 MiB |
| Open / query / read deadline | 300 / 60 / 60 seconds |

Cooperating publishers use an exclusive cross-process directory flock. Quota
scans occur only on open. New capacity is refused without evicting results.
Incomplete staging counts toward both quotas and is never a successful session.
Ordinary failures remove only their own staging. A crash or timeout can leave
staging for administrator reconciliation; automatic cleanup does not delete
another request's work.

After an uncertain publication reply, repeat the identical open while its
original source remains available. A caller holding the ID can directly read
the retained snapshot without the original. Administrator-owned private state
is the trust boundary; this is not hostile-same-UID or privileged-writer
isolation.

## Verification

Sibling executable tests cover source removal and same-owner reconstruction,
different owner/policy/root refusal, exact page/range results, source changes,
stable concurrent publication, capacity reuse, cross-chunk verification, targeted
corruption, damaged manifests/pages, state-path denial, symlinks, hard links and
staging quotas. A shipped-worker test captures a 9,000-tensor directory exceeding
the normal MCP response ceiling.

Test definitions alone do not establish qualification. Record actual results
from the configured development host and final integrated binary. Stable HTTP
cold-restart qualification is distinct from store-level same-owner recovery;
isolated test identities must not use production credentials.

## Cancellation and durable publication

The final publication worker owns both the actual cross-process store flock and an `Arc` of the server's effect-owner admission permit. It retains both through `renameat2(RENAME_NOREPLACE)` and parent-directory `fsync`. Dropping or timing out the awaiting MCP request does not release these guards while the actual commit is still running. An administrative owner freeze therefore cannot finish ahead of that admitted commit.

A cancelled or timed-out open has an **unconfirmed outcome**: the session may already be visible or may finish committing under the retained guards. No success receipt is returned before parent `fsync` succeeds. A visible rename followed by an `fsync` error is also unconfirmed. Retry the identical source path and expected SHA-256 with the same authenticated owner and policy to reconcile: open verifies the current source, manifest, complete retained index and all snapshot chunks, then confirms the parent directory with `fsync` before returning a reused receipt. This reconciliation parses the model directory zero times. It does require the original source; a caller which already retained a session ID can query/read its snapshot without that source.

Cancellation before the commit is scheduled can leave private staging, which counts toward both storage budgets and is never a queryable session. There is no detached publisher without the owner and store guards. Unit tests pause the real commit before rename and between rename and parent `fsync`, cancel the waiter, verify both real advisory locks remain held, then verify that the actual `fsync` completes before the locks are released. A separate injected post-rename failure confirms that mere visibility does not return a durable success.

## Discovering retained sessions after restart

The read-only rea_model_session_list tool takes no caller identity or path argument. Its server wrapper resolves the current authenticated owner, and the implementation enumerates at most 32 store entries. Only manifests bound to that owner and the exact current runtime policy are returned; IDs, paths, hashes, sizes and excluded-session counts for other owners or older policies are not disclosed. Restoring the same legitimate identity and policy makes its retained IDs discoverable after a controller restart, including after the original source file has been removed. An absent store returns an empty list; a published entry with an unreadable, malformed, mismatched or unsupported manifest returns an explicit store error instead of pretending that no sessions exist.

Each row includes the session ID, original path, full snapshot SHA-256, model format/version, byte and directory counts, and retained-snapshot semantics. Listing verifies the manifest identity and private snapshot inode/length but does not read the original source, parse a model directory or read/hash payload bytes. Index-page digests and accessed payload-chunk digests remain checked by query/read; listing does not claim a new full-content verification. Private incomplete staging is not listed as a recoverable session. The same credential/policy limitations as open/query/read apply, including the deliberately session-scoped stdio owner.

<!-- Copyright 2026 Muvon Un Limited -->
<!-- Copyright 2026 TrillionniumFoundation -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Observation socket cleanup after controller death

**Status: design proposal.** Automatic cleanup of a dead controller's socket
directory is not implemented or qualified here. Existing unknown artifacts must
remain untouched. This proposal concerns local observation sockets after
controller death on the same host and boot; it does not establish power-loss
recovery, target reboot recovery, or automatic host migration.

The measured implementation is A20. The reviewed A24 candidate has the same
relevant root, child ownership, master generation, and cleanup lifecycle code.
A24 had not completed qualification at the time of this source inspection;
this inspection itself supplies no qualification or adoption decision. A24
adds no crash cleanup mechanism. See the [A20 qualification receipt](evidence/x230-a20-qualification-20261023.json)
and the existing [execution durability boundaries](RUNTIME_DURABILITY_BOUNDARIES.md).

## What the recovery experiment establishes

The [public A20 recovery receipt](evidence/x230-a20-recovery-20261023.json)
records a controller SIGKILL followed by a fresh controller observing the same
six completed jobs:

| Observation | Recorded result |
|---|---|
| Before controller death | 12 calls, 12 successes, zero failures |
| After controller restart | 12 calls, 12 successes, zero failures |
| Original job identities and metadata | Preserved; no new private job identity |
| Descendant process observations | All 14 sampled process generations exited |
| Old filesystem artifacts after death and after recovery | One private root containing six socket entries remained |
| Separate verdicts | `read_only_recovery_passed=true`; `abrupt_cleanup_complete=false`; normal shutdown of the replacement controller passed |

The experiment sent no signals to descendants, deleted no socket artifacts, and
performed no automatic RPC retries. Fourteen is a set of sampled generations,
not an exhaustive census or a claim that all were alive at the instant of
SIGKILL. The receipt retains resource sampling permission errors. Successful
readback therefore establishes neither complete process containment nor
complete filesystem cleanup. The [recovery helper](../tools/x230/x230_controller_recovery_check.py)
and receipt preserve these separate outcomes.

## Current ownership checks and their lifetime

The current mechanisms are in
[ssh_observation_pool.rs](../src/mcp/runtime/ssh_observation_pool.rs) and
[ssh_observation_profile.rs](../src/mcp/runtime/ssh_observation_profile.rs):

| Current mechanism | What it checks while the owner exists | What is missing after abrupt death |
|---|---|---|
| `PrivateRoot` | A fresh random namespace, a held directory descriptor, and root/parent identity checks | A committed record binding a later cleaner to the original root |
| `OwnedChild` and the children ledger | The original `Child`, pidfd, process birth, UID, executable, and argument identity govern process ownership | The original capabilities and a persistent, complete producer census |
| `Master` | Generation ownership, socket `Stamp`, and peer binding before readiness | Recoverable expected identities for old generations and sockets |
| `unlink_socket` | Root verification and an exact expected socket stamp before descriptor-relative unlink | Authority to classify an old, previously unrecorded entry |
| `shutdown` and `PrivateRoot::drop` | Owned child cleanup, removal of known sockets, then empty-root removal | SIGKILL does not execute this shutdown or destructor sequence |

The command setup requests parent-death signaling. That request is not a receipt
that every possible producer has terminated. A fresh controller creates its own
namespace and validates its current authority; it does not adopt the old
directory. That separation allows read-only job recovery without deleting old
sockets.

These checks must not be expanded into a claim of atomic deletion against a
non-cooperating writer with the same UID. The path race described below also
limits what a future cleaner can guarantee.

## Proposed eligibility: a deliberately limited subset

A future cleaner could consider an owner only when all of the following have
been established:

1. A complete, supported, bounded ownership record was committed in a configured
   and verified registry before the relevant effects. A discovered manifest
   inside an old directory cannot grant itself deletion authority.
2. The registry, parent, root, generation, and individual socket still match
   their recorded identities. No unresolved creation or publication intent
   leaves a possible producer or entry unaccounted for.
3. The original controller and every process capable of publishing or replacing
   entries have been proved terminal. Sampling, a stale heartbeat, a missing
   PID in an unverified view, and connection failure do not satisfy this test.
4. Cleanup has exclusive access to the relevant names, with a stable ownership
   and locking protocol. Every deletion is limited to an individually recorded,
   verified entry; the root is removed only when verified and empty.

The six observed legacy sockets do not have these committed records. They are
outside this proposed subset. There must be no retrospective registration based
on filenames, present-day stamps, or the apparent age of a directory. Unknown
entries and incomplete records remain available for reconciliation.

### Minimum persistent facts

Records would live outside the candidate socket tree. Owner and generation
identities must never be reused. The existing random root nonce could identify
the owner without lengthening the constrained SSH control socket path.

| Record | Required facts and limits |
|---|---|
| Protocol and ownership | Version, bounded lengths, owner identity, monotonic sequence, integrity checks, and a stable lock identity. A checksum detects corruption; it does not authenticate ownership. |
| Host and process boundary | Host/boot binding, PID namespace and UID mapping boundary, original controller PID, birth identity and UID, and the trusted observation method. An executable or argument change is not evidence of death. |
| Root | Verified registry and parent identities, one-component relative root name, root device/inode/UID/mode and filesystem/mount binding, and committed owner marker identity. Persistent metadata alone is weaker than a retained descriptor. |
| Generation and producer | Generation, intended socket name, pre-spawn intent, actual producer incarnation, and original process proof. Pending intent means a producer may exist. |
| Socket publication | Exact relative name and full `Stamp`, generation, verified peer-to-producer binding, and commit sequence. A later observation cannot recreate a lost expected stamp. |
| Retirement | Terminal proof, unlink intent, confirmed removal and directory synchronization, root removal, and an external tombstone retaining the owner binding. |

The producer set must be justified from the pinned execution modes. Excluding
slave or effective-configuration processes requires proof that they cannot
create, transfer, or retain relevant namespace-writing authority. A sample of
descendants cannot justify that exclusion. Filesystem cleanup and complete
process/descriptor cleanup require separate verdicts.

### Commit order and unavoidable gaps

The proposed order is:

1. Commit owner preparation and stable lock identity; create and pin the root;
   commit its identity before allowing a socket producer to start.
2. Commit generation/spawn intent; spawn and validate the original child;
   commit the actual producer proof.
3. Validate root, socket stamp, and peer binding; commit socket publication;
   only then publish readiness to waiters.
4. During retirement, prove original producer termination, commit deletion
   intent, verify and unlink the recorded entry, synchronize the directory, and
   commit the result. Remove only an empty verified root and retain an external
   completion record.

Record replacement and file/directory synchronization need explicit success
results. A failed or incomplete commit cannot authorize dependent work.
This is a proposed protocol, not an existing journal or a power-loss test.

A controller can still die after creating a root but before recording its
identity, after spawning a child but before recording its proof, or after SSH
binds a temporary or final socket but before publication is recorded. Those
windows leave uncertain objects. Logging intent does not make them safe to
delete. Recovery of the cleaner itself must preserve the same distinction
between intended, observed, and committed effects.

## Death proof, concurrency, and path replacement

The strongest process evidence is an independent trusted holder retaining the
original pidfd or `Child` and observing that object become terminal. No such
cross-controller holder exists in this design's measured implementation. A
serialized descriptor number does not preserve that capability, and a later
cleaner cannot recover original parent/wait authority from a numeric PID.

A persistent-record approach needs an independently trusted kernel observation
bound to the recorded host, boot, namespace, and incarnation. Verified absence
in that boundary can support termination; a different birth identity identifies
a replacement that must not be signaled. Permission errors, unsupported
namespace changes, ambiguous handle binding, or mere path lookup failure remain
unknown. Observing termination as a non-parent is distinct from reaping the
original child. This proposal grants no signal authority to reconstructed PIDs.

Cooperating owners and cleaners need a stable lock object throughout the
namespace lifetime. Recreating a missing lock file can create a different inode
while another participant still holds the old one. A new controller always
uses a new owner identity; no heartbeat expiry authorizes takeover. Names must
be validated single components, with descriptor-relative operations and no
symlink traversal or recursive deletion.

**The final-name race is a real blocker.** A stamp check followed by
`unlinkat(name)` is two operations; unlink does not accept an expected inode.
Holding the directory descriptor avoids ancestor path re-resolution but does
not prevent a leaf replacement between those operations. Protocol locks do not
exclude a non-cooperating writer with the same UID. A stronger write-exclusion
mechanism or an explicitly narrower supported trust model is required before
claiming safe destructive cleanup under those conditions. Rechecking twice or
renaming to a quarantine directory does not resolve that authority problem.

Persistent stamps and checksums also do not resolve forged ownership records,
inode reuse, or unsupported mount changes. If the registry's trust and the
original object's identity cannot be established, preserve the artifact.

## Required fault-injection evidence

These are proposed qualification requirements; this document reports no new
cleanup implementation or fault-injection results.

| Failure or race | Required outcome |
|---|---|
| Legacy or forged same-prefix directory; unknown entry | Report and retain; never infer origin or create missing proof |
| Live or paused owner; expired heartbeat | No takeover or cleanup |
| PID reuse, namespace/boot mismatch, or observation denial | No signal to a replacement; unsupported or uncertain ownership remains unresolved |
| Truncated record, checksum failure, sequence rollback, unknown version | Bounded rejection; no deletion |
| Death around every root, spawn, bind, publication, or commit boundary | Uncommitted identities and unresolved producers remain uncertain |
| Producer not proved terminal | No early socket unlink |
| Root/parent/socket replacement, symlink, ordinary file, unknown directory | No deletion of replacement or unknown objects |
| Forced leaf swap between check and unlink | Expose the atomicity gap; no destructive qualification without effective exclusion |
| Two cleaners alongside a fresh controller | One valid cleanup owner; the fresh namespace remains unaffected |
| Cleaner death after unlink but before commit, or during root removal | Conservative reconciliation of known absence; no socket recreation or command replay |
| Write, sync, rename, unlink, disk-full, or read-only failure | Incomplete verdict; no false completion or dependent deletion |
| Readback of the original completed jobs after cleanup | Same identities and outputs; no new job or RPC retry |

Unknown entries can keep a root present after all eligible sockets are removed.
Report per-entry progress separately from whole-root, process, and readback
outcomes.

## Cost and feasible next work

This protocol would add persistent writes and synchronization at lifecycle
boundaries, registry parsing, locks, and identity checks. Qualification must
measure startup, master renewal, and shutdown latency alongside throughput,
CPU, memory, descriptors, and storage writes. Bound the number and size of
records, unresolved owners, and concurrent cleaners. Compaction must preserve
unresolved intents and ownership proofs; capacity pressure cannot silently
discard them or authorize deletion.

Closing every publication gap would require a larger mechanism: for example,
an independent lifetime keeper retaining original capabilities, a controlled
socket publisher, or authorized containment with a trustworthy emptiness proof.
Each changes process lifetime, resources, permissions, and failure handling.
None is present or qualified here, and merely adding a manifest does not supply
those properties.

Two smaller investigations are possible before destructive cleanup: a bounded
read-only inventory that classifies legacy, complete, live/uncertain, and
conflicting records; and an evidence-only journal for new owners to measure
commit windows, corruption handling, and cost. Neither should connect to old
sockets, signal reconstructed processes, backfill legacy authority, or delete
artifacts. Read-only recovery remains independently useful while safe cleanup
eligibility is unresolved.

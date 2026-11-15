# A27 socket custody: a bounded design and explicit implementation gates

**Design only. No automatic socket recovery or deletion is implemented by this
work.** The baseline is the exact qualified A26 source at commit
`65690e5bf8094888524ca2c2cd3cf4d01d846dc6`. The A26 completed-job recovery
experiment retained one directory with six old sockets despite successful
same-job recovery. Those legacy objects remain outside any proposed cleaner.

The useful next slice is a lifetime owner that keeps the original capabilities
when the controller dies, followed by an explicit namespace-mutation boundary.
Adding a PID, nonce, timestamp, or unlocked file to the current startup path
does not provide those two properties. This conclusion concerns socket
reclamation, not the independent A27 throughput and sampling work.

## What A26 actually owns

The following references are to
[`ssh_observation_pool.rs`](https://github.com/TrillionniumFoundation/hepta-runtime/blob/65690e5bf8094888524ca2c2cd3cf4d01d846dc6/src/mcp/runtime/ssh_observation_pool.rs)
and
[`ssh_observation_profile.rs`](https://github.com/TrillionniumFoundation/hepta-runtime/blob/65690e5bf8094888524ca2c2cd3cf4d01d846dc6/src/mcp/runtime/ssh_observation_profile.rs).
Their exact hashes are retained in the
[source evidence](evidence/x230-a27/recovery/source-evidence.json).

| Boundary | Existing implementation | Missing after controller SIGKILL |
| --- | --- | --- |
| Root creation | `PrivateRoot::create` creates an unpredictable name through a pinned parent, opens the new directory, and stores parent/root stamps. It checks the OpenSSH temporary-path length allowance. | The open directory and its trusted in-memory origin disappear. The name contains a PID and random bytes, but has no durable enrollment protocol. |
| Child creation | `Core::spawn` creates the child, opens a pidfd, registers the original `Child`, then performs fallible post-exec proof. | The registry, original process handles, approval state, and charged permits are not recoverable from a directory name. |
| Socket publication | `start_master` rejects an existing name. `master_socket_readiness` waits through a two-link publication state, then requires one link, the owned peer PID/UID, and an unchanged socket stamp. | A crash can occur before readiness, with temporary or partly published names. Persisting only ready masters cannot describe all such entries. |
| Orderly cleanup | `Core::shutdown` stops/reaps registered children, drains validation, and unlinks accepted sockets. Unknown entries prevent root removal. A26 also has the unconditional owner-side validation drain. | SIGKILL bypasses the Rust cleanup and both drains. |
| Path deletion | `unlink_socket` checks the socket stamp, then calls `unlinkat` through the pinned root. Root removal checks identity before removing a pathname. | There is no atomic inode predicate tying a previous check to the later named deletion. |

`Core::command` installs `PDEATHSIG(SIGKILL)` and checks the parent after setup.
This requests child termination; it is not an observation that every writer
has terminated or been reaped. Linux defines the relevant parent as the
creating thread, and does not send the signal if that parent was already dead
before setup. A26's persistent owner thread and post-setup check matter here.
See the primary [PDEATHSIG documentation](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html).

The existing stamp checks reject replacements observed before cleanup. The
counterexamples below demonstrate the limit of the subsequent filesystem
primitive; they do not show that a real unrelated object was deleted in A26.

## Four prerequisites for deletion

Any future destructive recovery must satisfy all four prerequisites before
its first namespace mutation:

1. **Origin:** the generation and exact objects were enrolled by a trusted
   owner before they became usable. A random name distinguishes generations;
   it does not authenticate a manifest that another same-UID writer can edit.
2. **Writer completion:** every admitted socket writer is terminal, and no
   new writer can be admitted. Preserve original child/pidfd custody or use a
   proven OS lifetime mechanism. A record containing a numeric PID is not that
   capability. Boot and PID-namespace identities and birth stamps are useful
   corroboration and diagnostics, not replacements for it.
3. **Exclusive namespace mutation:** no actor outside the cleaner can replace
   entries between inspection and deletion. Cooperating-owner exclusion and
   a boundary against an uncooperative same-UID writer are different contracts.
4. **Exact scope:** reopen through checked descriptors, bind parent/root and
   every authorized leaf, reject unknown entries or changed stamps, and never
   turn partial publication or an I/O error into deletion permission.

Linux `flock` belongs to an open file description; forked/duplicated descriptors
share it, and explicit unlock or closing the last descriptor releases it.
Ordinary local advisory locks do not prevent other permitted writers from
ignoring the protocol. Inheriting a descriptor therefore needs a separate
proof that the executable keeps that descriptor for its entire writer lifetime.
Our fixed Python helper deliberately closes it; this is not an installed-SSH
behavior test. See [flock documentation](https://man7.org/linux/man-pages/man2/flock.2.html).

Linux `unlinkat` accepts a directory descriptor and a name, with no expected
inode argument. The pinned directory controls where lookup begins, while the
name still resolves at mutation time. A symlink's own name can be removed
without following its target, which still does not authorize removal of an
unexpected replacement link. See [unlink documentation](https://man7.org/linux/man-pages/man2/unlink.2.html).

A same-UID `0700` directory, `chmod(000)`, a second stamp check, and an advisory
lease do not by themselves supply prerequisite 3: an owner of the directory
can change its permissions again. Moving a candidate into a random quarantine
also needs this prerequisite. Otherwise the rename can move an unrelated
replacement, and a later failed check cannot guarantee safe restoration.

## Smallest credible owner slice

The first implementation experiment should be a **standalone custody harness**,
with one controller, one surviving owner, and one controlled socket writer.
It should not yet transport runtime requests or scan historical roots.

The owner creates the generation root and is the actual parent of the writer.
It retains the original `Child`, pidfd, root descriptor, accepted socket stamp,
and finite admission state. The controller receives only an inherited,
bounded IPC channel. No writer is created by the controller and handed to the
owner afterward: controller death in that handoff interval would recreate the
missing-custody problem. The owner must survive the deliberately killed
controller, so it cannot share a controller-wide kill scope that defeats this
separation. Whole-process-group death is a separate failure mode.

On channel EOF or verified controller death, the owner freezes admission,
stops/waits/reaps its original children, drains actual validation work, and
reports retained or removed fixture artifacts separately. The EOF channel
must not be inherited by writers, or their extra descriptors could conceal
controller death. Deadline, cancellation, and all eight/two worker limits
remain real lifetime limits; no request is automatically replayed.

This slice can prove continued original-child custody during a controller
crash. It does **not** solve uncooperative same-UID namespace replacement.
General deletion remains disabled until prerequisite 3 has an OS-enforced
answer, such as a separately protected namespace/ownership broker that can
revoke other writers' directory-mutation authority. The current account-owned
directory contract supplies no such broker. No privileged installation or
namespace-policy change is part of this proposal.

If the custody experiment succeeds, moving the existing `Core` into that owner
is preferable to duplicating its authority checks in a new cleanup daemon.
The necessary integration is substantial but bounded:

- A private inherited IPC entry point, authenticated by inherited capability,
  with a versioned, byte-bounded request/reply protocol. It must not expose an
  arbitrary-command or arbitrary-path interface.
- The existing pinned profile, host allowlist, agent checks, child ledger,
  readiness logic, fairness, cancellation and output bounds remain on the
  lifetime owner. IPC must preserve the original deadline; transferring a
  request must not reset its budget.
- A controller shutdown waits for the owner's complete result. An owner that
  is still draining blocked I/O remains an observed, bounded outstanding owner;
  a timeout does not permit another cleaner to take over its objects.
- A profile-generation admission fence prevents repeated controller crashes
  from silently creating unlimited unresolved owners. That fence controls
  admission; its release alone still cannot authorize old-root cleanup.

This adds a process, IPC descriptors, supervision, and possible durable writes.
It therefore needs its own qualification and overhead measurement. It is not
a small startup sweep and is not proposed as an unmeasured performance win.

## Durable protocol if later owners must reconcile state

A durable ledger can retain evidence if both controller and owner die. It
cannot recreate their original handles or grant missing namespace authority.
The initial safe use is diagnostic: an incomplete generation blocks adoption
or deletion and remains explicitly unresolved.

Use a versioned, bounded manifest with a cryptographic generation nonce,
profile digest, parent/root device and inode, UID/mode, relative generation
names, complete accepted socket stamps, and boot/PID-namespace/birth metadata
for diagnostics. Reject duplicate fields, unsupported versions, unsafe names,
symlinks, unexpected links, mismatched metadata, and excess record counts.
Recheck the existing OpenSSH path budget for every generated pathname.

| Transition | Publication rule | Crash outcome |
| --- | --- | --- |
| Root intent | Allocate a nonce in the protected ledger before a writer is eligible. | An intent alone authorizes no directory or socket deletion. |
| Root committed | Create/open the private root; bind its identity; publish the complete record with file and containing-directory synchronization before writer admission. | An uncommitted root remains unresolved. Its name is not reconstructed into authority. |
| Writer admitted | The surviving owner creates and keeps the original writer. Record the intended generation before releasing it to create a socket. | If custody is lost or admission completion is unknown, retain the generation. |
| Socket ready | Require the original owned peer and single-link stable socket; commit its exact stamp before exposing it for requests. | Temporary or two-link names remain outside the ready set. |
| Draining | Freeze all admission and wait for original handles; never infer completion from unlocked state. | A draining or blocked owner retains authority and its limits. |
| Writers terminal | Record completion only after the original lifecycle evidence; acquire and retain the namespace-mutation boundary. | Missing completion or a lost boundary prevents cleanup. |
| Leaf/root removed | Under that boundary, verify exact known entries; synchronize each namespace mutation before marking it complete. Remove only an empty, verified root. | A journal entry lagging a deletion is an explicitly partial state, not permission to sweep remaining names. |
| Closed | Commit completion while keeping enough stable lease/manifest identity to exclude competing reconcilers. | Later metadata reclamation is a separate bounded protocol. |

File-and-directory synchronization makes the publication order explicit; it
does not establish power-loss guarantees for every filesystem or device.
Unknown/torn records confer no authority. Never unlink and recreate a lock
pathname while another owner can hold the old inode: that would let separate
lock objects appear to protect the same generation. Two simultaneous cleaners
must operate on the same pinned lock/manifest identity and admit at most one
generation transition. Old A26 roots and unsupported ledger versions are
reported without adoption, signalling, renaming, or deletion.

## Deterministic counterexamples prepared for x230

`ownership_counterexamples.py` has four fixed cases and no path arguments. It
uses only newly created private fixture roots under `/tmp`; it never scans an
old socket directory or invokes SSH. Its sole child is the current Python
interpreter running a fixed descriptor-gated helper. On an error, only that
original `Popen` child can be stopped, and uncertain fixture cleanup is retained.

| Case | Counterexample |
| --- | --- |
| `inherited_lease_release_does_not_end_writer` | The helper closes its inherited lease descriptor. After the original holder also closes it, a new opener obtains the lock while that helper remains alive, then the helper writes while the new lock is held. |
| `checked_socket_name_can_be_replaced` | An owned socket passes a check, is renamed aside, and a second owned socket takes its name. Descriptor-relative name unlink removes the replacement. |
| `checked_socket_name_can_become_symlink` | A replacement symlink is removed by the same name operation; its target is preserved. No-follow behavior does not establish the link's ownership. |
| `checked_empty_root_name_can_be_replaced` | A checked, pinned empty directory is renamed aside; name-based removal removes a newly created replacement directory. |

The receipt explicitly states that success means the unsafe inference was
reproduced. It makes no claim about installed SSH descriptor behavior,
PDEATHSIG timing, a real controller SIGKILL, or an implemented recovery fix.
The parent and fixed child have passed local AST checks only at draft creation;
root owns the single x230 execution and its result publication.

## Required implementation tests and useful diagnostics

Before any cleaner is enabled, require controlled crash barriers before and
after every transition above, including a crash during cleanup itself. Add
original-writer survival, missing pidfd, PID-reuse records, simultaneous
owners/cleaners, replaced lock inode, changed root/parent, symlink and hard-link
substitution, partial socket publication, malformed/truncated records, sync
failure, blocked I/O, and unsupported legacy instances. Each refusal must
leave the unknown object untouched. A passing controller-crash test cannot
stand in for owner death, reboot, power loss, or arbitrary remote effects.

Useful progress is possible before deletion: expose bounded in-memory counts
of admitted/ready/draining masters, retained-child and validation work, exact
cleanup refusal categories, and owner exit outcomes. Distinguish socket names,
accepted stamps, live observed peers, and unresolved publication entries.
A read-only inventory can report type/stamp and observation errors for
explicitly scoped roots without connecting to unknown sockets, accepting
their manifests as trusted, or proposing a deletion command. These diagnostics
should preserve complete counters while declaring any preview/detail limits.

The current decision is to retain the legacy residue and publish this concrete
custody/namespace gap. No runtime deletion patch is produced under an ownership
claim that the available primitives cannot yet support.

# R34 independent static review

**Conclusion: no blocking issue found in the frozen candidate.** This is a source review and read-only byte/hash comparison. No Rust compiler, formatter, application test, fixture, benchmark, Mac API, or x230 API was used during this review. It does not establish build correctness, performance, or adoption.

Reviewed package: `/tmp/hepta-runtime-recovery-20261106/r34`. Accepted baseline: `baab4def80be7af015b2e7a594cb302f66c4130e`. Candidate patch: 22,870 bytes, SHA-256 `1a73c219fcfd2a273354bcbe0e1eb3f2ba629b1eb9f4969591352c6dd1a4ffc0`. Frozen manifest SHA-256: `22c24ee1f14d1c267d2b88d14919b2fd6c35035af342f56a4c486ce776b1f90c`.

## Findings

| Boundary | Independent review |
|---|---|
| Ordinary-first selection | `ssh_direct.rs:560–612` tries ordinary admission, target, and global permits synchronously. Returning `None` or an error drops every acquired local permit before reserve admission or reserve waiting. An encountered closed semaphore is an error. No request waits on reserve capacity while retaining partial ordinary capacity. |
| Capacity | Ordinary limits remain 8 global, 2 per configured `ssh_target`, and 16 admitted identities. Reserve adds 1 global permit and 8 admission permits. Every reserved child retains that single global permit, so absence of an ordinary host permit cannot add more than one child to any target. Combined upper bounds are 9 execution permits, 3 per target, and 24 direct-transport identities. These are per controller and configured target string, not a quota shared by aliases or other controllers. |
| Owner channel | Production `mpsc::channel` is 9 at line 453. Every queued request already owns one of at most 9 execution permits. The new test at `ssh_direct_tests.rs:993–1045` reserves nine entries on the actual production sender before publishing a request, so the receiver cannot conceal an incorrect eight-entry channel. |
| Deadline and stop | Reserve waiting uses the unchanged absolute SSH deadline. `active` runs before selection, before reserve acquisition, after reserve readiness at line 607, and again in the original send/spawn/reply path. The test at lines 1049–1082 deliberately repolls only after both capacity and expiry/stop are ready. No fresh timeout or automatic retry is introduced. |
| Original-child custody | `capture_admitted` transfers the complete leases through the original request to the original `OwnedChild`. The queued/committed cancellation CAS, registry-before-spawn protocol, original-child wait, persistent cleanup deadline, and release-after-confirmed-reap remain intact. Caller abort and uncertain-wait fixtures at lines 1086–1185 cover reserve custody and persistent failed shutdown. |
| Cancellation scope | `jobs.rs:4571–4579` contains exactly two transport-call substitutions, both after full receipt validation and cancellation intent publication. The system wrapper constructs the same fixed cancel request; the Python branch keeps its bound helper, request, and 45-second timeout. Public ordinary SSH/Python/jobctl entry points remain ordinary. No user-selectable admission mode is added. |

Independent byte comparisons returned true for unchanged `ChildState`/`OwnedChild`/`Core`, cancellation state machinery, the full post-admission capture body, and shutdown/shared-owner/guard code. The ordinary acquire body changes only the host permit's `Some(...)` wrapper. The complete jobs file equals R24 plus the two identified call substitutions. Baseline and candidate maps both contain the same 220 keys, with exactly the four declared source files changed; their on-disk hashes match the candidate map.

All eight new test bodies and their existing owner/child fixtures were read. No definite Rust type, ownership, borrow, or Clippy issue was identified. In particular, sender permits borrow the live owner until publication, the pinned reserve future does not require moving `Owner`, and `Owner::finish` takes `&self`. This remains a static assessment; the original full qualification and CI gates are still required.

## Limits retained for measurement

The single ordinary-first decision is deliberate: a cancellation already waiting for the reserve does not reconsider ordinary capacity that later becomes free. This can delay work behind a reserved child; the README states that tradeoff accurately.

The candidate adds two semaphore allocations, one logical channel slot, optional host-permit storage, an extra possible transport child, and up to eight extra direct-transport identities. CPU, allocation, RSS, and latency effects are unmeasured. The 24-identity bound does not cover every upstream request allocation: JSON/script preparation still precedes direct admission. The existing job cancellation publication bound of 8 and preparation bound of 2 also remain in force, so eight slow cancellations followed by a ninth cannot by themselves test reserve entry through the public API.

No source, manifest, existing evidence, or Git ref was modified by this review. R31 pidfd, R32/R33 profile changes, router sharing, and JSON deferral are absent from this R24-based candidate.

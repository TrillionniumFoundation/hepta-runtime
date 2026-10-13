# V9 integrated bounded asynchronous request candidate

Full Desktop Commander replacement qualification remains **false**. Production still uses the installed V4 native runtime and facade, with Desktop Commander retained as the rescue channel. This slice adds real bounded asynchronous lifecycle behavior; further general operation/result support is being developed separately.

| Integrated input | Exact identity |
| --- | --- |
| Compile input fingerprint | `b376418a2b3346a707dfd2592f99ce6fbceb6c86c8445995069f1e4ac0ed32bf` |
| Optimized native binary | `92c3ae0eb64e8d2213e4938312ae636a2ab6d18ef417b2167086d0737d7664ce` |
| V9 contract | `3eb628812d0c70b9af8393ecf9d0ce47f69b1438a134148f75ae2dd3132e6761` |
| Approved successor loader | `0b039e2d667314fec32bde7827fd0f9ad01d35b8d3199e73a1e036c7b1eb3dde` |

## Behavior and boundaries

- `request_start` durably reserves an inner request ID and required idempotency key for exactly three typed, read-only operations: `host_list`, `host_health` on a configured host, and `effective_config`. The outer MCP audit request has a separate identity.
- The owned worker survives normal early SDK response cancellation and private-credential client reconnect. `request_cancel` controls that worker's future; it never accepts a caller-selected PID or signals an arbitrary process. Cancellation does not undo remote effects.
- A controller-wide limit of eight active requests and four per owner is enforced before new admission. Existing-key reconciliation and lookup remain available at capacity. Durable bindings are bounded at 128 keys per owner and 512 globally; a full store refuses new keys without rebinding or eviction.
- Identity-indexed intent, key-indexed primary record, and independent occupied-key record must form a complete consistent graph. Partial loss, mismatched audit identity, changed anchored directories or lock inodes, corrupt records, or policy/credential mismatch refuse access and admission. There is no automatic repair, replay, or execution resume after controller restart.
- V8 result retention continues to cover only the three reviewed successful DTOs, with a 64 KiB original native SDK snapshot and pages of 1..16384 bytes. Arbitrary file, process, image, document, or error output is excluded from this ledger.
- Admission reports `delivery_proven: false`. This implementation does not establish authenticated ChatGPT-user or tenant isolation. Ownership follows the verified private operator credential; native process/PTY resources retain their operator-account scope.
- All V8 tool definitions, including the original V4 subset, remain exact. The two new lifecycle definitions do not constitute replacement qualification.

## Preserved failure and correction

The first integrated Rust 1.99 full run passed 571 tests and failed the owner-capacity test with `EAGAIN` while acquiring a short metadata flock. A deterministic new Rust test reproduced the failure with an owned forked child retaining the same open-file description. The short metadata lock now explicitly unlocks before closing its parent descriptor; the long controller ownership lease retains its separate behavior. The corrected test passed, and its child cleanup uses non-reaping `waitid(...WNOWAIT)` observation and disarms signal ownership on `ECHILD`.

Original failed logs, original source maps, the pre-fix counterexample, independent causal fixture, source review, and every subsequent source map remain in `docs/qualification/dc-functional-v9-integrated-evidence-20261013`.

## Actual checks completed before source publication

The final frozen source passed Rust 1.99 format checking, strict all-feature/all-target Clippy, both default and all-feature/all-target tests (573 main tests plus 8 jobctl tests, 11 ignored), and debug/release build commands with identical before/after compile input maps. Fresh local native protocol cohorts passed catalog 14, retained results 12, asynchronous private fixed-health fixture 13, historical V4 operations 13, directory move 16, workspace guards 5, and concurrent text publication 6. New integrated mock/AST safety suites passed 18 and 24.

The fixed-health asynchronous cohort uses a private emulation fixture. It supplies no real six-host, production, model-origin, business, or DC-off qualification. The latest preceding pushed commit `3c924c0` has successful exact-head GitHub Actions run 38454185490; CI for the commit carrying this new source must be observed separately.

## Remaining qualification and engineering

Fresh postcommit six-target cohorts must bind this exact source commit, binary, contract, helpers and harnesses. The new rollback harness preserves the original eleven compatibility checks and adds six ledger checks per host, including two V9→actual copied installed V4→V9 ledger round trips. Its preparation and mock results are separate from real execution.

Concrete staging, read-only production preflight and exact private rollback backups remain required. First production maintenance still needs a workable dispatch admission/drain boundary for installed V4, legitimate administrator Refresh/Review and genuine new-tool model-origin calls, agreed real business workflows, and then an explicitly authorized P3 DC-off drill with out-of-band rescue. Vendor-only DC actions need truthful user/admin disposition. General asynchronous native operations and arbitrary-output recovery remain engineering work; the V9 three-DTO slice does not close those gaps.


## Postcommit continuation

The source carrying V9 is committed and pushed as `50372629e0522d19b5bc4c1a800bfc311e4597f9`. Its exact-head GitHub Actions run 38462662781 completed successfully. A separate detached source checkout remains frozen at that commit; subsequent documentation or checker commits do not relabel its artifact or acceptance.

Fresh R15 native private-controller rollback passed 17 checks on each of main, pocket4, rog, mac, x230 and ai395 (102 total). The original eleven job/PTY compatibility checks ran before six new ledger checks per host. Thirty-six retained snapshots preserved original IDs, bytes and SHA pins through actual copied installed-V4 rollback, and six configured SSH acknowledgement gates preserved the same idempotency key without redispatch. Twelve owned wrapper/SSH incarnations were absent/reaped; all owned controller/target fixture cleanup completed. R16 independently passed real configured-host health and owned-future cancellation on all six hosts. Both cohorts bind source 50372629, compile fingerprint b376418a2b3346a707dfd2592f99ce6fbceb6c86c8445995069f1e4ac0ed32bf, optimized binary 92c3ae0eb64e8d2213e4938312ae636a2ab6d18ef417b2167086d0737d7664ce and exact reviewed harness dependencies. They are native temporary-controller evidence, not new-tool model-origin or actual business acceptance.

R20 created an unactivated private stage with original installed-V4 rollback artifacts. R21 preflight failed on the DC unit's group-writable 0664 mode; its original failure is preserved. R22 saved exact original unit bytes privately and tightened only that unit's mode to 0600. Unit content, inode, owner, protected service PIDs and InvocationIDs stayed the same; no service reload/restart/stop occurred. This metadata change is an explicit exception to earlier statements that DC was unchanged.

R23 then completed preflight publication and exact private profile/installed-manifest/loaded-drop-in rollback backups. It remains HOLD. Inventory collection currently fails before RPC because the checker erroneously requires 0600 for the existing more-private 0400 token. Fix the checker with source review and offline regressions; do not weaken, copy, hash or publish the live credential. Original R21/R23 observations remain immutable. Installed V4 exposes no authoritative in-flight dispatch/queue inventory or admission freeze, so a readable inventory alone cannot qualify production cutover.

Generic native async/result support remains an engineering gap under separate V10 development. Production activation, administrator Refresh/Review, new-conversation model-origin acceptance, actual business workflows and a separately authorized DC-off/recovery drill remain unqualified. Keep Desktop Commander running as rescue. Full replacement remains false.


### Corrected credential preflight and private profile preparation

The preflight reader now accepts current-owner single-link regular credentials at exactly 0400 or 0600 inside an owner-only 0700 parent. It uses bounded nonblocking no-follow descriptors, checks stable descriptor/path identity, and produces no token snapshot, digest or metadata record. All 47 original offline preflight test algorithms remain unchanged; 13 new regressions are included in the complete 60-test passing run, with 26 stage regressions passing separately. The original failed new directory fixture and its correction, independent review and owned-0400 counterexample remain in R24. No installed token bytes, mode or ownership were changed.

R26 separately prepared an exact private candidate profile and installed-manifest packet without starting it. Only `mcp.commands[0].command` and the five stage-declared installed-manifest fields differ; other transport/authentication/settings remain semantically exact. Public evidence contains path-only commands and file pins, never the private profile or authentication values. The packet is HOLD and still needs review, fresh production inventories and the separate cutover prerequisites. The original candidate source and stage remain bound to 50372629; this checker change does not relabel the earlier native qualification.


### Optional private-profile proof and current observed blockers

The optional profile checker now validates the separate private R26 packet against exact stage/source/current input pins, descriptor identity, strict JSON types, preserved authentication/transport fields and the five independently derived installed-manifest updates. It never trusts a supplied administrator boolean: a valid packet remains prepared/HOLD with PRIVATE_PROFILE_REVIEW_REQUIRED. Default behavior retains UNPREPARED. All 60 previous offline preflight test algorithms are unchanged; 22 new cases are included in the full 82 passing tests, and 26 stage tests pass separately. R28 retains exact source, test, review and raw result pins.

Checker commit 3791c11 has successful exact-head CI run 38477326498. Documentation-only run 38476670079 was cancelled by the next branch push and is not claimed successful. Existing R27 blocked production observation files are retained with their pins; the later create-only attempt refused existing destinations before any helper execution. The original R27 producer is not independently established here. New read-only diagnostics independently confirmed valid private HTTP authentication followed by the 4096-row registry refusal; no zero-job conclusion is valid.

Actual production launch metadata has grown past 5600 records and installed V4 supplies no pagination/completeness/state fields in process_list. Complete bounded collection remains engineering work. The fresh R19 native search cohort failed on pocket4 ENOSPC (65/78 observed); original failure and unknown partial fixture custody remain preserved. Read-only SSH confirmed pocket4 /tmp is a 4 KiB tmpfs with no free blocks. No remount, sudo or guessed cleanup occurred; a new explicit HOME fixture preparation/custody variant is separate work. R19 large-registry native inventory also refused the exact 1 MiB response bound; a minimal compact-JSON candidate and future pagination remain separate engineering work.

R29 removed only three verified inactive Cargo incremental cache directories from owned candidate worktrees. Original refusal attempts are preserved. Compiled binary bytes/inodes/link counts, qualification/source evidence and protected service identities remain unchanged; the unrelated original operator worktree was untouched. No installed token was changed. The old R23 checker had computed a credential digest in RAM before its mode refusal; that digest was never published. The corrected reader no longer computes it.

V10 integration remains unqualified despite actual local test results: incomplete source-map and permission refusals are preserved, and its real native fixture exposed the V9 three-operation audit-reservation allowlist being incorrectly reused for ten new operations. Corrected closed admission, fresh full-input checks and actual native/six-target qualification are required. No V10 installation or full Desktop Commander replacement is claimed.

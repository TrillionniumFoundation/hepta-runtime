# R35 independent static review

**No static blocker identified.** This review covers the exact R24-based 3-file patch `89eed62593e1b3c5a675221d1df998d27aae4b6a0fdfa028e297544838fa049a`. It does not establish compilation, qualification or performance success.

## Source and scope

The baseline and candidate compile-input maps each contain the same 220 paths. Only `jobs.rs`, `ssh_observation_pool.rs` and its existing test file differ. The three original and candidate files were independently rehashed; the complete patch was reconstructed byte for byte from those files. The remaining 217 map entries match accepted R24; they were not reread individually in this review. No R34 reserve, R33 profile cache or earlier router/serializer change is introduced.

## The two production edits

`jobs.rs:4456–4517` retains reference validation and host lookup before dispatch. It moves the unchanged seven-field JSON construction into the direct Python branch that uses it. The pooled and system-jobctl branches skip an unused local allocation. Offsets, default/max limits, remote command selection, completion audit, errors from those operations and returned serialization stay in their original order.

`ssh_observation_pool.rs:1378–1534` already owns the queued `Request`. Its private execution method now borrows that request mutably for one awaited call, then returns an owned result before `reply.send` consumes the sender. At line 1511, `mem::take` transfers the command's existing string buffer into the owned argument vector. The host borrow used to build that vector has ended, and production code does not use `request.command` again. Capture receives the same command bytes, stdin, deadline, cancellation token and permits. All authority checks, admission/host/global limits, socket verification, response checks and original-child cleanup remain unchanged. No new public API or dependency is added.

The test file changes only four lines needed by its two existing direct private-method calls: two `mut` bindings and two mutable borrows. Fixtures, assertions and test inventory are unchanged. There is no apparent new Rust borrow/type or Clippy issue, but this conclusion is static and must be confirmed by the original qualification pipeline.

## Historical attribution

The jobs-only patch is **byte-for-byte identical to the preserved R26 selected-change patch**. This is an isolated reuse on accepted R24, combined with the command ownership transfer. Both changes must not be presented as newly discovered. The inspected R25/R26/R28 full patches and R27 serializer/compiler/router-cache/capacity12 pool snapshots retain the original command clone; this bounded search does not cover every unpublished experiment.

R26's combined qualification, CI and observation outcomes did not isolate this JSON change, and its combined lifecycle result was rejected. No causal performance claim follows from that history.

## Verification boundary

This review used local source reading, hashing, JSON parsing and exact text comparisons only. It did not modify source, import candidate/helper code, run Rust formatting, build, Clippy, tests or benchmarks, call x230/Mac/SSH, or update Git refs. Qualification, exact required CI, and the original performance gates remain required before adoption.

The accompanying `independent-review-01.json` records complete identities, source locations, checks and the historical-review identity.

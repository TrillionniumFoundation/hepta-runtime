# Original-owner engine scratch closure — 2026-11-05

This change binds Java engine scratch to the existing durable job owner. It does not create another process supervisor or claim full REA replacement qualification.

## Scope and behavior

- Operator static Ghidra/JADX jobs receive a private, exclusive `engine-scratch` directory bound to the original job ID, launch nonce, device and inode. The worker records a private adoption claim and leaves cleanup to its original owner, including normal completion.
- Cleanup proof is limited to the original process group, as named by `original_process_group_stopped`. The real harness observes the fixed worker, Java and native decompiler PGIDs and requires equality. Arbitrary escaped descendants, unknown engines and full descendant isolation/recovery remain unqualified.
- The original owner retains custody of the unreaped workload leader while observing and stopping its original process group. Only after that proof and original child reap can it remove its own directory. The cleanup receipt is covered by the original terminal publication witness.
- Directory cleanup checks the pinned parent, current parent, relative leaf and absolute leaf identities. Rebinding a parent or replacing a leaf preserves the original and replacement directories. Symlinks are removed as leaves, never followed; recursion and mount traversal remain bounded.
- Status queries never clean directories. Original-owner loss or uncertain custody preserves unknown outcome and scratch. Normal/cancelled/timed-out/crashed outcomes and their receipts survive controller restart without redispatch.
- Native output uses the terminal outcome, including cancelled exit code zero, and exposes the original cleanup receipt. Invalid partial output from a failed/cancelled worker remains queryable. Unknown cleanup-owner values and contradictory states are rejected.
- New isolated jobctl launches generate 32 lowercase hexadecimal nonce characters. Existing stored identities are not rewritten. The contract regression calls the production generator and the actual worker adoption code, then publishes and observes the original terminal wire.
- Isolated `ProtectProc=invisible` and all existing systemd hardening remain unchanged. Restricted original-group visibility produces a negative-only `engine-scratch.retained.json`, readable from status and output queries without a terminal witness. It never authorizes deletion or claims a known final exit. Positive isolated engine cleanup qualification remains **HOLD** under this restriction.

## Evidence retained here

`red-ghidra.json` records a real Ghidra 12.2 run against the previous immutable runtime. Eight semantic/original cancellation checks completed, then the strengthened harness failed because the original owner had no cleanup receipt. The harness did not remove the leftover scratch.

`focused-fixtures.json` records the intermediate all-feature Clippy run, 11 engine-related Rust tests, 39 jobctl tests, 22 native tests and seven operator supervisor fixtures. Synthetic tests are identified as such. The earlier debug-profile mismatch and explicit cancellation are preserved and excluded from successful validation.

The independent parent-directory replacement counterexample is retained at:
`/home/qian-qi/work/hepta-rea-engine-review-ca464-20261105/{baseline.stdout.json,fixed-r1.stdout.json}`.
The original implementation incorrectly cleared the owned leaf and deleted an old-parent substitute. The fixed helper rejected verification and removal; both directories and the owned data remained.

## Real-engine qualification requirements

Use `tests/rea_ghidra_analysis_external.py` with Ghidra 12.2 and JDK 25. Its checks require original-owner cleanup after cancellation during actual native decompilation, an original worker SIGKILL with live Java/decompiler descendants, and an original-owner timeout. Controller restart and the same-key original result are checked. The helper verifies exact original process identities; it does not remove engine scratch.

Use `tests/rea_java_external.py` for real JADX, and `tests/rea_ghidra_external.py` for real Ghidra inventory. Both require owner cleanup on cancellation and restart readback.

A debug binary with all features is sufficient for correctness. Final qualification must rerun these harnesses against the same frozen binary used by the complete root matrix. An intermediate engine-branch candidate is not that combination.

Installed paths:
- Ghidra: `/home/qian-qi/work/hepta-rea-engines-20261103-r1/ghidra/ghidra_12.2_PUBLIC`.
- JDK 25: `/home/qian-qi/work/hepta-rea-engines-20261103-r1/jdk25/jdk-25.0.5+8`.
- JADX: `/home/qian-qi/work/hepta-rea-engines-20261103-r1/jadx`.
- JDK 21: `/usr/lib/jvm/java-21-openjdk-amd64`.
- Real Chrome: `/opt/google/chrome/chrome`; native capture harness `tests/rea_browser_external.py --native-capture`.

The deployed-owner GDB cancellation fixture predates this candidate and remains separate evidence. Missing IDA, Hopper, Frida and Electron qualifications are not promoted by these changes. Operator supervision still includes the existing Python owner; this is not a claim that the complete owner path has been rewritten in Rust.

## Final focused candidate build

After the nonce/retention changes, all-feature Clippy with `-D warnings`, all 45 jobctl tests, and an all-feature binary build completed with exit zero. The real worker consumer is compiled into the nonce contract test, sharing the same Directory implementation; no parser mock or handwritten valid nonce is substituted. `final-focused-build.json` preserves command output and authoritative terminal metadata. This candidate is explicitly separate from the final combined root build.

## Live scratch sampling follow-up

The first candidate run (runtime `678ca51a70330ccf43040fb27bdba194aab11b9a93167de774e5f683911b6e32`) passed real JADX's eight checks, including original-owner cancellation cleanup and restart readback. Its real Ghidra run stopped during cross-reference analysis with a bare `ENOENT`; the failed original job and successful cleanup receipt remain retained. **The original failing stack was not captured.** Six separate managed xrefs observations with backtraces enabled subsequently succeeded; these do not erase or qualify that failure.

An independent copy of the original scanner, with error-path contexts and an explicit 20 ms enumeration-to-stat scheduling delay, observed a real Ghidra cache file disappear while Java remained live:
`ghidra/ghidra18396893581974543027.cache`.
The diagnostic root remained device 2050 / inode 7097944, and Java PID 1222154 / start time 93477577 was in state S. This establishes the live-entry race mechanism under an observer scheduling intervention. It is not a direct attribution of the earlier uninstrumented failure. Full source identities and receipts are in `sampling-race.json`.

The follow-up sampler traverses from the worker's already-owned directory descriptor, verifies the original root and parent before and after, checks enumerated inode identity, and uses no-follow descriptor-relative metadata and directory opens. Only a just-enumerated descendant's confirmed disappearance is a missing sample. A vanished root, replacement inode, permission error, symlink, mounted descendant, unsupported type or traversal-budget failure remains an error. A child that disappears before opening is absent from that sample. For directories already opened, removal requires zero links; a still-live directory moved away is rejected. The sampler does not claim to detect every unobserved rename between samples. This remains sampled accounting, not a hard filesystem quota.

The first four deterministic fixtures passed in an independent small Rust target: disappearing descendant, replaced leaf/root, permission/symlink/resource errors, and vanished root. Review added a fifth regression contrasting unlink of an already-open child directory with moving that live directory away; its focused receipt is retained separately. Runtime/JRE pin and Ghidra installation inventory errors also gain path/stage context without becoming ignorable. The full root build and real Ghidra/JADX/Chrome qualification must still run against one frozen final binary.

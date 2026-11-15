# Complete functional matrix on explicit tmpfs — 2026-11-03

**Passed.** Original job `1a1a1e7759c-96a-71d7` terminated as `succeeded`, exit 0, with complete output.

| Gate | Actual result |
| --- | --- |
| Format | Passed |
| Strict all-target Clippy, all features | Passed |
| Strict all-target Clippy, no default features | Passed |
| All-target nextest, all features | 1,844 run; 1,844 passed; 39 skipped; 179.153 seconds |
| All-target nextest, no default features | 1,820 run; 1,820 passed; 27 skipped; 181.739 seconds |

Rust/Cargo 1.95.0, locked offline dependencies, one test thread, zero retries and no fail-fast were used. The exact commands and logs are in `summary.json`. Ignored opt-in tests and doctests are not included in these nextest totals; actual engine and weight qualifications have separate receipts.

## Source and storage identity

Source-before and source-after SHA-256:

`8faa46cb7ab44f019a2d912b97d608d73ad51bb0dacbcff42279d0513396ac3f`

The complete Linux source-change monitor reported zero events/errors. Both source-inventory files have SHA-256 `b8d6d47b2cd52a61f87cebf76f2d686c0f1fcebee98fa478864d18eb3e9ef453`. This is local monitoring plus content inventory, not a hostile same-UID or remote-filesystem proof.

Fixture storage was the explicitly created private executable tmpfs directory `/run/user/1000/hr2`, UID 1000 and mode 0700. Each gate was launched with `umask 0022`. `launch-environment.json` records the actual mount, selected environment and temporary-directory probe; `launch-wrapper.py` preserves the executed wrapper.

This short root keeps the existing SSH ControlPath check intact: with a seven-digit PID and initial generation, the fixture bound is 79 bytes against the 90-byte limit. The previous overlong-root attempt is preserved separately.

The passing source also changes the no-default remote-operation test's state_dir to an absent `state` child, so the real initializer creates 0700. Production private-root checks, query budgets, locks and synchronization are not relaxed.

## Executable observations

The observed `debug/hepta-runtime` artifact after both Cargo commands had SHA-256 `290fa949b7744c85018f9f26b32fbdd1884cce1c31ff202a9f076bc3d6a89c63`. That is also the fixed binary used by the final actual JADX/Ghidra operator runs.

The artifact fields record the executable present at that path after each command. Identical bytes are not a claim that two separately feature-identified standalone CLI builds were produced. Feature-suite qualification follows the exact Cargo arguments and conditional test targets, including the successful no-default remote-unavailable tests.

## Scope and remaining ext4 boundary

This is complete functional nextest qualification under the declared tmpfs condition. It does not establish physical-disk latency under load or physical power-loss durability.

The [ext4 focused failure](../rea-final-focused-20261103-r1/README.md) remains failed. The [single traced ext4 diagnostic](../rea-audit-budget-diagnostic-20261103-r1/README.md) reproduced an audit-statistics query budget refusal while acquiring the final store lock; the same three-second absolute budget also covered earlier work. No writer-fsync timing or complete lock-holder history was captured. The diagnostic does not establish that every earlier error had the same phase or one I/O call was the sole cause.

Actual application/session/web MCP tests on ext4 and actual Java operator runs retain their own evidence. GitHub exact-head/prospective-merge CI evaluates the publication commit independently; this on-host receipt does not assert its result.

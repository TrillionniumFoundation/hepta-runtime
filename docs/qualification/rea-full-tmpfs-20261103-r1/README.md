# First tmpfs matrix: preserved fixture setup failures

This complete run is **not qualified**. Job `1a1a1d2ebf8-96a-715f` terminated as failed, exit 1. Formatting and both strict all-target Clippy configurations passed. Both nextest stages completed with one thread and zero retries:

| Configuration | Result |
| --- | --- |
| All features | 1,844 run; 1,840 passed; four failed; 39 skipped |
| No default features | 1,820 run; 1,815 passed; five failed; 27 skipped |

Source before/after inventories are identical and the Linux source monitor completed without events/errors. Source SHA-256: `eff016991ae56572d55f6ba487550c8ded550a68028a0c24184ec75aa52e64d7`. The explicitly selected temporary root was on executable tmpfs: `/run/user/1000/hepta-rea-functional-tests-20261103-r1`.

## Shared path failures

Four SSH observation-pool fixtures in each configuration failed with `observation socket path is too long for OpenSSH temporary publication`. The root selected for this attempt was 53 bytes long.

The existing Linux check allows 90 ControlPath bytes: 108 minus OpenSSH's 17-byte temporary suffix and one NUL. With locked tempfile 3.27.0's ten-byte default directory name, the fixture path length is `TMPDIR bytes + 53 + PID digits + generation digits`. At the host's seven-digit PID upper bound and generation 1, this attempt produced **114 > 90**.

This was an unsuitable test root selected by the qualification wrapper, not a reason to weaken the production check. The separate later matrix uses `/run/user/1000/hr2` on the same mount: 18 root bytes, giving an initial bound of **79 < 90**. Its own launch receipt records that input.

## Additional no-default setup failure

`remote_operations_reject_both_schemes_without_touching_local_files` passed a default 0755 tempfile directory directly as runtime state under 0022. The strict private-state initializer correctly refused it before the remote-operation assertions.

The subsequent one-line test-only change uses an absent `state` child so the real initializer creates 0700. SSH/SFTP rejection, direct/unified refusal, untouched sentinel, local I/O and process-isolation assertions are preserved. The outer temporary directory is not chmodded and production validation is unchanged.

Original test file SHA-256: `6f9edbeb69feadfaaaacf62290e44891ab9e8fccff58a5dd81e10af6465bdc44`.
Corrected test file SHA-256: `e2aead7aafde2b97d85f414d6a75c03d701fec71c1aa60a9516c8ab1bd46289c`.

## Environment boundary

The continuous-publication audit test passed in the all-feature tmpfs run in 0.102 seconds, including its completion-progress and observation checks. That is scoped to this environment and does not identify the original ext4 failure's exact cause or establish disk latency under load.

The [separate single ext4 diagnostic](../rea-audit-budget-diagnostic-20261103-r1/README.md) reproduced the deadline at the final store-lock acquisition. Its added tracing/backtrace and separate timing are explicit; the original ext4 failed receipt is unchanged.

This matrix concerns functional behavior, not physical power-loss durability. Source identities, commands, logs, launch wrapper and filesystem/environment receipt are preserved. The later short-root matrix and GitHub committed-tree checks have separate records.

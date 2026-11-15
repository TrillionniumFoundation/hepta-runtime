# R34 capacity component — archived source preparation 02

This is a frozen, **unformatted, uncompiled and unexecuted** preparation package. R34 failed the original normal-observation C8 throughput gate, so the parent stopped all capacity builds/cells and normal-lifecycle execution. This package preserves source work for a separately reviewed future revision; it is not an executable sealed campaign and establishes no capacity or performance benefit.

## Stop context

The parent reported the completed original R34 normal observation: C8 A=55.16012773058447 rps, B=51.33357826615478 rps, B/A=0.9306283429378647, below the unchanged 0.95 gate. The original summary is 13,933 B, SHA256 `91dc92426ac74a7802f827df05ae93a59e97b97f5e6b915a1e927ac96bec7a33`; the original Mac holder job was `1a1af308953-fc05-6698`, reported succeeded/0 with its owned agent reaped. These are parent-provided identities, not a new remote read or independent performance measurement by this preparation task. R34 was not adopted; accepted R24 remains the baseline.

## What is implemented

The original implementation-01 crate, fixtures and single-cell coordinator remain the starting point. Its original source manifest and README/BUILD are retained under `reference/`. The Rust driver and Python fixture bytes are unchanged here. The coordinator adds an explicit SIGINT/SIGTERM/SIGHUP error handler so original outer-stage interruption enters the existing primary-error/cleanup path rather than bypassing it as KeyboardInterrupt.

`run_capacity_campaign.py` implements the fixed serial eight-cell outer order: A1-x230, A1-mac, B1-x230, B1-mac, B2-x230, B2-mac, A2-x230, A2-mac. It stops on the first failed or incomplete cell, keeps unsubmitted rows explicitly present, retains all raw evidence and does not retry or select favorable cells. Its stage ownership/cleanup body and 90-second quiet block are copied byte for byte from the reviewed original R34 parent. The exact original held-agent launcher is retained unchanged. Original compiler-monitor functions, limits, policy and validator are loaded from the exact bound parent as non-main definitions; they cover prerequisites, quiet, all cells, original cleanup and final input checks.

The proposed capacity sockets use a separate `/home/qian/h34g01` through `h34g08` namespace. Original normal observation uses `h34c01`; no old directory is removed or reused. Future actual freshness is checked before creation; it has not been probed in this source-preparation task.

`materialize_capacity_campaign.py` is a read-only prerequisite binder followed by one create-only actual input. It verifies the actual completed R34 qualification/CI and the closed component build pair before writing an input. It does not start a compiler, agent query, monitor, SSH helper or fixture. Current templates contain null actual pins and refuse before materialization. Every cell has identical fixed policy, helper source and environment; only its original arm, victim, private nonce and derived namespaces differ. Generated cell inputs and profile/config/wrapper dependencies are included in before/after input checks, and the coordinator's retained actual input bytes must equal the preregistered cell input.

`record_build_invocation.py` is the actual-native-job build-stage producer. It observes the supervisor-provided native job ID, original request/child/launch metadata and self identity before creating a Cargo child. It records the actual x230 monotonic clock/boot, command, effective controls, child identities, original output and cleanup. `seal_arm.py` consumes those receipts plus original native terminal and complete read pages, including byte-for-byte output comparison. `PRODUCER.md` describes this source interface and its finite cleanup/unknown-outcome boundaries. None of it has been invoked.

`capacity_monitor_verifier.py` preserves the original completed-monitor verifier except for adding the fixed capacity output directory to its allowlist. It is a source fragment for the unfinished final closure; no validator was executed during preparation.

## Remaining boundaries

- No rustfmt, Rust parse/compile, Cargo resolution, Clippy, Rust tests, helper, driver, fixture, coordinator or remote command has run for this package. The source manifest remains `unformatted_uncompiled`; build preparation refuses this state.
- No actual component lock, metadata graph, toolchain/cache validation, invocation, ELF or cell result exists. Actual native job/build/holder pins are not fabricated. The producer's real toolchain paths and filesystem link characteristics remain unverified.
- The outer program is a static draft with the reported field/namespace fixes. It has not been validated by execution. Its end-to-end artifact aggregation and exceptional paths still need real qualification in any future revision.
- The external Mac holder finishes after the remote outer program exits. A dedicated final holder/native/read closure program was **not implemented** before this candidate was rejected. The remote report explicitly leaves external holder closure open; it cannot alone claim a completely closed campaign.
- Hard parent loss without a final original custody receipt remains failed/unknown. Direct-child parent-death signaling cannot prove every possible grandchild gone. No independent guardian or new mandatory systemd backend was added merely to erase that uncertainty.
- Independent static review is scoped to source preparation. It is not a capacity acceptance, normal-performance pass or authorization to revive this rejected run.

## Source and correctness boundaries

R34's production package is unchanged: accepted R24 plus its separately frozen ordinary-first reserve patch `1a73c219fcfd2a273354bcbe0e1eb3f2ba629b1eb9f4969591352c6dd1a4ffc0`. This external component does not modify its 220 compiler inputs, Python helpers, original admission/owner/reap rules, SSH authority, profiles, firewall or services. It does not mix R31 pidfd, R33 path cache or any later candidate.

The fixed component distinction remains: same-process public `ssh::run_capture` saturates eight ordinary direct slots including two on the victim target; the original `native::cancel` targets a real existing owned job. B would require the same eight gate generations plus a ninth direct/third target child and a completed original remote cancel-request observation before fixed release. Original ACK, terminal, witness, exact stream/read/key and original-owner cleanup checks remain separate. TTL and sampled absence are not terminal/reap proofs.

All summaries are component-scoped. Two samples per arm/victim permit individual values and descriptive medians; they do not establish population p95, full MCP throughput, whole-system CPU, or RSS savings. The original resource sampler limitations are retained.

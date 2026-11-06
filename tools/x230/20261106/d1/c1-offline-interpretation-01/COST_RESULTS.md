# D1 C1: measured phase costs from the preserved original campaign

The new offline interpretation completed once with exit 0. It established the strict bidirectional mapping for all **468 ON requests**, including **384 measured calls**. All eight original trace files passed the unchanged raw parser. Its selective phase arithmetic exactly reproduced the parser's full-trace phase distributions and per-request totals before selecting measured requests.

The **original campaign parent and adapter remain failed**. The independent original native auditor subsequently ran for the first time in a separate namespace and verified the complete 936-call workload. The interpreter did not rerun that auditor, the workload, the runtime, or any host operation. Its output is diagnostic evidence; accepted R24 and every existing adoption gate remain unchanged.

## The material CPU region

All values below use only the 192 measured calls in each ON round. Controller CPU comes from the original synchronous before/after process counters, not the 100 ms resource sampler.

| Quantity | ON round 1-B | ON round 2-B | Both ON rounds |
|---|---:|---:|---:|
| Measured calls | 192 | 192 | 384 |
| Controller CPU, ms/call | 29.47917 | 16.40625 | 22.94271 |
| Recorded synchronous exclusive CPU, ms/call | 20.81268 | 11.61405 | 16.21337 |
| Recorded synchronous CPU / controller CPU | 70.6013% | 70.7904% | 70.6689% |
| Validation worker + owner CPU, ms/call | 18.07351 | 9.95395 | 14.01373 |
| Validation / recorded synchronous CPU | 86.8390% | 85.7061% | 86.4332% |
| Validation / controller CPU | 61.3094% | 60.6717% | 61.0814% |

Validation is the largest region in both rounds. Absolute costs vary substantially, so the stable ranking and shares are more persuasive than a single pooled timing. These are two rounds of one finite campaign, not a confidence interval or evidence that diagnostic ON is faster than OFF.

### Measured exclusive CPU by phase

| Phase | ms per measured call | Recorded CPU events |
|---|---:|---:|
| `validation_owner` | 7.663595 | 2,304 |
| `validation_worker` | 6.350136 | 2,304 |
| `spawn` | 0.702880 | 384 |
| `router_build` | 0.590075 | 384 |
| `process_identity` | 0.350495 | 768 |
| `audit_critical` | 0.212500 | 384 |
| `audit_sync` | 0.113355 | 384 |
| `arguments` | 0.051346 | 384 |
| `expected_argv` | 0.043769 | 384 |
| `audit_write` | 0.036526 | 384 |
| `decode_observation` | 0.027170 | 384 |
| `encode_observation` | 0.020577 | 384 |
| `prepare_observation` | 0.019936 | 384 |
| `audit_prepare` | 0.014102 | 384 |
| `audit_mutex` | 0.007626 | 384 |
| `socket_and_boundary` | 0.006199 | 384 |
| `logical_admission` | 0.003080 | 384 |

The 2,304 events for each validation phase mean **six complete worker validation sweeps and six complete owner validation sweeps per request**. Each sweep checks the six fixed pinned files and its existing policy/shell requirements. The result does not distinguish an individual file, path traversal, metadata/xattr operations, read syscalls, byte comparison, SHA fallback, cancellation fences, or policy checks within those sweeps. Calling the entire 14.01373 ms “hashing cost” would be unsupported.

The two operations have nearly identical recorded synchronous means: `process_read` 16.16455 ms/call and `process_status` 16.26218 ms/call. Host means range from 15.98812 to 16.43459 ms/call. This supports examining the common local validation path before another tiny serializer/allocation change; it does not establish which validation substep is expensive.

## Wall time and the unrecorded CPU remainder

The mean recorded request wall span is 111.85538 ms. Capture is 63.04337 ms and child wait is 60.69549 ms; stdout and stderr drain spans overlap that interval. Agent snapshot is 24.05668 ms. Admission/pre-capture/post-capture profile spans are about 12.99/12.66/13.35 ms. These nested and concurrent wall intervals are **nonadditive**. They cannot be summed into request time or labeled pure network or remote-helper work.

Recorded synchronous CPU accounts for 6.225932847 seconds of the 8.81 controller CPU seconds in the two ON measured windows. The signed remainder is 2.584067153 seconds, or 6.72934 ms/call. It includes uninstrumented work, background activity, diagnostic overhead and the difference between the request intervals and wider process-counter read windows. The original process counter resolution is 10 ms. The interpreter retains signed values rather than clipping them, and does not assign this remainder to SSH children, remote CPU, or networking.

Nested synchronous children are subtracted from their parents exactly once. For example, the `audit_critical` figure is exclusive of its recorded write/sync children. Missing phases are zero-filled in per-request distributions; a phase with no CPU events is not a zero-cost CPU measurement. OFF traces contain no phase data.

## Consequences for the next change

The evidence justifies **D2 diagnostics inside validation**, with the existing fresh opens, full reads, metadata/capability checks, final reopens, cancellation/deadline fences, owner permit, and all twelve sweeps preserved. A per-file and substep breakdown should determine how much is path/open/metadata, full read, comparison/hash, shell resolution, policy and boundary verification. No optimization patch is supported solely by the aggregate validation number.

Two tempting shortcuts were rejected before implementation. D1 did not record the per-file reference branch or demonstrate exhaustion of the existing 2 MiB public-executable reference budget, so expanding that budget is unsupported. A direct full-path `openat2` replacement also changes the authority contract: R24 opens each intermediate directory with `O_RDONLY|O_DIRECTORY`, which requires read permission, while path resolution requires search permission. An execute-only ancestor can therefore be accepted by the proposed shortcut and rejected by the existing walk. `RESOLVE_NO_SYMLINKS` addresses symbolic links, not that permission difference. See the primary [open(2)](https://man7.org/linux/man-pages/man2/open.2.html), [path_resolution(7)](https://man7.org/linux/man-pages/man7/path_resolution.7.html), and [openat2(2)](https://man7.org/linux/man-pages/man2/openat2.2.html) documentation.

Earlier rejected candidates remain rejected. This status/read-only campaign does not validate cancellation improvements from R31/R34, reverse the R33 observation rejection, or override the R35 normal-lifecycle cancellation-throughput failure. A future optimization must still pass the original correctness, observation, and normal lifecycle/cancellation gates. D2 is a separately scoped diagnostic step, not a new optimized release.

## Exact evidence

The original failure archive is 2,220,914 bytes, SHA256 `522f79c7601612adfc093df876fb2962b201551e08016e9293d01424bbea36cb`. Its 408,940-byte manifest is `15cf694a7366f666bebbe696d0a8ef3266a64bba0955974693952fa3b94de691`.

The new interpreter is 41,876 bytes, SHA256 `7857a1f8960e82cbb1ba7700c1e805b87f7363cf5d8c3fecf32c5ebbf0dfa870`. Its sealed 1,868-byte input is `ad12f1602f60d4432ed1c5cdd4e2397a858c90de8964934aa01eb6d80de70aec`. The actual complete result is 7,881,638 bytes, SHA256 `3f2fa638154101f9aec9184b09807fa658f2bb8dc3935ceda9e396b8b4bf408e`.

The lossless delivery archive retains every original output of this single offline execution, including the complete result JSON, eight controller records, eight unchanged-parser summaries, input, execution receipt and stdout/stderr. Its per-file manifest allows byte-for-byte verification without rerunning any interpreter. `cost-summary.json` is a compact view derived from the complete result; it does not replace the full evidence.

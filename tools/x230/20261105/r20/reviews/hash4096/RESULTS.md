# X230 R20 request-hash 4 KiB component: independent result

**Decision: reject the fixed 4,096-byte stack-buffer candidate under its preregistered mechanism screen.** Canonical correctness and execution succeeded; the performance screen failed. No production integration was prepared from this candidate.

## Independent verification

The local offline auditor passed 225 checks against the complete received archive. It verified 96 fresh-worker cells and 102 stages: six preparation/check stages plus 96 workers. All original stage receipts, stdout/stderr, exit-zero and wait/reap fields agree. Two actual Cargo tests passed; the separate check process covered six canonical fixtures and seven buffering boundary cases. A Python reconstruction independently reproduced the six serialized lengths and full canonical SHA256 values.

All four block changes were recomputed from original integer CPU nanoseconds and iteration counts using exact fractions before the final conversion to floating point. Every report CPU/wall statistic and RSS/HWM list matched. The 23-package reduced lock contains 22 external package identities, all present in the frozen R19 lock. Actual project source bytes match the frozen bundle; the R19 baseline excerpt matches its original complete source.

## CPU result

Each block value is `100 × (mean B / mean A − 1)` for that block. The decision uses the median of the four block ratios. This is different from dividing the pooled arm medians. Negative values mean less CPU per digest.

| Scene | Block 0 | Block 1 | Block 2 | Block 3 | Block-ratio median | Screen |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| small_176 | +10.3898% | -1.7898% | +22.7198% | +11.5990% | +10.9944% | **reject** |
| escaped_small | +4.3100% | +10.8716% | -1.4931% | +7.6311% | +5.9705% | **reject** |
| plain_64k | -0.3365% | +11.6797% | +12.8173% | +0.2718% | +5.9758% | **reject** |
| escaped_64k | -12.1322% | -14.7303% | -11.5053% | -9.1831% | -11.8187% | pass |
| plain_1mib | +38.1103% | -9.4763% | +0.3499% | +1.3947% | +0.8723% | pass |
| escaped_1mib | -18.9403% | -8.8045% | -16.1901% | -13.6202% | -14.9052% | pass |

The unchanged small/plain-input gate requires median CPU regression ≤2%. It rejects `small_176`, `escaped_small` and `plain_64k`. Both large escaped cases satisfy ≥5% median improvement and improve in all four blocks; that does not override regressions in common smaller/plain requests. No threshold, sample count or outcome was altered after the run.

The observed writer-fragment reduction is substantial for escaped data: 65,604 to 49 inner writes at 64 KiB, and 1,048,644 to 769 at 1 MiB. This supports the specific batching mechanism on those fixtures. It does not establish that stack initialization caused the small-input regressions, nor does it establish status/read or process-start throughput improvement.

## Resource and timing scope

CPU is CLOCK_PROCESS_CPUTIME_ID around the digest loop, including the same full-hash equality assertion in both arms. Process startup, fixture construction, warmup and resource snapshots lie outside the timing interval. Worker-stage wall time includes subprocess startup and orchestration and must not replace the measured loop wall time.

All 96 workers reported the identical lifetime HWM of **21,098,496 bytes (20,604 KiB)** before and after the loop. Its origin was not separately diagnosed. VmRSS values are before/after process snapshots; neither metric is per-call allocation, stack consumption or whole-cluster memory. These measurements establish no RSS gain.

## Evidence identities

| Artifact | Bytes | SHA256 |
| --- | ---: | --- |
| Received archive | 170,013 | `50bcf7471f5ca400569a103bd625f571cac8053f94581b01bbc7d804b4bdce7f` |
| Original report | 107,284 | `c8b96746a42c7a70f332be0afd1263093e6e6528d9cc9a2e7275245505dafde1` |
| Original raw cells | 93,153 | `a6c6bd8d5ab83b28a01bb7745070279f42e9854b0971b56c7fb2ff6d423dce36` |
| Actual resolved lock | 5,094 | `ec33648eaa4429e75dbcc81d67281f5424126f82996c602d3143b27e9be5ac66` |
| Frozen input manifest | 1,839 | `646122205a408311e52555c944e3650079eebe3824605e5eb43deeca7ae7b55b` |
| Independent review | 27,027 | `f036c037c408498e4eefede08005e8e375ea55a849667a006b5f951579444d07` |
| Offline recompute tool | 16,396 | `483dd556bf5fa217498ee8d627eac4d438f03f9263ea9b6bdcd2fdd45b795977` |

The archive contains 333 regular members: 332 source/evidence files plus its export manifest. Every member size/hash was checked before extraction into a fresh directory. The compiled probe ELF is deliberately excluded; its remotely rechecked identity is 462,544 bytes / `12250f7827ed412113be7747f2c96848d3eeebb74f7a5d03a4ac383973798b64`. This is a remote current-byte hash witness, not an offline binary reproduction. No target ELF, object, or rlib is archived.

```sh
python3 -B recompute_01.py --evidence received --output independent-review-replay.json
```

## Preserved preparation and transfer failures

The first local report-assembly attempt exceeded the exec argument-length limit; the command process was not created. The same already-read bytes were then saved as two bounded pieces and SHA-verified. No remote performance operation was retried.

The first evidence exporter exited 1 before creating its output because its generic evidence-file reader required nlink=1 for the compiled target ELF. The actual Cargo target ELF has nlink=2. Exporter revision 2 permits stable hardlinks only when hashing that explicitly selected compiler output, retains full fd/path stamps and whole-file hashing, and still requires nlink=1 for all archived evidence/source files. Its successful result and the original failed launch/output/status receipts are retained. This was an archival-scope error, not a probe correctness or performance failure.

## Only authorized follow-up

The parent authorized one separate 64-byte candidate, chosen as the SHA-256 compression-block size. It tests a fixed-buffer/initialization-cost hypothesis under the identical six scenes, four ABBA blocks and original screen. It is prepared in a separate bundle, with no production changes and no performance execution performed during preparation. No adaptive policy or additional buffer-size sweep is authorized; if it also regresses, this direction ends for this round.

All remote reads/export operations for this review have ended. Subsequent review and bundle preparation are local-only. No global optimum, statistical significance, or full-chain throughput/RSS gain is claimed.

# A48 small archive regression result

The complete small comparison and independent numeric evaluation passed all
six preregistered gates. Both opposite-order blocks finished, with **8,192
measured calls and 8,848 total tool calls, all correct**. Each actual source
contributed four rounds and 4,096 measured calls. No historical results were
pooled and no failed/partial subset was selected.

The original evaluation is unchanged: **19,045 bytes**, SHA-256
`fddd74bde8b465fdcec8e41092a3891b3cc3e3165f09e677fc9bdf2e94af1bfe`. It completed at `2026-10-26T04:11:20.173704+00:00` and binds
outer report SHA-256 `877b93e7daa09857103d280f7dd44cfc79d5e7aac19ed443780153385712f513` and
protocol SHA-256 `abca1770b8eb27c489d30f52427439f0efc76f7bad969aeee20ae22dad409a5e`.
[small-summary.json](small-summary.json) retains every original round, all six
gates, both stage observations and the exact evaluation receipt.

## Observed results and interpretation

| Metric | r07 | A48 |
|---|---:|---:|
| Measured-loop wall | 34.426635 s | 31.971360 s |
| Controller CPU in measured intervals | 30.13 s | 27.82 s |
| Fixed-loop successful calls per second | 118.977647 | 128.114663 |
| Maximum original whole-round wait4 RSS | 35,020 KiB | 34,996 KiB |

The observed wall change is **-7.132%** and controller CPU change
**-7.667%**. These describe this fixed C1 RPC plus DTO/oracle and
journal-flush loop. They are not saturated-server throughput measurements.

The small fixture stays below the `base_count > 16384` condition and its complete
observation remains serial. **The approximately 7% difference cannot be
attributed to A48's two-reader branch.** This comparison is r07 versus A48,
not an isolated A42-versus-A48 trial. Compiler/layout, ordering and host variation
are possible contributors, not established explanations. The 24 KiB RSS
reduction is an observed whole-life peak difference, not a steady-state memory
improvement claim.

## All six gates

| Fixed gate | Observed value | Result |
|---|---|---|
| All reported/journaled calls correct | 8,848 / 8,848 | Pass |
| Each actual arm has 4,096 measured calls | 4,096 / 4,096 | Pass |
| Both opposite-order blocks complete | 2 / 2 | Pass |
| Candidate/baseline wall ≤ 1.10 | 0.928680956 | Pass |
| Candidate CPU upper / baseline CPU lower ≤ 1.10 | 0.933600267 | Pass |
| Candidate wait4 peak RSS ≤ max(1.10×baseline, baseline+4,096 KiB) | 34,996 ≤ 39,116 KiB | Pass |

CPU guards include the original `/proc` quantization allowance: each round has
±0.04 s and each arm's sum ±0.16 s. Thus the guarded ratio uses A48's 27.98 s
upper bound over r07's 29.97 s lower bound. RSS uses the maximum of four original
whole-round wait4 observations per source.

## All eight original rounds

Each row contains 1,024 measured calls. Round numbers are the original
zero-based indices within each block; CLI arm labels are retained in the JSON.

| Block | Round | Actual source | Wall seconds | Controller CPU seconds | Whole-round peak RSS KiB |
|---|---|---|---:|---:|---:|
| 0 | 0 | r07 | 8.088008 | 7.05 | 22260 |
| 0 | 1 | A48 | 7.642988 | 6.65 | 25344 |
| 0 | 2 | A48 | 8.939053 | 7.84 | 30092 |
| 0 | 3 | r07 | 8.751519 | 7.69 | 35020 |
| 1 | 0 | A48 | 7.946042 | 6.91 | 22264 |
| 1 | 1 | r07 | 8.541894 | 7.46 | 25456 |
| 1 | 2 | r07 | 9.045214 | 7.93 | 30072 |
| 1 | 3 | A48 | 7.443277 | 6.42 | 34996 |

The two ordinary qualification chains and A48's final entry/worker postchecks
were verified by the evaluator. Its report-level numeric pass still requires
the separate original wire/fixture, qualified-source/ELF and custody review
before adoption. It authorizes no performance adoption by itself. Large C1/C4
ABBA gates and the final decision remain separate; this small result does not
make a stopping or large-success claim.

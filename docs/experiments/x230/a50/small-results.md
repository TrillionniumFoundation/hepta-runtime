# A50 small archive: all fixed regression gates passed

**The complete small comparison passed all six preregistered regression gates.**
All eight rounds and both opposite-order blocks are included: 8,192 measured
calls and 8,848 total tool calls, with zero reported/journaled call failures.
Each actual source has four rounds and 4,096 measured calls. No retry, omitted
round, successful subset or historical result contributes to these totals.

The observed A50 totals were **2.376% higher wall time** and **2.503% higher
measured CPU** than r07. This result does not show a small-archive speedup.
It passes the fixed 1.10 regression limits. The original evaluator retains
`performance_adoption_authorized=false`; the small result alone neither
authorizes adoption nor establishes the large comparison outcome.

## Complete inventory and unchanged workload

The comparison ran from `2026-10-26T06:07:28.407946+00:00` to
`2026-10-26T06:09:03.531859+00:00`. Block 0 uses r07/A50/A50/r07; block 1
uses A50/r07/r07/A50. Actual release identities, rather than the CLI A/B labels,
determine the aggregate arms. Every controller has 64 native seed records,
1,024 measured C1 calls and two runtime workers. Product/client budgets remain
3/10 seconds, with the original 300-second helper budget for each block.

| Purpose | All eight rounds |
|---|---:|
| Native seed | 512 |
| Preflight | 40 |
| Warmup | 64 |
| Measured | 8,192 |
| Postflight | 40 |
| **All tool calls** | **8,848** |

Each source's measured calls comprise 1,368 `usage_stats`, 1,364
`request_history` and 1,364 `request_archive` calls. Both block reports retain
actual original-child reaps, clear before/after host gates, exact journal
coverage, unchanged qualified inputs and no unexecuted or unknown-count stage.

## Aggregates and every fixed gate

| Metric | r07 | A50 | Interpretation |
|---|---:|---:|---|
| Measured calls | 4,096 | 4,096 | Four complete rounds each |
| Measured loop wall, s | 32.519600830 | 33.292333194 | A50/r07 = 1.023762049 |
| Observed measured CPU, s | 28.37 | 29.08 | A50/r07 = 1.025026436 |
| Conservative measured CPU interval, s | 28.21–28.53 | 28.92–29.24 | Candidate upper / baseline lower = 1.036511875 |
| Successful measured calls/s | 125.954806 | 123.031329 | A50 observed rate is 2.321% lower |
| Maximum original whole-round wait4 RSS, KiB | 34,880 | 34,900 | Candidate limit = 38,976 KiB |

The conservative CPU allowance is four ticks per round (two ticks for each
endpoint). At the captured 100 Hz, this is ±0.04 seconds per round and ±0.16
seconds across each source's four rounds. The CPU gate uses **29.24 / 28.21**,
not the ratio of the two central observations. The RSS limit is
`max(1.10 × 34880, 34880 + 4096) = 38976 KiB`.

| Frozen gate | Actual | Result |
|---|---|---|
| Both opposite-order blocks complete | 2/2, all eight rounds | Pass |
| All reported/journaled tool calls correct | 8,848/8,848 | Pass |
| Both actual arms have all measured calls | 4,096 each | Pass |
| Wall ratio ≤ 1.10 | 1.023762049 | Pass |
| Candidate upper CPU / baseline lower CPU ≤ 1.10 | 1.036511875 | Pass |
| Whole-life peak RSS regression guard | 34,900 ≤ 38,976 KiB | Pass |

## Every round retained

Each row below contains all 1,024 measured calls for that original controller.
The exact Decimal values, complete original round observations and all six
gates are retained in [small-summary.json](small-summary.json).

| Block | Round | Actual source | CLI arm | Measured wall s | Measured CPU s | Whole-round peak RSS KiB |
|---|---|---|---|---:|---:|---:|
| 0 | 0 | r07 | A | 7.891501 | 6.88 | 22,264 |
| 0 | 1 | A50 | B | 7.952181 | 6.94 | 25,420 |
| 0 | 2 | A50 | B | 8.393739 | 7.31 | 30,084 |
| 0 | 3 | r07 | A | 8.505013 | 7.46 | 34,880 |
| 1 | 0 | A50 | A | 8.541502 | 7.48 | 22,264 |
| 1 | 1 | r07 | B | 8.422262 | 7.36 | 25,216 |
| 1 | 2 | r07 | B | 7.700825 | 6.67 | 29,972 |
| 1 | 3 | A50 | A | 8.404912 | 7.35 | 34,900 |

Whole-round wait4 CPU totals are 30.279103 seconds for r07 and 31.110512 seconds
for A50. They include work outside the measured interval and are kept separate
from the measured CPU gate. All recorded FD endpoints are 20/20; that is an
endpoint observation, not a continuous stability or soak result.

## Interpretation and review limits

The 64-record small fixture is below the production **>16,384-record** parallel
selector. This workload continues to use the serial small path; it does not
exercise A50's two-reader, 32-record batch path. Its observations cannot be
credited to that path. The comparator is **r07 versus A50**, not A48 versus A50,
so it also does not isolate the incremental effect of the batching change.

The wall and calls/s figures describe the fixed C1 native RPC loop including
full DTO/oracle validation and journal flushing. They are not saturated-server
or multi-host throughput. RSS is the maximum original whole-round wait4 value,
used only as the fixed regression guard. Neither it nor the 64-task admission
limit establishes a hard bound on all cache decoding, heap allocation or RSS.
The earlier approximately 16.3 KiB estimate is limited to validated Record
payload, not every decoded or transient allocation.

This review independently recomputed every aggregate with 50-digit Decimal
arithmetic from the eight original outer-report CPU/wall/wait4 observations,
using the captured 100-Hz quantization information. It reconciled both block
journal-coverage summaries, per-source counts and all-purpose totals. Every
round value, aggregate, ratio and gate matches the original evaluator.
The pinned evaluator read the original child reports and complete journals;
this local review did not independently reread their 8,848 individual row
bodies, raw process endpoints, wire files, full fixtures or remote ELF/source
bodies. Those limits are explicit in the machine summary.

## Immutable originals and publication review

| Original | Bytes | SHA-256 |
|---|---:|---|
| Small outer report | 125,572 | `c5392c11d408d770f11e630a377c0cec05064d2650720e38bf874b683348b363` |
| Captured protocol | 8,557 | `3fd4104ad342c0403359a96baab757ec6b6db47992bc27b0c5b09ae40f615750` |
| Original numeric evaluation | 19,006 | `d3c22db54735637765a2fa84ebe71e32281ae50cd92b97e6a3cccabd8b158b3f` |

All three complete raw bodies were reviewed for credentials, private keys,
tokens and unrelated full-host process/environment inventories. No such
publication blocker was found; owned-task/custody metadata and nonsecret
synthetic identifiers can remain. No raw original was edited, no remote call
or workload was executed by this review, and the large result remains separate.

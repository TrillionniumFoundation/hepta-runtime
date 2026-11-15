# R31 observation: complete execution, rejected performance

R31 remains an unadopted candidate. The accepted source is R24
`baab4def80be7af015b2e7a594cb302f66c4130e`. The original attempt-02 measurement
completed its correctness and evidence stages, but C1 throughput failed the
unchanged preregistered floor.

Original Mac holder `1a1ae66710c-fc05-5f6e` succeeded with exit 0 and complete,
durable, untruncated stdout/stderr (308/0 bytes); its owned agent was reaped.
The parent report's `passed: true` describes execution/evidence completion.
Its separate `observation_gate_passed: false` and the independent summary
reject performance adoption.

## Actual original matrix

| Concurrency | R24 A calls/s | R31 B calls/s | Change | Throughput gate |
| --- | ---: | ---: | ---: | --- |
| 1 | 7.974917871 | 7.574879420 | -5.016208% | Fail |
| 8 | 54.805486431 | 53.990176721 | -1.487643% | Pass |
| 16 | 55.998785595 | 55.890588047 | -0.193214% | Pass |

C1 B/A is **0.9498379221405816**, below **0.95**. The measured change is
**-5.0162077859%**. Rounding it to -5.0% would obscure the failed gate.
No threshold changed, no samples were discarded and no original workload was
replayed.

| Concurrency | A → B p95 ms | Change | A → B controller CPU ms/call | Change |
| --- | ---: | ---: | ---: | ---: |
| 1 | 179.830768 → 186.734058 | +3.8388% | 30.781250 → 31.223958 | +1.4382% |
| 8 | 191.336507 → 188.310052 | -1.5817% | 19.114583 → 19.088542 | -0.1362% |
| 16 | 338.520473 → 337.760139 | -0.2246% | 19.583333 → 19.817708 | +1.1968% |

All p95 and controller CPU gates passed. Sampled controller RSS was
**18,836 → 18,940 KiB**, +104 KiB, below the 19,348 KiB bound. These samples
are not cluster memory or allocator bounds.

The matrix has 12 cells × 192 = **2,304 successful measured calls**, zero
failed measured calls and four original ABBA rounds. All seven parent stages
returned zero and their owned processes/groups closed. All eight observation
controller normal/restart shutdowns closed without survivors. The compiler
ledger has 300 samples, zero missed required samples, zero detected compilers
and zero errors; sampled monitoring does not prove absence of all unsampled
activity.

Boundary evidence contains 32 successful calls and 32 capacity refusals, zero
other errors, and successful drain/recovery. Refusals are not counted as
successful throughput. The six-host recovery canary completed six starts,
12 cancellations, 12 same-key lookups, 90 native calls and 36 independent SSH
checks, including the recorded interruption on rog. It is a correctness
canary, not normal lifecycle ABBA performance or saturated cancellation proof.
The archive compact accounts for all 12 ordinary observation/boundary/recovery
shutdowns separately from the intentional interruption.

## Downstream lifecycle refusal

Original lifecycle materializer `1a1ae6ce842-fc05-5f8b` failed with exit 1
because `completed_observation` requires a passing performance gate. Its
message was `RuntimeError: normal observation campaign did not close and pass`.
This is the expected prerequisite behavior. No lifecycle input, parent output
or lifecycle ABBA directory was created, and no normal lifecycle workload ran.
The original failed native terminal and complete stdout/stderr are retained.

The helper component's favorable cancellation-wait result remains separate.
No whole-runtime cancellation-performance benefit is established for R31.
[Source review](OBSERVATION_PATH_REVIEW.md) identifies no direct path adding
the changed CANCEL_CODE to timed status/read payloads; it neither explains the
measurement nor attributes it to code, network or machine conditions.

## Original identities and complete evidence

| Original | Bytes | SHA-256 |
| --- | ---: | --- |
| Parent report | 130426 | `d52a34b1b5a5870f1676d1b060744834901bc7982ff967ec82fc492ee89321d1` |
| Independent summary | 13619 | `a35f08d2ad7afa70bd3e1f806709a355643febff549eba52bbdab91dd74c0b30` |
| Native observation report | 3559647 | `e0c29c5be7967ddcc272955c810bd156b14e6b3491adfba82805ee5a7c2115cf` |
| Complete archive | 3150234 | `b3e443d4a871b7d77f809d55b161be0e29ced8c722382a7a68bba66668a610d5` |
| Archive manifest | 1084771 | `ba545dd018a8b771991c7ec21293466443a0b1f4c250fb193c9969ab9222ac1c` |
| Compact | 37631 | `646a999d0834fccbb27ffccb076504d81d2abed1511ef2f5ca80cd07c71f38a1` |

Candidate runtime SHA-256 is
`70767e3ef78ec8519b81d7f600b37d012965b3c1b96abaf6c47c8273c73ee450`.

[The archive](observation-evidence-01.tar.gz) includes 4,220 selected files /
31,229,842 original selected bytes. The frozen verifier checked member hashes
and receipt relationships without extracting or executing archived programs;
receipt binding errors were empty. Both observation attempts and the failed
lifecycle materializer are preserved. [Manifest](observation-evidence-01.manifest.json)
and [compact](observation-evidence-01.compact.json) accompany it.

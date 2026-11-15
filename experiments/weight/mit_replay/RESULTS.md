# Public-reference diagnostic replay, 2026-11-03

The published MIT p50c BF16 edit was reconstructed exactly and replayed on six
productive/repetitive context pairs and two premature-closure controls. All 28
paired forwards completed. The predeclared diagnostic mechanism gate passed.

This is a **mechanism replay of public author-selected contexts**. It does not
independently discover the edit, reproduce a blind evaluation or a full math
benchmark, or show that the edit improves a different task.

## Measurements

Changes are edited minus base mean branch log probability, in nats/token.

| Case | Productive | Repetitive |
| --- | ---: | ---: |
| 0 | −0.052601 | −0.086860 |
| 1 | −0.004466 | −0.165464 |
| 2 | +0.003696 | −0.084588 |
| 3 | −0.003256 | −0.078294 |
| 4 | −0.007826 | −0.115360 |
| 5 | −0.006804 | −0.087083 |
| Mean | **−0.011876** | **−0.102942** |

All six repetitive branches decreased. Five productive branches also decreased,
including the −0.052601 change in case 0. The gate compares mean effects; it does
not establish universal preservation. The two one-token premature-closure
controls increased by +0.370565 and +0.309103 nats. Their edited absolute log
probabilities remained approximately −19.38 and −19.48. No broader closure
non-inferiority or generation claim is made.

The base is Qwen/Qwen3.5-0.8B revision
`2fc06364715b967f1860aea9cf38778875588b17`, with 852,985,920 loaded parameters.
The complete checkpoint matches upstream SHA-256
`04b1c301231dd422b8860db31311ab2721511346a32cb1e079c4c4e5f1fe4696`.
The sparse edit is pinned to the source commit documented in `reference.py`.
All four published before/after tensor hashes match. Exactly 130,188 BF16
coordinates changed after rounding, across 64 selected columns in each of layers
15 and 19. The source checkpoint was unchanged.

The replay used CPU BF16 eager inference with four threads. Every raw public text
had the expected published token length, and parent/edited token IDs matched.
The saved token arrays reproduce all 28 branch means. Matching arrays in the
first attempt and completed run were identical.

| Cost | Completed replay |
| --- | ---: |
| Wall time including load and cleanup | 13.644536 seconds |
| Loading and verification | 2.892638 seconds |
| Sum of forward durations | 10.147565 seconds |
| Forward calls | 28 |
| Input-token evaluations | 3,422 |
| Scored branch-token evaluations | 1,594 |
| Generated tokens | 0 |
| Peak RSS | 3,151,864 KiB |

Preparation downloaded 1,770,305,147 bytes and took about 489.6 seconds. Isolated
dependency installation took about 132.1 seconds concurrently. These costs are
not included in the 13.6-second inference figure. Editor tokens and total session
elapsed time were not measured.

A first four-forward attempt failed while serializing a Transformers metadata
set. Its valid token arrays and failure were retained, and the serializer was
fixed. **Including that attempt, total actual inference was 32 forwards, 3,984
input-token evaluations and 1,884 scored branch-token evaluations.**

## Portable evidence

`portable/report.json` is an explicitly derived view of the completed raw report:
it preserves numerical results, immutable source identities, runtime versions,
costs and source code hashes, while omitting local filesystem and host metadata.
It includes the SHA-256 of the unmodified original report. It must not be described
as the original byte-identical report.

`portable/token_logprobs.npz` and `first_attempt_token_logprobs.npz` are unchanged
copies of the public-text score arrays, with their hashes in the portable report.
Raw operational receipts and original reports are retained privately; they are
excluded from this public source tree. No private model inputs, predictions or
market outcomes are included.

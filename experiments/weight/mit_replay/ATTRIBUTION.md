# Reference provenance and licenses

**Sparks of Weight-Space Programming: LLMs can natively read & write neural network
weights**, Rikiya Takehi, Jayden Teoh, Alex Zhang and Omar Khattab, MIT CSAIL,
research blog published 2026-11-02:

https://rikiyat.github.io/blog/weight-space-programming/

Public experiment repository, pinned commit:

https://github.com/RikiyaT/lm_understand-logs/tree/4d09ba6d6a7e891dd8063974dfe81b3d78e3494f/exp8_math

Exact patch manifest and sparse replacement data:

https://github.com/RikiyaT/lm_understand-logs/tree/4d09ba6d6a7e891dd8063974dfe81b3d78e3494f/exp8_math/runs/p50c/edit

Raw public diagnostic request:

https://github.com/RikiyaT/lm_understand-logs/blob/4d09ba6d6a7e891dd8063974dfe81b3d78e3494f/exp8_math/runs/p50c/requests/fwd_24.json.claimed

Qwen base revision:

https://huggingface.co/Qwen/Qwen3.5-0.8B/tree/2fc06364715b967f1860aea9cf38778875588b17

The upstream repository's LICENSE distinguishes author-written Python and shell
scripts (MIT), logs/data/networks excluding third-party content (CC BY 4.0),
MinAtar code (GPL-3.0), and third-party benchmarks/content under their own terms.
Acquisition preserves that exact license in `source/UPSTREAM_LICENSE`. The Qwen
base is obtained separately and remains subject to its own model license.

The verifier, adapter and runner in this directory are new implementations; they
do not vendor the original harness or author-written scripts. Downloaded
diagnostic texts and sparse edit data remain attributed to the original authors.
Behavioral evidence produced here must identify its use of those public contexts
and must not present their reuse as a blind replication or independent discovery.

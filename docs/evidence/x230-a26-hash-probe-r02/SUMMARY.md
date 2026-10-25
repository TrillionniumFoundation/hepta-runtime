# Hash-buffer experiment: keep 16 KiB

The complete fixed experiment passed its integrity checks: 32 measured cells, 128 full-file hashes per cell, eight ABBA blocks, and eight warmup iterations per buffer size. The measured region is the same read/hash window for both sizes; metadata checks occur outside it, and fixed clock/bookkeeping overhead remains.

The median paired thread CPU improvement for 64 KiB was **0.920486%**, with **1.356476 percentage points MAD** and positive improvement in **5 of 8 blocks**. The median paired wall improvement was **0.919215%**. The CPU gates (at least 3%, at least 7 positive blocks, and improvement greater than twice MAD) all failed. The wall regression gate passed. The predeclared decision is **keep the current 16 KiB buffer**; no runtime speedup, memory reduction, or concurrency gain is established.

The first standalone build failed after formatting because the existing qualified release rlibs use panic=abort while the initial probe compiler used unwind. That failed attempt, its exact source/input hashes and complete compiler logs are retained separately. No probe ran in that attempt. The second build verifies the qualified Cargo.toml panic strategy and adds -C panic=abort; its actual formatted compilation source is preserved under build-r02/hash_buffer_probe.rs. The measurement source, plan, and decision rules did not change.

The compressed JSONL retains all 37 original events and all 4,096 measured plus 16 warmup iteration receipts, in their original order. Private paths and environment identities are replaced in place with stable receipts; the manifest retains both the complete original-byte hash and the published-byte hash. No rlib or executable body is included; their complete-file hashes and provenance receipts are retained.

Publication verification passed.

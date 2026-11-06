# R36 validation-scratch: first preparation attempt

This attempt did not reach the qualifier, compiler, or tests. Native job `1a1b1bedd38-fc05-7a99` exited 1 with complete durable output. The original preparation reports `qualification_started=false`, `passed=false`, and a missing D2 historical cache executable at `target-build/release/hepta-runtime`. The failure and all native original text bytes are retained here.

The reviewed 03 deployment installed 22 members successfully in the separate scratch namespace. Its only preparation changes relative to the prior package were the unique ROOT and actual Cargo home; the two candidate Rust files and original eight qualification stages were unchanged.

## Environment preparation

The original historical Cargo home was absent. A read-only inventory found `/home/qian/.cargo`. The first `cargo metadata --offline --locked --format-version=1` failed because the locked `aead 0.6.1` dependency was not cached. Separate `cargo fetch --locked` completed successfully, preserving the original Cargo.toml and Cargo.lock. A subsequent offline locked metadata preflight resolved 280 packages; it compiled and tested nothing. Both the original failure and actual repair receipts are retained.

## Cold build continuation

After the preparation failure, a read-only inventory found no target/cache directory under D2 or its source, and 42,487,177,216 free filesystem bytes. The next preparation will use a new private empty target in `/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02`. It will not claim that a historical cache was transferred or that the failed attempt passed. The first root, preparation report and all original records remain intact.

The accepted production baseline is R24. Current candidate qualification, exact CI and performance acceptance remain unproven. The older audit-cache R36 is a separate rejected candidate; its results cannot qualify this scratch candidate.

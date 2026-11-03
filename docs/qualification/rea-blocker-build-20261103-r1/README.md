# Blocker build evidence, 2026-11-03

This archive binds the benchmark/test executables to their actual build inputs.
The baseline release is clean 23246a5313957e9e97e324303bc47a91808f1ea8.
The candidate is that base plus six reviewed Rust modifications, inventory
0d4d316c6ea9de52276e359e711749a404d3e60191c4d37d7fcd8dcb2c39a28c,
diff 79cef8bff8213a1f159c310a98ce5fdf29505113745a93b07debd2f61ef651ec.
It is not relabeled as a clean base build or as the final publication commit.

## Preserved original attempts

| Attempt | Actual outcome |
| --- | --- |
| Baseline release | Exit 0; qualified; unchanged source and zero monitor events/errors |
| Candidate preflight r1 | Exit 1 before Cargo: the wrapper stripped the leading porcelain status column |
| Candidate build r2 | Fmt, all-feature compilation and exact warm-store test exited 0; enclosing result remained failed because the summary regex was overescaped |
| Candidate continuation r3 | Exit 0; qualified; reused the verified r2 artifact and passed both native-client test configurations, no-default compilation and release build |

The original job receipts and complete stdout/stderr remain under original-jobs.
The original request JSON preserves exact shell, arguments and explicit build
environment. Runner failures are not presented as product-test failures, and
successful artifact reuse does not erase a failed enclosing attempt.

The two full inventories in source-manifests preserve all 7,902 recorded paths.
Byte-identical before/after and r2/r3 copies are deduplicated only after exact
comparison; evidence-index.json records every original path and full JSON hash.
The inventory's own content digest is distinct from its serialized JSON hash.
Build linkage is not a cryptographic compiler attestation.

Executable images are not committed. Their SHA256 and original paths remain
in the artifact receipts. The browser/Python/documentation additions happened
after these Rust builds. Exact publication-head and prospective-merge CI must
validate the final tree; these main-host receipts do not replace those gates.

Run sha256sum -c SHA256SUMS from this directory to verify retained bytes.

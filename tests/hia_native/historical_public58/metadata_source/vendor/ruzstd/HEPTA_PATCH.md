# Local block-bound checks for ruzstd 0.9.1

This directory contains the exact published ruzstd 0.9.1 crate, except for the two production changes listed below and this provenance documentation. Its original license, version, manifests, and upstream files are retained. The original archive SHA-256 is `69e4ce4a039f42bf25920b95667e4d789e98749ab11bbb8d2c2936f788421bb5`; UPSTREAM_SOURCE.json records every original file hash and each changed file's before/after hash. The registry cache is not modified.

1. Check the regenerated literal count against min(Window_Size, 128 KiB) before decoding the literals. This also covers the zero-sequence path.
2. Check the sum of executed sequence output and remaining literal tail before appending that tail. The existing per-sequence check alone did not include the final literals.

These are format limits, not new host resource budgets. Both checks reject the complete malformed frame and do not return partial accepted data. Local changes follow the crate's existing MIT license. No native compression library is linked.

Independent actual REA 6.8.0 / Node v22.23.4 comparison established two over-limit sequence-tail negatives and three valid boundary/control positives. The root parser regression tests exercise these frames and the zero-sequence block cases directly against this dependency. The original failed comparison remains in the external qualification evidence.

The full inspect_elf_notes operation is not qualified by this patch. Malformed Zstd diagnostic-message differences, the full MCP contract, delivery/retention, and native operational limits require their separate gates.

Integration: keep ruzstd =0.9.1 with default-features=false and features std/hash; apply the root [patch.crates-io] entry ruzstd = { path = "vendor/ruzstd" }. Root Cargo.toml and Cargo.lock are maintained by the integration owner.

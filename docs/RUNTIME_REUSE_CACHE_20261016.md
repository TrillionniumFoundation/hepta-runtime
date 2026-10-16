# R22 durable-job idempotency reuse: positive-only cache candidate

**Status:** isolated Rust source and tests; not deployed to the live V4/V11 controllers.

## Real 2026-10-16 evidence

- Six parallel `process_start(/usr/bin/true)` requests on main, pocket4, rog, mac, x230, ai395: 6/6 accepted and launched; client-side batch wall 29.071 s.
- All six authoritative original `process_status` calls: 6/6 succeeded, exit 0, output complete.
- Resubmitting the exact six original idempotency keys: 6/6 reused the original IDs, none re-launched, client-side batch wall 29.717 s.
- Single repeated `main` key also took about 5.015 s at the full ChatGPT/plugin boundary.
- The live job directory held 23,347 JSON records / 46,257,139 bytes. Three standalone read/parse passes took 831.9, 819.1 and 817.8 ms (not the Rust start-job timing).
- These timings include tool connector and disk/network overhead; no isolated Rust scheduling speedup is claimed.

## Source change

- Base is the host-scoped START_LOCK candidate (PR #12), not the live R22 binary.
- Cache **only** an observed positive `(configured host, idempotency key) -> original job ID` for an already-launched job. Cache never authorizes a new launch or serves negative lookups.
- Every hot hit re-reads the original record, checks exact host, idempotency key and ID, and requires the same directory device/inode/mtime/ctime observation.
- A changed directory generation invalidates fast hits but preserves previously observed bindings as refusal evidence; disappearance or rebinding cannot create a replacement task.
- Unknown keys, pending/failed/unknown launch states, corrupt records, duplicate original bindings and uncertain reconciliation remain on the full historical scan or fail closed.
- The cache has a strict 4,096-entry limit and is private to one controller process; controller restart rebuilds from authoritative disk records.

## Retained limitations

- New unique job keys **still scan the entire legacy JSON store**. This intentionally does not install a potentially unsafe negative cache.
- Fast-path known launched identities may bypass unrelated in-place tampering to another JSON file if directory metadata is unchanged; the current private single-owner state-root requirement remains essential. This candidate is not an adversarial full-tree integrity proof.
- Positive-cache hot-path performance on temporary synthetic state is not SSH/TPS throughput or verified production speedup.
- Do not merge or deploy until R22 exact source provenance, owner-fence single-writer guarantees, live 6-host launch/reuse A/B, controller restart and rollback are established.
- Original Desktop Commander and the V4 production effect owner remain untouched.

## Qualification

On the isolated exact source: `cargo test --offline --locked ... mcp::runtime::jobs::tests` returned **31 passed, 0 failed, 1 manual benchmark ignored**. The complete offline locked Cargo suite returned **655 passed, 0 failed, 13 ignored** for the main binary and **8 passed, 0 failed** for `jobctl`; `cargo fmt --check` and `git diff --check` passed. Separately executing the explicitly ignored 6,000-record filesystem microbenchmark returned cold **91.204 ms** versus hot **0.044 ms**, with the same original job ID. These measurements apply only to synthetic on-disk records and a single controller process; they do not establish live SSH throughput, A/B production improvement, or R22 source/binary parity.

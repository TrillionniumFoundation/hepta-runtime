# Exact CI source-profile successors for operation 9

The first normal CI runs on commit
`bb1b1e4bc05a7a036e83db0f20db9e5ae6b57fec` rejected the new owner at two
frozen source checks. The historical58 materializer and current-default124
reader still expected the preceding operation-8 owner. Both jobs stopped before
running a compiler or application. Their complete decoded job logs and failure
identities are retained in `ci-compatibility.tar.xz`; they are not reported as
successful runs.

## Source changes and preserved requirements

The historical profile advances from v6 to v7. It checks the 537 exact current
graph files and excludes the new integration record when materializing the old
58-image graph. All 120 historical restore pins remain identical. Its original
graph binding, original domains, authority inputs, workflows and budgets remain
fixed. The materializer changes four schema/count literals only. The test
reconstructs the complete original profile and materializer, then actually
materializes and checks the historical source view. The local checkout contains
the complete required source closure; unrelated repository files are not used
to claim a historical application execution.

The current-default reader retains its original 536 source rows and seven-edit
default-entry proof. A new helper accepts only the four exact operation-9 source
identities and reconstructs the complete preceding owner, bridge and binding
bytes. The original checks then validate every original row. All 533 unrelated
bound sources are still required exactly, and the added integration record is
checked separately. The preceding reader is retained verbatim, and the ten
reader edits must reconstruct it completely.

For the exact successor, the expected executable is the real operation-9
product ELF already exercised by the public-route regression. The old capture
still requires the original old ELF. The source and result records explicitly
distinguish these two identities. All original requirements for 116 fresh
direct compiles, eight fresh packed compiles, zero reused member images, owned
worker processes, whole image bytes, 117 physical images, 69 descriptors,
180-second guarded reads and false full-runtime/production flags remain.

The default workflow contains two exact recipe-manifest SHA checks. These two
SHA values are updated to the final new recipe digest. Replacing those two
values with the old digest reconstructs the complete original workflow bytes.
All commands, source-mode checks, timeouts, build requirements, evidence upload
and independent uploaded-data reread steps remain unchanged. No CI step is
skipped or bypassed.

## Observed local results

`CI_RESULTS.json` records the observed assertions. The supplementary archive
contains the full fresh default capture, both complete guarded read proofs,
all 120 historical restored sources and the complete materialization receipt,
the original profile/workflow bytes, source
corruption results and the first normal CI failure logs.

- The unchanged default builder actually compiled all 116 direct and eight
  packed HIA members from source, with zero reused member images. It used the
  verified pinned compiler bootstrap and completed in 109.99 seconds.
- The 26,288,128-byte product ELF has SHA256
  `65e34dfe467405beb4f00245bd5d94d4f0467934c28c93ed680b89cc15b5328e`, exactly
  matching the separately exercised product. HIA linking and packing ran.
- The final reader completed the full new capture under its unchanged
  180-second limit, including all 11 read-only enforcement probes. The
  before/after inventories are identical.
- The final reader also completed the retained old default124 capture. Its
  complete evidence object is identical to the original old-reader result,
  including the old ELF, original source binding and all scope flags. This
  reread runs no compiler, application, Rust or SSH.
- Physical single-byte changes to the current owner, bridge, binding,
  integration record and an unrelated frontend are rejected. Removing only
  the integration record cannot make the new owner fall back to the old
  profile. Every original byte is restored before the next positive check.
- All 120 historical pins remain identical; a real mutation of the restored
  old owner is rejected by the complete materialized-source verifier.

These observations are local build/source/DATA evidence. The normal repository
CI results are separate observations. The earlier Rust exact-head and
prospective-merge jobs were still running at the recorded snapshot; no full
Rust or full-runtime PASS is inferred from the local results. The existing
public-handler regression remains unchanged, and public `binary_write` still
requires the missing integration work listed in `README.md`.

## Reproduce the source controls

The archive is stored as `ci-compatibility.tar.xz.part1` and `.part2` because
the upload connector limits an individual request to 16 MiB. `CI_EVIDENCE.json`
pins both volumes and the complete joined archive. Verify the two volume
hashes, join them in numeric order, then verify the joined SHA256:

```bash
cat ci-compatibility.tar.xz.part1 ci-compatibility.tar.xz.part2 \
  > /absolute/owned-output/ci-compatibility.tar.xz
```

After verifying and extracting `ci-compatibility.tar.xz`, use its
`frozen-inputs` directory and a complete current checkout:

```bash
python -I -S -B tests/hia_native/binary_root_product/verify_ci_profiles.py \
  --source /absolute/current-checkout \
  --frozen-inputs /absolute/ci-compatibility/frozen-inputs \
  --output /absolute/fresh-source-control-output
```

For a fresh default build, run the unchanged workflow sequence: prepare using
`qualification/public124_default_entry_v1/source/entry.py`, invoke
`scripts/hia_native_runtime_mcp_build.py` with the pinned Hepta checkout, then
run the guarded reader. The retained local capture contains every build output
needed for a DATA reread; the compiler/bootstrap identity and full build
process records remain in that capture.

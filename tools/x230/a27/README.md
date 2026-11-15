# A27 x230 experiment tools

These tools accompany [`docs/X230_A27_20261024.md`](../../../../docs/X230_A27_20261024.md).
They are isolated diagnostic programs and evidence publishers. This checkpoint
does not change or deploy runtime source. Existing A26 qualification and its
full source map remain the baseline.

## Frozen source bundles

The original layouts, manifests, plans, and failures are retained in
[`docs/experiments/x230-a27`](../../../../docs/experiments/x230-a27):

- `owner-path-source-r01.tar.gz`: the initial preparation that refused two
  qualified `serde_json` profiles before compilation or a workload.
- `owner-path-source-r02.tar.gz`: exact-profile dependency selection, the
  unchanged full owner-verification probe, semantic checks, ABBA runner,
  analyzer, and rejected path-iterator candidate.
- `archive-build-subset-r01.tar.gz`: the exact five source inputs used by the
  native complete-source A/B release build, plus its manifest.
- `archive-probe-source-r01.tar.gz`: the complete 19-file archive candidate,
  fixed 49,152-query experiment, external resource sampler, analyzer, pure
  logic checks, and source/bundle manifests. Both arms keep the public API's
  original three-second deadline and eight actual query closures.
- `archive-materializer-source-r01.tar.gz`: a source-copy tool gated on an
  actual complete passing archive analysis. It does not itself qualify or
  adopt a runtime. Its exact candidate is one changed file and one new test
  file, with no probe hooks.

Extract each bundle into a fresh directory and inspect its own plan and CLI.
All actual Rust formatting, compilation, testing, and workload execution in
this investigation happen on x230. Tools bind specific qualified source,
toolchain, dependency, plan, and output identities; an arbitrary checkout is
not interchangeable. Do not edit a frozen tool or overwrite an earlier output
to make an attempt pass. A preparation or evidence-publisher correction uses
a separate version and preserves its predecessor.

## Completed native fixtures

`resources/` contains the external `/proc` sampler, its sixteen unit tests,
and its fixed native permission-denial probe. Resource fields that could not
be observed remain unknown. The complete error JSONL and its final hash are
separate from the bounded preview. Sampled tree aggregates are non-atomic
estimates.

`ownership_counterexamples.py` exercises four newly created local fixtures;
it neither scans nor reclaims older runtime roots. `custody/` contains the
three-process, single-request owner experiment. It sends SIGKILL only through
the original fixed controller's pidfd, drains the original writer after EOF,
and retains the new socket. The README in that directory defines the excluded
recovery claims and private identity files.

## Original evidence and public views

The original owner experiment is retained on x230 and bound by its complete
archive hash. Public views retain every cell, operation, failure, and metric,
with identity/opaque values represented by separate hash receipts. They are
not byte-identical copies of the private originals. See the
[publication notes](../../../../docs/evidence/x230-a27/PUBLICATION_NOTES.md)
and [publication receipt](../../../../docs/evidence/x230-a27/publication-receipt.json).
The superseded public-view r01 package is not published.

`build_syscall_publication.py` reuses the frozen A26 complete sanitizer and
its two imports. Its fixed original workspace-relative input layout is
recorded in the script; restore that layout before reproducing publication.
`recompute_owner_result.py` expects to sit beside the extracted private
`a27-observation-probe-run-r02` and `a27-observation-probe-build-r02`
directories. It checks complete stdout/stderr bytes and recalculates the
paired CPU/MAD gates without starting any operation. Public sanitized data
and a successful publisher exit do not replace native qualification or a
performance-adoption decision.

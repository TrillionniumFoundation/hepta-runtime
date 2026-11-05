# X230 R24 evidence and tooling

**Acceptance evidence:** full qualification and the formal six-host campaign passed all frozen gates. Complete campaign control, source/input stability, child reaping and standalone lifecycle verification are closed. Exact GitHub publication identity is established by its separate commit/ref readback. R23 remains the retained failed experiment.

The formal A baseline is accepted R22 commit `afec5354d1e0eca09f10ccabd73a01be2f14092c`. R24 retains the unadopted R23 extension of the bounded public executable references and adds typed known-terminal master renewal strictly before slave submission. See the [R24 report](../../../../docs/X230_OPTIMIZATION_20261105_R24.md).

## Verified qualification

Eight qualification stages returned zero. Across five test targets, 1,645 passed, 0 failed, 34 were ignored, 1,679 were selected, and no test was retried. All 220 formatted `source_tested` inputs equal `source_after` and the complete local source bytes. The only formatting change was one wrapped test assertion; production code matches the independently reviewed candidate exactly.

| Evidence | Scope |
|---|---|
| [Full qualification report](reviews/qualification-report-01.json) | Exact 83,365-byte terminal report; SHA-256 `bf0c5814d28b163e4a90405026cd4d90e399370d1f910f8ac48cb580af1e4971` |
| [Compact qualification](reviews/qualification-compact-01.json) | Stage outcomes, test totals, audit error list, output identities |
| [Isolated test summary](reviews/isolated-tests-summary-01.json) | Five target inventories, selected/ignored counts, no retries |
| [Qualification closure](reviews/qualification-closure-01.json) | Full report, complete input maps, actual output identity checks |
| [Qualification and format review](reviews/qualification-review-01.json) | Review scope and limits; known-terminal regression fixture |
| [Output identities](reviews/qualification-output-identities-01.json) | Independent remote full SHA-256/size receipts for the three output files |

The complete audit body and ELF bodies were not downloaded for this qualification closure. Audit-stage rc=0 comes from the full terminal report; the empty audit error list comes from the exact compact evidence generated from the terminal audit report. The original audit file's full SHA-256 and size were independently checked. Future raw archives remain separate evidence.

## Source and static review

| Evidence | Scope |
|---|---|
| [Qualified source map](reviews/qualified-source-map-01.json) | All 220 SHA-256 inputs; map SHA-256 `c3415beaf7697b3eb07a763ef24f424138de80af31acfd6c224cf682f3c67cbd` |
| [Closed source/Git binding](reviews/qualified-source-binding-01.json) | Five changed source files relative to R22; complete leaf hashing and tree reconstruction |
| [Preserved prequalification binding](reviews/source-binding-prequalification-01.json) | Earlier source-tested-only record, unchanged after closure |
| [Independent static review](reviews/source-review-01.json) | Terminal proof, ownership/capacity, authority checks, no command replay, regression fixture |
| [Formatted file identities](reviews/formatted-source-identities-01.json) | Prepared and actual post-format source identities |
| [Formatting diff](reviews/pool-tests-format-01.diff) | Only a multi-line `assert_eq!` formatting change |

The actual candidate `src` tree reconstructed locally is `b71cac25e2c2138837f27f3c74f6a2dc5c56b565`. This hash alone is not a publication receipt. Root/socket/peer checks, captured-command handling, final authority checks, original retirement custody, and all configured capacities remain unchanged. Only a known terminal original Child before slave creation can join existing singleflight renewal; later transport failures are not automatically replayed.

## Frozen plan and actual inputs

- [Measurement plan](measurement-plan-01.json) is the original frozen preparation artifact. Its candidate fields intentionally retain their historical pending values.
- [Actual campaign inputs](campaign-inputs-01.json) binds the completed R24 qualification and actual candidate binaries. The launcher computes and records its full source-input identity in the campaign report.
- [Campaign launcher](campaign-tools/r24_campaign.py) and [summary/gate calculation](campaign-tools/summarize_r24_campaign.py) retain the fixed R22 baseline and original native, capacity, and lifecycle harnesses.
- [Actual-input preparation](campaign-tools/prepare_campaign_inputs.py) binds the qualification outputs and writes the compact qualification receipt.
- [Preparation and qualification launcher](qualification-tools/prepare_and_qualify_r24.py) records the isolated R23 source/cache provenance while keeping R22 as formal A. It does not adopt R23.

The performance workload is completed-job `process_status` / `process_read` observation RPCs at C1/C8/C16 in ABBA order, with workers=2 and allocator arena=1. The C8 adoption gate requires at least 3% throughput improvement and at least 3% controller CPU/call reduction, while all three concurrency levels and the RSS gate must pass. RSS must satisfy both `A + 512 KiB` and `A × 1.05`; the 2 MiB reference payload cap is a different limit. C32 capacity and C6 cancellation/recovery are mandatory correctness gates, with no automatic RPC retries.

## Actual formal results

The campaign summary and independent analyses report 2,304 measured calls, 288 warmup calls and 72 preflight/restart calls, totaling 2,664 calls with zero failures. Independent local arithmetic recomputed successful rate from calls/elapsed and controller CPU/call from synchronous CPU totals, then checked all fixed ratios and gates.

| Concurrency | A → B successful RPC/s | Throughput change | A → B controller CPU ms/call | CPU change | p95 change |
|---|---:|---:|---:|---:|---:|
| C1 | 6.664 → 7.458 | +11.91% | 47.786 → 31.458 | −34.17% | −8.08% |
| C8 | 45.611 → 54.126 | +18.67% | 28.203 → 19.323 | −31.49% | −15.62% |
| C16 | 45.844 → 55.285 | +20.59% | 28.984 → 19.661 | −32.17% | −16.76% |

Maximum sampled controller RSS across all four controllers per arm was A=18,528 KiB and B=18,488 KiB, below the 19,040 KiB gate. The −40 KiB sampled difference is not an intrinsic allocation reduction: R24 retains 156,720 additional reference bytes. C32 had 32 successes, 32 capacity refusals and zero other errors across two bursts, with drain/recovery passing. C6 lifecycle verification reports 90 native calls, 36 independent SSH checks, six new fixtures, 12 same-key lookups and 12 cancellations, including the ROG master interruption and controller crash/restart.

| Formal evidence | Scope |
|---|---|
| [Complete campaign control](reviews/campaign-control-01.json) | Exact terminal 100,033-byte report; all seven stages passed/reaped; inputs and source unchanged |
| [Campaign gate summary](reviews/campaign-summary-01.json) | All fixed performance and correctness summary gates passed; no rejection reasons |
| [Native independent analysis](reviews/native-analysis-01.json) | ABBA aggregates, raw-evidence audit identity, topology, resource observations |
| [Capacity independent analysis](reviews/boundary-analysis-01.json) | Two C32 bursts, separate capacity refusals, 202 total calls |
| [Lifecycle independent verification](reviews/lifecycle-analysis-01.json) | Six original new jobs, ROG replacement generation, cancellation, crash/restart and durable terminal identity |
| [Independent arithmetic review](reviews/campaign-arithmetic-review-01.json) | Recomputed rates, ratios, thresholds, all eight RSS rows, and scope of verification |
| [Mac holder report](reviews/mac-holder-01.json) | Remote exit=0, owned agent reaped and socket/directory absent after context |

The complete control report has `passed=true`, `adoption_passed=true`, unchanged candidate/baseline source and unchanged inputs. All seven stages returned zero and record their original child and process group absent after reaping. A/B source digests were recomputed from all 220 complete local inputs on each side and match the actual campaign control; B also matches the qualified source and output binaries.

The control report SHA-256 is `066952f12414e8f7291e21e58a77d53d4cd712104557bd6bdfdd7c383f9f1e2a`. The actual candidate source size/SHA map digest is `e449e138216242c89b2ceff69babafe658411a42c73df0c66b222899540bdff7`. These are the actual completed campaign identities, not a replacement success wrapper.

Core source, qualification and campaign evidence may publish together. Full raw archives follow in a companion evidence commit for this same R24 version; download links are added after the archives are in the repository. The unchanged lifecycle harness stores this run's raw evidence at `/home/qian/hepta-runtime-optimization-20261104-r16/r24-cancel-recovery-01`, explicitly bound by the control report. Final publication success remains tied to actual GitHub commit/ref readback.

# Final merged release: independent Evidence and APK gates

This record qualifies the actual merged release executable, SHA-256
`0595fbf02e0f492bd151fec97eb90cb704a88810e9415b90582d348f3db99b6a`
(18,437,832 bytes), against the three committed external gates below.
The original release was copied and checked before and after preparation. Each
gate then used the same independently frozen executable. Selected production
sources, scripts, configuration files, all 20 APK fixtures, and both binary
copies were unchanged before and after the run.

The observed root checkout commit was
`618e8638c84cd9c95fb08b52ea9354e982ee0154`; the parent release build bound its
production source at `b857dc7d` before that documentation-only update.
This is a new final-binary run, not reuse of the earlier development-binary
results. The root Rust/Python matrix and other capability qualifications are
separate gates and are not asserted by this record.

## Actual results

| Gate | Result | Process duration |
| --- | --- | --- |
| Real REA 6.8.0 Evidence through public MCP | 438/438 accepted, no expected rejections, no mismatches; controller exit 0 | 55.289 s |
| APK native / real REA / Android oracle | 20 fixture projections, including 19 Android-valid inputs and one forged signature rejected; 4 malformed worker inputs rejected; 2,398 installed npm package files matched the frozen tarball | 22.015 s |
| APK public MCP | All 6 admission, identity, malformed-input recovery, cancellation, fixed-deadline and cold-recovery gates passed; both controllers exited 0 | 35.023 s |

The three groups ran concurrently, after the parent's registry-heavy Python
suite had fully stopped. The complete wrapper took 56.462 s within the unchanged
900 s overall limit. Each gate kept its original internal deadlines and checks.
The durable job `1a1a6d5e141-fc05-28f9` ended successfully with exit code 0,
complete durable output, no automatic retry and no timeout.

Ordinary MCP cancellation of an observed stopped native APK worker completed
in **0.014884 s**, within the original **5 s** observation limit. The separate
stopped-worker deadline gate used the production **30 s** limit and the original
**35 s** observation limit; it completed 30.072317 s after the stopped state was
observed. Both workers were killed and reaped by their original controller, and
a subsequent request succeeded. No manual worker cleanup or controller teardown
action contributed to a passing result.

## Regression coverage and honest boundaries

The Evidence corpus retains all historical cases and the 20 authentic decimal
halfway cases that the earlier 418-case corpus missed. The earlier exact RED
and old-release 20 rejections are retained in
`../rea-evidence-halfway-20261104-r2/`; this final run has zero rejections.
It qualifies the native digest-verification subset, not every upstream Evidence
schema, retained view, provider workflow or 229-tool contract.

The final APK run preserves the exponent-support boundary found by the independent
audit: the valid 33-bit RSA exponent is verified, while both Android-valid
34-bit-exponent fixtures return partial/unsupported. The original independently
generated `e = 8589934609` APK is included unchanged. A matching APK content digest
does not make the forged signature pass. Unsupported P-521/RSA-1024 boundaries,
v1 absence and v3.1 presence remain explicitly limited by the implementation.

The upstream tool `inspect_apk_signature` corresponds to the finite projections
tested against native `rea_inspect_apk_signature`; `inspect_apktool_client` is a
different upstream tool. These checks do not qualify the complete Android
installation verifier, all APK signature schemes, signing lineage, platform
policy, trust decisions or REA's complete Evidence/session lifecycle.
`full_upstream_parity_qualified`, `full_android_verification`, and
`rea_evidence_compatibility` remain false as applicable.

## Provenance and reproduction

All new files, temporary workspaces, Java helper output, logs, binary copies and
process working directories were outside the root checkout. Python used
`-B` and `PYTHONDONTWRITEBYTECODE=1`. The existing APK oracle hashes four source
files relative to its working directory, so the wrapper copied those four
frozen files byte-for-byte into an independent working directory and checked
their identities before and after. It executed the original committed script
and used absolute paths to the original, unchanged APK fixtures.

`combined-qualification.json` contains the exact argument vectors, working
directories, all selected input hashes, raw receipt hashes, durations, detailed
lifecycle results and the before/after checks. The three unchanged entry points
were:

- `scripts/rea-evidence-number-mcp.py`, SHA-256
  `5eeeb7fb9a6d7e3d2dcdfa65dd9afb116577bf76e554d91bed9d8d2e94bd7a1b`.
- `scripts/qualify_apk_signature_native.py`, SHA-256
  `e48840986768a84e29fbab1839e62699b60362179822b0e70d31a08abd5cb784`.
- `tests/rea_apk_signature_mcp.py`, SHA-256
  `633dd05e70696b5082f6d5f092e02a56f50ed5d43d7faf8b4ba64ff4105b1bbf`.

The orchestration wrapper remains at
`/tmp/rea-final-independent-20261104-r2/run.py`, SHA-256
`235103132a921ec9f8f313293eac629a486ca3f463b929b117329deea3d73577`.
It adds no relaxed expected rejections, fixture skips or extended per-gate limits.
The archived preparation receipt records the earlier preparation-only state;
the later combined receipt and durable terminal status prove execution completed.

Raw outputs and the independent frozen executable are retained outside the
repository at
`/home/qian-qi/work/hepta-rea-final-independent-20261104-r2/gates-r1/`.
The full APK oracle JSON is retained there as `apk-three-way.json`, SHA-256
`93148d13d0c334f02dc3c50caf1153cb026b8293578002986335b50ed99446db`.
The compact projection here preserves every fixture verdict and oracle
comparison while referring to that complete original report by hash.

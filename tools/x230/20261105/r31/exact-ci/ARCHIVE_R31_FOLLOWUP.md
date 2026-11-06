# R31 follow-up archive

`archive_r31_followup.py` currently implements **exact-ci only**. It reads existing evidence, accepts completed successful or failed native outcomes, and never runs Cargo, tests, benchmarks, SSH or programs stored in an archive. The collection and no-extraction verifier derive from the existing `archive_r31_evidence.py` (`237a05cebf47007a1f593bc415112474ec06cfd68997e1e2f6e75d795deb5a3f`).

## Frozen script and limits

- Script SHA256: `f1b542cf0abfb7f761c1493bf65c95a446a9d37a8f3ead524a5cfbb470eb4dce`.
- Selected source bytes: at most 64 MiB; one file: at most 8 MiB; selected files: at most 8,192. Manifest: at most 2 MiB. Compressed archive plus sidecars also must fit 64 MiB.
- Source reads use regular-file checks, no-follow opens, one-link checks and stable before/after identities. The local archive read and gzip expansion are separately bounded.
- Output files are create-only. A pre-existing output or partial earlier output causes refusal; no deletion, replacement or benchmark retry occurs.
- `source`, `target`, `target-build`, test ELF files, profiles and credential files are excluded. Known private-key markers cause collection to fail before writing an archive.

## Inputs to preserve before creation

The fixed root is `/home/qian/hepta-runtime-optimization-20261105-r31`. Required original result files are `rust-ci-plan-02.json`, `rust-ci-02/plan.json`, `rust-ci-02/report.json` and `rust-ci-native-02.json`. The native terminal must identify job `1a1ae572e9e-fc05-5f26` and be terminal. Successful and failed results are both supported.

Save complete, original parsed `process_read` objects under exactly one naming convention:

- One page: `rust-ci-native-read-02.json`.
- Multiple pages: `rust-ci-native-read-02-000.json`, `rust-ci-native-read-02-001.json`, and so on without gaps.

The collector requires coverage from offset zero through each final stored byte count and retains the native seen/stored, completeness, durability, truncation, timeout and cancellation fields. It does not relabel a failed or incomplete native outcome as success.

The package also retains the original five `rust-ci-tools-01` files, the six `rust-ci-tools-02` files, the failed `rust-ci-preflight-attempt-01` originals, all existing `rust-ci-02` logs, and fixed qualification/preparation references. `tools-01/r31_campaign.py` is included as the original receipt binder source, alongside its `campaign-inputs-01.json`; neither is imported or executed. The separate original qualification archive remains referenced by SHA256 `f802c5fed5e3b79773825a12cbe9c888570e3ea19f954009857350e93c8071d2`. Its compressed case logs and retained test binaries are not copied again.

## Create once on x230 after the CI task has closed

After uploading the frozen script, use:

```sh
/usr/bin/python3 -B /home/qian/hepta-runtime-optimization-20261105-r31/archive_r31_followup.py \
  --kind exact-ci \
  --plan-sha256 901597a4a8052d66ccad4eabb81b75dd26024638e7db8ab9027b430366e76b0f
```

This creates `exact-ci-evidence-01.tar.gz`, `exact-ci-evidence-01.manifest.json` and `exact-ci-evidence-01.compact.json` in the fixed root. The compact summary preserves `reported_passed`, original errors, stage results, nextest audit counts when actually present, source/child-closure flags and receipt-binding discrepancies. The archive is not an independent nextest rerun, hosted Actions result, performance pass or adoption decision.

## Verify the transferred archive locally

Use the archive SHA256 returned by the original creation receipt:

```sh
python3 -B archive_r31_followup.py \
  --verify /absolute/path/to/exact-ci-evidence-01.tar.gz \
  --expected-sha256 ACTUAL_ARCHIVE_SHA256
```

Verification checks the bounded compressed and expanded sizes, regular safe members, exact per-file bytes/hashes and membership, excluded-content rules, and re-derives the compact summary from the stored receipts. It extracts zero files and executes zero archived programs. Use this same frozen script: its SHA is part of the archive manifest.

Eight directed local synthetic checks passed, including failed and successful result round trips, create-only preservation, source/profile/ELF exclusions, symlink and private-key-marker rejection, oversized input rejection, corrupted archive rejection and native-read pagination. The checks are not real CI executions; their temporary fixture archives were removed. See `archive-r31-followup-local-checks.json` and `archive_r31_followup_checks.py`.

## Later archive path drafts

These are planning notes only; `observation` and `lifecycle` are not CLI choices in this frozen version. Adapt them after actual reports exist.

| Kind | Core reports and candidate fixed inputs |
|---|---|
| Observation | Original `campaign-01/report.json` failure; completed `campaign-02/report.json` and its raw stage directories; `campaign-inputs-01.json` / `campaign-inputs-02.json`; `tools-01` / `tools-02`; actual boundary/lifecycle tool manifests; original holder terminal/read receipts for attempts 01 and 02. The original canary lives outside R31 at `/home/qian/hepta-runtime-optimization-20261104-r16/r31-cancel-recovery-02`; if used, map that one explicit root to a named archive prefix rather than following arbitrary report paths. |
| Lifecycle | Actual `lifecycle-campaign-02/report.json`, `lifecycle-abba-02` raw reports/logs, lifecycle input receipts, lifecycle tools/manifests and original holder terminal/read receipts. Require actual core reports and retain unsuccessful outcomes. Confirm actual stage paths and cleanup references from the completed parent report before sealing selection. |

Mac holder files must be explicitly retained as original receipts before an x230-only archive can include them. The archive script should never fetch them over SSH or infer credentials from a profile.

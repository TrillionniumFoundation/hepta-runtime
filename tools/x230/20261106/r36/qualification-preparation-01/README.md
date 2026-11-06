# R36 qualification preparation — unsealed template 01

Status: offline source/input preparation only. The preparer, qualifier, tests, compilers, native jobs and host probes have not been executed by this preparation. D2 recovery attempt 02 has no result in this package. Do not deploy or launch this unsealed template. Final owner receipts and a reviewed actual input seal are still required.

## Source, protocol and output

Source construction is accepted R24 `baab4def80be7af015b2e7a594cb302f66c4130e` plus the already-published R36 draft03 patch. The source package has 12 files, including its manifest, and a complete 220→220 map. Only `ssh_observation_profile.rs` and `ssh_observation_reference_tests.rs` change. The two added fixture test names are bound as real source additions; no future test count is predicted.

The source catalog is `c140350897adc751682e7eacd6e1874325d86538`; publication reference is commit `2ce91de7aac7393f9271690fc3f350caa8cb4500`, draft PR108. The candidate package remains immutable. D2 provides only its ended build cache, never source for R36.

The original R35 preparer is Git `2409b4cfc8b3f3a34ac70bcd1efc614a510b9826` (32,838 B / 68706558…). All 13 general helper bodies are retained byte-for-byte. The original 19 harness pins are unchanged. The qualifier itself is the exact 7,661-byte Git `9e0224291058d67740f603db982fa9220fca92b1`, SHA256 `95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d`.

The eight stages remain format, fmt-check, harness-tests, clippy, test-build, isolated-tests, audit-isolated-tests, release. The original offline/locked/all-targets/all-features selectors, Cargo +1.95.0, environment filtering, jobs=2, zero automatic retries, stage-timeout default 3600 seconds, isolated test timeout 180 seconds and 3 GiB free-space minimum are untouched. No stage or assertion is filtered to make the two new tests pass.

New root: `/home/qian/hepta-runtime-optimization-20261106-r36`. The preparer report schema is `hepta-x230-r36-preparation/v1`; the original qualification report remains `hepta-x230-composed-qualification/v1` at `qualification-01/report.json`. `preparation.json`, source, qualification-01 and target-build must be fresh. A successful qualifier must bind source_input to the frozen pre-format map, and source_tested/source_after/source-map.json to the actual formatted map. Only the two changed files may differ from R24 after formatting.

`preparation.candidate_patch` retains four fields: path, bytes, sha256, git_blob. Consumers must not compare it to an invented three-field shape.

## Cache owner closure

The cache is `/home/qian/hepta-runtime-validation-cost-20261106-d2/target-build`. Its last actual build is the closed ordinary-01 job `1a1b1014af6-fc05-74d2`, followed by postflight `1a1b1217f3f-fc05-7616`. The feature qualification and exact-CI jobs are respectively `1a1b0cc0f51-fc05-7301` and `1a1b0f08c41-fc05-7434`. These are historical D2 facts, not predicted R36 outcomes.

The new owner body follows D2's already-reviewed direct-document model (`b36509c248d80ed0c932bf14d5a3d5fa0a009857`). It reads the bound Q/CI/ordinary receipts and native streams directly; it does not recursively invoke their old binders, rerun any auditor, or launch another diagnostic.

The unsealed closure has 28 fixed roles: 19 known identities, nine pending C1 identities. D2 Q/CI counts and ordinary counts are read from their original reports. The current D2 source is independently rehashed against its qualified 222-input map. It is not compared to R24's different 220-input map.

The first C1 parent is preserved as its real failed preflight: stages=[], FileNotFoundError, inputs_unchanged=false, source_inputs_unchanged=false, no quiet period or native workload. The monitor and original Mac holder still need their complete raw closure evidence. Those false flags are not promoted to true. Four original missing output files are required to stay absent; actual failure evidence must confirm the pending closure before sealing.

Recovery02's three Linux output paths are fixed to c1-campaign-02/report.json, c1-campaign-02/compiler-monitor.audit.json and c1-observation-02/report.json. Its parent/monitor/native/holder/source facts and four rounds/eight controller shutdowns must close. The owner checker records the actual diagnostic verdict without requiring that verdict to mean performance adoption. A failed analysis may close ownership if its complete original workload and actors have closed; a partial/unknown cleanup is not accepted.

Six Mac provenance files are to be copied byte-for-byte to R36's owner-closure-provenance: first/recovery native, read and holder. No JSON reserialization, added newline, modified prior result or invented native receipt is allowed. Current placeholders remain null.

The cache release programs bind to ordinary-01, not qualification-01:
- hepta-runtime: 14,373,416 B / 28164587372674ac0d09908fb88966f4a544f88098abaa0cd97b2be3499f8c11
- hepta-runtime-jobctl: 739,016 B / 61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62
- examples/native_process_driver: 2,896,456 B / 1a9cae1a4b1565937b8e77ceabfe486b12857e1439213b7a8be123428d906727

All three separately preserved feature programs and all three ordinary programs remain bound and rechecked. The unchanged retained_programs helper also preserves the original qualification's retained test ELF custody. The live original process scan still runs immediately before cache movement. Same-filesystem rename keeps device/inode, requires the old cache path to disappear and records zero full-cache-copy bytes. After rename, retained copies and the three moved cache release bytes are rechecked before any new build starts.

## Necessary changes relative to R35

The complete diff is supplied. Changes are limited to namespace, exact two-file candidate/package identities and test metadata, D2's real owner closure replacing obsolete R34 claims, an unsealed-input guard before claiming the attempt, and preservation of both D2 build selections across the same-FS cache rename. The source copy, git apply check/apply, qualification command and subprocess calls remain the original R35 forms.

The closure intentionally cannot be sealed yet. Pending values include C1 raw receipts, both actual holder job identities, the recovery verdict and confirmation that the declared owners are no longer running. Any final actual schema mismatch must be resolved in a separately reviewed revision before execution; this template does not relax a gate or predict future success.

## Files and planned invocation

The preparation package includes candidate/, preparer, unsealed input/closure, original R35/D2 references, the exact qualifier reference, static byte/AST checks and the full preparer diff. Reference tools are evidence only. Future deployment consists of candidate's 12 members, prepare_qualify.py, qualification-input.json, cache-owner-closure-inputs.json and the six exact Mac provenance sidecars. No deployment tar, installer run or native launch has occurred for this template.

After actual closure has been filled and reviewed, the original CLI form is:

```text
/usr/bin/python3 -B -u /home/qian/hepta-runtime-optimization-20261106-r36/prepare_qualify.py --input-sha256 <actual sealed input SHA256> --owner-closure-sha256 <actual sealed closure SHA256>
```

Run context remains the fresh root, empty explicit environment and the root operator's original qualification time envelope. This package supplies no runnable invocation with unknown pins. R36 qualification, formatted map, test counts and release program identities remain null.

## Static verification performed

Python syntax was parsed, not executed. The 13 helper bodies, eight-stage list, original qualifier hash, jobs/disk literals and all main subprocess ASTs were compared with R35. All 12 candidate members were rehashed; the complete maps have 220 keys and exactly the two stated differences. No target helper, preparer, qualifier, auditor, Rust compiler/test, workload, host API or Git ref was executed or changed.

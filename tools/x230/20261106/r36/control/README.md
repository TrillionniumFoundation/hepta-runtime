# R36 control package

This package prepares the existing X230 measurement and exact Rust CI controls for the R36 audit-cache ownership candidate. It does not run qualification, CI, SSH, or performance workloads. The private candidate root is `/home/qian/hepta-runtime-optimization-20261106-r36`.

## Scope and preserved controls

The production candidate is accepted R24 source plus the frozen changes to `src/mcp/runtime/request_audit.rs`, `src/mcp/runtime/request_audit_lookup_tests.rs`, and `src/mcp/runtime/request_audit_tests.rs`. Its Git parent may be the current evidence-only head `86155fbf3b89e5a77e2a4aadebd2128c663fe50b`; the actual compiler-input preimage must still equal the accepted R24 qualification map. The selected candidate keeps the input cache clone and moves ownership only at the two final cache publications.

The new binder replaces the R35 historical candidate/cache-transfer fragment. It checks the real frozen input map, real original terminal, all eight unchanged qualifier stages, complete isolated-test inventory and independent audit, retained test source references, actual final source map, three qualified binaries, and the accepted R24 baseline. Test counts and future artifact identities are taken from actual receipts.

All other observation controller functions are preserved after changing the round and socket identities. `derive_control.py` verifies this function by function. The lifecycle controller and its materializer are unchanged apart from round identity. The two lifecycle core files with fixed R35 paths are changed only to the new R36 root; all 27 original lifecycle tool bodies are verified against the observed R35 manifest before derivation. The compiler monitor, summary gates, resource limits, no-retry rule, immutable inputs, owned-process cleanup, and held-agent checks remain in place.

The observation protocol remains ABBA at C1/C8/C16 with 192 measured and 24 warmup calls per cell. Each concurrency must meet throughput B/A ≥ 0.95, p95 B/A ≤ 1.10, controller CPU/call B/A ≤ 1.10, and both RSS limits (512 KiB extra and ratio ≤ 1.05). The normal C6 lifecycle ABBA keeps aggregate, launch, and concurrent-cancel gates. No saturated-cancellation claim is made for this candidate; the launcher preserves the R35 two-stage normal-lifecycle scope.

## Files to install

The deployment archive contains only the files listed in `control-package-manifest-01.json`, plus that manifest. Install them under the fresh R36 root after the preparer has created it. Do not place templates in `rust-ci-tools-01`: the postqualification materializer creates that directory with exactly the original six-file inventory.

Keep these existing independent inputs where they are:

| Input | Existing location |
| --- | --- |
| Accepted R24 source, binaries, qualification and publication receipts | `/home/qian/hepta-runtime-optimization-20261105-r24` |
| Observation measurement tools, original boundary tools and topology | `/home/qian/hepta-runtime-optimization-20261104-r16` |
| Frozen original jobs | `/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01` |
| Original benchmark profile | `/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json` |
| Original exact CI manifest and pinned nextest | `/home/qian/hepta-runtime-optimization-20261105-r25` |

The campaign itself creates the new private boundary-tool copy from the pinned R16 originals. Do not rename benchmark host aliases: the frozen profile's `main` and `mac` are distinct historical benchmark hosts.

## Preparation receipt contract

The parent preparer owns source creation and the single actual qualifier launch. `qualification-input.json` must contain `schema: hepta-r36-direct-qualification-input/v1`, `sealed: true`, the accepted `baseline_commit`, actual `git_parent`, the three `changed_paths`, full `baseline_compile_inputs` and `candidate_compile_inputs` maps, the unchanged `qualification_harness_sha256` map, and file identities for `baseline_qualification`, `candidate_patch`, and `preparation_tool`.

The successful `preparation.json` must contain:

- `schema: hepta-x230-r36-preparation/v1`, `passed: true`, a nonempty `finished_utc`, and no `error`.
- `qualification_returncode: 0`, `automatic_retries: 0`, `production_services_modified: false`, and `source_baseline` equal to accepted R24.
- `qualification_command` using `/usr/bin/python3 -B -u` with the unchanged `source/tools/x230/20261028/qualify.py`, private source/output/target paths, original Cargo home, and `--jobs 2`. Explicit `--stage-timeout 3600` is accepted because it is the same original default.
- `target_fresh_before_start: true`, `qualification_started: true`, `owned_child_closed: true`, `owned_group_absent: true`, and no true `timed_out`.
- `input_binding` and `candidate_patch` identities matching the actual files. `qualification_report` must equal the actual report identity; the original SHA-only `qualification_report_sha256` form is also accepted.

Retain the actual native qualification terminal as `qualification-terminal-status-01.json`. The binder requires success/exit 0, no retry/cancel/timeout, durable and complete publication, both original streams synced and untruncated with seen bytes equal to stored bytes. No placeholder terminal or synthetic test result is accepted.

## One postqualification sealing step

After the actual qualification has succeeded and its owner has closed, run this file-only command with the observed identities. This creates the two input examples, real qualification bindings, and the exact Rust CI package. It does not launch a workload or any subprocess.

```bash
/usr/bin/python3 -I -B /home/qian/hepta-runtime-optimization-20261106-r36/materialize_control_inputs.py \
  --manifest-sha256 ACTUAL_CONTROL_PACKAGE_MANIFEST_SHA256 \
  --qualification-input-sha256 ACTUAL_FROZEN_QUALIFICATION_INPUT_SHA256 \
  --preparation-sha256 ACTUAL_COMPLETED_PREPARATION_SHA256 \
  --qualification-terminal-sha256 ACTUAL_ORIGINAL_TERMINAL_SHA256 \
  --qualification-job-id ACTUAL_ORIGINAL_QUALIFICATION_JOB_ID
```

The result `control-materialization-01.json` records every output identity. Its `commands_run` and `workloads_started` are both zero. Keep this receipt and all original qualification files. All output paths must be fresh; an interrupted materialization is investigated, never silently replayed.

## Exact Rust CI

With no compiler or measurement campaign overlapping, invoke the generated launcher once through the established native job interface:

```bash
/usr/bin/python3 -I -B /home/qian/hepta-runtime-optimization-20261106-r36/rust-ci-tools-01/launch_exact_rust_ci_01.py \
  --launcher-sha256 ACTUAL_GENERATED_CI_LAUNCHER_SHA256
```

This preserves the published exact Cargo check and nextest commands, version preflight, structured inventory and complete exact case comparison, all no-retry rules, original process ownership, input rechecks, and output custody. The outer budget remains 6600 seconds. This is external X230 Rust CI evidence; it does not claim hosted GitHub Actions, the prospective merge check, or separate Python CI have passed.

## Observation then normal lifecycle

Materialize the observation input with the existing preparer and the actual identities. This remains file-only:

```bash
/usr/bin/python3 -B /home/qian/hepta-runtime-optimization-20261106-r36/tools-01/prepare_campaign_inputs.py \
  --example-sha256 ACTUAL_OBSERVATION_EXAMPLE_SHA256 \
  --preparer-sha256 ACTUAL_OBSERVATION_PREPARER_SHA256 \
  --preparation-sha256 ACTUAL_COMPLETED_PREPARATION_SHA256 \
  --qualification-terminal-sha256 ACTUAL_ORIGINAL_TERMINAL_SHA256 \
  --qualification-job-id ACTUAL_ORIGINAL_QUALIFICATION_JOB_ID
```

Use the original Mac holder `/Users/qianqi/work/hepta-runtime-x230-r21-20261105/held_agent_campaign_02.py`, SHA-256 `715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65`. Give it the verified local copy of the new `r36_campaign.py`, a fresh holder-output path, and a 3600-second timeout. It transmits that exact script, supplies the launcher hash, owns the temporary agent, uses only configured identities, retains original streams, and closes its agent. This package does not infer credential paths, change SSH configuration, or replace the holder.

Only after the observation report passes and the original holder/controller/monitor are closed, materialize the lifecycle input:

```bash
/usr/bin/python3 -B /home/qian/hepta-runtime-optimization-20261106-r36/tools-01/prepare_lifecycle_inputs.py \
  --example-sha256 ACTUAL_LIFECYCLE_EXAMPLE_SHA256 \
  --preparer-sha256 ACTUAL_LIFECYCLE_PREPARER_SHA256
```

Run the original holder once with the verified `r36_lifecycle_campaign.py` and a new holder-output path. Preserve failures without retries. A failed observation gate stops deeper performance testing; a failed normal lifecycle gate rejects this candidate. Successful nonregression gates alone do not establish a measurable improvement: report the actual ratios and resource deltas, with their sampling limits.

## Local review and provenance

`derivation.json` records the original script identities and unchanged control functions. `local-review.json` records Python parsing, pure receipt-binder acceptance/rejection checks, and CI constant sealing checks. Those use explicitly synthetic receipts and are not X230 qualification or performance evidence. No remote calls, candidate tests, CI commands, performance loads, commits, or pushes were run to prepare this package.

The new runtime controls do not require `derive_control.py`, `review_control.py`, or this README. Keep them with the local source work and publish the complete final evidence only after scanning raw and decoded native stream exports for credentials. Preserve failed attempt originals and hashes; do not replace original output with a success summary.

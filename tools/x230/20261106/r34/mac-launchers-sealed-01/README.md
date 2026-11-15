# R34 Mac launchers: frozen scripts and operator sequence

The three launch scripts are frozen local copies. This preparation has not deployed them on the Mac, started an SSH agent, invoked a holder, materialized observation inputs, or run a workload. The proposed Mac directory is the prior R33 deployment layout with only its release name changed:

```text
/Users/qianqi/work/hepta-runtime-r34-recovery-20261106/parent-staging/mac-launchers-01
```

The package `r34-mac-launchers-01.tar.gz` is **30,345 bytes**, SHA256 `cf64ff49996ef4f6909482063928ff2047aced00cf651c62ec1ca2c0949f926d`. Its five regular members expand to 124,914 bytes: the three scripts, `launcher-seal-manifest.json`, and `operator-argv.json`. The target directory's existence has not been checked by this task; deployment must be create-only and verify the exact member bytes before any launch.

| Script | Bytes | SHA256 |
| --- | ---: | --- |
| `held_agent_campaign_02.py` | 11,374 | `715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65` |
| `r34_campaign.py` | 81,762 | `c7508892959e9393f7ade10948ef7a96a18f1930d7308e293b74a321435f4cee` |
| `r34_lifecycle_campaign.py` | 25,109 | `cebf9a0dbfba562548ea6809ac604fabdaa0fdf969d83b19a4e8827eb73524b9` |

The holder is byte-identical to its original published object `c642b45500ed44abee56ba45614932855cd29892`; its historical filename, schema, key discovery, temporary agent custody, foreground SSH options, timeouts and cleanup are unchanged. The two parents are byte-identical to the already-reviewed R34 generated scripts, with the candidate/owner binder adaptation documented in the earlier parent-preparation package. This Mac packaging introduces no further source changes. The observation parent matches the exact 81,762-byte R34 parent that the coordinator verified installed on x230.

## Before the one normal observation

The original first qualification is job `1a1aef7882f-fc05-6499`, with actual original summary/audit counts 1653 passed, 0 failed, 34 ignored, 1687 selected and zero retries. Its report, formatter-final map and three runtime identities are bound by the installed parent.

The original exact CI job is `1a1af1ebf1d-fc05-65f2`. Its final result is not assumed here. The coordinator must first close and verify that original CI's native terminal, complete logs, plan/report and source bindings. A running job or a passed Cargo check/list stage is not the completed CI gate.

The original parent installer job `1a1af17eded-fc05-65b4` completed with zero workloads started. Its original receipt is `ROOT/parent-tools-install-01.json`, 26,390 bytes, SHA256 `b783a85e4b41e5202305b7739e63eace75c71d4ea65f14fcbe7d05e5ceef30a2`. The example identities below were supplied from that actual installer stdout/receipt and match the frozen R34 inputs; they are not guessed future hashes.

Close all compiler, build, component, archive and transfer activity before the held observation window. The root coordinator controls the exclusive Mac/x230 API window. Do not add status probes or other work to those hosts during the quiet/measurement interval. The unchanged parent enforces the original 90-second quiet interval, monitor, ABBA schedule, thresholds, sample counts, child custody and cleanup. This package supplies no automatic rerun.

## 1. Materialize the observation input on x230

Run the already-installed original materializer once, after the required gates and before the exclusive held window:

```sh
/usr/bin/python3 -B /home/qian/hepta-runtime-optimization-20261106-r34/tools-01/prepare_campaign_inputs.py \
  --example-sha256 ba091a5c4c67e0de4f4cf36264d649bb377ddfe847abf83b1fcc3eb43a342cde \
  --preparer-sha256 503c8894c6cc2ea7fb5b9578323dd52a52f05bdac91c3aefe49c753633eb4ee4 \
  --preparation-sha256 16193325e19f7025631a2802d6322c332a1b79eb6c6b2c2112740c4e602d9db6 \
  --qualification-terminal-sha256 0be0d08ef301d3a119d307940f324e52b6b6c8b29fbf94ad6ee69fca2637c14c \
  --qualification-job-id 1a1aef7882f-fc05-6499
```

The original example is 4,480 bytes. The materializer rebinds actual preparation/terminal/report, current candidate and baseline source, retained executable bytes, unchanged original harness/audit inputs and the rejected-but-closed R33 cache owner. It creates `ROOT/campaign-inputs-01.json` and `ROOT/qualification-compact-01.json` with no workload or monitor start. Preserve its actual native terminal/read and the exact resulting identities. Existing input, compact or campaign paths make it fail closed; do not overwrite them or silently select a new attempt.

## 2. Start one original Mac holder

After exact deployment verification and input materialization, the normal observation CLI is:

```sh
/usr/bin/python3 -B -u /Users/qianqi/work/hepta-runtime-r34-recovery-20261106/parent-staging/mac-launchers-01/held_agent_campaign_02.py \
  --remote-script /Users/qianqi/work/hepta-runtime-r34-recovery-20261106/parent-staging/mac-launchers-01/r34_campaign.py \
  --out /Users/qianqi/work/hepta-runtime-r34-observation-holder-01 \
  --timeout-seconds 3600
```

The original holder must run as the existing non-root Mac operator. Its original runtime-controller plist and configured identity discovery remain unchanged. Key material stays on the Mac; only its own temporary agent and foreground SSH child are controlled. This package contains no credentials or SSH configuration dump.

Keep the original native job ID and complete native stdout/stderr, holder report and unmodified forwarded streams. A holder exit 0 and parent `passed: true` establish workflow completion. Performance acceptance still requires the actual parent/summary observation gate and performance gates. A false gate remains a rejection even when all child processes exited cleanly; do not change thresholds or rerun the measurement to obtain acceptance.

## 3. Normal lifecycle is conditional on the actual observation gate

The installed lifecycle example is 3,247 bytes, SHA256 `edcfc2eeb7c8937aabfae70b5606111ea209250759e4c0a02f55ce6e7183f27b`. Only after the real observation closes and its original gate passes, materialize the normal lifecycle input:

```sh
/usr/bin/python3 -B /home/qian/hepta-runtime-optimization-20261106-r34/tools-01/prepare_lifecycle_inputs.py \
  --example-sha256 edcfc2eeb7c8937aabfae70b5606111ea209250759e4c0a02f55ce6e7183f27b \
  --preparer-sha256 9cbcf5fe1427ce285fecb3483bef3ba4997f7125aefcb2a38b95b0c1b57c221a
```

The unchanged materializer refuses an observation that did not pass its gate. If it creates the actual lifecycle input successfully, the separate later holder command is:

```sh
/usr/bin/python3 -B -u /Users/qianqi/work/hepta-runtime-r34-recovery-20261106/parent-staging/mac-launchers-01/held_agent_campaign_02.py \
  --remote-script /Users/qianqi/work/hepta-runtime-r34-recovery-20261106/parent-staging/mac-launchers-01/r34_lifecycle_campaign.py \
  --out /Users/qianqi/work/hepta-runtime-r34-lifecycle-holder-01 \
  --timeout-seconds 3600
```

The global-8 saturated cancellation capacity proof remains a separate gate. Normal observation or normal lifecycle completion does not imply that proof passed. No performance, saturation or adoption result is supplied by this launcher package.

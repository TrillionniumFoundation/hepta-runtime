# Continue an interrupted native process canary without resubmission

`native_canary_resume.py` reads the two existing original jobs from a failed
checked-entry canary. It has no start or cancel code path. It does not change
`report.json`, the saved requests, the worker markers, or the private authority.
The runtime may append its normal observation audit records.

Use this narrow continuation when the first report already contains the complete
controller-death/restart/same-key/changed-payload/success/output proof, and records
exactly one acknowledged cancellation of the second original job. Missing or
unknown historical launches are not repaired by this helper.

## The interrupted main-host receipt

The original report is
`/tmp/hepta-runtime-p0-evidence-20261030-01/native-process-43yrcj04/report.json`,
SHA256 `1601ba24e2836f7c965b2b9a3403100d78d70a694cc4fa540aa622760d26bf0e`.
Its `passed` value is false and must stay false.

- Resume job `1a18d17305a-45243-1` already completed successfully with the same
  durable request, one worker attempt and the exact expected stdout/stderr.
- Cancellation job `1a18d173ad9-4563e-1` was launched once. Its first status call
  failed with SSH exit 255 and `Connection closed by 127.0.0.1 port 22`.
- The original script's cleanup then cancelled that original job and received
  `stop_requested` with `termination_confirmed=false`. That acknowledgement is
  not a terminal result. The interruption's root cause is not established.

The helper verifies the first report SHA, the exact original driver SHA, the
existing private config and owner fence, the original request payloads, and the
original launch/cancellation evidence before making any observation.

## Run on the original host and private evidence directory

Pass the exact candidate-v4 driver used by the first canary. Its SHA256 must be
`b98634263c3f41d39e140aab8c98bbe2f5e219248880bf134252beb60bcee878`.
Replace the two executable source paths below with their actual deployed paths;
the report and receipt paths are the exact original main-host paths.

```bash
/usr/bin/python3 -I -S /absolute/helpers/native_canary_resume.py \
  --resume-report /tmp/hepta-runtime-p0-evidence-20261030-01/native-process-43yrcj04/report.json \
  --expected-report-sha256 1601ba24e2836f7c965b2b9a3403100d78d70a694cc4fa540aa622760d26bf0e \
  --driver /absolute/candidate-v4/debug/examples/native_process_driver \
  --receipt /tmp/hepta-runtime-p0-evidence-20261030-01/native-process-43yrcj04/read-continuation-001.json
```

No externally supplied fence override is needed. The helper validates the
original `authority/.owner.json` and `.owner.lock`, then explicitly sets the
three private-fence variables for each driver process. It refuses to run against
a copied report whose recorded root differs from its real location. An existing
continuation receipt is never overwritten or automatically resumed.

Each job uses three fresh driver processes: observe its original request, read
its original job's entire small stdout/stderr, and observe the original request
again. All six calls must consume zero checked entries. Job/request binding,
complete durable publication, lossless byte counts, stream EOF, terminal nonce,
outcome and publication time are validated. Read-before and read-after terminal
proofs must match; the worker marker and single attempt must remain unchanged
during this continuation. The resume proof/output must also match the first
report. The cancellation job must actually be `cancelled`; `timed_out`, unknown,
or pending does not pass.

An observation failure or timeout stops this helper and records an incomplete
new receipt. It never issues an automatic retry, replacement start, or another
cancellation. A separate explicitly chosen later observation can use another
new receipt path while preserving both prior attempts.

## Interpretation

`complete=true` belongs only to the new read-continuation scope. It does not turn
the failed first run into a clean pass. The receipt preserves the first error,
keeps cancellation end-to-end duration null, and records whether a historical
running observation for the cancellation job really existed. New observation
timings must not be reported as original cancellation latency. Current marker
metadata is not retroactively substituted for missing historical metadata.

This is private systemd user-job qualification, not production FinalUse, full
Agentd recovery, host reboot, or proof about every descendant/cgroup cleanup.
The existing long-output starter still requires its documented passed-canary
prerequisite; do not edit the first report to bypass it.

## Local helper checks

```bash
python3 -B -m unittest -v test_native_canary_resume.py
```

The ten tests use a synthetic interrupted receipt and a fake local driver. They
check the private fence, original identity, incomplete/unknown/timeout handling,
short output, publication drift, immutable first report and no duplicate call
on an existing continuation path. They are not evidence of real SSH or systemd
execution. The real host's new receipt must supply that evidence separately.

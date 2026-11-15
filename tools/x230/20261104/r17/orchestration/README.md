# R17 final campaign launcher — prepared, not executed

The parent installs these two Python launchers on the existing Mac operator
account. `held_agent_r17_campaign.py` uses the already configured identity union
and a private, short-lived agent, then forwards that agent over exactly one
foreground `x230-ts` connection. Existing SSH masters and services are untouched.
The remote Python source is sent as stdin, with its SHA recorded on both sides.

This launcher contains no build, retry or automatic selection step. It cannot
run a measurement until `/home/qian/hepta-runtime-optimization-20261104-r17/`
`final-measurement-selection.json` exists and all gates pass.

## Parent-owned selection manifest

Schema: `hepta-x230-r17-final-measurement-selection/v1`, documented in
`selection.schema.json`. `selection.template.json` is deliberately invalid and
non-runnable until its placeholders are filled. Do not copy it into the final
selection path as if it were a completed decision.

After the real R17 qualification has completed, the parent writes the manifest
with selected workers 1, 2 or 4, arena1, exact baseline/candidate hashes, exact
qualification-report/implementation-ready/source-freeze hashes, and the raw
configuration report and independent-analysis hashes used for the decision.
At least one configuration basis entry has role `selection` and a `selected_arm`
whose live-observed worker count equals `selected_workers`. Other completed
configuration campaigns may have role `context`. All basis campaigns must use
the same preserved R14 binary in both arms and must have an independently
verified report with eight actual worker-environment observations.

The remote gate requires:

- `qualified` is exactly true, and qualification `source_tested == source_after
  == implementation-ready.source_inputs`.
- Every frozen R17 source input still hashes correctly, the actual candidate
  binary matches the qualification report, and the baseline is R14 SHA
  `51480b3cf630a95419d3afeb571eec17c90cffa5944101920d05333673de031d`.
- Implementation-ready is exactly
  `acc9d0a095f43e6ea66d2f1b017a21c3eaf481dfe204c30da85a7d9378a40aef`,
  and source-freeze is exactly
  `5fc473e65ac9d278f88f844a3b6e25e44c7462c079efa93ecccab4fe8770f4c2`.
  This selects the parent-frozen R14 + jobctl BufReader + lazy Value candidate;
  it does not incorporate the R16 profile candidate.
- The same frozen historical topology/profile and all 12 unchanged R16
  measurement scripts are used.
- Output directories and the private socket parents are fresh. Existing results
  cause a refusal, never automatic resume or rerun.

The selection, qualification, binaries, source inputs and harness are rechecked
before and after every stage. A qualification verdict is recorded only after
those checks actually succeed; this preparation does not claim R17 is qualified.

## Execute once on the Mac, after the parent opens a measurement window

```sh
python3 -B /path/to/r17-final-campaign/held_agent_r17_campaign.py \
  --remote-script /path/to/r17-final-campaign/r17_campaign_remote.py \
  --out /tmp/hepta-r17-final-campaign-01 \
  --timeout-seconds 3600
```

The existing launch-agent plist identifies the runtime host map. Identity-file
paths are resolved with `ssh -G`; that complete configuration output and private
key bytes are never retained. The same target union as the existing R16 holder
includes x230-ts, main and configured ai395/desktop/mac/main/pocket4/rog/x230.
The private agent is always reaped. A foreground connection timeout is explicitly
recorded as unknown remote completion and is never retried automatically.

## Fixed remote plan and evidence

All measurement and recovery outputs stay under the R16 root, preserving the
unchanged recovery harness DEV_ROOT contract:

1. `r17-native-observation-01`: same arena1 and the same selected workers for A
   and B, R14 versus the qualified R17 binary, ABBA, C1/C8/C16, 96 measured calls
   per cell, and 24 balanced warmup calls.
2. The frozen native analyzer writes that campaign's `independent-summary.json`.
3. `r17-cancel-recovery-01`: qualified R17, arena1, the same selected workers,
   six historical entities, owned ROG transport interruption, new starts,
   same-key lookups, cancellation and restart verification.
4. The frozen recovery analyzer writes its `independent-summary.json`.

The campaign receipt is `R16/r17-final-campaign-01/report.json`; its `selection.json`
is an exact copy of the selection bytes consumed. Each stage records its full
argv, script SHA, start/end monotonic clocks, environment/load/frequency/thermal
snapshots, return code, exact stdout/stderr byte counts and SHA, and resulting
artifact hashes. Original error logs and tracebacks remain intact; there is no
truncation or error reclassification. The Mac receipt additionally preserves the
exact forwarded script, foreground SSH argv and complete forwarded logs.

The holder's agent/discovery logs are private operational evidence. They should
not be folded blindly into a public performance bundle. Use the existing explicit
publication allowlist, while retaining the measured campaign's original raw
transport, index, resource and recovery artifacts for posthoc auditing.

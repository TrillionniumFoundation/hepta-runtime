# R31 campaign 02: isolated namespace correction

This package corrects a parent-runner preflight error. It changes no production
source, qualified binaries, workload, numerical threshold, monitor policy,
sampling schedule, or cleanup protocol. The accepted baseline stays R24.

The original R31 holder job `1a1ae37dda9-fc05-5e42` failed with exit 1 at
`2026-11-06T00:17:41.461538+00:00`. Its parent report contains `stages: []` and no
quiescence or stage plan. The error was `private socket directory already
exists`: the previous parent retained `"h30" + prefix + attempt` from R30 and
attempted to reuse `/home/qian/h30n01`. The complete original failed report,
input, parent, holder native terminal, source snapshots and compiler-monitor
evidence are required by the new binder. No prior performance observation is
discarded or replaced; this original attempt never started a measurement stage.

The separately preserved earlier preparation failure is also still required.
Corrected preparation v2 and the original eight qualification stages succeeded
as job `1a1ae1c32b8-fc05-5d7a`; their source and binary identities remain unchanged.

## Sealed files and namespaces

Upload the five complete scripts and manifest from `generated/` to the new
operator-owned mode-0700 directory:

`/home/qian/hepta-runtime-optimization-20261105-r31/tools-02`

Manifest SHA256:
`6ba2c155317e0bf7caed1c4bd64153667a6f6a58559c1fdd3c81fa05bf05b1c0`

| Purpose | Fresh location |
|---|---|
| Observation parent and inputs | `campaign-02`, `campaign-inputs-02.json` |
| Boundary tool copies | `boundary-tools-02` |
| Native / boundary / recovery socket parents | `/home/qian/h31n02`, `/home/qian/h31b02`, `/home/qian/h31c02` |
| Original six-host canary output | `/home/qian/hepta-runtime-optimization-20261104-r16/r31-cancel-recovery-02` |
| Lifecycle tools and inputs | `lifecycle-tools-02`, `lifecycle-inputs-02.json` |
| Lifecycle parent / ABBA / tool tests | `lifecycle-campaign-02`, `lifecycle-abba-02`, `lifecycle-tool-tests-02` |
| Lifecycle socket prefix | `/home/qian/r31lc2` and its four `-number-arm` suffixes |
| Input templates / compact / install receipt | `*-inputs-02.example.json`, `qualification-compact-02.json`, `parent-tools-install-02.json` |

The original `qualification-01`, `qualification-terminal-status-01.json`,
`preparation-02.json`, both earlier failures, original R29 inputs, and original
R30 cache-owner evidence remain on their existing paths. Frozen manifest and
compiler-policy filenames inside the new tool directories keep their `01`
suffix. The policy's `runtime_attempt: "01"` is unchanged frozen policy data.

Two original lifecycle tools already require root-path adaptation. In those same
two files only, the fixed `lifecycle-abba-01` output constant also becomes
`lifecycle-abba-02`, so their original strict output guard accepts the new path.
The other 25 lifecycle files are copied byte for byte. All functions and numeric
protocol parameters in those two tools remain unchanged.

The main parent is 76,998 bytes; use a transfer capable of handling more than
64 KiB. Retain every existing `tools-01`, input and evidence directory.

## Install once on x230

```sh
/usr/bin/python3 -B /home/qian/hepta-runtime-optimization-20261105-r31/tools-02/install_measurement_tools.py \
  --bundle-sha256 6ba2c155317e0bf7caed1c4bd64153667a6f6a58559c1fdd3c81fa05bf05b1c0
```

The installer performs bounded local file checks and create-only copies. It
starts no monitor, compilation or workload. The original failed holder native
object must already be saved byte for byte as:

`/home/qian/hepta-runtime-optimization-20261105-r31/observation-holder-native-01.json`

It is 727 bytes, SHA256
`33b1f440fa260db903c66d8c4472a19abc0a86d07ec9dfde883a4f481b253e96`.

## Materialize observation inputs from actual completed qualification

The example SHA comes from the new successful installation receipt. The other
arguments below are the already observed original qualification identities.

```sh
/usr/bin/python3 -B - <<'PY'
from pathlib import Path
import json
import subprocess

root = Path('/home/qian/hepta-runtime-optimization-20261105-r31')
install = json.loads((root / 'parent-tools-install-02.json').read_bytes())
assert install['passed'] is True
assert install['bundle']['sha256'] == '6ba2c155317e0bf7caed1c4bd64153667a6f6a58559c1fdd3c81fa05bf05b1c0'
subprocess.run([
    '/usr/bin/python3', '-B', str(root / 'tools-02/prepare_campaign_inputs.py'),
    '--example-sha256', install['files'][str(root / 'campaign-inputs-02.example.json')]['sha256'],
    '--preparer-sha256', '8d191ffd1fc3ec5486dd7627314ce3cfc5093fa67b874cb5071df364942c3ed2',
    '--preparation-sha256', '77bdf6f1b008b65dfbedcac24b7ea3026e3946ad4fbff68ca96e5980b660d003',
    '--qualification-terminal-sha256', 'f9f6de27c19b015e072f8169e7155783102d9b2ef3bc6ff2d8705927c0016b4e',
    '--qualification-job-id', '1a1ae1c32b8-fc05-5d7a',
], check=True)
PY
```

This also checks the original failed campaign's complete native terminal, exact
error, zero stages, absence of workload output, unchanged sources and its original
compiler ledger. The old parent is read by fixed SHA and loaded with a non-main
module name solely to call its pure completed-monitor verifier against the old
`tools-01` evidence. It does not start the old parent, monitor or workload.

The new candidate remains the independent qualification copy
`qualification-01/hepta-runtime`, SHA256
`70767e3ef78ec8519b81d7f600b37d012965b3c1b96abaf6c47c8273c73ee450`.

## Mac launcher files and observation command

The local `mac-launchers-02/` directory contains the full original holder plus
the two full new parent scripts. Copy those three files into a fresh:

`/Users/qianqi/work/hepta-runtime-r31-launchers-02`

Original holder SHA256:
`715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65`.

Start the holder only after the separately authorized R31 exact Rust CI work has
closed and there is no other compiler or measurement workload. Its original
90-second quiescence and full continuous compiler monitoring then apply.

```sh
/usr/bin/python3 -B /Users/qianqi/work/hepta-runtime-r31-launchers-02/held_agent_campaign_02.py \
  --remote-script /Users/qianqi/work/hepta-runtime-r31-launchers-02/r31_campaign.py \
  --out /Users/qianqi/work/hepta-runtime-r31-launchers-02/observation-held-02 \
  --timeout-seconds 3600
```

The unchanged holder owns and reaps its temporary agent and foreground SSH child.
It transmits the exact parent bytes to x230. There is no automatic replay.

## Lifecycle only after observation passes and its holder closes

```sh
/usr/bin/python3 -B - <<'PY'
from pathlib import Path
import json
import subprocess

root = Path('/home/qian/hepta-runtime-optimization-20261105-r31')
install = json.loads((root / 'parent-tools-install-02.json').read_bytes())
assert install['passed'] is True
assert install['bundle']['sha256'] == '6ba2c155317e0bf7caed1c4bd64153667a6f6a58559c1fdd3c81fa05bf05b1c0'
subprocess.run([
    '/usr/bin/python3', '-B', str(root / 'tools-02/prepare_lifecycle_inputs.py'),
    '--example-sha256', install['files'][str(root / 'lifecycle-inputs-02.example.json')]['sha256'],
    '--preparer-sha256', '5d1f2c3289d0e70dbf66249414a4a0b24fb37e81f4556d09858d1db723284be4',
], check=True)
PY
```

Then on the Mac:

```sh
/usr/bin/python3 -B /Users/qianqi/work/hepta-runtime-r31-launchers-02/held_agent_campaign_02.py \
  --remote-script /Users/qianqi/work/hepta-runtime-r31-launchers-02/r31_lifecycle_campaign.py \
  --out /Users/qianqi/work/hepta-runtime-r31-launchers-02/lifecycle-held-02 \
  --timeout-seconds 3600
```

The lifecycle materializer requires the new `campaign-02` observation to pass,
checks its full monitor evidence, and carries forward the exact same qualification
and candidate binary identities. No future measurement outcome is assumed.

## Review and limits

Nine local checks passed. They cover the actual original failed report and native
terminal, negative zero-stage/terminal-log cases, exact 5-file AST equivalence
outside the explicit namespace/input/receipt additions, the full seven-stage
observation argv, lifecycle output guards, preserved qualifier inputs and source
scope, and frozen bundle byte hashes. One initial validator-only comparison
failed because its assignment target used an AST `Load` context instead of
`Store`; that local validator was corrected. No deployed script changed as a
result. The generated package passed an independent read-only review.

No remote command, candidate compilation or measurement ran during this package
preparation. The actual remote materialization remains the full file-binding
check. A successful qualification or preflight correction does not by itself
mean R31 is adopted. The saturated cancellation-capacity blocker remains open.

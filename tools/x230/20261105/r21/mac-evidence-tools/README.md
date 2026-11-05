# R21 Mac holder terminal evidence

This package is a local preparation. It does not start the holder, connect to any
host, load identities, signal processes, or run a workload. Run the exporter only
after the parent has independently confirmed the Mac holder is terminal and the
measurement window is closed.

## Reviewed holder change

`holder02-peer-01.json` binds the exact 11,374-byte
`held_agent_campaign_02.py` (SHA256
`715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65`).
Reversing only its documentation/schema change, two owned-path assignments and
post-context absence-check block restores the original 10,636-byte R19 holder
byte for byte. SSH arguments, identity selection/loading, timeout behavior and
the owned agent's terminate/wait behavior are unchanged.

The two added fields record `lexists` snapshots after the `TemporaryDirectory`
context exits. They do not establish whole-machine process inactivity or remote
X230 completion. The old holder and its original installation receipt remain
untouched and are retained as historical installation material.

## Fixed actual inputs

Mac root: `/Users/qianqi/work/hepta-runtime-x230-r21-20261105`.

| Input | Size | SHA256 |
|---|---:|---|
| `held_agent_campaign_02.py` | 11,374 | `715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65` |
| `campaign-bootstrap-01.py` | 1,929 | `de42d946174b996d14c5e04892c0eeea9436d578d7ded6e2f8c0298b8bf5d0b1` |
| `campaign-tools-installed-01.json` | 569 | `43e80b18f9dbf944dedd7fd72ec2168ceaea4d8c3975421e4025f72d73eeaab3` |
| Legacy `held_agent_campaign.py` | 10,636 | `287d5026951923728c9b7661f5e3f843045791fbdb0b766c396b7331d45e5dce` |

The fixed legacy `holder-installed-01.json` is also retained. Its full current
identity is recorded; the exporter does not pretend to know a previously
unprovided hash for that receipt. The pinned current installation receipt binds
both actual source hashes and the earlier installation's unchanged status.

## Installation and success export

Install the exact exporter as a regular owned file at
`/Users/qianqi/work/hepta-runtime-x230-r21-20261105/export_mac_holder_01.py` and
verify its frozen size and SHA256. **Do not execute it through Python stdin.**
It reads `__file__` to retain its own exact source and requires a direct regular
file with the existing operator as owner.

After terminal confirmation, obtain the actual complete SHA256 of
`campaign-01/report.json`, then run:

```sh
python3 -B /Users/qianqi/work/hepta-runtime-x230-r21-20261105/export_mac_holder_01.py \
  --mode success \
  --expected-report-sha256 ACTUAL_MAC_HOLDER_REPORT_SHA256 \
  --expected-bootstrap-sha256 de42d946174b996d14c5e04892c0eeea9436d578d7ded6e2f8c0298b8bf5d0b1 \
  --terminal-confirmed
```

The default output is the previously nonexistent direct directory
`export-holder-01`. It contains:

- `holder-evidence-01.tar.gz`: the original `campaign-01` report, every permitted
  producer log, `remote-script.py`, both actual installed sources, both known
  installation receipts, the legacy holder, and the exporter source.
- `manifest.json`: exact original-path/member mapping, full size/SHA256/mode and
  source identity stamps, validation outcomes, and current cleanup metadata.
  Its bytes are also the archive's `_export-manifest.json` member.
- `receipt.json`: full archive/manifest identities and source checks performed
  after archive creation. The receipt is external to avoid hash self-reference.

The recommended repository mapping is
`tools/x230/20261105/r21/evidence/holder-01.tar.gz`, with the external manifest
and receipt selected alongside it or within the final closed review package.
Keep the original archive bytes; no need to commit its expanded files again.

The exporter preserves complete original stdout/stderr; it does not summarize or
rewrite the producer's report. Only known holder-generated names are read in
`campaign-01`. Unsupported names and nonregular entries are recorded as errors
without opening their contents. No SSH config, runtime config, identity file,
private-key body, agent socket contents, full environment, or X230 file is read.
No command or subprocess is started.

## Exact success meaning

Success requires the actual report SHA, pinned holder/bootstrap/install bytes,
terminal `finished_utc`/`passed`/returncode fields, zero SSH retries, the owned
agent's recorded wait/reap and returncode, and the holder's two absence flags.
Foreground PID and monotonic timing fields must agree. The source-bound holder
uses `communicate()` and records its returned code; it has no separate
`foreground_waited_and_reaped` boolean, and the exporter invents none.

The recorded temporary path must be this holder's `/tmp/hr19a-*` directory and
its `agent.sock`. The exporter only reads metadata at these two exact paths.
`FileNotFoundError` is absence; permission and other errors remain unknown.
Both must be absent for the success branch. There is no new cleanup operation.

Every original log must match the producer's recorded full size and SHA256. The
last nonempty line of `forwarded.stdout` must be JSON that closes the R21 X230
campaign report path and reports `passed: true`, with a boolean
`native_regression_screen_passed`. A **false native screen is retained as a
completed correctness run with a rejected performance screen**; it is not
converted to adoption or hidden by an exporter failure.

That final console line does not provide the X230 report's SHA. The exporter
explicitly records `x230_report_bytes_read: false`,
`x230_report_sha256: null`, and
`cross_package_report_identity_binding_required: true`. Root must compare this
Mac source/console/returncode proof with the independently downloaded X230
campaign report and its archive in the final orchestration receipt.

## Failed or uncertain terminal runs

Use `--mode failed` after independently confirming that this Mac holder has
stopped. Supply the actual report SHA when available; omission is explicitly
unknown. The bootstrap SHA is optional in this branch but the known pinned
bootstrap is still checked and any mismatch retained.

```sh
python3 -B /Users/qianqi/work/hepta-runtime-x230-r21-20261105/export_mac_holder_01.py \
  --mode failed \
  --expected-bootstrap-sha256 de42d946174b996d14c5e04892c0eeea9436d578d7ded6e2f8c0298b8bf5d0b1 \
  --terminal-confirmed
```

Failure mode retains safe readable originals, including `report.next` and
`holder.error.txt` when present, while listing every missing, invalid or unstable
input. `export_succeeded` in this mode only describes evidence preservation;
`complete_success_evidence_verified` remains false unless all success evidence
actually verifies. It does not change the original producer or assert remote
completion when the holder recorded a timeout or unknown state.

An attempt never overwrites an existing output. If a reviewed correction needs a
new export attempt, explicitly select a fresh `--out` such as `export-holder-02`;
preserve the first output, manifest, receipt and any `export.error.txt`. There is
no automatic retry or workload rerun.

## Closure and resource limits

Every captured file is regular, owned, non-writable by group/others, single-link,
and direct; fd/named identity stamps and full bytes are checked before and after
packaging. Each file is limited to 32 MiB and captured payload to 128 MiB. The
campaign inventory must stay unchanged. Tar members are generated from the
fixed safe mapping, with original file modes in both tar and manifest and
normalized tar ownership/time metadata.

The final receipt can reject an archive after an input changes during packaging;
retain that archive and its failure record. Do not treat the earlier embedded
manifest's pre-archive checks alone as a complete export verdict. A receiver must
verify the external receipt, whole archive hash, exact member set, and every
manifest member before trusting an extraction.

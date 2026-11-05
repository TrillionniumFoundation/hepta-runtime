# R21 six-host campaign tools

This bundle prepares one R19-to-R21 campaign. Preparing and reviewing it did not
run a campaign, compile a runtime, invoke SSH, or change a production service.
The launcher descends from the already reviewed R20 launcher **02**, including
its narrowly scoped compiler-ELF hardlink reader. The R20 formal campaign was
never executed and remains a superseded, retained preparation stage.

The final R21 production source contains the STATUS and CANCEL lazy-import
changes only. Both RequestHashWriter buffer experiments failed their original
small-request regression screen. Neither the 4 KiB nor the 64-byte buffer, nor
the conditional unqualified integration draft, enters this campaign.

## Installation layout

The source root for `manifest.freeze-01.json` is the local **R21 preparation
root**, the parent of this `campaign-tools` directory. Each `bundle_source` is
relative to that root and equals the corresponding relative remote path.
Install its six files below
`/home/qian/hepta-runtime-optimization-20261105-r21`:

| Local path relative to R21 preparation root | Relative remote location |
| --- | --- |
| `campaign-tools/run_six_host_campaign_01.py` | `campaign-tools/run_six_host_campaign_01.py` |
| `boundary-tools/run_native_boundary.py` | `boundary-tools/run_native_boundary.py` |
| `boundary-tools/audit_native_boundary.py` | `boundary-tools/audit_native_boundary.py` |
| `boundary-tools/test_native_boundary.py` | `boundary-tools/test_native_boundary.py` |
| `boundary-tools/harness-freeze.json` | `boundary-tools/harness-freeze.json` |
| `boundary-tools/capacity-policy.json` | `boundary-tools/capacity-policy.json` |

The manifest does not contain itself. Qualification and lifecycle tools have
separate immutable manifests. Install the 17 lifecycle payload files and their
manifest from `R21/lifecycle-tools` at the corresponding remote directory.
Their manifest SHA256 is
`445a325931f2a9147401ea241782a29617480c2047c6d5b760f2e59f9037cb1f`.
The three qualification tools are bound by manifest SHA256
`126976a5005fbbb5b09360d6999c85fd46d14e96e9b7d037c55ea2d40b40cc8d`.

All five boundary files and all twelve original measurement files are unchanged.
The lifecycle execution scripts differ from their R20 predecessors only in
the R21 root, schema labels and one root-specific error message. Updated
`source-delta.json` and `instrumentation.patch` describe that derivation.
`lifecycle-boundary-derivation-01.json` records original and copied identities.

The unchanged boundary producer guards its output relative to `HERE.parent`,
which permits `R21/native-boundary-01` when installed at `R21/boundary-tools`.
Both boundary commands receive the explicit frozen R16 measurement-tools root.
The launcher hashes the five original R16 files and the R21 copies before and
after every stage. It does not install or rewrite any harness file.

## Startup contract

The existing Mac holder sends only `python3 -B - --launcher-sha256 <stdin SHA>`.
After qualification closes, the root workflow prepares a short stdin bootstrap
that reads the fixed installed launcher, verifies this bundle's frozen source
SHA256 and executes those same bytes with four additional actual proof values:

- `--expected-acceptance-sha256`: `R21/independent-acceptance-01.json`.
- `--expected-control-report-sha256`: terminal `R21/qualification-control-01/report.json`.
- `--expected-qualification-report-sha256`: `R21/qualification-01/report.json`.
- `--expected-candidate-sha256`: actual `R21/qualification-01/hepta-runtime` ELF.

No future candidate ELF hash is embedded in this bundle or its manifest. The
Mac `--launcher-sha256` value describes the stdin bootstrap, not an independent
remote self-hash of the installed launcher. The campaign separately records
the installed launcher's complete identity; the bootstrap verifies its bytes
immediately before execution.

The launcher requires Linux UID 1000, the reserved direct R21 root, the same host
as the accepted qualification, an existing held `SSH_AUTH_SOCK`, and entirely
new campaign output and socket names. Existing paths are not deleted or reused.

## Qualification and component-chain gates

The four actual startup hashes must bind successful independent acceptance,
terminal qualification control, all eight successful qualification stages and
the candidate runtime bytes. Before any measurement, the gate verifies:

- The full 281-file source map and 219 compiler inputs against before, middle
  and after proofs. Only `src/mcp/runtime/jobs.rs` may differ from accepted R19;
  the final source SHA256 is
  `1f1f086e3bc0fc62184ed51949964e1f82e337b87d330225097ae38722e4ac8c`.
- The three qualified ELF copies against qualification, acceptance, control
  and the actual fresh-target release copies. Only the three exact compiler
  target paths may have stable hardlinks; actual executed copies, ordinary
  evidence and source remain subject to the single-link gate. All files retain
  complete SHA256, size, ownership, mode, identity and stability checks.
- Strict jobctl SHA256
  `61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62`.
- Accepted R19 source and proofs, with runtime SHA256
  `adab5f27f89b3cac6adaec916110a48d80697db9667e3bd7ee0fc713fe770a09`.
- The same component-chain descriptor in acceptance, freeze, launch and
  control; the actual chain file and its nine source, report and tool inputs;
  the ordered R19→STATUS-only→STATUS+CANCEL source transitions; and both
  original producer semantic reports and their fixed identities.
- All three protected qualification tool sources. Every recorded qualifier
  or controller child must have a successful wait/reap receipt, and the
  current read-only process scan must find no matching active qualifier,
  component-chain creator, cargo or rustc process or unresolved scan error.
- Frozen plan SHA256
  `aa4ad30b746b267d005c675f81ba634c43cd81a6f5893963445949abaa6e82f6`,
  profile SHA256
  `fe1e9551b5b8812ad6ed3da018c282b7261f7caeb2f49e4dcfefba7ff784ab08`,
  topology SHA256
  `8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287`,
  original six job records, twelve measurement files, five boundary files
  and all lifecycle-manifest entries.

The chain does not relabel the earlier STATUS measurement as a direct
cold-process run of the final combined source. It records
`final_was_directly_coldprocess_tested: false` and requires independent raw audits
before adoption. The final source was directly exercised by the CANCEL
component; full qualification and this six-host campaign are separate gates.

The host set is `ai395`, `mac`, `main`, `pocket4`, `rog`, `x230`. Historical `main`
is the separate Linux qian-qi machine, not the connector's current Mac main.

## Fixed execution order

1. Validate all inputs and terminal qualification, then wait at least 90 seconds
   with progress and read-only compiler checks approximately every 15 seconds.
   An active compiler causes failure; this is not a wait-and-retry policy.
2. Run unchanged native ABBA: C1/C8/C16, 192 timed and 24 warmup calls per cell,
   workers 2 and arena 1. Run the original independent raw analyzer.
3. Run two C32 bursts and the unchanged boundary auditor. Keep successes,
   exact internal capacity refusals and other errors separate. No manufactured
   16/16 split is required, and refusal is not counted as successful throughput.
4. Run the lifecycle helper once: four A/B/B/A rounds, C6, six new private jobs
   per round. It runs the original recovery auditor once per round and then
   the aggregate analysis. The outer launcher does not repeat those audits.

Timeouts remain fixed: native 1,800 seconds, native audit 180 seconds, boundary
600 seconds, boundary audit 180 seconds and lifecycle helper 3,600 seconds.
There are no automatic RPC, stage or campaign retries.

New raw outputs are `R21/native-observation-01`, `R21/native-boundary-01`,
`R21/lifecycle-abba-01` and `R21/campaign-control-01`. The native and boundary
socket parents are `/home/qian/h21n1` and `/home/qian/h21b1`. The lifecycle helper
receives nonexistent prefix `/home/qian/h21lc1` and creates four fresh parents
ending `-0-A`, `-1-B`, `-2-B`, `-3-A`; the outer launcher never creates the prefix.

Every stage retains stdout, stderr, command, source hash, timeout, PID/start
ticks, wait/reap, before and after system snapshots and input checks. The native
nonregression screen remains aggregate success-rate B/A ≥0.95 and pooled p95
B/A ≤1.10. Native p99 and both adjacent A/B pair directions remain visible;
p99 is not an adoption gate. Performance rejection does not suppress later
correctness stages.

## Failure and interpretation limits

On timeout or interruption, the launcher first sends SIGINT to its exact
`Popen` child, allowing the frozen harness to perform private cleanup. Signals
to the process group are permitted only while its original unreaped leader
anchors that newly created group. Once the leader is reaped, the launcher does
not derive signal authority from the numeric PGID alone. Forced termination,
cleanup errors and uncertain escaped descendants remain in the evidence and
fail the campaign.

The original analyzer cleanup contracts do not prove that every unobserved
descendant anywhere in the cluster has exited. Compiler checks are read-only
snapshots, not continuous whole-machine inactivity proof. No compiler, shared
service or unrelated process found by preflight is signalled.

Native rate and CPU describe completed observation calls. Lifecycle data cover
four bounded C6 rounds with the original status and terminal polling, so no
fixed total of 90 RPCs per round is assumed. The fixed four-round counts are
24 new starts, 48 same-key lookups and 48 cancellations. Resource traces retain
their original sampling limits. The launcher reports finite correctness and
native nonregression outcomes; it does not determine production adoption or
claim global optimality, statistical significance, cluster RSS improvement or
maximum sustainable launch throughput.

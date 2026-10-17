# 2026-10-17 native maintenance and control-channel recovery

This directory is a complete, task-specific source bundle for the maintenance
performed on the existing main host. It is not a general upgrade command. The
rollout pins the reviewed preflight files, state roots, original process
identities, old binary hash, service names, and release expectations from that
maintenance. Running it again against the already upgraded production services
must fail its preflight. Do not refresh those inputs merely to bypass that
refusal.

The originally executed `native_rollout.py` is preserved separately with SHA256
`a49bd49329d7732a11d75fefc259b0a89ec9dcf7a799a09b7a9646b69d394874`.
The file here is a reviewed follow-up source revision, not the bytes that ran in
the completed cutover. The original recovery helper is likewise preserved;
its SHA256 is
`daef2b0e0fe39ee1f17abe63591b1a35bd473f3792bea04f1ca9ca0d73841ed4`.

## Observed problem

The saved follow-up observation records the native apply receipt beginning at
2026-10-17 11:07:25.786598 UTC and finishing at 11:08:00.116805 UTC, with
`passed=true` and `activated=true`. The receipt SHA256 is
`29314abafb88cbe1fddb19f168c8b92223e6582296ada8414c2aaca07965d69e`.
Its three running native binaries matched
`346c3f7553e9c6515739ed9dbad8b06369bc4af822427c34859e1d6d06c9a73d`.

The live unit graph and systemd journal showed why local rollout success did
not restore the external entry point:

| Entry point | Service requirements | Observed behavior |
| --- | --- | --- |
| `hepta-openai-full-operator.service` | operator and frontend | Stopped at 11:07:30 UTC; frontend returned at 11:07:47; tunnel was started again at 11:40:05. |
| `hepta-chatgpt-bridge.service` | operator | Stopped when operator was stopped; the follow-up observation found it inactive. |

The old rollout explicitly restored the frontend but did not restore these
dependent services. The transient cutover service and timer were subsequently
garbage collected, so a recovery check requiring `LoadState=loaded` could not
recognize the completed cutover. A missing unit's default `Result=success` is
not historical exit evidence.

## Included sources

- `native_rollout.py`: same core deployment and rollback procedure, with
  task-specific dependent-service capture and restoration added.
- `native_benchmark.py`: unchanged protocol/receipt helpers imported by the
  rollout. Original SHA256:
  `593469156a2afcd66b4ba7317199ad079f1f8668aeb09332627d3e4f83dd76e8`.
- `pager_acceptance.py`: unchanged local frontend acceptance used by the
  rollout. Original SHA256:
  `b85760d658769978495a14045fa8e0b39d65a0ca11f3862da3d2716beefad2a2`.
- `recover_control_channel.py`: the fixed-receipt, fixed-tunnel recovery helper,
  extended to recognize a completed cutover after transient-unit collection.
- The two `*_tests.py` files use synthetic temporary fixtures and mock service
  calls. They do not use live credentials, contact a host, or invoke systemd.

`source-manifest.json` records every included file hash and their common closure
hash. The rollout imports its protocol helper and invokes pager acceptance from
this same directory, so those dependencies travel with the source bundle.

## Runtime inputs and scope

All runtime input/output paths remain fixed under:

```text
/home/qian-qi/.local/state/hepta-runtime-optimization-20261017-0940
```

The deployment requires the original, privately maintained
`native-rollout-preflight.json`, `native-async-preflight.json`, and the reviewed
`native-release-current.json`. The pager check additionally reads
`pager-release-candidates.json`, imports protocol constants from the referenced
reviewed release, and reads the existing frontend token file specified in its
source. These operational inputs and credentials are intentionally not copied
into this source bundle. No token is printed or embedded in the sources.

The native release and frontend bundle must exist and pass the existing full
manifest checks. This source revision does not create a release, rewrite an
input preflight, restore a state directory, delete a runtime lock, or replay an
effect.

## Dependent-service restoration

Before any frontend stop, the revised rollout records each entry point's
active state, service dependency graph, and unit/drop-in file hashes. It rejects
an unexpected service dependency before changing a service.

After the core candidate checks finish, or after a complete core rollback, it
restores the originally active read-only bridge and then the originally active
full-operator tunnel. An already active service is not restarted. A service
that was originally inactive is not started. Configuration drift is preserved
and reported instead of being overwritten. Required operator/frontend services
must already be running before any control service start is submitted.

Incomplete core rollback leaves the dependent services unchanged and records
why restoration was skipped. Each control restoration error is recorded
separately. Once a control entry point is restored, new requests can arrive, so
an error in this final phase never initiates another native rollback.

The original core `passed`, `activated`, `rolled_back`, and exit-code meanings
are preserved. In particular, rollout exit code 0 means the core checks
succeeded; inspect `dependent_services_restored` and
`control_service_restoration.errors` for the separate service-restoration
outcome. `external_mcp_verified` remains false until independent external
verification; this local script never sets it true.

## Recovery after transient-unit collection

The recovery helper still reads only the exact `native-cutover-v1-apply.json`
receipt and controls only `hepta-openai-full-operator.service`. It does not
retroactively assume a bridge baseline absent from that original receipt.

A collected cutover service is eligible only with a valid finished receipt,
inactive/dead state, no MainPID or queued service job, exclusive acquisition of
the existing maintenance lock, and unchanged receipt bytes on a second read.
The exact timer must also have no active or queued trigger. The actual host renders a zero pending job as an explicit `Job=`; the helper accepts this empty value while refusing a missing field or nonzero job. An unset monotonic timer may render as `infinity`, which is accepted only for that field. A loaded cutover
service retains the original exit-status checks; a collected one explicitly
records that exit-property evidence is unavailable. The tunnel itself must
remain a loaded, known service.

```bash
python3 -B recover_control_channel.py --check-only
```

This produces the bounded decision and receipt/unit summary without starting a
service. Omitting `--check-only` permits one conditional start of the original
tunnel after all guards pass. Exit code 0 may mean that the helper safely took
no action because work is still running; always inspect `decision`.

## External acceptance

Local unit state, local HTTP health, and local pager acceptance do not prove
external polling. Through the original ChatGPT connection, record a new
`host_list` response, a new first `process_list_page`, its continuation, and an
exact repeat of that continuation. Check successful business results, equal
snapshot identities, and equal repeated page content. Use an actual returned
cursor; if the first page has no continuation, record that fact and use a
previously known job's read-only `process_status` instead.

Keep that external observation separate, bound to the apply receipt SHA and
current service identities. It establishes the observed request roundtrips;
it does not replace original-job status verification or a throughput test.

## Local verification

From this directory:

```bash
python3 -B native_rollout_tests.py -v
python3 -B recover_control_channel_tests.py -v
```

The native tests cover the original rollback/state guards plus restoring the
two dependent services, inactive-service preservation, no restart of an active
entry point, configuration drift, unexpected dependencies, and failure after
core commit. Recovery tests cover collected and loaded cutover states,
unfinished/corrupt/missing receipts, a held maintenance lock, queued
service/timer work, and conditional tunnel restoration.

## Follow-up verification

The original native rollout remains archived without being re-executed. The revised recovery helper passed its 24-case regression suite on the main host and the live `--check-only` path returned an already-active tunnel decision with `service_action=none` at 2026-10-17 12:07:52 UTC. The native rollout dependency-restoration suite passed 15 cases on that host. The old helper refusal was reproduced with the real empty-Job fixture before the correction.

# Complete ordinary Batch public fixture

This is a new, reproducible candidate. It does not recover or reuse the lost
private91 implementation or its inaccessible qualification. It binds the target
`d3d75c30719db966b004756f610007a7c723729e`, SDK 3.9.0, Tokio 1.53.3 and Rust 1.95.0.

The native graph contains 94 independently pinned HIA images. CI freshly compiles
all 94 members and separately compiles and executes the HIA ELF linker and packer
for two carriers. Both carriers use exactly the same 94 member images. The first
carrier is the actual JSON-lines public entry. The second adds observation and
setup selectors for two persistent server sessions, complete cache/scope/lease
state and process-shared history/file locks; public tool calls still traverse
the actual public SDK/frontend/gateway/caller/body path.

The unchanged target reference reproduces 106 retained original items, 15 Batch
body fragments and 2 parameter fragments. Its wrapper uses real SDK serve,
Parameters extraction, AsyncMethodAdapter and ToolCallContext. Fresh Cargo
metadata starts from the target lock, then a fresh locked offline build retains
every registry archive and verifies every actual compiler source file against
the archive checksum. This fixture does not include the whole production router,
authority/audit/retention settlement, remote SFTP or full asynchronous lifecycle.

## Fixed domains

| Domain | Complete rows per implementation | Process/session contract |
|---|---:|---|
| Typed legacy | 417 | One actual process, two persistent sessions |
| Typed modern | 417 | Same; session 0 starts with an inline tool call |
| Filesystem | 926 | One actual process, all original actions and state |
| Session interaction | 17 | Cross-session cache/history/undo effects |
| Public stdio legacy | 15 | Actual JSON-lines entry, no private selectors |
| Public stdio modern | 13 | Actual inline JSON-lines entry |

Every exchange retains its 60 second deadline. Every complete lane retains its
180 second deadline. A signal guard raises inside the recording driver so its
owned process group is closed or killed and reaped by the existing finally path.
It does not split persistent sessions or move large cases to a different cohort.

Both sides retain every attempted/accepted input byte, stdout/stderr byte, event,
filesystem snapshot, permission, hardlink relationship and observable native or
original state. Comparisons use identical absolute fixture paths. After process
exit and full independent reread, only each exact fixture is retired, with its
complete final snapshot and all removed object identities retained. Strict
readers remain valid after relocation and launch no process. Nineteen data-only
refusals use independent real copies and retain the complete changed bytes.

Every exchange is appended as one complete canonical JSON line before the next
exchange starts. After the owned process has been reaped, the recorder seals the
same complete JSON array once. The reader compares the entire append journal
with that final array, including all fields, ordering and timing observations.
Failure paths retain the completed prefix and the final failed exchange. This
removes repeated serialization of all earlier records without changing an
implementation input, output, observation, session, case or deadline.

The native build reader follows the frozen builder's exact profile encoding:
only the standard 8/8/32 MiB profile omits `buffer_profile`; every other profile
must name its fixed capacities. Separate refusal controls cover wrong standard
capacity and an omitted wide profile, in addition to all earlier controls.

## Invocation

Fresh execution is restricted to CI:

```bash
python3 -B run_recipe.py --phase all --hepta /path/to/exact/Hepta \
  --target /path/to/exact/original --rust-bin /path/to/rust-1.95/bin \
  --output /new/qualification
```

Complete independent reread:

```bash
python3 -B run_recipe.py --phase verify --output /copied/qualification
```

`--phase verify` performs no writes or process launches. The exported source and
evidence manifest bind complete file bytes; it does not rely on summary PASS text.

## Explicit remaining boundaries

The Batch route is exercised by this fixture but remains absent from the public
catalog until final integrated routing and declaration qualification. This
candidate uses the qualified public83 baseline, with authority91/Bellman later
composition still separate. Slots 47–52 and engine offsets +416/+424 belong to
Batch; 53–55 belong to shutdown/get_info/connection. Descriptor storage begins
at 8192 in the 16384-byte engine. Authority 56 and Bellman 57 are reserved by the
other independent overlays.

The 8 MiB Scope/Lease request window and 1,048,672-byte cache callback loan remain
explicit limits. Full concurrent execution, arbitrary cancellation, production
activation, all 136 handlers and whole-runtime replacement remain false.

Earlier development failures remain separate: internal projection limits,
disjoint-span rejection, and the v9 typed-legacy capture that completed 415/417
rows before SIGKILL. Its cause is not inferred from the signal. This recipe must
finish every declared row on the newly frozen source before it can pass.

The preceding complete CI run `43858641539` retained both 417-row typed pairs,
including all wide frames, and failed its native filesystem lane after 745 of
926 rows at the original 180 second total deadline. Its full failure artifact
is `14223046601`, ZIP SHA256
`bdd5dafd3f23f3c232457e7d2b791855a62b9958bc3afbbe62331c502797579f`.
The failed lane's 5,223 exchanges took 33.802 seconds in total; the remaining
146.121 seconds were outside exchanges. The old recorder serialized 12.53 GB
of cumulative prefixes for a 4.81 MB final exchange array. This version keeps
that failure separate and uses append plus final sealing. No HIA source or
native image changes as part of this recording repair.

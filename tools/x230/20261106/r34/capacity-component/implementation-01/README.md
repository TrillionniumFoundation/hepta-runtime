# R34 independent native capacity component — source preparation 01

This package contains an external component crate, one-cell coordinator, private fixtures and build-binding tools. It has not been formatted with rustfmt, compiled, run, or used to make a performance claim. Its Python files have only been read and parsed as source. All actual build and run input templates remain unsealed.

The accepted runtime A is R24 commit `baab4def80be7af015b2e7a594cb302f66c4130e`. Runtime B is the separately frozen R34 ordinary-first cancellation reserve candidate, patch SHA256 `1a73c219fcfd2a273354bcbe0e1eb3f2ba629b1eb9f4969591352c6dd1a4ffc0`. No file in either runtime source tree or the original 220-input compile maps is modified by this component package. The actual formatter-tested R34 map and successful original qualification must be supplied later; a future success is not prefilled here.

## Scope and remaining work

The implemented entrypoint is **one six-host native direct-transport cell**. It uses one process, one original production direct transport, public `runtime::ssh::run_capture`, and original `native::cancel` of a real existing durable job. It does not run the MCP dispatcher and does not establish complete MCP throughput or admission capacity. A normal C6 canary also does not establish global saturation.

`campaign-inputs.unsealed.json` fixes the intended eight cells: `A1-x230`, `A1-mac`, `B1-x230`, `B1-mac`, `B2-x230`, `B2-mac`, `A2-x230`, `A2-mac`. There is **no complete outer campaign program in this package**. Before formal measurements, a separate reviewed outer revision must bind the original held-agent authentication control, compiler monitoring, 90-second quiet period and all eight create-only inputs. It must run cells serially, stop at the first failure, retain that failure and its cleanup, and prevent omitted cells, automatic retries or selection of a favorable repetition. An incomplete occupancy witness remains failed or incomplete even if cancellation was fast.

The current Rust source has not passed a formatter. Before any actual compilation, create a new component source revision, run only its component formatter, retain the exact difference and refreeze its final manifest. Do not format the path dependency or rewrite this source-preparation package. The original R34 production freeze is independent of this step. `BUILD.md` describes the subsequent offline build contract; it is a future procedure, not a receipt of execution.

## Component behavior

| Item | Fixed behavior |
|---|---|
| Controller | Linux; one driver process; two Tokio workers; original runtime init and shutdown |
| Hosts | ai395, mac, main, pocket4, rog, x230; six distinct original configured SSH targets |
| x230 victim | Two gates on x230 and ai395; one each on the other four hosts |
| mac victim | Two gates on mac and main; one each on the other four hosts |
| Ordinary saturation | Eight original `run_capture` calls; remote ready receipts plus all eight still-pending requests plus the same eight live SSH generations |
| Gate bound | 30-second private remote TTL; 40-second original capture budget; 10-second ready barrier |
| Existing jobs | Six original native durable starts, one per host; own finite 90-second workload TTL and 120-second supervisor timeout |
| Victim | Original job ID/key; one original cancellation; one-second owned SIGTERM handling; no normal victim release marker |
| Release schedule | Gate release begins at original driver cancel-dispatch + 3 seconds, independent of A/B return time; excessive lateness fails |
| Follow-up release | Five nonvictim workloads only, after the fixed gate-release phase; failed-cell cleanup may release the victim but cannot pass the cell |
| Observations | 50 ms local occupancy sampling, maximum 250 ms gap; samples must begin and end before release |
| Reconciliation | All known original jobs even after partial start failure; at most 512 status attempts per job and fixed 150-second observation deadline |
| Retry | No new launch key, cancellation retry, gate retry or uncertain release retry |

The component avoids the misleading construction “eight slow cancellations, then a ninth cancellation”: the original runtime has `MAX_CANCEL_PUBLICATIONS = 8`, which can reject that ninth request before the transport. Long-running durable workloads after start ACK also do not keep their launch SSH slots occupied. The eight gates here explicitly occupy the ordinary direct SSH calls in the **same** runtime process that cancels the existing job.

For B, local sampling must positively observe the same eight original gate SSH generations plus a ninth matching cancel SSH generation, with three on the victim target. This is paired with a descriptor-validated read of the remote original `cancel-request.json`, completed before fixed release. Its job ID, launch nonce and final raw SHA must match. The coordinator makes the same bounded observation attempts for A; a late read cannot count as before-release evidence. Local ninth-child appearance alone, or low latency alone, is insufficient.

The valid original cancel result is restricted to `stop_requested` or `term_sent`; `cancel_unknown`/`unknown`, automatic retry, missing audit confirmation or invalid platform identity semantics fail. An ACK is explicitly not a terminal proof. A must not return its valid cancellation ACK while the original eight ordinary gates are held.

## Original identities, output and cleanup

The driver and fixtures never modify production Python helpers, runtime cancellation identity, admission limits, registry ownership or SSH policy. Only new private names under the already authorized original remote state bases are created. Source records must be actual existing operator-mode Python job records with the original alias, executable and argument policy. All directory and file accesses to fixture evidence are bounded, owner checked, no-follow and tied to their original private identities.

Each of the six jobs must close through the original supervisor contract: matching request/job/launch nonce and witness digest, confirmed terminal publication, exit code zero, no timeout, complete durable output, synced channels, no log error or truncation, and exact stored/seen byte counts. The native read replies must match offset zero, EOF, sizes and original stdout/stderr bytes; stdin and the expected workload output are checked too. The victim must be cancelled and the other five must not be cancelled. Original `observe_request` must recover the same job/key without retrying a launch. The eight gate captures are compared with their independent private finished receipts and ready identities.

Partial durable-start failures retain known jobs and the primary error; they skip gate admission but still reconcile those known identities. Unknown outcomes retain the original request/key instead of restarting. Gate futures are all drained even after an inner failure. Successful direct startup followed by observation-pool startup failure explicitly awaits direct shutdown. Both owner guards are awaited on the normal outer path, and cleanup errors remain distinct from the original failure.

The coordinator owns every local helper through its original `Popen` and, when established, a pidfd. `waitid(WNOWAIT)` observes; original `waitpid` proves reap. Post-spawn setup failures still return custody of the original child. Deadline cleanup signals only that owned child; it preserves uncertain handles and fails rather than inventing reap. Stream-file errors close already-reaped local descriptors. A held pidfd to an observed driver descendant permits bounded cleanup of that owned generation; unexpected survivors fail the cell even when cleanup succeeds. An external observer seeing absence does not replace the runtime owner's original join/reap proof.

Remote TTL is a final bound on a private fixture after a coordinator failure. It is **not** terminal proof. No output directory, raw failure, original job evidence or uncertain receipt is automatically deleted. No firewall change, external service restart, unrelated process signal or production test hook is used.

## Resource and build boundaries

The external root repeats R24's six release declarations exactly: LTO, one codegen unit, abort panic, stripped output, opt-level 3 and disabled overflow checks. It pins anyhow 1.0.104, serde_json 1.0.151, tokio 1.53.1 and libc 0.2.189, all already present in the accepted runtime lock. This is not a claim that an actual component lock or ELF has been produced.

The actual resolver must run offline against the explicitly bound existing Cargo cache. Both selected package/feature graphs and checksums must agree after normalization of the two local source roots; no test-only rmcp client feature is allowed. Qualification binds A to the exact accepted R24 report and map and B to the actual eight-stage R34 report and formatter-final map. Only the four original R34 source paths may differ. Python include inputs are separately bound in full.

The original design's separate target-per-arm sketch is superseded by the controller disk constraint: **one new independent shared component target**, serial A then B builds, and a separate create-only preserved ELF for each arm. No whole runtime cache is copied or moved. A's preserved ELF must exist and be pinned before B's first build command begins. Stage intervals and the post-fsync preservation timestamp use Linux `CLOCK_MONOTONIC` with the same actual boot ID; client timestamps cannot be substituted. Both arm reports must close before any cell starts.

`reference/observation_resources.py` is the original unchanged sampler. Its measurements cover the driver's owned process tree, with its documented sampling and RSS summation limitations. Coordinator SSH probes are separate controlled processes and are not silently counted as runtime direct slots. Component cancel timings, occupancy, controller-tree CPU and sampled memory cannot be presented as whole-runtime RPS, whole-system CPU or RSS savings. No numerical benefit is asserted by this preparation.

## File interfaces

| File | Role |
|---|---|
| `component/src/main.rs` | Same-process public-runtime driver and unconditional original-job reconciliation |
| `component/fixtures/common.py` | Shared private path/identity/file helpers, concatenated into the actual helper strings |
| `component/fixtures/gate.py` | TTL-bounded owned ordinary SSH gate |
| `component/fixtures/workload.py` | Existing durable workload with bounded SIGTERM handling and exact output |
| `component/fixtures/coordinate_remote.py` | Private prepare/inspect/release operations; reads original runtime receipts without modifying them |
| `coordinate.py` | One-cell local coordinator, before-release witnesses, owned child custody, original-output reconciliation |
| `prepare_build.py` | Read-only runtime validation, then create-only external workspaces; never invokes a compiler |
| `check_graphs.py` | Validates actual offline lock/metadata outputs; never reports a compile success |
| `seal_arm.py` | Validates actual build receipts and preserves one actual ELF; never invokes it |
| `*.unsealed.json` | Missing actual identities deliberately remain null and refuse execution |
| `source-manifest.json` | Exact source-preparation identities; status records unformatted/uncompiled |
| `static-review.json` | Limited source/AST/hash checks actually performed, with non-executed boundaries |

Passing a future single cell would support only its defined component claim. Adoption still requires the parent's independent original qualification, exact CI, complete frozen capacity campaign and unchanged normal observation/lifecycle acceptance gates.

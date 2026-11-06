# R34: bounded direct SSH capacity for existing-job cancellation

**Status: rejected by the original C8 throughput gate; R34 is not adopted.
Full qualification and exact native CI passed. Accepted runtime remains R24.**

The initial source commit is `5d0b180b832e7f2a8120078231e97ef9e702608a`,
independently based on accepted R24 `baab4def80be7af015b2e7a594cb302f66c4130e`.
The original 22-file candidate package remains under ../r34-candidate/ with its
original pre-execution statement and hashes. This directory records subsequent
preparation and actual execution without rewriting that frozen snapshot.

## Runtime change and bounds

Only four of the same 220 compiler inputs change. An existing-job cancellation
first tries the ordinary admitted, target and global permits immediately.
If capacity is unavailable, all partial ordinary permits are dropped before
waiting in a separate reserve with eight admitted identities and one executing
request. The original absolute deadline, stop fence, ownership state machine,
confirmed reap and uncertain-wait custody remain. The nine-entry owner channel
can accept eight ordinary ready requests and the one reserved ready request.

Ordinary direct limits remain 16 admitted identities, eight executing requests
globally and two per configured SSH target. Combined ordinary plus reserve
bounds are 24 admitted identities, nine executing globally and three on one
configured target, within this controller's direct transport. These are not
a cross-controller or physical-host alias quota. The existing upstream cancel
publication limit remains eight. ACK and final job completion remain distinct.

The change affects only the two validated existing-job cancellation dispatches.
Original remote helper bytes and job identity/intent checks are unchanged.
A reserve waiter does not switch back to subsequently freed ordinary capacity.
The latency/resource tradeoff still requires original measurement.

## First complete qualification

Original native job: **`1a1aef7882f-fc05-6499`**, started once with a two-hour
outer timeout and no automatic retry. The 19 original qualification tools,
eight stages and `jobs=2` remain unchanged.

All eight original stages closed with exit code 0. The unfiltered isolated
inventory reports **1653 passed, 0 failed, 34 ignored, 1687 selected and 0 retries**;
the original independent auditor reports success with no errors and 1653 executed
cases. The native terminal is succeeded/0 with complete, durable, synced and
untruncated 1108-byte stdout and empty stderr. This was the first qualification
execution, with no automatic retry.

The actual final source map contains the same 220 paths. Exactly the original four
candidate paths differ from R24; 216 are unchanged. Formatting changed only the
candidate test file, which is now published at src/mcp/runtime/ssh_direct_tests.rs
with SHA256 `b3ad50032291f32eb4492ca09d3198937b0dcda4eb9abc228d91d2f5b0b847c6`.
The three production source files remain identical to the initial R34 candidate.
Postflight re-read the complete 220-file map, 19 original harness files and all
three retained release binaries and confirmed their qualified identities.

| Retained program | Bytes | SHA256 |
|---|---:|---|
| hepta-runtime | 14,379,112 | `85211f3d60844554c778fbe460d455320425aa43b5525bf8786b3cc51a992c30` |
| hepta-runtime-jobctl | 739,016 | `61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62` |
| native_process_driver | 2,903,568 | `d6f7ca735830a17fd7d243fd6bb0b3b2b70e94bd931c19ecce1e706a0d1926b4` |

Original report, map, summary, complete native streams and postflight are under
qualification-01/. The earlier interim read remains historical evidence.
The full bounded qualification archive was created once by native job
`1a1af1c9f22-fc05-65e1`: 3,307,677 bytes, SHA256
`488f38422ffca19dc28ecc986fda5218cff090fe8a906053a217eee8e741cb1b`.
Its complete 51-chunk immutable transfer and local zero-extraction verification
both passed: **3654 files / 18,310,016 selected bytes / 0 extracted**. The full
archive, manifest, compact summary, transfer identities and verification are now
published under qualification-01/. The manifest is 648,209 bytes with SHA256
`1b0d379b32f7de16f525b46452e449ee1f1173aa9033048b58755c95c7c565b6`.

The sealed 30-file installation package is 265,304 bytes, SHA256
`16d21b200f3e871f58ad30d6ea130d342c467963d432a93bf362fed4748998e4`.
The actual install readback confirms all 30 files before qualification. Candidate
files live under candidate/; the preparer creates a fresh runtime source from
R24 and applies the frozen four-file patch. R33 contributes only its closed
build cache. R33's C8 rejection and lifecycle refusal remain mandatory owner
closure inputs and are not composed into this source.

## Recorded capacity preparation

The original 3 GiB free-space requirement was preserved. Actual capacity was
initially 2,652,098,560 bytes. Only these two rebuildable project artifacts were
eligible for removal from the inactive R33 cache:

- debug/deps/hepta_runtime-1b8b761b89392e3b
- debug/deps/libhepta_runtime-564505b54e9d81cd.rlib

The retained test executable is an independently stored, single-link inode
with the original audited SHA256
`e2096aa99096233152ffbd11fd1d42aa145cbfa1ef9f4fa81b8191e9055ad3b1`.
The cleanup tool checks owner closure, all retained program hashes, process
references, fixed object identity, stable complete hashes, and full before/after
cache metadata. It deletes no directory and does not run a compiler or test.

The original cleanup job `1a1aeeea99f-fc05-6440` failed before deletion because
root had passed nanosecond timestamps through JavaScript Number. The two pins
differed from original integers by +35 ns and −124 ns. Its original native
streams and report are preserved with zero deletions; both cache inventories
and both owner reports were byte-identical.

An independent read of the original text, failed inventory and live file metadata
confirmed the exact integers. Separately reviewed cleanup version 02 uses decimal
strings and strict equality, with no tolerance or relaxed condition. Its original
job `1a1aef5957d-fc05-6486` passed, deleted exactly the two authorized artifacts,
kept retained programs and all unselected cache entries unchanged, and reported
**3,566,792,704 free bytes**. The original failure was not overwritten or restarted.
This maintenance correction is separate from the first runtime qualification.

The actual cleanup report is 4,426 bytes, SHA256
`51fae444ad2ec1a11ba371a26f5e4ed5d12df3e2d2ca36187a9f60159b1b9b87`.
Its unchanged helper, original source/closure bindings, exact native originals,
static reviews and execution catalog are retained under cache-prune-01/ and
cache-prune-02/.

## Exact CI and original six-host result

The first original exact native CI job `1a1af1ebf1d-fc05-65f2` succeeded with
**1653 ordinary PASS / 0 failed / 34 ignored / 1687 selected / 0 retries**.
All six version/check/list/run stages passed. The exact unfiltered case inventory
and ignored set match the qualification; the final source map still matches
all 220 qualified inputs. Every original child was waited and reaped, original
process groups were absent, and the report records no service modification.
Native output is complete/durable/synced/untruncated: 1541 stdout bytes, empty stderr.

The original all-target/all-feature commands, pinned nextest 0.9.137, one test
thread, no fail-fast and zero retries were preserved. This is native x230
execution using the explicit offline cache, not a hosted GitHub Actions result.
The original report is 14,129 bytes, SHA256
`f9be0abb116e162cba37b610701ad8474e52bd057159d68349ebae08bd970337`.

The complete CI archive was created once by job `1a1af2d4429-fc05-6676`:
320,213 bytes, SHA256
`9431da8651cfa3e43fe83a1ec3de3f2f85165e20316f2fd8142bacba004abd73`.
Immutable transfer and the original bounded local verifier passed: **34 files /
2,045,291 selected bytes / 0 binding errors / 0 extracted**. Full stage logs,
structured inventory, plan, tools, qualification references, native streams and
the original nextest audit are retained in exact-ci-results-01/ and its archive.
The original tests and nextest auditor were not rerun to prepare either archive.

The original observation input materializer succeeded once as
`1a1af2cbada-fc05-666d`, creating no workload. The unchanged Mac holder and R34
parents were installed once and reverified. Normal observation closed
as original Mac job `1a1af308953-fc05-6698` with original quiet90, compiler
monitor, ABBA order and thresholds. Native exit 0 and parent workflow closure
are distinct from its rejected performance gate. The original six-host observation gate failed at C8. Normal lifecycle ABBA and
the separate capacity proof were not started after this failed prerequisite.

Saturated direct cancellation requires a distinct same-process component using
the actual shared production DIRECT owner: eight ordinary requests held across
six hosts before dispatching the existing-job cancellation. Existing-job
cancellations alone cannot establish global-eight saturation because the
upstream publication limit is eight. The component's implementation-01 source package and independent static review
are now published under capacity-component/. It is explicitly unformatted,
uncompiled and unexecuted. A new formatted revision, actual offline A/B builds,
retained ELF identities and the complete outer eight-cell campaign remain required. No saturated result is claimed
by this preparation or by a normal six-host recovery canary.

The experimental branch retains the candidate and its rejection evidence. R34
is not adopted, and no saturated-capacity benefit is claimed. Later optimization
candidates must independently start from accepted R24.

## Rejected first observation: original data

| Concurrency | R24 calls/s | R34 calls/s | Throughput change | P95 change | CPU/call change | Throughput gate |
|---|---:|---:|---:|---:|---:|---|
| C1 | 7.616621 | 7.922035 | +4.0098% | +0.3397% | −10.8020% | pass |
| C8 | 55.160128 | 51.333578 | **−6.9372%** | +8.7372% | +3.6735% | **fail** |
| C16 | 55.492312 | 53.046655 | −4.4072% | +2.4113% | +3.0343% | pass |

The C8 throughput ratio is **0.9306283429378647**, below the unchanged 0.95
minimum. P95 and same-controller CPU gates pass independently at every level.
Sampled controller RSS peaks are 18,788 KiB (A) and 18,544 KiB (B), a 244 KiB
reduction; the unchanged combined RSS ceiling is 19,300 KiB and passes.

The original audit verifies 2304 successful measured calls, 288 warmups and 72
preflight/restart calls, 2664 total with zero failed calls. Capacity boundary
results remain separate: 32 successes, 32 expected capacity refusals, zero other
errors, and drain/recovery passed. The original recovery canary passed; it does
not establish the unexecuted global-eight saturated cancellation proof.

All seven original parent stages returned zero with actual child wait/reap and
original process-group closure. Inputs, both source maps and retained program
identities were unchanged. The original compiler monitor's independent audit
passed 301 samples. Its scope is 1 Hz sampled observations; it does not rule out
unsampled activity or prove the entire machine was idle. The Mac holder reaped
its own agent and closed its temporary socket/directory.

This is one finite six-host campaign. No measurement was repeated, no historical
run or adjacent pair was selected to override the rejection, and no causal claim
is inferred from the finite comparison.

Original parent, summary, native holder/read/report, independent call/monitor
audits and the postflight are in observation-results-01/. The postflight
`1a1af3c8508-fc05-66fa` succeeded once, rechecked all 220 current compiler inputs
(including embedded Python sources), and found all three normal lifecycle paths
absent. The lifecycle materializer was not invoked; there is no fabricated
failed-materializer receipt. The cache was neither moved nor deleted by this
postflight, and no test, benchmark or auditor was reexecuted.

The complete bounded observation archive is published in observation-results-02/.
The source of the unexecuted capacity component is retained as preparation only.


## Observation archive attempt 01: packaging failure preserved

The first bounded observation collector, job `1a1af44cd02-fc05-6739`, failed with exit 1 and `frozen original input differs` before creating an archive, manifest or compact result. Its original frozen source, bindings and static review remain under observation-archive-sealed-01/; the native failure and subsequent read-only diagnostic remain under observation-archive-failed-01/.

The stable diagnostic job `1a1af47b4a8-fc05-674c` checked all 99 fixed identities: 96 matched and exactly three lifecycle-tool pins did not. The collector had inherited the R33 hashes for the two lifecycle scripts whose root paths the original R34 installer rewrote, and for the resulting lifecycle manifest. All three actual R34 hashes exactly match the original 26,390-byte parent-tools-install receipt (SHA256 `b783a85e4b41e5202305b7739e63eace75c71d4ea65f14fcbe7d05e5ceef30a2`) and two independent reconstructions from preserved older source bytes. This is a collector prebinding error; no original measurement was altered or repeated. A separately reviewed collector 02 and its separate output namespace preserve this failed first archive attempt in the completed archive described below.

## Unexecuted capacity preparation 02

capacity-component/implementation-02/ retains 40 frozen source/preparation files (572,177 bytes), with its independent review alongside. It is unformatted, uncompiled and unexecuted. R34's rejected observation prerequisite ended its execution chain: no capacity build, cell or normal lifecycle run followed. Actual inputs remain unsealed and the external holder's final closure procedure is not implemented. These materials establish preparation only, with no capacity result, throughput benefit or adoption claim.


## Complete original observation evidence: archive 02

Collector job `1a1af5208bf-fc05-67a0` completed once with exit 0, complete durable and synced stdout/stderr, no retry, timeout, cancellation or truncation. Its archive preserves **4,165 files / 30,617,958 selected bytes**, including the original parent stages, native per-call evidence, boundary and recovery records, unchanged monitor and its original audit, original holder report/terminal streams, postflight, original archive failure and stable pin diagnostic. No test, measurement or original auditor was rerun to create it.

| Artifact | Bytes | SHA256 |
|---|---:|---|
| observation-results-02/observation-evidence-02.tar.gz | 2,988,567 | `0673ccf701866ee7de17e18bc56f7005b5d75670352ceb9e7ab5ab1344b64eef` |
| observation-results-02/observation-evidence-02.manifest.json | 1,077,406 | `574fa09ca1a04d3cb3c3d45329abc8edf491a966080f930982bf8bad782d63b0` |
| observation-results-02/observation-evidence-02.compact.json | 38,108 | `a1f3b715c5d9980ef1f4615cb8679efa5839aa55d341e125e4717e916c85dfdf` |

Transfer verified all 46 archive chunks and 17 manifest chunks against fixed source versions, per-chunk and complete SHA256, and exact Git blob identities. The original frozen collector then verified every archive member and reconstructed the summary locally with **zero extraction**. Manifest and compact sidecars match the archive; receipt binding errors are empty. The local verification and original collector native/read receipts are retained alongside the archive.

This evidence preserves workflow success separately from performance rejection: the original 12 observation cells contain 2,304 successful measured calls; C8 remains below the unchanged throughput threshold. All 12 recorded standard shutdowns were clean; the original recovery's intentional crash remains separately recorded. Neither normal lifecycle ABBA nor the separate saturated capacity component ran. The complete Mac holder report retains its log identities, while the separate Mac log bodies are not copied into this archive. Compiler monitoring remains 1 Hz sampled evidence, with no whole-machine-idle or causal-performance claim. R24 remains accepted.

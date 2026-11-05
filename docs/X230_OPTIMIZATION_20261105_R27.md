# X230 R27: fewer serialization allocations; not promoted

## Decision

R27 improved the fixed serialization component in all six cases. The ordinary
status/read fixture mix saved **0.61852976 microseconds per preparation call** and reduced allocation
calls from an average of **13 to 2**. This is a useful local result, but the direct
CPU saving is small beside the existing controller cost. The serializer-only
candidate is **not promoted to full qualification or six-host acceptance**.

The full acceptance gates were **not run and not evaluated**; they did not fail.
R27 remains on the independent `experiment/x230-r27-serializer-20261105` branch.
The source checkpoint is `9d01233e21ef57190b43661afa18674cf1e837e9`, based on accepted
R24 source. No shared performance branch or production service was changed by
this experiment. Further speculative Vec-capacity tuning on this path stops here.

## Code change and scope

The candidate runtime-source delta is confined to `src/mcp/runtime/ssh.rs` and seven new sibling
tests in `ssh_observation_serialization_tests.rs`. A private borrowed `Serialize`
enum replaces the intermediate owned `serde_json::Value` map. It removes map-key
and identity-string allocations. The source diff leaves the existing serialized field
order, original-size guard, command construction order, numeric values, wait
clipping, deadlines, system newline, and final combined 64 KiB budget unchanged.

The component embeds the actual R24 and candidate preparation functions with
source/excerpt hashes. Both arms use an identical short Python command stub.
It therefore measures request preparation plus fixture adaptation and output
destruction, not real command construction, SSH, queueing, remote execution,
whole-runtime throughput, or RSS. The system command and newline are real; the
64 KiB boundary case is exact under the benchmark's stub.

The seven repository regression tests were added and statically reviewed, but
the complete runtime test suite and those tests were not executed as a Cargo
qualification. Successful compilation of the extracted component is not full
source qualification.

## Original executions

Attempt 01, X230 job `1a1ab85c2c3-fc05-4e78`, failed before any compiler or sample.
Its R25 dependency-cache fingerprint path no longer existed. Its report retains
`stages: []`; the error and native terminal are preserved. The cause of the cache
absence was not established.

A separate read-only inventory, job `1a1ab8a92a8-fc05-4e8c`, found the current
R26 release cache and four direct dependencies matching its pinned product fingerprint. Attempt 02
changed the cache location, pinned and preserved the actual product fingerprint,
and used a new output directory. No benchmark function, fixture, loop, order, or
sample count changed. The only direct `--extern` dependencies were `anyhow`,
`serde`, `serde_json`, and `libc`; no Hepta runtime library was linked.

Attempt 02 ran once as X230 job `1a1ab92f54d-fc05-4ebe`, stable key
`hepta-x230-b96-r27-serializer-component-20261105-02`. The native terminal is
succeeded, exit 0, complete and durable output, no timeout, cancellation or
truncation. Compiler identification, both builds, timing and allocation stages
all exited zero. The ordinary allocator binary recorded CPU/wall timing; the
separate counting binary recorded allocations without making timing claims.

The fixed design used two ABBA rounds per case, 100,000 calls per ordinary batch
and 2,000 per near-limit batch. Every one of **48 timing records** was retained.
Each allocation arm/case used 1,000 calls, yielding **12 allocation records**.
All six byte/command/timeout/system equivalence checks passed in both binaries.
The independent audit re-extracted and verified all 11 source excerpts, all
record identities, sample order, divisions, summaries and readback hashes.

## Complete component results

CPU values are process CPU microseconds per preparation call. Allocation counts
below exclude `realloc`, which is reported separately and did not change.

| Case | Baseline CPU us | Candidate CPU us | CPU change | Allocation calls A to B | Realloc calls A to B |
|---|---:|---:|---:|---:|---:|
| Python status | 0.859366 | 0.403238 | -53.08% | 12 to 2 | 1 to 1 |
| Python read | 1.242566 | 0.461635 | -62.85% | 14 to 2 | 1 to 1 |
| System status | 0.294194 | 0.114197 | -61.18% | 7 to 2 | 0 to 0 |
| System read | 0.654317 | 0.207641 | -68.27% | 10 to 2 | 0 to 0 |
| Escaped/Unicode Python read | 1.256226 | 0.560301 | -55.40% | 14 to 2 | 2 to 2 |
| Python read at stub 64 KiB boundary | 66.907685 | 47.905418 | -28.40% | 14 to 2 | 2 to 2 |

The ordinary workload is an equal mix of Python status/read. Only these two cases
enter its comparison: CPU falls from **1.05096617625 to 0.43243641625 us/call**,
saving **0.61852976 us**. Allocation calls fall from **13 to 2** while one realloc
remains. Cumulative requested allocation bytes fall from **1,256.5 to 426 bytes**
per call, saving 830.5 bytes in this component. Requested bytes sum allocation
sizes and realloc target sizes; they are not net live memory or RSS.

System and extreme-input cases are retained separately. Their larger relative
or absolute improvements are not substituted for the actual workload mix.

## Why this does not justify another full campaign

The published R24 C8 result records **19.322916666666668 ms of controller PID
utime+stime per call**. This excludes SSH children and the harness. A 3% reduction
at that historical scale is **579.6875 us/call**. The ordinary component saving is
about **0.003201%** of the historical controller cost, or roughly **937 times
smaller** than that 3% budget.

This is a magnitude comparison, not a measured whole-runtime prediction or a
universal upper bound. The component uses a command stub and its own build;
allocation/layout effects in a full program can differ. No evidence currently
shows an additional effect large enough to bridge that gap. The pre-execution
prioritization therefore stops this serializer-capacity branch while preserving
the positive component result and the candidate source.

The preregistered full gates remain unchanged: C1/C8/C16 throughput B/A >= 0.95,
p95 <= 1.10; at C8 throughput >= 1.03 and controller CPU/call <= 0.97; sampled
controller RSS must satisfy both A + 512 KiB and A * 1.05 limits. Full qualification,
boundary/recovery testing and six-host acceptance remain necessary before any
future production adoption. This finite result does not establish global optimality.

## Evidence and remaining limits

The [R27 index](../tools/x230/20261105/r27/README.md) links the exact source, original
failed attempt, complete successful text outputs, native identities, dependency
inventory, arithmetic and independent review. The successful report is 16,368
bytes, SHA-256 `75c5cef16803e0a3135cdb44ceb93f7ed4958e1e8ecde8179fb1caaec03901fa`.
The unchanged benchmark source is SHA-256
`eb088497f092b82c21d70dd8a17ef191e5430164f6e9967b9816d95514504e35`.

Before build, before timing and after timing, the runner observed no competing
compiler, private test/runtime, campaign/monitor or archive process. Standard
PAM/SSH/key-agent executable links had limited visibility; visible comm/cmdline
checks and that limitation are retained. Three snapshots are not continuous
exclusivity proof. Binary and rlib hashes are native launcher evidence; their
ELF/archive bodies were not downloaded or locally rehashed. All 12 retrieved
text artifacts were independently verified byte for byte against their receipts.

The larger capacity investigation should use actual phase measurements of worker
reads, owner reads, boundaries, queues and agent checks. This experiment neither
supplies those measurements nor attributes the remaining controller cost to one
of those phases.

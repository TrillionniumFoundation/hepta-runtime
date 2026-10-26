# A51: CI repair and opt-in metadata timing

A51 is an independently qualified diagnostic derived from A50. It is not a throughput adoption. Its 170 compiler inputs passed the original six Cargo stages on X230, using Rust 1.95.0, two workers, offline/locked dependencies and explicit stage umask 022. The original qualification worker was reaped with wait status 0, no signals and a quiet original process group.

## Fixed identities

| Artifact | SHA-256 |
|---|---|
| Qualification report | `2d1b86efc358ccf34e0529e279242cff687b2fd56666b915bf5ffb9e820611c3` |
| Entry report | `6bc137775d50ae8ee378da67391622476bee958326ae2ae8efaed01405e96d17` |
| Worker report | `f630fd93ecbc63c01a1b2ed634859a1b536f369aaec87cb4a4ed1e7e6e18513d` |
| Release ELF | `5935fff4e8427b738d5ae07c536aed513e97028a85a66c36ee20742dcf4ed118` |
| Main test ELF | `6fbf1db23580d17758ed8db58bcf56400f97405d35152078269e618706bb9c5e` |
| Diagnostic report | `6f806dd3fac57f13d1cb9041c2905ee12e536d758e7ded35912552f61da1413d` |
| Original metadata trace JSON | `0cfec2026463cbd7669ac63e5d60641f609e574d31266025f6e613e910faee28` |
| Diagnostic analysis | `1baecec98d398384da7d506742d88d1dd45eb292a9da00b5b5acd134fa058a8b` |

Both ELFs have a fresh Cargo compiler-artifact event. Source maps before testing and after release match. Metadata tracing was disabled during qualification.

## One new diagnostic attempt

The diagnostic enabled `HEPTA_METADATA_TRACE=1` and the existing index timing flag for one native Rust MCP controller. It reused the fixed A50 workload implementation: 65,536 archived records, four owners, 512 hot records, one real native seed, one index kickoff, exactly 60 seconds idle, one fixed archive warmup, four C1 calls and four C4 waves. The original 3-second product deadline, 10-second client deadline, 300-second controller budget, original-content oracles and original wait4 cleanup were retained. There were no retries or pooled prior results.

All **20 measured calls succeeded**, with no failed or unexecuted measured slots. The original fixture was unchanged, controller cleanup completed and the source/ELF fences matched. All **3,287 trace events** were captured with contiguous sequence numbers, zero drops and zero parse errors. The four measured C4 waves each formed a four-member cohort. The four C1 cohorts each contained one member.

This attempt **did not reproduce the earlier C4 failure**. It therefore does not prove that blocking-pool scheduling caused that failure. It also cannot estimate a failure rate or certify a performance improvement: tracing adds work and this is a single diagnostic arm.

The initial index kickoff returned the original metadata-deadline error; the later fixed archive warmup and all measured queries succeeded. Consequently the report deliberately retains `product_passed: false` while `complete: true`. A complete capture must not be relabeled as all setup operations succeeding.

## What the trace resolves

Complete original verification dominated each successful scan: approximately **1.8–2.75 seconds** in this traced sample. Admission waits were 0–2 microseconds, and observed blocking-pool queue waits were approximately 10–670 microseconds. The slowest measured C1 call used about 2.75 seconds of its unchanged 3-second product budget. Request projection and final fences were much smaller components.

The next A52 candidate therefore combines a return to the existing complete serial page-verification kernel with async cohort registration and owned group permits. Earlier A46 results motivate the serial CPU-cost hypothesis. Owned async waiters are a separately tested lifecycle and resource improvement; A51 did not establish a measured scheduling speedup. A52 must pass fresh qualification, the unchanged fixed small/large comparisons, native recovery and integration gates before adoption.

## Trace and permission boundaries

The trace is opt-in and records local numeric call/cohort IDs, timing, limit and cursor-presence only. It excludes owner/request IDs, paths, cursor contents and error text. A bounded nonblocking channel retains explicit drop counts. The worker flush runs after its product locks, original reader joins and permit have been released. A cancelled caller can separately flush its boundary event while the original worker still owns its cleanup; that flush neither waits for nor releases the worker's custody.

The independent CI repair is described in [ci-repair.md](ci-repair.md). It gives ordinary test fixtures explicit private permissions and declares the existing integration-test dependencies. Production permission checks, all original reads, final namespace fences, original reader joins and original query budgets remain in force.

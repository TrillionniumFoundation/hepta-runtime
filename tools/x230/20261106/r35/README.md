# R35: read JSON allocation and observation command ownership

R35 is a candidate based directly on accepted R24 `baab4def80be7af015b2e7a594cb302f66c4130e`. **The first complete x230 qualification is in progress; there is no completed qualification, CI, performance or adoption result yet. R24 remains accepted.**

## Exact source change

The same 220 compiler-input paths are retained, with exactly three changed files. `read_job` constructs its original seven-field legacy JSON only in the branch that consumes it. The observation pool transfers its already-owned command String at the original consumption point, using `std::mem::take`; two existing test callers receive the required mutable-reference adaptation. There are no new test cases or assertion changes, no dependency/profile change and no capacity-policy change.

The JSON adjustment is the exact previously published R26 selected delta, isolated here on R24. Earlier combined-candidate results do not isolate its effect. The full frozen candidate and historical/independent review are in ../r35-candidate/. The original source commit is `d77190730651114c41837228a2180b412713cee3`; no R34 reserve implementation is included.

## First actual qualification

The sealed preparation contains 39 files / 1,383,630 expanded bytes. Its 354,738-byte package SHA256 is `7303e1ded7ac4aab5f02c5240b1e6211bbaf7ca8cd7ebe19d686546842366dba`. Independent static review checked every package member, the unchanged 19-file original harness, full 220-path source map including embedded Python, exact three-file overlay and the original eight-stage commands with jobs=2 and no automatic retry.

The first actual qualification job is `1a1af619097-fc05-6813`, using the exact sealed argv. At this progress milestone, format, fmt-check, harness-tests, Clippy and test-build have returned zero, and isolated-tests is running. Future test counts, formatted source custody and retained program hashes will be bound to actual completed original reports; no count or success is predicted here.

The preparer revalidates the original closed R34 qualification/CI/observation evidence, all retained executables, absence of cache users/compiler processes and at least 3 GiB free space before a single cache rename. R34 contributes rebuildable cache only; source is copied from accepted R24 and the frozen R35 patch is applied. R34's C8 rejection remains rejection, and its lifecycle materializer and lifecycle run were never started.

## Installation history kept separate from qualification

The initial installation request `1a1af5e240e-fc05-67f8` returned launch_unknown. Its original status/read errors reported the durable job directory absent; no successful or failed native terminal is fabricated. A separate read-only reconciliation `1a1af5f2833-fc05-6802` observed the new root and original job directory absent, and the original unit not found/inactive with MainPID=0. The cause of the transport failure is not established.

The identical frozen package was then delivered through six bounded binary-upload chunks. Commit verified its total size and SHA256 before making the destination visible. A small staged installer `1a1af611834-fc05-680f` completed with exit 0 and validated all 39 files. Before installation, free space was 6,835,855,360 bytes. That installer did not start qualification, materialize source or move/delete the cache. Only then was the first qualification launched.

All original launch responses, unavailable-native errors, reconciliation terminal/read streams, upload responses, staged-install terminal/read streams, exact scripts and installation receipt are retained in installation-originals-01/. Installation recovery is not a qualification retry.

## Subsequent gates

exact-ci-preparation/ preserves the original commands, nextest 0.9.137, full test inventory, auditor, canonical workflow and guard-before-effects behavior. Actual qualification job/count/source-map/receipt pins remain null until the successful first qualification closes; the sealer cannot substitute predicted results. The original six-host ABBA throughput, latency, CPU, memory, boundary/recovery and normal lifecycle gates are still required before adoption. No threshold is relaxed and no measurement is repeated to reverse a rejection.


## Prepared measurement control and optimization headroom

parent-preparation/ retains the reviewed original normal observation/lifecycle protocol with fresh h35 namespaces and a binder for actual R35 qualification and closed R34 cache-owner evidence. The parent package is 34,133 bytes (SHA256 `3788a8595ff5e5e08e7757546d176fb96385d493b26cd4b1722c610b94e76715`). It contains no new measurement or acceptance result. The original installation logic derives two lifecycle-script roots and their manifest from R29; future archive pins must come from the actual R35 installation receipt.

qualification-archive-template-01/ is also unsealed. Its fixed 54 inputs are the 39 qualification-preparation files and 15 small installation originals; actual terminal/results/counts remain null. It retains bounded collection and zero-extraction verification, and distinguishes unknown installation state from actual first qualification.

The preserved ../r24-headroom-review/ reports distinguish two remaining static allocation opportunities from measured runtime benefit. Prior component evidence gives no basis for assuming that a few microseconds per call would move the observed throughput plateau. Reducing per-request SSH/Python process creation is a structural direction requiring explicit framing, freshness, deadlines and process-custody design; no such implementation or benefit is claimed here. The roughly 20 ms/call reference is controller CPU only, excluding SSH-child and remote Python CPU. All estimates and historical limits are identified in the report.

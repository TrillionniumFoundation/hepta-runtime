# Final merged release: real Chrome and Ghidra regressions

These are new runs against the merged release executable with SHA-256
`0595fbf02e0f492bd151fec97eb90cb704a88810e9415b90582d348f3db99b6a`
(18,437,832 bytes). Chrome's three gates ran in order, and Ghidra began only after
Chrome's durable outer job had completed successfully. Every original gate
harness remained unchanged. The parent held the registry-heavy Python rerun
until all of these external jobs were terminal.

The qualified release build receipt has SHA-256
`67b79efc7820f6d77b86ba1727f2fe0c16d5f96fc9d5abcacbafd038f2d0c75b`.
It binds source commit `b857dc7d646dc938e29a51fa82a5856d9b96f842`, source tree
digest `0ab735bb69893f88ea4f81c73d5d64d5220d234d3ead90cba88c55542eec9abb`,
equal before/after source manifests, and zero source-monitor events or errors.
The wrapper rechecked that receipt, the original release, the independent
binary copy, selected source/test/configuration inputs, and all original
harness hashes before and after these runs.

## Results

| Gate | Observed result | Harness duration |
| --- | --- | --- |
| Real native Chrome capture and saved HAR operations | All 11 checks passed | 20.475 s |
| Independent comparison with retained Python reference | All 10 selected before/after resource pairs and the independently authored body/metadata oracle passed | 0.474 s |
| Fixed native browser deadline | All 6 checks passed with the original 1 s manifest deadline and 100 s child-job ceiling | 6.280 s |
| Real Ghidra analysis and native decompiler | All 8 checks passed | 247.839 s |

Chrome's outer job `1a1a6e0fb5e-fc05-293d` took 27.753 s. Ghidra's outer job
`1a1a6e19fef-fc05-2943` took 248.410 s. Both authoritative durable statuses
report exit 0, complete durable output, no timeout and no automatic retry.
The original 1200 s outer ceilings were retained. The requested resource limits
also matched the prior wrappers: CPU 400%, nice 10, 4 GiB for the Chrome suite
and 8 GiB for Ghidra. The unchanged inner gate timeouts were not extended.

## Chrome evidence and limits

The observed browser was `Chrome/156.0.8078.79`. The native checks exercised
the actual release's durable-job and MCP routes, changed-resource admission
refusal, complete/empty/base64/missing and repeated-request observations,
receipt durability, original-key reuse, cold-controller recovery, saved HAR
inspection/comparison/replay, and cancellation with private browser/profile
cleanup. Replay sent zero requests to the two owned live sentinel origins.

The independently retained Python reference was read without mutation or a new
reference run. Its qualification SHA-256 remains
`797f986ef548582956a91dac5bac364f7f328b40003b00128b553120820148c7`.
The finite projection preserves the distinction between an empty body and
missing, unrecorded content. The complete new differential report is retained
outside the checkout and bound by SHA-256; the compact projection here keeps all
10 case keys, body/metadata equality outcomes, independent-oracle outcomes and
explicit scope flags.

The deadline fixture still contains 32 delayed requests, each with a 2 s authored
resource delay, and a 1 s native capture deadline. A real original Chrome process
started; the original job then failed with the specific native capture-deadline
error. The observed request-to-terminal interval was **2.693 s**, including the
job/startup/observation path. The outer 100 s job timeout did not fire. No HAR or
successful capture receipt was published, the original browser process group
and private profile were gone, and the same key reused the original failed job
without a new Chrome launch.

This scope is fixed, owned HTTP-resource observation. It does not qualify
application script execution, page DOM inspection, general browser-session
replay, process-level network isolation, changed-session descendants, full HAR
equivalence, raw HTTP wire equivalence or application-behavior equivalence.
The original explicit false flags remain in the archived reports.

## Ghidra evidence and limits

The test used the existing pinned Ghidra 12.2 installation and JDK 25.0.5,
in operator mode with the explicit localhost SSH flag. It compiled owned
nonexecuted ELF fixtures, compared analyzed function entries with GNU nm and
incoming calls with GNU objdump, observed real native decompilation, verified
the selected function's returned C digest, recovered the original result after
controller restart, rejected changed/invalid/interior selectors, and cancelled
during a real Java plus native-decompiler execution.

The cancellation was observed through the original durable owner. The original
Java and native-decompiler process identities were recorded and then confirmed
gone. The cancelled result remained unsuccessful, and original-key reuse did
not launch a new engine process. **One private scratch directory was removed by
the unchanged test harness after cancellation.** This record therefore does
not claim that the runtime itself cleaned every cancelled scratch directory.

The eight checks qualify this bounded same-host operator path. They do not
qualify an isolated-host deployment, the full upstream Ghidra tool family, all
function-wide xref semantics, or the complete REA Evidence/session contract.
`isolated_host_qualification` and `rea_full_parity` remain false, and the provider
executed zero target programs. Each count in this record refers to its named
finite gate; the frozen 229-tool parity ledger remains open.

## Retention and reproduction

The exact command vectors, working directories, release/source bindings,
individual log hashes, original harness hashes and durations are preserved in
`browser-wrapper.json` and `ghidra-wrapper.json`. No source, test, script or
configuration was changed. Python used `-B` and
`PYTHONDONTWRITEBYTECODE=1`; all new working directories, process working
directories, outputs and logs were outside the root checkout.

Raw new evidence remains under
`/home/qian-qi/work/hepta-rea-final-independent-20261104-r2/browser-r1/` and
`/home/qian-qi/work/hepta-rea-final-independent-20261104-r2/ghidra-r1/`.
The wrapper is
`/tmp/rea-final-independent-20261104-r2/run_engine_regressions.py`,
SHA-256 `39ba0397665a0bbec695a89255812c9029fcfddb06476f9ee11d4413b77e1d8f`.
It validates the build binding and preserves the original gate commands and
budgets. It adds no retry, fixture skip, relaxed assertion or success substitute.

The earlier qualification archives and failures remain unchanged. In particular,
these external successes do not resolve or explain the separate Python21 r1
canary timeout; that matrix has its own retained results and rerun.

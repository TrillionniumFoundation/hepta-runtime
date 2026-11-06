# D1 C1 offline interpretation, revision 01

## Purpose and preserved outcome

This package interprets the original, already completed C1 diagnostic campaign. It does not replace or rerun that campaign. The original parent and adapter remain failed: the adapter required an `io.hepta.runtime/request-v8` marker that `process_status` and `process_read` do not expose. The actual first response frame confirms that the marker is absent. The new interpreter checks absence again in **every** correlated original response frame; it never fabricates a wire request ID.

The original native workload report completed all four rounds. The original unchanged native auditor was subsequently executed **for the first time** as job `1a1b09af362-fc05-71a6`, in the separate `c1-offline-interpretation-01/native-independent-summary.json` namespace. Its original output verifies 768 measured, 96 warmup, and 72 preflight/restart calls: 936 total, zero failures. That successful independent audit does not rewrite the failed parent or create the originally missing `c1-observation-01/independent-summary.json`.

The earlier `d1-c1-offline-interpretation-design-01` files remain a historical design snapshot from before the first wire frame was returned. This implementation adds the confirmed frame, actual failure archive, and separately completed auditor bindings. No old bytes are replaced.

## Inputs and execution boundary

`interpret_c1.py` reads the fixed original archive and its exact original first-member manifest. It reads selected members into memory through `tarfile.extractfile`; it never extracts a member to the filesystem. The whole archive SHA, side-manifest SHA, selected member SHA, original reports, original source files, and the auditor's four original receipts are all bound. It does not run the archive collector, native auditor, runtime, benchmark, Cargo, or any host API.

The only imported project code is the exact archived adapter and raw parser under non-main module names. The interpreter calls the original adapter's pure `closed_matrix` function and the original parser's `summarize` and `distribution` functions. It never calls the adapter's failed `select_trace`, its main entry point, its environment hook, or any original controller/benchmark constructor. The original source bytes are preserved by their archive member hashes.

The actual-input JSON must be sealed, match the supplied input SHA, and bind the interpreter's own SHA before it creates an output directory. The output directory must be new. The program saves the exact input bytes and writes derived controller records, original-parser summaries, and one final report using exclusive creation. An ambiguity, missing or extra request, parser failure, or any other exception produces a failed derived report with the partial records and unmatched candidates retained. It does not retry, reuse the output directory, or modify a source record.

The first draft has only been parsed as Python syntax and reviewed statically. No execution or interpretation result is asserted by this preparation README. The actual run, if authorized after review, has its own input and output receipts.

## Correlation rule

There are eight original controller contexts in the fixed order:

| Round | Mode | First controller | Restart controller |
|---|---|---:|---:|
| 0-A | OFF | 222 original calls | 12 original calls |
| 1-B | ON | 222 original calls | 12 original calls |
| 2-B | ON | 222 original calls | 12 original calls |
| 3-A | OFF | 222 original calls | 12 original calls |

For each context, the original environment binding, PID, process birth ticks, and original startup/close evidence are fixed. The trace header must have that PID/birth, expected mode, the declared feature ELF hash, the original six-host table, and a time window inside its original controller lifetime. All eight trace headers must agree on the boot ID. The original adapter had completed its before/after boot check before setting `trace_interpretation_started`; it did not persist the pre-run boot ID. This limitation is explicit. The interpreter never substitutes the current machine's boot ID for a missing historical receipt.

Each original call is tied to its actual contiguous raw response frame/index entry, original JSON-RPC ID, canonical request bytes/hash, and canonical response hash. The raw reader's `read_start_monotonic_ns` may precede an RPC because the reader was already waiting; it is **not** used as the request's lower bound.

An ON trace request may match an original call only when all of these are true:

1. Both belong to the same original controller generation.
2. The original host alias and operation equal the trace metadata.
3. The entire trace `request` interval is contained in the original RPC interval.
4. The RPC interval is contained in the original call interval, and a measured/warmup call remains inside its original cell interval.
5. The trace request has exactly one candidate call, and that call has exactly one candidate trace request.

All ON requests and calls must participate: 222/12 per controller, 468 across both ON rounds, including exactly 384 measured calls with complete six-host/operation balance. Internal native IDs must be unique across the four ON controllers; `(boot, PID, birth, trace slot)` is the unique slot identity, since raw slot numbers legitimately restart at zero in each process. No nearest-time, positional, response-content-only, job-ID-only, or partial-success match is accepted.

Each match records `wire_native_request_id: null`, `native_id_publicly_observed: false`, the real internal `trace_native_request_id`, the original frame identity, and both time intervals. The new relationship is explicitly named an offline correlation, not an original on-wire identity.

OFF traces must retain their original complete header/footer and contain no request or event rows. They supply no phase CPU observations. An empty OFF trace is not a claim of zero runtime CPU.

## CPU and wall interpretation

The unchanged parser first validates every complete original trace: counts, request scopes, same-thread synchronous CPU, nested CPU spans, non-overlap, end reasons, and complete owner/transport footer. The new interpreter then performs **new selective arithmetic** to produce measured-only phase tables. It uses the same immediate-child subtraction as the parser and calls the original `distribution` function. Before any filtering, it must exactly reproduce all original full-trace phase wall/inclusive/exclusive distributions, each request's exclusive CPU total, and the full trace exclusive total.

Only then are the original preflight, warmup, measured, and restart categories selected. The measured denominator is 192 per ON measured cell, 384 combined. Whole first-controller phase totals include 222 requests and are never divided by 192. Per-operation and per-host summaries use their own complete matched request counts. Missing phases are zero-filled in per-request distributions. A zero CPU value alone does not prove absence: wall-only phases have no synchronous CPU observation, and an actual synchronous span can also have a measured duration of zero. A phase's `cpu_event_count: 0` means that no synchronous CPU observation was available for that phase.

For each ON measured cell, recorded synchronous CPU is compared with the original synchronous `/proc/PID/stat` before/after counter window. PID, birth, clock tick rate, and window bracketing must match. The signed difference is preserved, including any negative value; it is not clipped or assigned to SSH, remote work, or the network. It can contain uninstrumented work, background activity, diagnostic bookkeeping, counter quantization, and the slightly wider counter-read window. No 100 ms sampled process-tree data is used to reconstruct controller CPU.

Phase wall durations can overlap, nest, or cover awaited work. Their sums are nonadditive, and none is labeled pure network or remote-helper CPU. The parser's per-request queue spans remain available in each matched record. Nested audit write/sync CPU is subtracted once from its synchronous parent.

The original OFF/ON performance figures and large round variation are retained as descriptive diagnostic overhead evidence. They are not an optimization benefit, statistical-significance result, runtime adoption, or substitute for the unchanged full observation and normal lifecycle/cancel gates.

## Preparation and single-run invocation

`input.unsealed.json` records the real archive/auditor inputs but cannot execute. After the source review is closed, create a new `input.sealed.json` with the final source SHA, `sealed: true`, and a fresh derived output directory. Save its exact SHA before starting.

```sh
python3 -B /tmp/hepta-runtime-recovery-20261106/d1-c1-offline-interpretation-01/interpret_c1.py \
  --input /tmp/hepta-runtime-recovery-20261106/d1-c1-offline-interpretation-01/input.sealed.json \
  --input-sha256 ACTUAL_SEALED_INPUT_SHA256
```

The interpreter prints only its derived report identity and interpretation status. It does not imply that the original parent passed. Preserve its process exit, stdout/stderr, all partial or complete outputs, and exact source/input identities. No automatic second invocation is part of this package.

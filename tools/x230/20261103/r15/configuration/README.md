# X230 glibc execution profile — R15 candidate

This opt-in launcher selects `MALLOC_ARENA_MAX=1` when the caller has not explicitly selected an arena policy. It reuses the qualified R14 runtime without Rust changes or a new build. It is a candidate for the formal R15 comparison; the diagnostics alone do not establish acceptance or a universal optimum.

## Launch and process behavior

```sh
/path/to/hepta-runtime-x230-glibc.sh /absolute/path/to/hepta-runtime mcp --runtime-config /absolute/path/to/runtime-config.json
```

The first argument is an existing absolute executable path. Every following argument is passed unchanged. The shell checks Linux and GNU libc, then replaces itself with the executable using `exec`; it keeps no supervisor, worker pool, or background task. The launcher writes no stdout banner, preserving MCP stdout. Usage, platform, and executable errors go to stderr. Binary verification belongs to the qualification/launch gate and is not repeated inside every wrapper invocation.

The tested system is X230 with glibc 2.39. The Linux/glibc check prevents accidental use on unsupported libc/platform families; it does not qualify every Linux/glibc machine.

## Inheritance and override policy

| Environment observed by the wrapper | Action |
| --- | --- |
| No `MALLOC_ARENA_MAX`; no exact `glibc.malloc.arena_max=` tunable | Export `MALLOC_ARENA_MAX=1` |
| Any present `MALLOC_ARENA_MAX`, including empty or invalid | Preserve it; do not inject a default |
| Exact colon-delimited `glibc.malloc.arena_max=` entry | Preserve tunables and do not inject a default |
| Both controls present | Preserve both; glibc decides the effective value |
| Other `GLIBC_TUNABLES` entries only | Preserve them and inject the default |
| A similarly named key such as `glibc.malloc.arena_maximum` | It is not an explicit arena_max override |

The wrapper does not normalize or repair caller values. Dynamic loaders can sanitize invalid tunables before a program observes its environment; this wrapper preserves the values it actually receives. The environment applies to this exec and to subprocesses that inherit it. It does not change a login profile, system service, remote host, or global configuration.

GNU libc documents `glibc.malloc.arena_max` as superseding `MALLOC_ARENA_MAX`. The accompanying `loader-precedence.json` records fresh `--list-tunables` observations on this actual host, including conflicts in both directions. Its values are evidence of this glibc build, not a promise about every allocator or operating system.

Primary references:

- [GNU libc 2.39 memory allocation tunables](https://sourceware.org/glibc/manual/2.39/html_node/Memory-Allocation-Tunables.html)
- [GNU libc 2.39 tunables and loader inspection](https://sourceware.org/glibc/manual/2.39/html_node/Tunables.html)

## Why arena1 is the next candidate

The unchanged R14 code limits physical cancellation preparation to two simultaneous operations while preserving eight publication continuations. That does not assign all allocations to two permanent threads: the Tokio blocking pool is shared, and the diagnostics observed 19–20 process threads at peak, dropping to 10 after idle, under every allocator setting.

Two completed diagnostics used the same qualified R14 binary, fresh owned local children, 4 MiB escaped synthetic receipts, workers=2, concurrency=8, two warmup waves, 24 load waves, and 12 seconds idle. The orders were default/2/2/default and 1/4/4/1. Every child handled 208 wrong-host cancellation refusals and 26 host_list calls, including warmup. No SSH dispatch or cancellation intent occurred.

| Setting | CPU seconds, mean of two processes | Whole-child HWM, KiB | RSS after 12-second idle, KiB |
| --- | ---: | ---: | ---: |
| Default | 6.225 | 102,028 | 102,028 |
| Arena1 | 6.315 | 30,788 | 17,244 |
| Arena2 | 6.375 | 39,014 | 17,476 |
| Arena4 | 6.340 | 52,988 | 36,424 |

Arena1 had the lowest observed HWM and idle RSS similar to arena2, with no clear additional CPU disadvantage. Its mean CPU was descriptively 1.45% above default; CPU differences across the two campaigns are not strong causal comparisons. Background archive upload and independent audit I/O may overlap, and no diagnostic throughput claim is made.

The CPU interval is ready through completion of warmup and load, divided by 234 only when reporting mixed RPC cost. It is not isolated cancellation CPU. HWM covers the whole child since exec; RSS is a point sample. The original smaps observations show allocator-reservation-shaped mappings, which are a heuristic rather than direct enumeration of malloc arenas. The raw smaps files remain available.

The independent summary verifies all 1,872 response hashes and expected results, 24 smaps file hashes, process CPU ticks, memory fields, counts, and completed shutdowns. See the R14 `diagnostic-summary.json` and its bound input reports. The R14 formal throughput regressions remain part of the decision; diagnostic memory improvements do not erase them.

## Formal evaluation is deliberately environment-bound

Formal R15 drivers execute the same qualified R14 binary directly. They do not use this inheritance-aware wrapper:

- Baseline children receive a clean allocator environment with all `MALLOC_*` and `GLIBC_TUNABLES` removed.
- Candidate children explicitly receive `MALLOC_ARENA_MAX=1`.
- Each long-lived controller and restart records the actual post-exec `/proc/PID/environ`, PID generation, binary hash, and configuration fingerprint.
- Formal same-binary comparison, final R11 comparison, native multi-host concurrency, and recovery are assessed separately.

The wrapper self-checks use short Python/loader children, not a Rust workload. They cover default injection, explicit values, empty values, exact tunable matching, conflicts, argument preservation, PID preservation, stdout silence, and error exits.

## Remaining risk and scope

A single arena can increase allocator lock contention in other allocation patterns. Native concurrency 8 and recovery still need formal validation. A clear measured contention regression would justify evaluating arena2; there is no reason to run an enlarged matrix merely because additional values exist.

This profile changes allocation policy, not scheduler concurrency or persistence semantics. The R14 source, its three qualified release artifacts, publication=8, preparation=2, receipt validation, durable audit append, acknowledgement ownership, phase-boundary pin hashing, and cancellation recovery remain unchanged. A dedicated preparation-worker pool is a separate design with shutdown, panic propagation, queue ownership, and handoff costs; it is not implemented here.

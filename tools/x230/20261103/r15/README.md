# X230 / glibc R15 execution profile

**Current qualification:** completed on the recorded X230/glibc 2.39 host. The frozen R14 runtime plus the opt-in arena1 profile passed 1,637 tests, with 0 failed and 33 ignored out of 1,670 selected; 1,647 actual allocator-environment observations were verified and none was unavailable. The two local comparisons, two native comparisons, six-host recovery, and independent qualification/performance/recovery audits all succeeded.

See [the complete R15 report](../../../../docs/X230_OPTIMIZATION_20261103_R15.md) for all measurements, regressions, evidence hashes, and limits. R15 adds no Rust changes and performs no new compilation; it reuses the qualified R14 source and artifacts.

## Launcher

The wrapper is [configuration/hepta-runtime-x230-glibc.sh](configuration/hepta-runtime-x230-glibc.sh).

~~~sh
tools/x230/20261103/r15/configuration/hepta-runtime-x230-glibc.sh \
  /absolute/path/to/hepta-runtime mcp \
  --runtime-config /absolute/path/to/runtime-config.json
~~~

When neither explicit MALLOC_ARENA_MAX nor an exact glibc.malloc.arena_max tunable is present, it defaults MALLOC_ARENA_MAX to 1. Caller controls, including empty values, are preserved; GNU libc resolves conflicting controls. The wrapper validates Linux/glibc and the absolute executable, writes no stdout banner, then execs the runtime without a supervisor.

The formal drivers deliberately bypass this inheritance-aware wrapper and set clean child environments. Their same-binary comparison binds binary SHA256, allocator environment, PID/start generation, and actual post-exec /proc observations. An explicit caller override therefore falls outside the tested arena1 profile.

## Evidence and historical state

configuration/README.md and configuration/configuration-ready.json are immutable preparation-time records and still describe a candidate. Their hashes are retained. This README and the final report provide the post-measurement qualification outcome without rewriting prior evidence.

The large-receipt HWM benefit has CPU, throughput, and tail-latency tradeoffs; the complete report retains every negative directional result. Native observation full transport envelopes were not retained and are not claimed to have been independently rehashed. Live successful cancellation overlap was C6; it is not a successful-cancel C8 throughput proof. No power-loss, reboot, WAN-partition, or universal exactly-once claim is made.

The current decision stops at a validated engineering tradeoff. Prep4 remains unmeasured, and neither an absolute nor a Pareto optimum is claimed.

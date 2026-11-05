# Rejected persistence streaming experiment — X230, 2026-11-03

## Decision

Do not adopt the two-pass count + 16 KiB BufWriter candidate in this optimization round. It reduces the transient serialization allocation, but increases pure CPU cost in all eight synthetic groups. Ordinary large strings cost about 64–95% more CPU; heavily escaped large strings cost about 194–205% more.

The current `save_record_with_registry_gate` holds the global `REGISTRY_ACCESS` write lock through serialization and durable publication. Extra serialization CPU increases that critical section. There is only one serialized Vec under this lock at a time per process, so memory savings must not be multiplied by the number of workers.

No active runtime source was changed by this experiment. No more measurements are scheduled for this candidate.

## Execution and retained setup failure

Successful durable job: `1a1a0fa780c-96a-6bf1`, host `x230`, stable idempotency key `x230-runtime-r11-persistence-probe-20261103-performance-review-v2`. Authoritative state: succeeded, exit 0, no timeout, complete untruncated output.

The job used nice 15, CPUQuota 50%, MemoryMax 536870912 bytes, and a 120-second overall timeout. The standalone rustc stage took 7.393 seconds and the probe took 1.883 seconds. End-to-end launcher time was 9.384 seconds.

Compiler: `rustc 1.95.0 (59807616e 2026-04-14)`. Dependency: cached serde_json 1.0.151. Probe optimization flags do not rebuild the cached dependency. The correct lockfile was `/home/qian/hepta-runtime-optimization-20261103-r10/source-r10e/Cargo.lock`.

The first job, `1a1a0f6cbe9-96a-6bca`, failed before compilation because the launcher read `/home/qian/hepta-runtime-optimization-20261103-r10/Cargo.lock` instead of `.../source-r10e/Cargo.lock`. Its original FileNotFoundError traceback and metadata are preserved in the evidence JSON. One correction was explicitly authorized. Read-only file checks confirmed the correct lockfile, unchanged source SHA256, and cached libraries before the corrected job started. The Rust source and measurement design did not change.

All remote files were isolated under `/home/qian/hepta-runtime-optimization-20261103-r11/persistence-probe`. No credentials are present in the archived source, commands, or results.

## Exact commands and reproduction inputs

The exact successful rustc argv, rendered as a command, was:

```sh
/home/qian/.cargo/bin/rustc --edition=2021 -C opt-level=2 -C debuginfo=0 -C codegen-units=1 --extern serde_json=/home/qian/hepta-runtime-optimization-20261103-r10/target/debug/deps/libserde_json-7c0b68a9d08b39d5.rlib -L dependency=/home/qian/hepta-runtime-optimization-20261103-r10/target/debug/deps /home/qian/hepta-runtime-optimization-20261103-r11/persistence-probe/probe.rs -o /home/qian/hepta-runtime-optimization-20261103-r11/persistence-probe/probe-v2
```

The executable invocation was:

```sh
/home/qian/hepta-runtime-optimization-20261103-r11/persistence-probe/probe-v2 /home/qian/hepta-runtime-optimization-20261103-r11/persistence-probe
```

`launch_persistence_probe_v2.py` contains the actual correction launcher, including the resource-independent subprocess timeouts (45 seconds compile, 65 seconds run), preflight checks, environment paths, and median extraction. Hepta process_start supplied that script to `/usr/bin/python3 -c`, passed `persistence_probe.rs` on stdin, used the isolated directory as cwd, and applied the external limits listed above. The launcher intentionally requires the existing, hash-verified source from the failed setup and refuses to overwrite completed results. Reproduction must use a fresh isolated output directory and an explicitly approved job; this archive does not request another run.

Source SHA256: `5a8b14e2d6086b0a47f5d349b9b804de225d21e52d5339504bc1dd56211d0d34`.
Original raw results SHA256: `ee3d5e16614cf99250d4eb5efb627176906eaeb545eaede019514a06919cc535`.

The complete original result arrays, exact metadata/argv, unrounded values, successful stdout, original setup traceback, and remote hashes are in [persistence-probe.json](../../../../tests/evidence/20261103-x230-r11/persistence-probe.json).

## Measurement scope

This is a fixed JobRecord-like `serde_json::Value` fixture with a sorted Value map, not the production JobRecord type. It contains identity, execution-parameter, status, UTF-8, and ordinary/escaped string fields. Encoded output sizes are exactly 1024, 65536, 786432, and 4194272 bytes (4 MiB minus 32); boundary verification also uses exactly 4 MiB and 4 MiB plus 1.

A is `to_vec_pretty → size check → write_all`. B is `to_writer_pretty(count) → size check → to_writer_pretty(BufWriter) → explicit flush → into_parts`. The second path retains the same pretty serializer and bounds buffer capacity at min(encoded size, 16 KiB). The counting pass precedes all temporary-file creation so oversized records still have no filesystem effects.

Pure serialization uses a common non-copying ProbeSink whose write has noinline and black_box. Each case runs two ABBA cycles. Calls per block are 128, 24, 4, and 1 as size increases. CPU uses Linux CLOCK_PROCESS_CPUTIME_ID; wall uses Instant. They are reported separately.

A global allocator wrapper delegates to System. Its counters are enabled only for a separate one-call allocation sample after fixture construction; timing disables the counters but still includes the wrapper switch-read overhead. Peak means logical live **requested** bytes: it excludes the fixture, report, allocator metadata, and transient old/new overlap internal to realloc. It is not RSS. Every allocation sample ended with zero tracked live bytes.

R11 compilation was running in the background and CPUQuota was 50%. Wall includes contention and throttling. This short probe is not production TPS, a release-build performance claim, or full runtime recovery qualification.

## Median CPU, wall, and transient allocation

Each CPU/wall median below covers four blocks for each mode within the same size/shape. Arrows are A → B.

| Encoded bytes | Payload | CPU µs/call | CPU increase | Wall µs/call | Peak requested bytes |
|---:|---|---:|---:|---:|---:|
| 1024 | plain | 3.188 → 4.417 | +38.6% | 15.531 → 4.396 | 1660 → 1024 |
| 1024 | escaped | 3.373 → 6.012 | +78.2% | 3.353 → 5.991 | 1024 → 1024 |
| 65536 | plain | 85.432 → 166.193 | +94.5% | 189.545 → 292.113 | 129854 → 16384 |
| 65536 | escaped | 147.952 → 435.505 | +194.4% | 267.264 → 573.974 | 65536 → 16384 |
| 786432 | plain | 1232.833 → 2022.313 | +64.0% | 1952.054 → 2772.442 | 1571646 → 16384 |
| 786432 | escaped | 1713.568 → 5228.835 | +205.1% | 5813.509 → 6349.965 | 1048576 → 16384 |
| 4194272 | plain | 5509.750 → 10616.587 | +92.7% | 5677.738 → 13580.689 | 8387326 → 16384 |
| 4194272 | escaped | 9150.478 → 27580.648 | +201.4% | 11253.971 → 66469.801 | 4194304 → 16384 |

Vec capacity growth makes the largest plain-string sample use approximately 8 MiB of logical transient allocation; B uses 16 KiB. The escaped sample goes from 4 MiB to 16 KiB. The near-4 MiB CPU costs are 5.510 → 10.617 ms for plain text and 9.150 → 27.581 ms for escaped text.

The anomalous 1 KiB plain A wall median is background/quota-sensitive. It must not be used to claim a wall speedup for B when its measured CPU is higher.

## Correctness and assertion accounting

All **22 dedicated contract scenarios** passed:

- 10 byte-for-byte comparisons: five sizes × plain/escaped, including exactly 4 MiB.
- 4 oversized-record checks: A/B × plain/escaped at 4 MiB + 1; both formal and temporary files remain absent.
- 8 fault-injection cases for the new buffered helper: 1 KiB/64 KiB × write failure, partial write then ENOSPC, WriteZero, and underlying flush failure. The io::Error type/raw error code is preserved; after the first failure there are zero additional write/flush calls, including Drop.

There were also **8 byte-for-byte comparisons after actual durable saves**, one per durable sample. These are separate from the 22 dedicated scenarios.

For precise accounting, the completed source loops execute **2790 explicit Rust assert!/assert_eq! checks**. This is a source-derived count, not an added assertion-counter instrument. It excludes expect/unwrap checks and all dependency-internal assertions.

| Explicit assertion category | Executions |
|---|---:|
| fixture_bounds_and_exact_encoded_length | 52 |
| byte_equality_in_dedicated_verification | 10 |
| oversize_error_and_no_files | 8 |
| fault_error_kind_failure_and_no_drop_retry | 24 |
| pure_warmup_bytes | 16 |
| allocation_sample_final_live_zero | 16 |
| timed_serialization_bytes | 2512 |
| clock_gettime_success | 144 |
| durable_file_byte_equality | 8 |
| Total | 2790 |

The fault checks exercise serialization/write/flush errors; they do not simulate a power loss, fsync failure, or every rename/recovery race. The candidate retains create_new, 0600, file.sync_all, rename, and directory.sync_all order in its proposed implementation. The entire production runtime was not rebuilt with this candidate.

## All pure ABBA blocks

The following tables preserve every observed block in execution order. CPU/wall values here are rounded to 0.001 µs; the evidence JSON stores full precision. Mode A is Vec, mode B is count + stream.

### 1024 bytes, plain

| Cycle | Position | Mode | Calls | CPU µs/call | Wall µs/call |
|---:|---:|:---:|---:|---:|---:|
| 1 | 1 | A | 128 | 3.252 | 12.159 |
| 1 | 2 | B | 128 | 4.502 | 4.478 |
| 1 | 3 | B | 128 | 4.235 | 4.213 |
| 1 | 4 | A | 128 | 3.286 | 18.903 |
| 2 | 1 | A | 128 | 2.805 | 2.785 |
| 2 | 2 | B | 128 | 4.393 | 4.372 |
| 2 | 3 | B | 128 | 4.442 | 4.420 |
| 2 | 4 | A | 128 | 3.124 | 21.171 |

### 1024 bytes, escaped

| Cycle | Position | Mode | Calls | CPU µs/call | Wall µs/call |
|---:|---:|:---:|---:|---:|---:|
| 1 | 1 | A | 128 | 3.118 | 3.097 |
| 1 | 2 | B | 128 | 5.934 | 5.907 |
| 1 | 3 | B | 128 | 6.038 | 6.013 |
| 1 | 4 | A | 128 | 3.370 | 3.350 |
| 2 | 1 | A | 128 | 3.375 | 3.357 |
| 2 | 2 | B | 128 | 6.104 | 23.617 |
| 2 | 3 | B | 128 | 5.985 | 5.968 |
| 2 | 4 | A | 128 | 3.450 | 3.434 |

### 65536 bytes, plain

| Cycle | Position | Mode | Calls | CPU µs/call | Wall µs/call |
|---:|---:|:---:|---:|---:|---:|
| 1 | 1 | A | 24 | 83.946 | 208.734 |
| 1 | 2 | B | 24 | 166.284 | 284.663 |
| 1 | 3 | B | 24 | 166.101 | 299.562 |
| 1 | 4 | A | 24 | 90.006 | 211.818 |
| 2 | 1 | A | 24 | 85.474 | 85.310 |
| 2 | 2 | B | 24 | 175.629 | 593.266 |
| 2 | 3 | B | 24 | 163.368 | 187.841 |
| 2 | 4 | A | 24 | 85.389 | 170.357 |

### 65536 bytes, escaped

| Cycle | Position | Mode | Calls | CPU µs/call | Wall µs/call |
|---:|---:|:---:|---:|---:|---:|
| 1 | 1 | A | 24 | 152.732 | 277.054 |
| 1 | 2 | B | 24 | 428.011 | 554.702 |
| 1 | 3 | B | 24 | 428.896 | 679.908 |
| 1 | 4 | A | 24 | 150.208 | 150.077 |
| 2 | 1 | A | 24 | 137.310 | 261.801 |
| 2 | 2 | B | 24 | 448.784 | 579.904 |
| 2 | 3 | B | 24 | 442.114 | 568.044 |
| 2 | 4 | A | 24 | 145.696 | 272.727 |

### 786432 bytes, plain

| Cycle | Position | Mode | Calls | CPU µs/call | Wall µs/call |
|---:|---:|:---:|---:|---:|---:|
| 1 | 1 | A | 4 | 1205.650 | 1788.796 |
| 1 | 2 | B | 4 | 2007.241 | 2753.576 |
| 1 | 3 | B | 4 | 2000.589 | 2750.640 |
| 1 | 4 | A | 4 | 1205.428 | 1860.139 |
| 2 | 1 | A | 4 | 1260.016 | 8519.815 |
| 2 | 2 | B | 4 | 2037.386 | 2791.308 |
| 2 | 3 | B | 4 | 2143.100 | 2902.947 |
| 2 | 4 | A | 4 | 1294.880 | 2043.968 |

### 786432 bytes, escaped

| Cycle | Position | Mode | Calls | CPU µs/call | Wall µs/call |
|---:|---:|:---:|---:|---:|---:|
| 1 | 1 | A | 4 | 1687.361 | 2617.168 |
| 1 | 2 | B | 4 | 5310.920 | 15369.044 |
| 1 | 3 | B | 4 | 5154.655 | 7422.876 |
| 1 | 4 | A | 4 | 1739.775 | 2493.317 |
| 2 | 1 | A | 4 | 1762.698 | 9009.850 |
| 2 | 2 | B | 4 | 5186.515 | 5190.790 |
| 2 | 3 | B | 4 | 5271.154 | 5277.055 |
| 2 | 4 | A | 4 | 1476.932 | 13981.286 |

### 4194272 bytes, plain

| Cycle | Position | Mode | Calls | CPU µs/call | Wall µs/call |
|---:|---:|:---:|---:|---:|---:|
| 1 | 1 | A | 1 | 5557.018 | 5550.423 |
| 1 | 2 | B | 1 | 10919.608 | 63940.340 |
| 1 | 3 | B | 1 | 10954.929 | 16805.679 |
| 1 | 4 | A | 1 | 4898.724 | 4894.885 |
| 2 | 1 | A | 1 | 5809.891 | 5805.053 |
| 2 | 2 | B | 1 | 10259.809 | 10300.633 |
| 2 | 3 | B | 1 | 10313.565 | 10355.698 |
| 2 | 4 | A | 1 | 5462.482 | 8451.401 |

### 4194272 bytes, escaped

| Cycle | Position | Mode | Calls | CPU µs/call | Wall µs/call |
|---:|---:|:---:|---:|---:|---:|
| 1 | 1 | A | 1 | 9087.159 | 9154.875 |
| 1 | 2 | B | 1 | 28503.544 | 80258.807 |
| 1 | 3 | B | 1 | 28396.985 | 65503.597 |
| 1 | 4 | A | 1 | 9213.797 | 13336.013 |
| 2 | 1 | A | 1 | 9570.888 | 14641.958 |
| 2 | 2 | B | 1 | 26455.240 | 67436.005 |
| 2 | 3 | B | 1 | 26764.311 | 31721.349 |
| 2 | 4 | A | 1 | 9071.329 | 9171.929 |

## Durable full-path diagnostic samples

Only one ABBA cycle per size was run, giving two observations per mode. Each save includes temporary-file creation, serialization/write/flush, file.sync_all, rename, and directory.sync_all. After timing, bytes were read and compared with a precomputed Vec output. These are diagnostic samples with background-load sensitivity, not a statistically qualified filesystem throughput benchmark.

| Encoded bytes | Position | Mode | CPU ms | Wall ms |
|---:|---:|:---:|---:|---:|
| 1024 | 1 | A | 0.250 | 3.817 |
| 1024 | 2 | B | 0.335 | 6.324 |
| 1024 | 3 | B | 0.253 | 0.805 |
| 1024 | 4 | A | 0.214 | 0.742 |
| 4194272 | 1 | A | 14.467 | 25.367 |
| 4194272 | 2 | B | 17.464 | 32.930 |
| 4194272 | 3 | B | 17.401 | 49.185 |
| 4194272 | 4 | A | 12.718 | 27.462 |

Median wall was 2.280 → 3.564 ms for 1 KiB and 26.414 → 41.057 ms for near-4 MiB. This small sample did not show a full-path gain; the CPU and lock-duration tradeoff is sufficient to reject the candidate for this round without expanding the test.

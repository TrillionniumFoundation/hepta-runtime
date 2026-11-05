# R27 serializer component: independent review

**Disposition: component improvement established; do not promote to full qualification or campaign on this evidence; stop serializer capacity followups.** End-to-end gates were not run and are not classified as failed.

This review recomputed all existing samples and readbacks locally. It did not compile Rust, execute a workload, access a remote machine, or edit source.

## Complete evidence and fixed execution

- Native job `1a1ab92f54d-fc05-4ebe` completed with exit 0, complete durable output, no cancellation, timeout or automatic retry. The planned request, original launch, terminal job identity and final report seal match.
- All 12 attempt-02 readbacks match their UTF-8 bytes, size, SHA-256, saved local file and receipt. The two retained attempt-01 readbacks also match.
- All five stages completed: compiler version, plain System timing build, separate counting-allocator build, timing, allocation. Build flags include opt-level=3 and panic=abort; only anyhow, serde, serde_json and libc are direct external libraries. R26 supplies third-party dependencies, with no Hepta library linked.
- Both builds completed the sorted serde_json Map assertion and exact command/stdin/timeout/system tuple checks for all six fixtures, including the exact 65,536-byte combined boundary. Eleven extracted source items match the accepted R24 and candidate source bytes and hashes.
- All 48 timing rows follow six cases × two rounds × ABBA. The first five cases use 100,000 calls/sample, the boundary case 2,000: 2,008,000 calls per arm, 4,016,000 total. The 12 allocation rows each use 1,000 calls. Warmup is 10,064 calls per build and is excluded from measurements.
- Every raw per-call division, six aggregate CPU/wall summaries, and twelve allocation rows recompute correctly; all report summary arrays match original stdout. Both ABBA rounds improve CPU in each of the six cases.

## CPU and wall recomputation

All values below are ns/call. No case or sample is omitted.

| Case | CPU baseline | CPU candidate | CPU saved | Wall baseline | Wall candidate |
|---|---:|---:|---:|---:|---:|
| python_status | 859.366100000 | 403.238047500 | 456.128052500 | 859.418980000 | 403.263897500 |
| python_read | 1242.566252500 | 461.634785000 | 780.931467500 | 1242.661227500 | 461.647062500 |
| system_status | 294.194112500 | 114.196802500 | 179.997310000 | 294.206555000 | 114.227515000 |
| system_read | 654.316867500 | 207.640550000 | 446.676317500 | 654.687915000 | 207.741262500 |
| python_read_escaped_unicode | 1256.225562500 | 560.300910000 | 695.924652500 | 1256.639912500 | 560.588180000 |
| python_read_64k_boundary | 66907.685000000 | 47905.418250000 | 19002.266750000 | 67504.684125000 | 47936.882250000 |

## Allocation recomputation

| Case | alloc calls A → B | realloc calls A → B | requested bytes A → B |
|---|---:|---:|---:|
| python_status | 12 → 2 | 1 → 1 | 1247 → 426 |
| python_read | 14 → 2 | 1 → 1 | 1266 → 426 |
| system_status | 7 → 2 | 0 → 0 | 833 → 175 |
| system_read | 10 → 2 | 0 → 0 | 862 → 175 |
| python_read_escaped_unicode | 14 → 2 | 2 → 2 | 1748 → 938 |
| python_read_64k_boundary | 14 → 2 | 2 → 2 | 262126 → 196046 |

These are per-call allocator request counts/bytes, not RSS or live-memory reduction. All zeroed allocation counts are zero; deallocation counts equal allocation counts. Across the 6,000 measured calls per arm, allocation calls are 71,000 → 12,000, reallocations 6,000 → 6,000, and requested bytes 268,082,000 → 198,186,000. These mixed-case totals are audit checks, not workload averages.

## Absolute relevance to the ordinary Python workload

Only the ordinary Python status/read fixtures enter the equal mix. System, escaping/Unicode and 64 KiB edge fixtures remain separate.

- CPU: **1,050.96617625 → 432.43641625 ns/call**, saving **618.52976 ns = 0.61852976 µs/call**, a 58.853441% reduction in this component.
- Allocation calls: **13 → 2 per call** on average; reallocations remain **1 → 1**. Cumulative requested bytes: **1,256.5 → 426**, saving 830.5 requested bytes per call.
- Historical accepted R24 C8 controller CPU: **19.322916666666668 ms/call**. The component saving is **0.003201016548%** of that historical cost.
- The historical 3% CPU scale is **579.6875 µs/call**. The measured component saving is **0.106700552% of that scale**, approximately **937 times smaller**. The actual future adoption gate would still use its paired baseline; this historical comparison does not redefine any gate.

Formula: `(618.52976 / 1,000,000) / 19.322916666666668 × 100 = 0.003201016548%`. Even eliminating the entire remaining measured ordinary component cost would only correspond to about 0.002238% of this historical controller cost. This is an opportunity-size comparison, not a measured or universal end-to-end upper bound.

The source-extracted component has a real improvement. Its ordinary-request absolute cost does not support spending a full qualification/campaign on this change or further Vec-capacity tuning. There is no measured R27 RPC throughput, controller CPU, RSS or lifecycle result, and no failed end-to-end gate should be invented.

## Prior attempt and limitations

Attempt 01 remains failed: job `1a1ab85c2c3-fc05-4e78`, exit 1, `stages: []`. It stopped on a missing prior cache fingerprint before invoking a compiler or recording any samples. Attempt 02 used the same benchmark source and a corrected R26 third-party cache. It is not a rerun of a performance result.

The fixed command stub omits actual command construction and all transport, scheduling, validation and lifecycle costs. Six successful fixture equivalence checks do not replace complete runtime/sibling tests. Three quiet process snapshots do not prove continuous exclusivity. Local readbacks permit independent hashing of the twelve fetched artifacts, source and launcher; the rlib and executable bytes were not fetched and their hashes remain native-launcher evidence. All frozen adoption thresholds remain unchanged.

## Evidence

- [Raw timing](sandbox:/workspace/scratch/b96be991ab90/serializer-component/attempt-02/timing.stdout)
- [Raw allocations](sandbox:/workspace/scratch/b96be991ab90/serializer-component/attempt-02/allocation.stdout)
- [Original report](sandbox:/workspace/scratch/b96be991ab90/serializer-component/attempt-02/report.json)
- [Original native start](sandbox:/workspace/scratch/b96be991ab90/serializer-component/attempt02-original-native-start.json)
- [Original native terminal](sandbox:/workspace/scratch/b96be991ab90/serializer-component/attempt02-original-native-terminal.json)
- [Historical R24 summary](sandbox:/workspace/scratch/806ba5f52f94/r24-results/summary.json)
- [Complete arithmetic and receipt review](sandbox:/workspace/scratch/b96be991ab90/serializer-component/review/independent-review-01.json)

Primary SHA-256 values:

```text
report.json        75c5cef16803e0a3135cdb44ceb93f7ed4958e1e8ecde8179fb1caaec03901fa
timing.stdout      0d19da01fcfd480b4ea901b504954c13fa8e2b1ce7a5aaa2977166d64a11ec9a
allocation.stdout  23a00f8ce535f2b07f98ef790e846f43fbdef62becc52c3c4abc9ac7f3061b3d
bench.rs           eb088497f092b82c21d70dd8a17ef191e5430164f6e9967b9816d95514504e35
```

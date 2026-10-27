# A55: complete diagnostic trace and scan phases

**The diagnostic completed, but the product result failed: 14 of 20 measured calls succeeded.** All six failures, the failed index kickoff and the original three-second request deadline are retained. No performance adoption is established.

The [whole-original audit](metadata-diagnostic.independent-audit.json) reconciles the complete report, stderr and metadata trace: 3,483 events, 22 local calls, 11 cohorts, no dropped events and no sequence gaps. The 216 aggregate events describe 12 serial scans: nine complete scans (one warmup and eight measured) and three partial scans. The [arithmetic summary](metadata-diagnostic.phase-summary.json) independently matches every phase and counter back to the original trace.

## All six failed calls

Each affected C4 wave split into two independently frozen two-member cohorts. The later pair entered after the earlier freeze and waited behind the earlier complete scan. Its fresh scan then reached the original deadline; no result from the earlier scan was reused.

| Wave | Failed slots / RPC IDs | Later leader | Store wait (us) | Budget at scan start (us) | Partial scan (us) | Verified / attempted members |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 5 | 9,10 / 14,15 | 13 | 2,180,080 | 818,025 | 818,044 | 23,387 / 23,388 |
| 6 | 13,14 / 18,19 | 17 | 2,209,834 | 788,443 | 788,465 | 22,827 / 22,828 |
| 7 | 17,18 / 22,23 | 22 | 2,194,128 | 803,963 | 803,983 | 21,546 / 21,547 |

The preceding complete scans took 2,178,517, 2,207,048 and 2,193,417 us. Later API entry followed their earlier cohort freeze by 141, 124 and 119 us. The three partial scan end observations were 19, 22 and 20 us beyond their original deadlines. Failed-call permit waits were 0–1 us; the late leaders waited 19, 22 and 22 us in the blocking queue. These events identify the store wait and subsequent deadline boundary; they do not identify the cause of the late API arrivals.

## Eight complete measured scans

This table excludes warmup call 2 and the three partial scans. Each of calls 3, 4, 5, 6, 7, 11, 15, 19 independently verified all 65,536 archive members. Their outer verification times range from 2,152,423 to 2,275,827 us; median 2,189,476 us and mean 2197.700125 ms. The eight phase sums total 17,581,290 us, with 311 us between the aggregate phase clocks and enclosing spans.

Percentages divide by the sum of the fifteen phase clocks. These are wall-time categories including their named bookkeeping and any scheduling delay; they are not CPU measurements or isolated syscall costs.

| Category | Mean per complete measured scan (ms) | Share of phase time |
| --- | ---: | ---: |
| Namespace before and after | 680.616875 | 30.970054% |
| ROW lookup and ORDER join | 501.773625 | 22.832164% |
| Named stamps and descriptor checks | 465.461625 | 21.179862% |
| Open original | 157.606500 | 7.171556% |
| Read original body | 143.142875 | 6.513419% |
| Parse and domain checks | 87.526875 | 3.982728% |
| Compare and close | 89.257750 | 4.061488% |
| Walk and layout fences | 55.987375 | 2.547589% |
| Filename construction | 13.511875 | 0.614830% |
| Pending selection | 2.775875 | 0.126310% |

### All fifteen phase categories

| Phase | Mean per complete measured scan (ms) | Share of phase time |
| --- | ---: | ---: |
| `content_namespace_before_us` | 368.209125 | 16.754590% |
| `content_namespace_after_us` | 312.407750 | 14.215464% |
| `content_row_lookup_us` | 308.036625 | 14.016565% |
| `content_order_check_us` | 193.737000 | 8.815599% |
| `content_open_us` | 157.606500 | 7.171556% |
| `content_body_read_us` | 143.142875 | 6.513419% |
| `content_stamp_after_us` | 119.582250 | 5.441341% |
| `content_descriptor_after_us` | 119.297125 | 5.428367% |
| `content_stamp_before_us` | 113.356625 | 5.158057% |
| `content_descriptor_before_us` | 113.225625 | 5.152096% |
| `content_compare_and_close_us` | 89.257750 | 4.061488% |
| `content_parse_and_domain_us` | 87.526875 | 3.982728% |
| `content_walk_and_fences_us` | 55.987375 | 2.547589% |
| `content_filename_us` | 13.511875 | 0.614830% |
| `content_pending_selection_us` | 2.775875 | 0.126310% |

The filename category is small in the resulting A55 code. This is not a measurement of the total cost of CString handling, and it does not measure the improvement from A54: work inside namespace validation is separately timed, and the diagnostic has no matched uninstrumented baseline. All namespace observations, original reads, ROW/ORDER joins and final fences remain required.

## Implication for the next candidate

The measured full scan already consumes about 2.2 seconds. A later independent cohort that first waits about 2.2 seconds cannot finish another full scan within its original three-second budget. Bounded shared page readers therefore address the observed serialization directly: each reader still performs its own full original verification, keeps an immutable database/snapshot token, rejects active publication or recovery work, and verifies the terminal state and namespace before release.

This is a reason to test the A56 design, not a guarantee of deadline closure. Simultaneous scans can contend for CPU, filesystem and database resources. The complete original small/large comparisons, resource limits, native custody/recovery runs, six-host suite and exact-head CI remain separate acceptance requirements. The uninstrumented warmup and C1 behavior must also pass unchanged.

## Evidence boundaries

- This is one trace-enabled A55 diagnostic, not an uninstrumented ABBA throughput/resource comparison.
- The primary phase aggregate excludes warmup call2 and all three partial scans; the separate nine-complete summary includes warmup explicitly.
- Phase percentages divide by the sum of fifteen phase clocks. Outer-span totals and their small residual are separately retained. Durations are wall time including scheduling and each category bookkeeping, not CPU time or isolated syscall/allocation cost.
- The filename category is not total CString cost and does not measure savings relative to A54. No causal speedup or regression is inferred from comparing the two instrumented success counts.
- Only the fixed closed diagnostic waves and unique query shapes establish call/RPC correspondence; there is no general RPC identifier mapping.
- The three originals retain fixture witnesses, not every fixture or RPC-wire body. This trace audit does not replace a complete original-body performance evidence audit.
- All six measured failures and the failed index kickoff remain failures. Warmup succeeded only in this diagnostic and does not replace the earlier failed A54 uninstrumented warmup.
- The trace does not show why later API entries arrived after cohort freeze. No executor/ingress cause is invented.
- A56 bounded shared readers directly targets the observed wait, but two simultaneous complete scans may still contend for CPU, storage or database resources. All original workload,deadline,resource,custody and six-host gates remain required.

Inputs and exact SHA256 bindings are recorded in the linked JSON summary and complete independent audit. No remote call, Rust command or business retry was performed by this local arithmetic summary.

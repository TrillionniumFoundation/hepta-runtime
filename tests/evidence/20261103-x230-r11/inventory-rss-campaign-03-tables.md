# Inventory RSS campaign 03: independent recomputation

All 16 retained measurement samples reproduce the runner statistics; 128 successful calls, four cases, ABBA order. All 20 GNU time receipts (including four enumeration children) pass text/hash/exit checks. The qualified 213 compiler inputs equal the after map and local source. No benchmark was launched by this analyzer.

A is R10e with the identical benchmark module; B is the qualified R11 candidate. RSS is the median of two direct-child lifetime peaks per arm, in KiB. CPU and calls/s use the existing Rust timed interval. Percent changes are B/A − 1.

| Payload / C4 | Mode | RSS A → B KiB | Δ RSS | CPU A → B ms/call | Δ CPU | Calls/s A → B | Δ calls/s |
|---|---|---:|---:|---:|---:|---:|---:|
| plain 768 KiB | list | 25022 → 20664 | -17.42% | 92.656 → 78.618 | -15.15% | 28.904 → 32.716 | +13.19% |
| plain 768 KiB | page | 23992 → 21470 | -10.51% | 93.951 → 76.266 | -18.82% | 28.516 → 34.000 | +19.23% |
| escaped 64 KiB | list | 15824 → 16150 | +2.06% | 155.451 → 145.876 | -6.16% | 18.011 → 16.854 | -6.43% |
| escaped 64 KiB | page | 16414 → 16724 | +1.89% | 158.044 → 145.494 | -7.94% | 14.229 → 19.482 | +36.92% |

| Payload / C4 | Mode | Direct peaks A KiB | Direct peaks B KiB | p50 A → B ms | p95 A → B ms |
|---|---|---|---|---:|---:|
| plain 768 KiB | list | [24916, 25128] | [20472, 20856] | 102.628 → 103.206 | 193.499 → 168.152 |
| plain 768 KiB | page | [23212, 24772] | [21192, 21748] | 102.332 → 88.338 | 193.632 → 158.707 |
| escaped 64 KiB | list | [15696, 15952] | [15828, 16472] | 182.516 → 201.465 | 318.922 → 298.233 |
| escaped 64 KiB | page | [16368, 16460] | [16596, 16852] | 232.862 → 153.539 | 462.932 → 297.863 |

## Limits and regressions

Plain 768 KiB RSS falls 17.42% for list and 10.51% for page. Escaped 64 KiB RSS rises 2.06% and 1.89%. Escaped list calls/s falls 6.43% and its p50 rises 10.38%; plain list p50 rises 0.56%. These results do not support universal improvement. With sixteen latencies per arm, nearest-rank p95 equals the maximum.

RSS includes fixture verification, warmup, measurement and teardown. Twelve final GNU time peaks exceed the earlier Rust snapshot by 128–384 KiB. Wrapper wait4 floors remain 25,572 KiB (plain) and 20,916 KiB (escaped); those values are retained for audit and excluded from native RSS aggregation.

The before/after snapshots retain cargo PID 1950444 and no rustc entry; this was not a background-free host. Thermal readings changed from 68/69 °C to 74/71 °C. Endpoint observations are not continuous monitoring. The small ABBA sample is descriptive and does not establish statistical significance or a production TPS result.

The earlier campaign 02 CPU/rate/latency results are unchanged. Its wrapper RSS comparison cannot establish direct-child memory behavior because of the demonstrated inherited RSS floor. This four-case follow-up changes neither the qualified Rust source nor the CPU/wall timing boundaries.

## Reproduce from retained evidence

From the repository root: `python3 -B tools/x230/20261103/analyze_inventory_rss_campaign_03.py`.

Inputs: [plain](inventory-rss-plain.json.gz), [escaped](inventory-rss-escaped.json.gz), [campaign](inventory-rss-campaign-03.json.gz), [qualification](r11-qualification.json.gz). Complete values, usage hashes, raw hashes and environment: [summary](inventory-rss-campaign-03-summary.json). RSS floor evidence: [probe](rss-floor-probe.json.gz).

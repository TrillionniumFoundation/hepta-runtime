# A55 — checked component reuse and complete-scan phase measurements

**Qualification passed on X230. A55 is an intermediate source and diagnostic
checkpoint. Performance adoption and the complete integration acceptance gates
are not established by this checkpoint.**

The actual qualification, complete source export and full diagnostic evidence
are retained here. The diagnostic completed with **14 successful and 6 failed
measured calls**; performance adoption remains false. The [design proposal](DESIGN.md)
records the prequalification motivation and preserved observations. Its pending
status is historical; the qualification and diagnostic results below are actual.

A55 extends published A54 commit
`34b961941a211025f2083b9fd24470de32cb5b2f` / tree
`797878008d5ae6d8035766e53a3f6619b76a38c1`. Eight existing compiler files change;
167 inherit their qualified A54 identities, for 175 compiler inputs in total.
No additional compiler path, dependency, service configuration or authentication
source is introduced.

## What this checkpoint changes

Each complete original-record read creates one checked filename `CString` and
borrows that same component for the two namespace fences, two independent named
stamps and the original descriptor-relative open. The component entry point
derives its canonical identifier from those same bytes. It cannot receive a
separate, mismatched filename and shard identity.

The complete read still observes the original namespace, named inode,
descriptor policy and stamp, body through EOF, JSON and identifier domain,
fresh descriptor state, fresh named stamp, final namespace and absolute
deadline in their original order. Legacy and sharded namespaces, duplicate
refusal, the exact held descriptor, final directory binding, no-follow flags,
permissions and ownership retain their original behavior. Static full-filename
construction counts decrease from seven to one with a shard layout and from
five to one without a layout. The corresponding sixteen and ten stat/metadata
observations are retained. These are source call counts, not measured throughput
or CPU improvements.

A55 also adds default-disabled aggregate timing inside the serial archive scan.
An active metadata trace context chooses the instrumented kernel once per scan;
ordinary reads and the original parallel kernel use a statically dispatched,
zero-sized observer. The source path creates no phase timer, counter array or
per-record event in that ordinary observer. This source-level property is not
an assembly-level or measured zero-overhead claim.

The instrumented scan accumulates fifteen phase durations as nanoseconds and
converts the final sums to microseconds. It attempts eighteen bounded,
nonblocking events: fifteen durations, records attempted, records verified and
whether the scan itself completed. The timer sum excludes preceding transaction,
table and count/pending setup, the final event sends, and later table/transaction
drops. A complete scan can still be followed by failed projection, snapshot or
caller-deadline checks. Diagnostic wall time includes instrumentation and
scheduling costs; it is not pure syscall CPU time.

## Actual six-stage qualification

The original job was `1a179bb1f79-96a-13ac`. The qualification report covers
**2026-10-26 19:41:10–20:01:49 UTC** and ends qualified with all six stage return
codes zero. Original operator status records success, exit code 0, complete
untruncated output, zero stderr and no cancellation or timeout. The original
reports were captured byte for byte against separately obtained size, SHA256
and version receipts.

The run used Rust 1.95.0, the original offline/locked Cargo commands, two Cargo
jobs, two test threads and two Tokio workers. Incremental compilation and
metadata tracing were disabled, and the original stage budgets and 022 umask
were retained. No Rust compilation, formatting, Clippy or test was run on the
local review machine.

| Original stage | Exit code | Original stage wall time |
| --- | ---: | ---: |
| format | 0 | 2.450 s |
| fmt-check | 0 | 2.021 s |
| clean-package | 0 | 0.379 s |
| clippy | 0 | 128.640 s |
| test | 0 | 795.491 s |
| release | 0 | 306.670 s |

The original unfiltered suite summaries contain **1,337 passed tests and 23
existing ignored tests**: 18 + 1,311 + 8. Two filtered nested subprocess results
are retained and excluded from that total. Stage wall time includes compilation
and setup, so it is different from the inner test harness's reported duration.

The five added tests cover changed named inodes and private-inode policy,
component opens and flags, all physical namespace choices, nanosecond aggregation
and saturation, and successful/failed/expired instrumented scan accounting.
Six existing record-fence tests were expanded for the component interface.
The [complete original test log](qualification-test.original.log.gz),
[new-test coverage](new-test-coverage.json) and
[expanded-test coverage](expanded-test-coverage.json) establish each of these
eleven exact test names once. The source export independently retained all
previous test declarations and excluded the two filtered nested summaries.

| Original object | SHA256 |
| --- | --- |
| [Qualification](qualification-r01.original.json) | `67abac1fa0c3a0b496b0101a551ce828e697d43fd94b9de82ecc5875d9f16688` |
| [Guarded entry](entry-r01.original.json) | `50c8272612c8f923b496279aff37da51f75eb4b50de789f283840064d425dd3b` |
| [Original worker](worker-r01.original.json) | `3256f99182d1d3b73c6e289cbe634bf84ff33b4f60694c65c59db5c84a735a8a` |
| Release executable | `e78eae3e563ef4112f1639cc833a4023e91c6b27a26b02e93b2a541a95f34014` |
| Test executable | `b50178ff2d21d40eb2241e697f4c145557a5ea6453dca67b58f92bf5b2153121` |
| Complete 175-input tested/after map, compact JSON | `03537b606d582b5c1cd85e5a24d3ff99044e258ac3cebc1c5abb16c04affa447` |
| Full original test log | `a4196882ad4027be360ac00362f74f22be31d410170d38a8c7ffa3adcae3e2a5` |

## Actual source and publication boundary

The eight actual formatted X230 source bodies were downloaded in full and
each rehashes to the qualification's tested/after map. The
[original source export](qualified-source-export.original.json.gz) and its
[independent download verification](qualified-source-export.download-verification.json)
recheck all 175 source bodies, the six original gate bodies, all three original
reports and the full test log, with a final stable-read fence on all 186 inputs.
All eleven changed-behavior test names are observed once. Executable body hashes
are retained from the actual qualification; this export does not claim a new
independent executable-body capture.

| Existing source | Actual qualified SHA256 from the original report |
| --- | --- |
| `src/mcp/runtime/request_archive_content.rs` | `4d94aceb1ff57c123c60d0af159510e0b9cb8893064d84bdda975897b575e5b8` |
| `src/mcp/runtime/request_archive_content_tests.rs` | `426db96c777e5f9b55bbc9e083207a62c14231db2b6316b2dea10fecbf9c1280` |
| `src/mcp/runtime/request_archive_index.rs` | `21984a42edfaaf5a3b16e10b18905ce3245cf8cc88cf5b9ff01131193c89546a` |
| `src/mcp/runtime/request_archive_store.rs` | `9a2c38c78a1be939101c8e22b692525d8732e56febbbf59dbe455560c2b916a7` |
| `src/mcp/runtime/request_archive_store_tests.rs` | `4f602d6918a701b41e3ae1a68e3276e4b5aa8c3ba070184ecf3a0c11bf43e933` |
| `src/mcp/runtime/request_audit.rs` | `6f923cd8b4479ae0fdeca590c13d7de0fc22762829ea703520f83fd9093e1901` |
| `src/mcp/runtime/request_audit_tests.rs` | `b8625d89f6d53e67f1c66340c480e15b1d07e950ba4e13021f9592b40a0e0da3` |
| `src/mcp/runtime/request_metadata_trace.rs` | `6dcf3eee6e58f295030c86af23298090cc19bdce5a87e065f98b4e490cddd4ac` |

The local publisher rehashes those eight downloaded bodies and inherits the
other 167 blob IDs only after checking their qualified SHA256 equality and the
complete published A54 tree. Its 175-entry expected Git blob and mode maps define
the source publication. The final commit must directly extend A54's `34b96194`
checkpoint. A separate postpublication audit checks the complete captured Git
tree, every declared asset and all other inherited parent leaves.

The combined commit will also retain the historical A53/A54 evidence. Earlier
failed large workloads remain failed. Successful evidence capture or audit does
not change the original workload outcome, and evidence from a different
executable does not count as A55 acceptance.

## Actual same-executable diagnostic

The original diagnostic job was `1a179d51c68-96a-13ef`; the separate read-only
transport job was `1a179db1c4f-96a-13f9`. The original product run completed its
fixed 20-call, eight-wave schedule with **14 successes, 6 failures and no
unexecuted slots or automatic retries**. The native seed and archive warmup
succeeded; the index-kickoff setup call failed. The original child shut down
through stdin EOF and was reaped with exit code 0. A completed diagnostic job
and successful evidence audit do not mean its product checks passed.

The run kept the original single controller, 65,536 archived plus 512 hot
records, 60-second idle period, one-millisecond cohort window and three-second
absolute product budget. Only the two original metadata/index trace switches
were enabled. The [original report](metadata-diagnostic-report.original.json),
[complete trace](metadata-diagnostic-trace.original.json.gz),
[complete stderr](metadata-diagnostic-stderr.original.log.gz) and
[independent audit](metadata-diagnostic.independent-audit.json) preserve every
successful and failed call. The audit independently reparses **3,483 events,
22 calls and 11 cohorts**, with no dropped events and every stage pair closed.
It verifies original source/ELF/input fences and process custody. Fixture
unchanged witnesses come from the original report: this three-file trace
capture does not contain every fixture body or the RPC wire bodies.

Three later two-member cohorts fail after waiting for an earlier cohort's
complete scan and final fence. All six failing slots are accounted for by the
observed timing boundaries; no unmatched cohort is assigned a guessed cause.
Wave and slot numbers below are the original zero-based numbers.

| Wave | Failed slots | Later store-lock wait | Budget at later scan entry | Later scan until error |
| --- | --- | ---: | ---: | ---: |
| 5 | 9, 10 | 2.180080 s | 0.818025 s | 0.818044 s |
| 6 | 13, 14 | 2.209834 s | 0.788443 s | 0.788465 s |
| 7 | 17, 18 | 2.194128 s | 0.803963 s | 0.803983 s |

The trace contains twelve serial scan aggregates, each with the exact eighteen
events: nine completed scans, including warmup, and three incomplete scans.
The incomplete scans verified 23,387, 22,827 and 21,546 of 65,536 archive records
before the original deadline stopped them. The following phase arithmetic uses
only the eight complete **measured** scans; it excludes warmup and incomplete
work. Their enclosing full-verification spans range from 2.152423 to 2.275827
seconds. Percentages divide each phase's summed microseconds by the sum of all
fifteen phase categories across those eight scans. The
[phase summary](metadata-diagnostic.phase-summary.json) retains the exact totals
and contributing call IDs.

| Instrumented wall-time category | Mean per complete measured scan | Share of measured phase time |
| --- | ---: | ---: |
| Walk and final scan fences | 55.987 ms | 2.548% |
| ROW lookup | 308.037 ms | 14.017% |
| ORDER check | 193.737 ms | 8.816% |
| Pending selection | 2.776 ms | 0.126% |
| Checked filename component | 13.512 ms | 0.615% |
| Namespace before read | 368.209 ms | 16.755% |
| Named stamp before read | 113.357 ms | 5.158% |
| Descriptor-relative open | 157.607 ms | 7.172% |
| Descriptor before body read | 113.226 ms | 5.152% |
| Body read through EOF | 143.143 ms | 6.513% |
| JSON parse and domain checks | 87.527 ms | 3.983% |
| Descriptor after body read | 119.297 ms | 5.428% |
| Named stamp after read | 119.582 ms | 5.441% |
| Namespace after read | 312.408 ms | 14.215% |
| Entry comparison and close | 89.258 ms | 4.061% |

The two namespace categories together account for about 30.970% of this
instrumented phase time. ROW lookup and ORDER checking together account for
about 22.832%. The remaining checked-filename category is about 0.615%; it is
not a before/after measurement of CStr allocation savings. These measurements
do not justify removing any namespace, inode, body or final-fence observation.

The remaining blocker is still visible: serialized independent complete
validations consume most of the second cohort's original deadline. CStr reuse
has not closed that blocker. Trace flushing and timers affect scheduling;
the 14/20 diagnostic result is neither an uninstrumented throughput comparison
nor evidence that A55 regressed relative to A54's separate 16/20 diagnostic.
No CPU, memory, production throughput or multihost adoption claim follows.

## Retained bytes and reproducibility

Original qualification reports, gate records, operator receipts and source
export are retained byte for byte. The complete test log and two larger trace
originals use deterministic gzip; [compression receipts](compressed-originals.json)
record both original and compressed sizes and SHA256 values. The transport gzip
is retained without recompression as two ordered binary parts, each below the
publication's 512 KiB per-blob limit. The
[part manifest](metadata-diagnostic-originals.transport.parts.json) gives their
offsets, lengths, SHA256 values and the unchanged complete transport SHA256.
Concatenating the parts in listed order reconstructs the exact 776,727-byte
original package before gzip decoding.

Frozen [qualification and diagnostic tools](../../../../tools/x230/a55/README.md)
retain their original input bindings and path contracts. The
[prepublication compiler manifest](compiler-publication.prepublication.json)
deliberately records final Git verification as false: a postpublication audit
must verify the actual commit and full captured tree. No future commit ID or
GitHub CI result is invented inside this commit's own payload.

## Acceptance ledger for this intermediate candidate

| Gate | A55 checkpoint state | Boundary |
| --- | --- | --- |
| Original six-stage X230 qualification | Passed | Actual reports and original worker custody |
| Eight actual source bodies, full175 export and complete log coverage | Passed | All 186 export receipts, eight actual bodies, six gates, full log and eleven changed-behavior names independently checked |
| Same-executable 20-call diagnostic | Completed; product checks failed, 14/20 successful | Full 3,483-event audit passed; six failures and three partial scans retained; performance adoption false |
| Fifteen Python commands plus dependency precheck | Not executed for this intermediate candidate | Actual bindings are prepared; no A55 command result is claimed |
| Native concurrency | Not executed for this intermediate candidate | No result inherited from A54 |
| Controller/reply/owner loss | Not executed for this intermediate candidate | Three-case tools are bound; no new plan or effect result is claimed |
| Small and large archive acceptance | Not executed for this intermediate candidate | No 8,192-call or 80-call adoption result is claimed |
| Six-host integration and soak | Not executed for this intermediate candidate | All original stages remain required for a candidate proposed for adoption |
| GitHub CI for the new commit | Pending publication | Requires the exact newly published commit |

The following production candidate must close its own complete control, native,
recovery, small-archive, large-archive and six-host gates. A55's successful
qualification and completed diagnostic can inform that candidate; they do not
satisfy those adoption gates on its behalf.

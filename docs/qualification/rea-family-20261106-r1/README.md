# ELF Evidence and fixed Ghidra family continuation

This continuation implements the complete-byte native Evidence readback path and repairs two real fixed-profile Ghidra reference differences. Its source, complete build evidence, original MCP wire, full differences, failed attempts and independent consumers are retained separately. The public 229-tool replacement ledger remains **0 qualified / 229 OPEN**; finite successful checks do not close every operation or P0–P5 gate.

## Delivered source and actual build

| Identity | Observed value |
| --- | --- |
| Binary-producing source | `fe3223cabbd2a8f1aa75a4ab57507bdb72291242` |
| Parent candidate | `c9c79e27a2bf56bd204df6591ca2311dc872e317` |
| Selected execution-input tree | `1a83f83cf62bf3d96e50c944722977b6971ffe686aecd131cab5e728dd802424` |
| Final binary SHA-256 | `260205be5fd4cdf363b8f426002c057d1d939ce299843f979770a585bb72faf6` |
| Final binary bytes | 51,146,872 |
| Original matrix summary SHA-256 | `ac9bd1e247ee2e2dc95f080f3b078ddb0d6cb2e82ed2bb4f641f18dba713c407` |
| Independent matrix assessment | `48b7045b56cbbdb91ac67fa5ab67245279d466be4fd53a7ffe9749b799632fdd` |

The later evidence-only Git commit is a separate identity. It is not described as the source used to compile the binary. The final matrix used the pinned Rust 1.95.0 toolchain and offline, locked dependencies, four build jobs, one test thread, no retries, no fail-fast, and explicit all-targets coverage in both feature configurations. Ignored tests follow nextest's normal policy; doctests are outside this matrix.

| Gate | Actual result |
| --- | --- |
| Formatting | PASS |
| Clippy, all features, warnings denied | PASS |
| Clippy, no default features, warnings denied | PASS |
| All-feature nextest | 2,327 passed / 40 reported skipped; test execution 911.280 seconds |
| No-default-feature nextest | 2,298 passed / 28 reported skipped; test execution 990.776 seconds |
| Explicit final all-feature binary build | PASS; all features, `default`/`remote-fs`, `fresh: false`; 148.651 seconds |
| Selected source before/after and continuous write monitoring | PASS; 1,429 selected files, identical original before/after snapshots, zero recorded source events and complete monitoring |

The original nine stages include the three tool-version observations. The independent reader authenticates the complete original summary, source snapshots, monitor record and all eighteen original stdout/stderr logs. It binds all 1,429 selected source files to the frozen Git commit and checks compiler artifacts and the actual binary. Build success is scoped to this matrix; it is not an operation-parity certificate. The developer build profile and observed systemd unit resource data do not establish release cost, deployment, upgrade or rollback qualification.

The wrapper measured 2,706.367 seconds from producer invocation through the resource query. Whole-unit `MemoryPeak` was 6,863,306,752 bytes and `CPUUsageNSec` was 2,791,605,110,000; these include launcher/prelude overhead. I/O byte counters were unavailable. The requested limits were a CPU-time quota of 400% (four CPU-seconds per second), 12 GiB of memory and zero swap. The actual final Cargo artifact used `opt_level: 1`, `debuginfo: 0`, `test: false`, the `default`/`remote-fs` features and `fresh: false`. See [the final matrix originals and independent replay](matrix-observations-r3/README.md).

## Pure Rust ELF notes and Evidence

The native profile `hepta.evidence-bundle-readback.v1` adds `rea_read_evidence_bundle` and `rea_close_evidence_snapshot`. The production readback implementation uses Rust and session-owned memory. Node/npm are used only as the independently pinned reference in the qualification workflow.

A successful initial read selects the complete canonical bundle bytes. Every page contains its actual byte offset, hex bytes, chunk SHA-256, full snapshot SHA-256, total length, next offset and EOF state. The snapshot is immutable across later registry changes. Release is explicit and idempotent. Snapshots are not inherited by a new session. After an authorized export and explicit import, the new session must create its own snapshot before continuation; identical canonical bytes may yield the same content-derived ID.

The limits are 1–262,144 bytes per page, 64 MiB per snapshot, four retained snapshots and 128 MiB of encoded payload per session. One encoder owns its permit until its blocking worker actually exits. Cancellation or budget failure cannot publish a partial snapshot. These are payload and per-session limits, not a whole-process or multi-client memory guarantee.

The final actual family receipt and independent replay report:

- 50/50 finite comparisons passed: 40 complete CallToolResult comparisons with unchanged opaque text, three schema-set comparisons and seven canonical export-byte comparisons. Whole raw JSON-RPC frames were separately unequal in all 40 pairs.
- Eight of eight owners closed normally: three Node reference owners and five native Rust owners. Each recorded exit 0, a stopped reader, original process exit observed through its retained pidfd and no remaining owned process group; every forced-cleanup list was empty.
- The actual 25-page continuation reassembled 6,302,590 bytes, SHA-256 `c6517498ecbf04562c50f6a93c66e6fa9f17123df0a645d759df701b61ae8be8`. The original snapshot remained stable across a later registry mutation; release and new-session isolation checks also passed.
- Seven canonical export-byte comparisons passed across producer, restored and cold sessions, including exports retained after refused truncated, tampered and missing imports. The original cold extension verified full canonical re-export after explicit import; it separately rejected the old cursor, created its own snapshot, read seven bytes and released it. The complete 25-page reconstruction occurred in the earlier native extension owner.
- Real body/bundle overflow paths preserved usable retained Evidence: summary, complete export and the native byte-page continuation were exercised. The two native-only extension workflows made 53 actual calls in total, including import, export, summary, refused requests, paging and release.
- The original family and lifecycle archives contain 556 and 76 regular-file members respectively. Both were physically unpacked into a new directory, every member was checked, and both actual relocated consumers returned 0 with stdout/stderr byte-identical to their original independent outputs. The two complete 22-file build bundles were also revalidated after relocation.

The additional cold-session full-page readback reports PASS in a separate fresh native owner: 34 actual calls and 25 pages reconstructed all 6,302,590 imported bytes through EOF, exactly matching source export SHA-256 `c6517498ecbf04562c50f6a93c66e6fa9f17123df0a645d759df701b61ae8be8`. Both original cursors were refused before and after import; the new session explicitly created its own snapshot, then completed the full read and re-export, released the snapshot and refused its released cursor. The independent wire consumer passed, the owner closed normally without forcing, and its final PID/group observation was empty. See [the supplemental cold-session evidence](elf-cold-full-observations-r1/README.md). Its 166-member supplemental archive and the original 556-member source-family archive were actually unpacked and verified; the archived consumer replay returned 0 with byte-identical stdout/stderr, and the complete build binding matched after relocation. Its owner, calls and observations are separate from the original 50-comparison family receipt; the original receipt is unchanged.

The first C9 run had 40 passing and 10 failing comparisons. Every failure was in opaque error text ordering, even though the parsed diagnostic values matched. R5 corrects the admitted frozen ELF/Evidence error shapes, including the shared `inspect_analysis_view` `unsupported_target` branch, and retains the previous complete fallback for unknown shapes. The ten original texts remain pinned fixtures. The first failed receipt is preserved; the final run is a new execution with a separate source/binary binding.

The original `inspect_analysis_view` rejects ELF-notes parents. The native byte pager is an explicit extension and does not change the frozen upstream tool schema or invent an upstream cursor.

The lifecycle evidence separately records six passing sessions: reference/native active cancellation, native four-worker capacity cancellation, native worker deadline, and reference/native active EOF. Four gates passed; the combined/reference deadline gate stays OPEN because reference deadline injection was not established. The original assessment remains unchanged and its source attestation is supplied by a separate enclosing R5 build proof. The subsequent census observed all 14 owners across the eight-owner family and six-session lifecycle runs, plus six recorded workers, absent, with all 14 original process groups empty and no census errors. In particular, an observed Node cancellation notification or owner close must not be promoted into proof of a separately stopped native worker deadline. The combined deadline and broader operation/platform gates remain explicit in the original independent assessment.

See [the operation contract](../../rea-native/ELF_EVIDENCE_FAMILY.md), [the preserved C9 observations](elf-observations-r1/README.md), and [the final observations](elf-observations-r2/README.md).

## Fixed Ghidra Provider

Revision 4 is bound to Ghidra 12.1.4, the pinned JDK, the exact owned ELF, `x86:LE:64:default`/`gcc`, all 146 Analysis option entries, 26 enabled analyzers and four disabled analyzers. It is a separate identity from revisions 2 and 3. The original bridge source selects the default configuration; a complete analysis-option snapshot from that original session was not directly sampled. The original POSIX NoReturnFix post-script has not been generally ported; the retained original observation reports zero affected functions, sites and refits for this exact fixture only.

The real C9 comparison exposed an extra synthetic incoming Entry Point reference and two stack addresses rendered as `Stack[-0xc]` instead of the original `stack:0xfffffffffffffff4`. R5 traverses the actual function body plus its entry, filters the real `isEntryPointReference()` predicate, deduplicates the original five-field identity and sorts using Ghidra's Address ordering. Non-default address spaces use the original UTF-8 encoding and unsigned 64-bit offset representation. It does not hardcode a fixture address or a textual Entry Point label.

The 4,096 raw-reference budget counts filtered and duplicate observations before either operation. Reports and summaries distinguish filtered, duplicate, unique, returned and budget-omitted counts. Both identities must hold:

- raw = filtered + duplicate + unique;
- unique = returned + budget-omitted.

The historical total omitted remains raw minus returned, with its broader meaning stated. Rust rejects noncanonical addresses, wrong address spaces, selectors or the body-owned endpoint of a reference outside the declared body ranges (including gaps), duplicate returned identities and inconsistent or overflowing counts. Legacy revision 2/3 behavior remains unchanged.

The final actual native execution reports 15/15 finite analysis and owner-lifecycle checks passed, including both entry and interior fixed-reference oracles, real native-decompiler cancellation, original-job queries after controller restart, worker SIGKILL, owner timeout, and three durable scratch-cleanup receipts. All five recorded native controllers closed normally with no forced cleanup. The actual MCP executable was the harness copy `mcp-native-r5-r1/hepta-runtime-qualified`, whose 51,146,872 bytes and SHA-256 `260205be5fd4cdf363b8f426002c057d1d939ce299843f979770a585bb72faf6` match the final build target. The original six-field oracle is restricted to ordered reference rows on this exact fixture; full Evidence is assessed separately. All five controller instances retain complete launch, original wire, stderr and close receipts. A forced or failed final close downgrades the harness and cannot hide a primary analysis failure.

The first controller reads the actual native Evidence bundle before any Provider starts and after the normal Provider operations, before closing that same controller. Both actual observations contained seven empty data arrays, zero records and zero unknowns; the native assessment is `DIFF_EMPTY_NATIVE_BUNDLE_AFTER_PROVIDER_ANALYSIS`. This confirms a missing integration path: `rea_static_read` returns `rea_provider::read` and its non-REA-compatible report without appending to `rea_session`, while `rea_get_evidence_bundle` reads that session. Complete Provider Evidence remains unqualified. The captures retain different complete tool histories. The same-controller native interval independently contains four successful complete Provider reads, and its before/after bundle remains empty; complete upstream history-equivalence stays open. The engine report is never substituted for a missing bundle.

The final cross-implementation comparison reports all 11 complete Provider/error pairs as DIFF: 0/11 matches of exact CallToolResult bytes, parsed complete CallToolResult objects (keeping `content[].text` opaque), opaque text or raw frames. The two separate Evidence-tool pairs have 1/2 matches of parsed complete CallToolResult objects (keeping `content[].text` opaque) and 1/2 opaque-text matches (the empty baseline), and 0/2 complete CallToolResult-byte or raw-frame matches. The narrower function inventory has 60/60 common fields equal across 15 rows; all four ordered six-field xref projections match, and both complete 63-byte C texts match. The four actual completed Provider reads between the native bundle samples also match their retained native CallToolResults in full. The retained 11,387 field rows include matching, differing and one-sided fields across five layers; their counts are not a qualification score. It retains complete fields and opaque content, and treats a shared projection as a narrower result. Missing symbols, locals, basic blocks, nested procedure data or provenance remain visible.

The native R4 collector and independent state consumer report 23/23 independently rederived comparisons passed: eight parsed retained reports, five complete refusal CallToolResults, five registry-membership comparisons and five directory-membership comparisons. All ten additional adjacent before/after membership facts for the five negative requests passed. The original 11 state files bind the actual 19 tool calls and 43 wire frames. A separate post-execution census observed 40 original PID/start identities absent or reused, six normally closed recorded native controllers, no current members in the 14 explicitly owned job units or six original controller process groups, no census errors and no signals sent. Each negative replay retains original request/response frames and complete before/after registry and directory-member observations. The initial-baseline comparisons and the ten adjacent membership facts are separate counts. They are samples at stated times, not an atomic snapshot or a proof that no transient side effect ever occurred.

The original Ghidra cancellation experiment was performed exactly once. Its observed live-decompiler witness, notification, drained responses, recovery and owner close are retained. No additional original cancellation was introduced in R5, and no causal or durable-job equivalence is inferred from that observation.

See [the fixed-profile contract](../../rea-native/GHIDRA_ANALYSIS.md), [the preserved C9 full wire and differences](../rea-ghidra-mcp-c9-20261106-r1/README.md), and [the final R5 observations](../rea-ghidra-mcp-r5-20261106-r1/README.md).

### Original readback precision

The independent C9 review distinguishes parsed values, opaque text, complete CallToolResult values with unchanged text, original result slices, whole JSON-RPC frames, and exact bundle-member/export bytes. The original explicit import returns equal parsed bundle values but changes 226 object-member orders in opaque text. The complete CallToolResult therefore differs too. Export bytes also differ from the original raw bundle member, while the declared canonical encoding agrees. Other repeated-page and import-page observations have their own narrower equality results. The seven internal checks are not described collectively as seven raw-byte equalities.

## Preserved failures and audit artifacts

[The R5 repair archive](repair-observations-r5/README.md) retains the original initialization/bootstrap failures, all review packages, actual failed wrappers, source/command identities and the independent reassessment. A first Ghidra test filter selected only the three opaque-error tests. The corrected filter actually ran 31 Ghidra/summary tests successfully, but its postprocessor failed because of an over-escaped regex. A separate reader then authenticated the original logs and all eight new case names without rerunning the tests or rewriting that failed wrapper. These narrow observations are distinct from the complete final matrix.

The earlier `31c577b` matrix exposed two actual test failures: accepting `GPL//file` in the Ghidra manifest and omitting snapshot release from the owner-fence retained-state classification. Its remaining gates were not reported as passed. The later C9 matrix passed, while C9 ELF operation comparisons and complete Ghidra response comparisons still exposed their own differences. Every candidate and layer keeps its own result.

## Frozen reference identities

| Reference | Exact identity |
| --- | --- |
| npm package | `rea-agents@6.8.0` |
| npm tarball SHA-256 | `8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb` |
| Installed package-owned files | 2,398 files; aggregate SHA-256 `8f5a44ea76e5d93b27f8882d902e9449d7f41895e5428c213fe6ed3619592891` |
| Original Git reference | `93b8b82db70279e40f484114cff9dc1958dc14ee`; a separate identity from the npm archive |
| Node | v22.23.4; executable SHA-256 `94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90` |
| Real ELF notes input | `/usr/bin/true`, 26,936 bytes; SHA-256 `8a63c98320173f79e263115e10cefc170155e47d1fd4b5a70e4429d2699cae28` |
| Ghidra release archive | 12.1.4; SHA-256 `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db` |
| Java executable | 25.0.5+8; SHA-256 `1bf1aaef01e4f8d7c85d913c60fb2ee4624cbe54d4053254c59657b7ea913b25` |
| Ghidra owned ELF | 15,680 bytes; SHA-256 `ec301f409d22314b43b4392fa80ada28213cd75ca77c6cbbbbfe1454555dd64a` |

The actual catalog audit checks all 229 original names, ordering, input/output schemas and annotations against the frozen ledger. Titles and descriptions are retained separately and are not silently counted as equal. Original Git/npm identity and fixed execution identity do not by themselves establish behavioral equivalence.

## Remaining qualification scope

There are 34 native REA MCP interfaces in the final source, including the two new readback methods. That is not a count of replaced upstream tools. The frozen original inventory has 229 tools: 187 absent, 22 partial-operation mappings and 20 related facilities, with **0 qualified / 229 OPEN**. Static Provider tools are advertised only when configured profiles exist; the pure-native empty-profile session advertises 29 interfaces.

| Phase | Gates not closed by this finite continuation |
| --- | --- |
| P0 | Complete per-tool input/error/result/lifecycle contracts and real per-operation qualification across the 229-tool catalog |
| P1 | Complete provider Evidence compatibility, broader unknown-revision and concurrent failure behavior, and persistence beyond explicit export/import |
| P2 | Whole JavaScript application analysis, APK resources/permissions, full model formats and their exceptional inputs |
| P3 | Complete original Ghidra Evidence and behavior beyond this fixed fixture/profile; real IDA/Hopper and other engine/platform environments |
| P4 | Real browser/device/debugger/Frida tasks and interruption/recovery |
| P5 | Release build cost, multiple hosts, upgrades/rollback and deployment qualification |

The exercised Ghidra Provider requires a Linux controller and an executable Linux host. These observations do not qualify all Providers on macOS, Windows or Android. The implementation, finite observations, complete operation qualification and full P0–P5 replacement decision remain separate.

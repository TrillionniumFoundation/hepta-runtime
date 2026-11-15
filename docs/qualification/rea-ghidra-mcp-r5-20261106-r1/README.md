# Fixed Ghidra Provider: R5 execution and complete-result differential

The fixed native Provider passed **15 finite checks**, closed **five recorded
native controllers normally**, and matched the stated original-fixture inventory,
selected-function and ordered-reference projections, plus complete C text at both
the entry address and an interior address. The later native replay was independently
rederived as **23/23 comparisons plus ten adjacent membership witnesses**, all
passing. These results qualify the stated native profile and lifecycle scope.

**Complete upstream Evidence compatibility remains open.** Eleven declared
operation/error pairs differ as complete CallToolResults, opaque text, and raw
JSON-RPC frames. Actual complete Evidence sampled before and after Provider work
in the **same live native controller** contained zero records both times. The
fixed original capture contains thirteen records. No Provider report was
substituted for a native Evidence bundle.

The principal results are in [complete-comparison-summary.json](complete-comparison-summary.json),
[native-full-qualification.json](native-full-qualification.json), and
[native-raw-replay-assessment.json](native-raw-replay-assessment.json). All original
wire bytes, imports, exports, report bodies, lifecycle receipts, source snapshots,
and offline consumer inputs needed for these comparisons are retained in the
[raw archive](raw-evidence.tar.gz). The historical
[C9 assessment](../rea-ghidra-mcp-c9-20261106-r1/README.md) remains separate.

## Exact candidate and execution identity

| Item | Fixed value |
| --- | --- |
| Source commit | `fe3223cabbd2a8f1aa75a4ab57507bdb72291242` |
| Selected source tree SHA-256 | `1a83f83cf62bf3d96e50c944722977b6971ffe686aecd131cab5e728dd802424` |
| Executed runtime bytes | 51,146,872 |
| Executed runtime SHA-256 | `260205be5fd4cdf363b8f426002c057d1d939ce299843f979770a585bb72faf6` |
| Native full job | `1a1b2a8c219-fc05-7f2f`, durable exit 0 |
| Native raw capture job | `1a1b2b080c1-fc05-7f54`, durable exit 0 |
| Independent state consumer job | `1a1b2b58575-fc05-7f69`, durable exit 0 |
| Complete differential job | `1a1b2b790a2-fc05-7f74`, durable exit 0 |
| Archive relocation job | `1a1b2c8fc38-fc05-7fc3`, durable exit 0 |

The build target was
`/home/qian-qi/work/hepta-rea-family-ecb0b9d61c75-20261106-target/debug/hepta-runtime`.
The **actual MCP argv** used the private, same-hash copy
`/home/qian-qi/work/hepta-rea-ghidra-v4-ecb0b9-20261106-r1/mcp-native-r5-r1/hepta-runtime-qualified`.
The archive excludes the executable payload and preserves its measured identity,
actual launch arguments, and before/after execution checks.

The nine-stage matrix summary is 55,898 bytes with SHA-256
`ac9bd1e247ee2e2dc95f080f3b078ddb0d6cb2e82ed2bb4f641f18dba713c407`.
Its separate independent build assessment is 19,952 bytes with SHA-256
`48b7045b56cbbdb91ac67fa5ab67245279d466be4fd53a7ffe9749b799632fdd`.
Both are exact archived inputs. Build success is a separate gate from operation
equivalence.

The actual runs used Ghidra **12.1.4**, JDK **25.0.5+8**, ELF loader,
`x86:LE:64:default` / `gcc`, and revision 4 profile
`hepta.ghidra.12.1.4.elf-x86_64-default-functions.v1`. The fixture is 15,680 bytes,
SHA-256 `ec301f409d22314b43b4392fa80ada28213cd75ca77c6cbbbbfe1454555dd64a`.
The release ZIP SHA-256 is
`ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`.
The native installation manifest covers 3,139 files across `Ghidra/` and `GPL/`,
including the selected GNU demangler, and has SHA-256
`b417a0fbc11d88f12df1f816d1426f6cbc5506d399a064227b48786ce2e0d5ac`.
Selected JDK files and native helper identities are also recorded.

Native revision 4 validates all 146 canonical default analysis options, including
26 enabled and four disabled analyzer switches. The fixed original npm bridge's
source supports the default configuration; a complete original-session option
snapshot was **not directly sampled**. The original's NoReturnFix diagnostic was
`cleared=0`, `sites=0`, `refit=0` for this fixture. Native does not execute that
original repair pass, and other inputs remain unqualified. The original npm
identity is `rea-agents@6.8.0`, including its fixed tarball and all 2,398 owned
package files. Node transitive dependencies and host system libraries remain
within the trusted operator-host boundary.

This is a Linux controller and executable Linux x86-64 operator-host result.
The runtime/controller is Rust; the Ghidra Provider still executes a JVM and
native engine helpers. It does not establish Mac, Windows, Android, other engine,
isolated-host, or hostile-operator qualification. No inspected target was run.

## Actual finite behavior and the repaired differences

| Comparison | Actual R5 result | Meaning |
| --- | --- | --- |
| Function inventory | 15 original and 15 native rows; 60/60 common fields | Address, name, external flag, and thunk flag match for each row; original symbol and thunk-target metadata remain absent from native listing. |
| Inventory composition | 13 internal and 2 external functions | External functions are explicit, with address-space information and separate counts. |
| Entry and interior resolution | `0x401106` and requested `0x401107` resolve to entry `0x401106` | Exact function body is `0x401106..0x40111f`, 26 bytes; the requested interior selector is preserved. |
| Ordered references | 4/4 entry/interior × incoming/outgoing projections match | Six fields per row and their order match the fixed original oracle. |
| Complete C text | 2/2 exact 63-byte matches | Entry and interior both have SHA-256 `f5cfb8e45b727b130ef92c6511118695d2454bf9be1b340c66170611d125d029`. |
| Native owner lifecycle | All stated finite checks pass | Cancellation after a live decompiler witness, original-job readback across controller restart, worker failure, deadline cleanup, and original owner cleanup are independently retained. |

Incoming references now traverse body plus entry, filter the original synthetic
Entry Point source rule, deduplicate the original five-field key, and use Ghidra's
actual Address comparator. The fixture has **four raw references, one filtered,
zero duplicates, three unique, three returned, and zero budget omissions**.
Outgoing references have **two raw, zero filtered, zero duplicates, two unique,
two returned, and zero budget omissions**. The stack address is canonical
`stack:0xfffffffffffffff4`, rather than the historical display string
`Stack[-0xc]`.

Every raw reference, including filtered or duplicate entries, consumes the 4,096
scan budget. The accounting identities are `raw = filtered + duplicate + unique`
and `unique = returned + budget_omitted`. The retained compatibility field
`omitted = raw - returned` includes filtering and deduplication; it is not solely
a result-size truncation count. Byte fitting changes returned/budget-omitted
counts without changing scan completion or the raw/filter/duplicate/unique counts.
Revision 2 and 3 retain their historical contracts. See
[mapped-observations.json](mapped-observations.json) and
[the revision contract](../../rea-native/GHIDRA_ANALYSIS.md).

## Complete outputs and Evidence remain different

| Separately measured layer | Declared pairs | Matches | Differences |
| --- | ---: | ---: | ---: |
| Operation/error complete CallToolResult bytes | 11 | 0 | 11 |
| Operation/error complete typed CallToolResult | 11 | 0 | 11 |
| Operation/error opaque text | 11 | 0 | 11 |
| Operation/error complete JSON-RPC frame bytes | 11 | 0 | 11 |
| Additional Evidence tool complete CallToolResult bytes | 2 | 0 | 2 |
| Additional Evidence tool typed CallToolResult / opaque text | 2 | 1 | 1 |
| Additional Evidence tool complete JSON-RPC frame bytes | 2 | 0 | 2 |
| Native completed reads between the Evidence samples versus retained raw replay | 4 | 4 | 0 |

The two additional Evidence pairs compare the original fresh empty import
namespace with native before-Provider, and the original complete bundle with
native after-Provider. The empty pair has equal typed fields and opaque text but
different outer raw bytes. The completed bundle pair differs. These are separate
tool histories, explicitly retained; the operation sequences are not asserted
to be identical.

The first native controller, `controller-ee38af965f8d4fab8149e46fe33a6c67`,
PID 1913784 / start ticks 107644814, returned a complete bundle at both sample
points. **Records, unknowns, and all seven manifest arrays were zero before and
after.** Between those samples, its actual successful complete functions,
function, xrefs, and decompile reads are bound by request ID and wire ordinal.
Their complete typed CallToolResults, including opaque text, match the retained
native reads. A fresh replacement controller was not used to infer this absence.
See [complete-evidence-layer.json](complete-evidence-layer.json) and
[full-controller-evidence.json](full-controller-evidence.json).

The production gap is specific: `rea_static_start` / `rea_static_read` use the
durable Provider path; `rea_provider::read` returns its validated report with
`rea_evidence_compatible:false`, without recording it through the server's
`EvidenceSession`. `rea_get_evidence_bundle` reads that session. The ELF producer
has a separate explicit session-recording path. The selected-source excerpts
and hashes in [evidence-production-source.json](evidence-production-source.json),
together with the actual zero-record samples, locate the missing production
connection.

Missing original structures include symbol and thunk-target metadata, selected
function basic-block counts and locals, body descriptions and provenance,
nested source/target procedures and extended reference metadata, and the
Evidence schema identity, confidence, authority, environment, locations,
relationships, and evidence links. Error/recovery metadata and full outer
envelopes also differ. None were invented or populated from the original capture.
The [negative-case report](negative-cases.json) keeps unpaired negative inputs
separate; it makes no same-input parity claim for them.

The full field ledger has **11,387 rows** with explicit MATCH, DIFF,
ORIGINAL_ONLY, and NATIVE_ONLY statuses. The mapped Evidence/report layer has
195 equal leaves, 15 differing leaves, 1,010 original-only leaves, and 2,507
native-only leaves. Its 15 differing common leaves are nine operation-name
differences and six typed `26` integer versus `"26"` string body-size encodings;
the much larger missing-field and envelope differences remain visible. These
counts are mappings, not a qualification score. See
[field-differences.jsonl.gz](field-differences.jsonl.gz),
[mapping-definitions.json](mapping-definitions.json),
[mapped-value-differences.json](mapped-value-differences.json), and
[raw-and-opaque-comparisons.json](raw-and-opaque-comparisons.json).

The fixed original full bundle/export contains **13 records and 64,297 bytes**,
SHA-256 `fa5884427caa3bb8f3effef348f04bc23dccc6d187fd4bb50797f17f4cc57dbd`.
Its seven original round-trip checks pass at parsed-value or predicate level.
Cold-import complete result and opaque text are not byte-identical: the retained
independent C9 analysis lists 226 object-member ordering changes. Export bytes
also differ from the complete response's raw embedded bundle member despite
parsed-value agreement. This package preserves those distinctions.

## Native replay, cancellation, and resource ownership

The R4 collector made eight retained-job reads and five negative **start-surface
replays**, with registry observations. It saved eleven membership snapshots:
the initial baseline and each negative case's before/after state. All five replays
were refused; the recorded registry and immediate-directory snapshots showed no
new members at the sampled boundaries. These samples are not atomic and do not
exclude transient side effects between observations. The independent
consumer validated the original wire sequence and rederived 23 comparisons:
eight retained results, five complete refusal results, five registry memberships,
and five directory memberships. It separately required all ten adjacent
before/after membership witnesses to agree. Producer booleans were not used as
the independent result. The actual record is
[native-raw-replay-assessment.json](native-raw-replay-assessment.json).

The native lifecycle harness observed live owned engine processes before the
authorized cancellation/failure/deadline actions. The three durable cleanup
receipts report scratch removal, owner adoption, original-child reaping, and
original process-group stop, including restart readback. Controller close
receipts are a separate proof from those worker/JVM cleanup receipts.

The current execution census covered **six normally closed controllers** (five
full harness plus one raw replay), **40 recorded PID/start identities**, **14
exact original job units**, and the six original controller process groups.
All recorded identities were absent or reused; the exact units and groups had
zero current members. Census errors and emitted signals were both empty.
The census job `1a1b2b4515a-fc05-7f62` was durable exit 0 and explicitly released
the host. This is a current observation of recorded ownership, not a complete
process birth history or an isolated-host attestation. See
[post-execution-owner-census.json](post-execution-owner-census.json).

The original cancellation remains the **single historical C9 attempt**. An
owned live native decompiler was observed before `notifications/cancelled` for
the original request ID. After final close/drain, there was no result or late
success for that request, retained Evidence remained unchanged, recovery worked,
and the owner closed normally. The status is
`OBSERVED_LIVE_CANCEL_NOTIFICATION_WITH_NO_COMPLETED_RESULT_AND_RECOVERY`.
It establishes the recorded notification, activity, absence of a completed
reply, and recovery; it does not establish causal interruption or native
durable-job equivalence. No original Ghidra request or cancellation was repeated
for R5. See [cancellation-observation.json](cancellation-observation.json).

## Archive and actual offline relocation

The final [raw archive](raw-evidence.tar.gz) is **5,256,402 bytes**, SHA-256
`87ba1a9ba6035bbbb56444d058bc82d148cd5349671f482f626ae4603cd6a7b9`.
Its [manifest](raw-evidence-manifest.json) lists **1,408 source files totaling
45,762,539 bytes**; the archive has 1,409 members including that manifest. Every
member's type, safe relative path, size, and SHA-256 was checked, then all source
members were checked again. Runtime/engine/JDK/npm dependency payloads and engine
caches are excluded. The selected ELF fixtures and all complete wire/Evidence
bytes remain included. [Archive verification](archive-verification.json) records
the actual fresh extraction.

Two frozen offline readers then ran against the extracted copy:

- `consume_r4_states.py`, SHA-256
  `089849d73b315c242a20845cc325e29823592f7796047655ccbe52b583692ce3`:
  the 6,423-byte assessment reproduced exactly, SHA-256
  `a53e0f95b1a171ca506097fad1892b4eccd904af7805ed8e9234afc502f10323`.
- `derive_ghidra_final_diff_r1.py`, SHA-256
  `fc968ead6031164d565cb7137d0892df62e908f68c4c7fc6813c074bded19a64`:
  twelve of fourteen output files reproduced byte-for-byte. The input manifest
  changed only for the new plan filename/base/output and its digest; the summary
  changed only its input-manifest size/digest reference. All other fields and
  all conclusions were equal.

The [offline relocation assessment](offline-replay-assessment.json) is 7,735
bytes, SHA-256 `24dd0da10c19f5c0e6ce5be1ef3b4837f837e6a051962edae806c025efef63cb`.
The [invocation](offline-replay-invocation.json), separate reader invocations,
and stdout/stderr files retain the actual commands and terminal results. This
replay reads historical ownership evidence; it does not repeat those observations
or execute an inspected target, runtime, or engine.

One read-only inventory draft first assumed the manifest's `files` map was an
array. The first pack attempt then incorrectly selected its own active stdout;
the post-pack hash check correctly rejected the changed log before running any
offline consumer. Both failures and their original receipts/logs are preserved.
The successful r2 pack excludes its active logs and uses new output names. No
execution capture, comparison result, or failed artifact was overwritten.

Historical C9 limitations remain unchanged: its legacy full-harness controller
close did not record possible five-second forcing, and five R3 after-directory
snapshots were missing, so that capture independently proved only 18 of its
producer's 23 checks. R5 supplies current normal-close and complete state evidence;
it does not retrospectively repair C9. The global operation qualification ledger
is not promoted by this finite proof.

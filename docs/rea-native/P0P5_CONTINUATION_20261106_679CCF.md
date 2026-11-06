# REA P0–P5 integration — 2026-11-06, 679ccf

The [C2 observation record](C2_OBSERVATIONS_20261106_679CCF.md) gives the later frozen
candidate's finite results and remaining qualification boundaries. The [B2 observation record](B2_OBSERVATIONS_20261106_679CCF.md)
and the implementation and planned gates below retain their historical source,
binary and execution identities.

## Decision and exact qualification boundary

Full REA replacement and production qualification remain **HOLD / NO_GO**.
The authenticated npm inventory contains 229 public operations in 18 families.
This integrated source exposes 35 native interfaces and maps the original
operations as 22 partial operations, 20 related facilities and 187 absent
implementations. No original operation has complete replacement qualification.
The three checkpoint interfaces are native extensions; they do not increase the
number of equivalent original operations.

The fixed original target is `rea-agents@6.8.0`, archive SHA-256
`8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb`.
The separately pinned Git source at
`93b8b82db70279e40f484114cff9dc1958dc14ee` has its own declaration inventory.
The compatibility input manifest and original npm catalog remain the authority;
the Git declaration count must not replace the npm denominator.

Candidate A is the completed source/binary combination at
`c25e4cef0610816bfd1263b69d3dd63e4114aa49`, tree
`c6db025f5902570bd63520751cf84c57505eb6f4`, runtime SHA-256
`9cde66234030515651177e3d8ab113b2b6f674ee76196283c71874348a0b6c90`.
Its build is an all-feature **dev profile, optimization level 1**, with debug
assertions enabled, debuginfo 0 and overflow checks enabled. It is not a release
performance result. Its observations remain historical when the source changes.

The checkpoint/error-order implementation commit
`0f1456141bf53e89a668ff1019f71360672c35be` was merged with the independently
published recorded-core/model/JSON integration at
`42949877bcec4441e9d97034fd803306865a0083`. Merge
`5129bddfe7875c1b9cee8abe712166873b780261` preserves both histories. Subsequent
commits repair fixture digest formatting and a test iterator for the pinned
Rust 1.95.0 toolchain. No result from either parent is promoted to this combined
binary. The final candidate B commit, tree, source inventory, compiler records,
binary and binding are recorded by the fresh qualification run.

## What candidate A actually established

| Observation | Actual finite result |
| --- | --- |
| All-feature / no-default Rust matrix | 2,229 passed and 40 skipped / 2,201 passed and 28 skipped |
| Python source regression | 564 tests across 20 commands; no skips or expected failures |
| Four separately invoked original corpus gates | One actual selected test passed per gate: original Evidence, 1,052,304 finite numeric bit patterns, 438 fractional Evidence records, and 20 rejected-schema records |
| Fixed 116-input public MCP replay | 115 parsed responses matched; all 116 Evidence states matched; 1 complete response object matched; 0 raw transport frames matched |
| Change from the prior native baseline | 14 malformed-input semantic differences fixed, with no regressions on those 116 inputs |
| Original import / large import profiles | Existing 118 and 22 finite comparison rows passed under their original comparator boundaries |
| Independent audit of the old import comparator | All 38 JSON application errors matched as parsed values, but 0/38 matched exact error text or member order; all four plain SDK exceptions matched |
| JavaScript preload declarations | Seven cases matched both actual original REA and independent Node observations; seven additional raw worker executions completed |
| Provider profiles | Six finite groups completed: Ghidra, JADX, Chrome, APK oracle fixtures, APK public MCP, and actual AAPT2/signing/two-worker checks |

The 116-input replay therefore remains a recorded mismatch, not a complete
contract pass. Its remaining scalar-string refusal and the error-text audit
motivate the B changes below. The old 118/22 result cannot be used as evidence
that their previously untested error-text boundary passed.

The provider composition retains two preparation failures. The first assumed a
separate `libsunec.so` that the actual configured JDK did not contain; no child
command ran. The second observed a successful AAPT2 version command but
incorrectly expected its banner on stdout instead of stderr. The third run
consumed both original failed receipts, bound the actual complete JDK tree and
the exact version bytes, and completed the original fourteen commands and
fourteen checks. None of the failed receipts was rewritten.

Both c25 GitHub PR jobs were later observed completed/cancelled, without supplied
step records or logs. They are not GitHub passes. The local source-bound matrix
is independent of those cancelled jobs.

The [candidate A audit archive](../qualification/rea-p0p5-679ccf-20261106/candidate-a/README.md)
retains the original inputs, responses, logs and failed receipts. Its independent
consumer read all 5,056 regular archive members and verified every byte count and
SHA-256; the 4,157 selected original files remained unchanged. Explicit omissions
cover duplicate executables, generated signing credentials and unrelated history.
This archive verifies preservation of A's observations; it does not qualify B.

## P1: explicit authenticated retention

The new routes are documented in [Evidence checkpoints](EVIDENCE_CHECKPOINTS.md):

- `rea_evidence_session_checkpoint`
- `rea_evidence_session_resume`
- `rea_evidence_session_list`

They require the existing verified private HTTP operator credential and complete
runtime policy binding. A checkpoint ID, tool argument or untrusted header
cannot select a different owner. Stdio has no persistent authenticated
credential scope and refuses these routes. A new session remains empty; recovery
is explicit and only replaces a still-empty session after complete validation
and a final cancellation check under its registry mutex.

Each immutable checkpoint retains the full canonical Evidence bundle, all
Unknown revisions, first producer origin and imported object order. Its
content-derived ID binds an exact canonical manifest, both payload hashes and
lengths, authority, schema/profile identities and complete counts. Resume
authenticates the complete record/Unknown graph and every retention entry;
matching file hashes alone do not authorize a payload.

Storage has explicit count, parser, byte and concurrency bounds. It checks
2,048 records and 8,192 Unknown revisions before cloning retention maps, limits
the canonical bundle to 128 MiB and retention metadata to 16 MiB, and limits the
complete store to 32 checkpoint/staging entries and 256 MiB. Two blocking owners
are admitted per process. A legal live session that exceeds this profile receives
an explicit refusal; it is not partially checkpointed.

The storage owner retains its runtime admission, bounded execution slot and
cross-process lock until real filesystem work ends. Publication requires file
synchronization, explicit close, staging-directory synchronization, create-only
rename and parent synchronization. Every create/reconcile attempt also confirms
the complete configured state-directory parent chain, including directories left
by an earlier failed attempt. The final configured state path, checkpoint
directory and all three member identities are rechecked at the existing read and
commit fences. A detached old state-directory descriptor cannot authorize a
receipt for a replacement directory at the configured name.

Cancellation before publication refuses and cleans only proven owned staging
inodes. After rename, the blocking owner completes durability confirmation;
failure returns no confirmed receipt and preserves visible content for exact
same-ID reconciliation. The configured administrator path/account remains a
trusted boundary. The format does not claim encryption, protection from
arbitrary malicious code under the same Unix account, or individual ChatGPT user
isolation for a shared operator credential.

## P1/P2: exact refusals without fabricated values

The finite import error formatter now has explicit projection rules for the
actual observed invalid-JSON, bundle-integrity, import-input and missing/wrong-kind
file error families. It requires the known complete field sets. Extra fields,
richer unobserved issue forms, native-profile failures and other operations
retain the previous projection. The strengthened 118 comparator separately
requires nonempty parsed-value, error-member-order and exact UTF-8 error-text
gates; four plain SDK exceptions remain a distinct class.

The captured original peers actually negotiated MCP `2025-11-25`. The locked
`rmcp` SDK version is 3.4.1; its server normalizes a complete response for this
legacy protocol before transport serialization. Complete-result regression tests
therefore use the same SDK conversion and additionally assert the internal
`Complete` discriminator. They do not hand-filter fields or alter the original
expectations. Actual public response and raw-frame comparisons remain separate.

A complete escaped root string outside Rust's Unicode representation can prove
that the root is a string and must fail an object schema. It cannot produce a
decoded JSON value. The low-level parser and checkpoint-byte parser still return
a representation gap. Only the actual file owner can produce the opaque negative
proof after:

1. A bounded complete grammar observation and physical EOF.
2. Exact byte length, matching hashes from both full reads, and descriptor and
   current confined-name identity checks.
3. A conservative materialization check covering the string visit that serde
   skipped when it encountered the unpaired surrogate.
4. Successful actual descriptor close and a final cancellation check.

Cleanup failures keep their primary error and never become schema refusals.
Import and analysis-view routes preserve their existing root-type rejection
semantics. Nested unpaired surrogates and non-finite numeric values remain
explicit representation gaps.

Twenty-one additional controls were observed through actual Node 22.23.4 and
the original npm public MCP tool. The native test contract has eighteen expected
exact refusals and three explicit gaps. Eleven new native lifecycle tests cover
budgets, threshold boundaries, complete reads, real source replacement,
cancellation and cleanup priority. A separate analysis-view test checks native
route consistency; it is not mislabeled as a new original analysis-view capture.

## P2/P3: retained static and engine scope

The combined source retains the recorded-core parser/worker, bounded model-layout
work, JavaScript profile v4 and the corrected Chrome observation design from the
other integration. Their parent observations do not qualify B.

Every B provider profile must rerun against its own frozen binary. The six groups
preserve the existing engine command sets, time budgets, original job identities,
cancellation/timeout/crash observations, complete original log reads and cleanup
checks. The APK producer uses actual AAPT2, keytool and apksigner on generated
fixtures. It does not install or execute an APK payload on a device.

Installed engine/JDK inputs have explicit byte identities and bounded installation
inventories. These observations do not attest every operating-system loader
dependency. Current limited host inventory does not establish universal absence
of licensed engines, and it does not qualify native IDA, Hopper, GDB/LLDB, ADB or
Frida adapters.

## P4/P5: fresh bounded lifecycle gates

The planned desktop+x230 recovery profile uses new private roots, generated
credentials and two original native jobs. It checks connection loss/reconnect,
same-key job reuse in a new session, private controller termination/restart,
original-job cancellation and repeated cold durable log readback. Its scope
does not include a host reboot, network partition, storage failure, x230
controller restart or an actual engine workload.

The checkpoint upgrade runner exercises an actual A → B → A → B sequence under
one generated credential and complete policy. It must observe a default-empty
session at each start, B's complete mixed-origin checkpoint, actual server
termination before input deletion, unchanged checkpoint bytes/inodes during the
old-version rollback, and exact explicit recovery after B returns. Historical
A source is checked from its fixed Git tree and original build evidence; the
current source path is not mistaken for the old source after it advances to B.

These are finite profiles. Complete upgrade/rollback, device behavior and
production deployment remain separate requirements. A representative cost
comparison can only be reported after the same declared behavior has passed
and whole-lifecycle accounting is actually available. Direct-child CPU or a
sampled RSS maximum is not complete process-tree cost, and this dev build is
not a release benchmark.

## Required B evidence

The source implementation and prepared runners alone are not passes. The fresh
qualification must retain its exact commit/tree, selected-source inventory and
monitor, toolchain/build configuration, actual binary, original inputs, complete
stdout/stderr, and authoritative terminal records for:

- Both feature configurations of strict Clippy and the full Rust matrix.
- The four actual original Evidence/number/schema gates.
- The two explicitly ignored local GNU backend gates, with the exact same
  source-bound library test artifact, positive executed-test denominators, and
  pinned installed readelf/yes/sleep inputs. Other skipped tests require an
  explicit applicability decision; a skip is never a passing observation.
- The 116-input replay, strengthened 118 and 22 profiles, and their distinct
  parsed/body/order/raw-frame comparison layers.
- The JavaScript dual-oracle and raw-worker observations.
- The real HTTP checkpoint and authorization sequence.
- All six actual provider groups.
- The bounded multihost and A → B → A → B checkpoint lifecycle profiles.

All reports keep full replacement, full cost benefit and production decisions
open until the corresponding complete conditions have actually been met. The
publication remains a draft review; it is not a production cutover.

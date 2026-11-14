# Caller-authority integration contract

This file describes integration seams for the frozen serial authority component.
It does not change any shared runtime file or activate an HTTP/MCP route.
Integration base: be1b871ce482fec97e65664866731c0b145e79c3.
Keep compiler d3e2c90173cf733e42b299d0c4274df4b593a12f and all existing gates.

## Final source closure

The handoff has 30 files: three production HIA sources, profile/provenance,
four build/qualification scripts, five Python suites, three Python fixture/
supervisor owners, one probe HIA packer, two compressed fixtures, six original
Rust recipe files, and four native documentation/evidence files. Use the exact
handoff file map, not developer scratch, remote job wrappers or authoring
generators. Original source files are read from the repository and separately
pinned; they are not replacement implementations.

The final HIA/profile/core-test/oracle bytes were recovered exactly from the
original v4 source capture. Eleven lost build/report/documentation files were
reconstructed and have new hashes. The previous lost 30-file handoff hash is
historical. It is not a hash of this recovered handoff.

## Builder entry and artifacts

Add one mandatory MODULES entry:

    key: caller_authority
    name: caller-authority
    source: native/caller_authority.hepta
    companion_sources:
      native/authority_loader.hepta
      native/authority_packer.hepta
    builder: authority_composition
    manifest_env: HIA_AUTHORITY_ELF_MANIFEST
    test: test_caller_authority.py
    additional_tests:
      test_authority_loader_kernel.py
      test_authority_transport.py
      test_authority_packer.py
      test_authority_evidence.py

Call build_authority(hepta, build_root, source_root=ROOT) from
scripts/hia_native_authority_build.py. Also call
build_loader_probe(hepta, build_root, source_root=ROOT) from
scripts/hia_native_authority_probe_build.py. Both reuse the same verified B3
workspace. Both recheck dependency identity before cached artifact reuse.
Neither bootstraps a different compiler for each suite.

The caller_authority aggregate module record requires these fields:

    builder: authority_composition
    source: native/caller_authority.hepta
    manifest: relative authority composition manifest
    sha256: exact authority manifest SHA-256
    probe_manifest: relative loader probe manifest
    probe_sha256: exact probe manifest SHA-256

The authority manifest contains nine fixed source/image/capability rows. The
layout verifier follows the actual RIP-relative metadata pointer, checks the
normalized source-owned adapter bytes, every descriptor and actual embedded
image, padding, private workspace layout and final ELF length. Updating a
manifest hash after changing ELF/table/image bytes does not admit the file.

The probe manifest retains real compilation and packing input/output receipts.
It returns only owned test-fixture bytes and is never a production tool.

## Required suite environment

Use a fresh output/FOLDER where FOLDER is caller-authority-rust-oracle.
Clear all inherited HIA_* variables with the existing qualification sanitizer,
then set only the following required values. All source paths use repository
ROOT; no adjacent checkout name is assumed.

Global values:

- HIA_AUTHORITY_ELF_MANIFEST: the top authority composition manifest.
- HIA_AUTHORITY_MANIFEST: its module_00.json, not the top manifest.
- HIA_AUTHORITY_LOADER_MANIFEST: its module_08.json.
- HIA_AUTHORITY_PROBE_MANIFEST: the separately built loader probe manifest.
- HIA_SCOPE_MANIFEST: independently qualified deterministic fixture-scope
  composition. It deliberately is not the OS-scope profile.
- HIA_HEPTA_DIR: the pinned compiler checkout.
- HIA_BUILD_ROOT: the shared qualification build directory if needed.

| Suite | Required output variable | Relative FOLDER output | Exact groups |
|---|---|---|---:|
| test_caller_authority.py | HIA_AUTHORITY_CORPUS_DIR and HIA_AUTHORITY_TEST_REPORT | controller/ and controller.json | 8 |
| test_authority_loader_kernel.py | HIA_AUTHORITY_KERNEL_CORPUS_DIR | kernel/ | 5 |
| test_authority_transport.py | HIA_AUTHORITY_TRANSPORT_CORPUS_DIR | transport/ | 6 |
| test_authority_packer.py | HIA_AUTHORITY_PACKER_REPORT | packer.json | 4 |
| test_authority_evidence.py | HIA_AUTHORITY_EVIDENCE_REPORT | evidence.json | 7 |

Invoke each with the ordinary record_check command
python -I -B ROOT/tests/hia_native/SUITE. Give each 120 seconds. The existing
suite limits are not enlarged. Each receipt requires exact tests_run,
expected_tests, counts and expected_counts, with all failure/skip counters zero.
The strict source helper also checks actual retained unittest completion text.

There are 20 direct controller contexts, 112 requests, 23 lifecycle calls and
786 native entries. The exported original corpus is 122 rows: 17 starts,
100 requests, one reconnect, two shutdowns and two explicit private fixture
extension transitions. Three native-only control contexts are selected before
startup; their exclusion is recorded, not chosen after a mismatch.

The loader suite has 110 actual processes, including 26 supervised processes.
The transport suite has 48 actual processes, 144 frames and 143 responses.
Its 17 supervised processes inspect actual workspace/buffer/FD cleanup.
Packer tests perform 30 native calls and eight actual cached NativeBuild checks,
including six refusals. Evidence tests accept eight complete evidence objects
and reject 37 mutations, including two consistently rehashed real loaded-image
substitutions. Evidence checks create zero native or original executions.

## Aggregate evidence and retention

Import evidence and SUITES from scripts/hia_native_authority_qualification.py.
After all five suites, call:

    evidence(ROOT, output, report, completed_test_summary)

Store the result as report.caller_authority_evidence. This validates 45
operational source pins, 102 composition artifact files, 25 probe files and
52 retained corpus/report/trace files in the recovered qualification.
The generic build driver must include the four new scripts in its source
inventory. Keep the full cold gate unchanged.

Add all returned artifact.artifact_sha256 and probe.artifact_sha256 entries,
prefixed with build/, to rust_oracle_inputs. Add every corpus_sha256 entry
directly; those keys already include FOLDER. Also bind source_sha256 and all
new final source/documentation files through the aggregate source map.
This preserves the complete native cases and raw traces, not only summaries.

The helper binds each packed dependency to its separately qualified owner:
record, KDF, codec, AEAD, nonce, fixture scope and real OS entropy. The direct
controller's actual loaded list binds root 0/loader 8 to the packed authority
and slots 1..7 to the independent fixture-scope image files. Slot 7 is explicitly
the deterministic fixture in direct tests; it is real OS entropy in the ELF.

Re-run evidence during the Rust driver's input-pin check. Admit this builder
through a custom branch; do not treat its top composition manifest as a flat
module. Require the same mandatory classification discipline as other owners:
caller_authority is in RECIPES, not NEW_COMPONENTS or a Python-reference bucket.

## Actual original Rust recipe

Add one mandatory RECIPES entry and call the helper's compare_original:

    compare_original(
        ROOT, output, report, rustc,
        record_check=record_check,
        completed_test_summary=completed_test_summary,
        qualification_env=qualification_env,
        cargo=cargo,
    )

Pass the environment sanitizer function, not an already-mutated environment.
The helper actually executes four retained checks:

1. cargo fmt --manifest-path tests/hia_native/authority_oracle/Cargo.toml --check
   (30 seconds).
2. cargo build --locked --release with a fresh target directory
   (180 seconds).
3. The newly compiled hia-caller-authority-reference with all 122 captured
   controller rows on stdin (120 seconds).
4. The complete five-group loader kernel suite with that new original binary,
   pinned SHA-256 and a fresh original-kernel corpus (120 seconds).

The source recipe includes full unchanged caller_scope.rs and
operation_crypto.rs plus exact original HttpAuth/load/require and new_owner_id
segments. The generated files must byte-match all original segments and access
shims before execution. The locked graph contains 133 packages; every registry
version/checksum matches the original runtime lock. It has a reduced feature
closure, so complete lockfiles are not claimed identical.

The kernel comparison requires all 110 pairs and 26 normalized logical traces.
Only adjacent ordinary reads are collapsed to account for Rust buffering;
action order, error effects and open flags remain. Every raw trace stays
retained. Random owner bytes are never compared for equality. The original
replay adds zero native cases and rechecks native evidence after completion.
The new comparison receipt is written exclusively to FOLDER/rust-comparison.json.

Seven original source pins are declared in ORIGINAL_PINS. The existing
operation_crypto source pin is reused; add missing original main, caller scope,
caller scope tests, search jobs, Cargo manifest and Cargo lock pins, including
their exact Git blobs from the baseline. Also include repository rustfmt.toml.

## Historical capture and recovery evidence

authority_receipt_fixture.json.gz contains 107 exact fixture members: 104 raw
v4 capture members, the two old controller corpus files, and the new actual
packer receipt. Captured original evidence requires all 103 inventoried raw
members plus their inventory file, complete stdout/stderr, original generated
source bytes, real native ELF identities and the complete case/trace domain.
It returns capture_only=true and new_executions=0.

The actual historical original run uses Rust 1.99.1, and is separately identified
in authority_original_rust_comparison.json. Rebuilding this helper does not
constitute another Rust run. The new CI recipe must pass on its actual toolchain.

The reconstructed test's initial cross-filesystem hardlink failure is retained.
Only the owned-cache copy method changed to an ordinary copy; no production HIA,
profile, compiler budget, count or acceptance rule changed. The subsequent
complete five-suite run passed. The rebuilt helper defines its own normalized
trace serialization hash; original raw native/Rust traces remain byte-identical.

## Expected inventory delta and scope

Against the stated be1 integration base, this adds three production HIA sources,
one executable component, five native suites and one real Rust recipe:
31 production HIA sources, 24 components, 46 native suites and 19 Rust recipes.
The unchanged cold check makes 47 checks at the end of the native phase.
The actual Rust recipe adds four checks; the overall pipeline gains nine checks.

The expected aggregate source inventory is 303 pins if the prior base remains
266: 30 final authority files, six newly listed original files and rustfmt.toml.
Recompute this from the real source inventory when merging concurrent fixes.

Keep all 125 original MCP owner statuses and the existing seven-image file
service unchanged. This new profile does not activate production auth routing.
Concurrent HTTP, metadata annotations, complete runtime replacement and
old-stack removal remain explicitly unqualified.

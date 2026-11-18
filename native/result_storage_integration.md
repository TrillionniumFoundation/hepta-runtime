# Private result storage owners

This candidate adds nine source-owned components of `request_results.rs`. It
preserves the published runtime and all 125 original production tool owners.
It does not activate public request storage or qualify removal of the old stack.

The integration base is runtime commit
`3a2a6e6a9c6faade416c17ebe37dc20174fed329`, tree
`80a8ed291b1d705068d6504e71bf3cae8633a211`. `base.json` pins the 956 existing
qualification inputs and the 297 inputs of this new component family. The
source directory is an exact partial checkout for qualification, not a Git
working tree. It initially adds 267 files without changing a baseline file.

## Runtime scope

| Owner | Native source | Qualified private operation |
| --- | --- | --- |
| Safe DTO | `native/request_safe_dto.hepta` | Typed retention admission and exact configured-platform lookup through trusted configuration op10 |
| Record construction | `native/request_retention.hepta` | Original Record transitions, typed payload serialization, Base64 and SHA-256 through fixed native children |
| Storage JSON | `native/request_storage_json.hepta` | Original Record, directory identity, anchor and marker typed projections and serialization |
| Record integrity | `native/request_record_validation.hepta` | Exact identity, payload-length, Base64 and digest checks |
| Record IO | `native/request_record_io.hepta` | Real descriptor-based read, staging cleanup, new-file save and replacement save |
| Directory lease | `native/request_store_directory.hepta` | Original private directory admission and retained descriptor leases |
| Archive metadata | `native/request_archive_metadata.hepta` | Actual anchor/marker reads, identity-sensitive validation and the bounded FIFO cache |
| Archive publication | `native/request_archive_publish.hepta` | Anchor publication and marker creation with actual file operations and original cleanup order |
| Archive store | `native/request_archive_store.hepta` | Held archive and shard descriptors, creation, binding and verification of all 256 shards |

Each owner has an adjacent `_abi.md` and `_composition.json`. The fixed build
profile is `native/result_storage_profile.json`, SHA-256
`8038eddd75fe8abfb96d92a05c6bd2c436af6f52385bc9eea26d551c3cfbdb44`.
It declares 30 actual HIA images and six static executable graphs, including
the immutable configuration graph needed by safe DTO and retention.

Python is used for compilation orchestration and reference tests. The actual
runtime graphs contain HIA images and fixed native effect boundaries. No Rust
or Python semantic fallback is present in those executables.

These private operations do not by themselves close the public `call_tool`
admission, audit ordering, response retention, global mutex/poison semantics,
root-path preparation, or cancellation ownership. The separately frozen root
preparation and audit owners are subsequent inputs, not implicit parts of this
profile. The current generic Value child also retains its previously disclosed
special first-key RawValue success gap. A separately qualified replacement is
required before claiming that full input domain. All production and complete
runtime flags remain false.

## Fixed word operations and completed-process ordering

The follow-up to `86b5099550d92a4a9433257926929cb7656203f5` addresses two
observed failures without changing any case or deadline. That commit's native
PR exceeded the 180-second retention limit. Its native push completed every
native and original group, but final re-admission mistakenly treated the later
storage evidence-control process as an earlier process in the public-control
snapshot. Both failed qualifications remain historical failures.

The private `result_storage_value.hepta` replaces exactly three loop-based
eight-byte word helpers with explicit byte operations in the same order. Its
other 44 IR functions are unchanged. The retention owner uses the same three
helpers and preserves its other 24 IR functions. All offsets, wrap arithmetic,
individual byte loads/stores, trap order, resource limits, output admission,
and persistent state transitions remain in the original domain. No generic
Value, Record IO, common loader, compiler, or original Rust implementation is
replaced by this private derivation.

`scripts/result_storage_words.py` rebuilds the fixed helpers from their
source-owned authoring text. It independently checks all preserved functions
and reconstructs the complete prior retention source, whose digest must equal
the frozen baseline. Record IO retains its existing imported helper and exact
image; its import proof explicitly selects that reconstructed baseline rather
than falsely naming the changed current function. The seven reporting controls
reject coordinated edits to function bytes and their claimed digests, original
imports, authoring text, and child routing. The separately qualified RawValue
success repair is still not part of this graph.

Each public evidence-control snapshot must equal the exact complete prefix
before its unique actual process record. A later independent storage control
does not retroactively become part of that prefix. Missing, duplicated,
reordered, altered, and future process records remain rejected. The collector
still requires the complete fixed final process set and all three successful
evidence-control processes.

## Actual native entry points

`scripts/hia_native_result_storage_qualification.py` provides:

- `build_storage(hepta, build, root)`: executes the real source builder with an
  owned process, a 180-second deadline and three-second cleanup; retains its
  complete streams and then validates every compiled image and packed ELF.
- `build_evidence(root, build, hepta=..., require_process=True)`: independently
  validates sources, actual compiler and packer observations, full buffers,
  fixed profiles and embedded image bytes. It does not execute an owner.
- `commands(root, build, output)`: returns the exact 13 native command arrays.
- `domain_evidence(root, build, output, domain)`: checks one complete corpus and
  its source-derived expected cases, native images and retained streams.
- `native_evidence(root, build, output, completed)`: joins all 13 domains with
  their actual bounded process receipts and completed stdout. `completed` is a
  domain-to-process-directory mapping. It never launches HIA or Rust.

`scripts/build_result_storage.py` is the source-only builder CLI. It expects
`--hepta` and `--build-root`. Its output is `result-storage-build.json` in the
build root. Building into an existing completed storage result is refused.
The common build/loader bytes and compiler pin are unchanged from the base.

`tests/hia_native/run_result_storage_native.py` runs all 13 domains with
`--root`, `--build`, `--hepta` and `--output`. The four pure domains are
`storage_json`, `record_validation`, `safe_dto`, and `retention`; the remaining
domains are `record_io`, `record_io_faults`, `directory`,
`archive_metadata`, `archive_metadata_faults`, `archive_publish`,
`archive_publish_faults`, `archive_store`, and `archive_store_faults`.
Every individual process retains its original 180-second deadline.

The final source revision fixes a concrete repeated-admission issue: archive
case generators intentionally change their shared typed `ANCHOR`. The evidence
reader now loads the pure typed-case source into an independent module instance
for each check. The actual HIA and original test inputs are unchanged. Same-
process metadata, publication, and repeated metadata ordering produces the
original 4,221-row typed input SHA
`949851be2cdb1fa8e8b158c508b4dc4b1eabdab70cda292827b4bfc099da6cac`.
The earlier failed combined evidence admission is retained separately.

## Fresh original reference entry points

`tests/hia_native/compare_result_storage_original.py` takes `--root`, `--build`,
`--native`, `--output`, `--native-evidence`, `--native-evidence-sha256`,
`--rustc`, `--cargo`, and one `--domain`. Run it in an owned process group;
the script refuses an unowned group. The nine recipe names and their complete
observed domains are:

| Recipe | Actual original processes | Actual original requests |
| --- | ---: | ---: |
| `safe_dto` | 9 | 5,591 |
| `retention` | 13 | 6,315 |
| `storage_json` | 1 | 4,221 |
| `record_validation` | 1 | 9,361 |
| `record_io` | 282 | 666 |
| `directory` | 121 | 347 |
| `archive_metadata` | 1,672 | 3,550 |
| `archive_publish` | 1,694 | 3,378 |
| `archive_store` | 160 | 1,455 |
| Total | 3,953 | 34,884 |

These counts include the explicitly identified startup refusals and killed
fault cases. They do not assert that every entered request receives a response.
The native filesystems use separate fixtures; identity projection occurs only
after the test verifies the observed device/inode against its own live held
descriptor. Complete response bytes, filesystem observations, selected held
descriptors, short writes and recovery traces are retained.

`scripts/hia_native_result_storage_reference.py` validates 144 unchanged source
blocks, exact runtime-lock dependencies, original Rust 1.95 tool identity, all
actual registry source members before and after compilation, retained `.crate`
archives, the built executable, exact argv/cwd/input, and every response. The
nine recipes use separate writable Cargo/output directories and can be grouped
without sharing mutable reference targets. Current retained-native captures
are fully checked before and after each fresh original replay; those checks
add zero native executions. Historical fixture checks never count as fresh
Rust executions.

The complete wrapper uses nine separate 180-second process limits. It is not
one enlarged deadline. Builds use a private `TMPDIR`; ai395's shared `/tmp`
inode exhaustion is recorded as an environment constraint, not bypassed by
deleting unrelated files or increasing limits.

## Evidence controls and integration requirements

`scripts/check_result_storage_evidence.py` is a separate evidence-only entry.
It requires a quiescent, exclusively owned completed directory and the exact
native seal and original suite. It temporarily changes retained source,
compiler output, native images, ELF bytes, corpus bytes, actual process
receipts, original source/archive/binary and original complete streams.
Every modified file has an external restoration copy before the mutation;
the original bytes and mode are restored in `finally`. Full native and all
nine original admissions run before and after the controls. This entry counts
no new semantic executions.

The aggregate integration must register the actual 13 native processes and
nine fresh original recipes, validate their completed stdout and current
source maps, retain all complete outputs, and run the corruption controls only
after original processes have drained. It must not replace those processes
with the evidence-only readers. The component can use a separate native and
original partition to retain the existing 15-minute job and 180-second process
limits. Existing modules, tests, reference domains and source checks remain.

The private observed build reuses a byte-checked existing d3 bootstrap and
does not claim a new full compiler cold replay. The repository's fresh cold
gate remains required for the eventual integration commit. Publication of this
candidate is separate from the already published collection fix.

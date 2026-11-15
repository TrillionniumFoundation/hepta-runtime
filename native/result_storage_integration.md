# Private result storage owners

This family implements nine private owners from `request_results.rs`. It is
integrated with the current shared HIA JSON, regex and client-context owners.
The production target remains commit `737acf6f901e46c57b0b4374e323e0d1132e0d49`
with 136 handlers. These components do not activate public storage dispatch or
qualify production replacement and removal of the old stack.

## Owners and graph

| Owner | Native source | Private operation |
| --- | --- | --- |
| Safe DTO | `request_safe_dto.hepta` | Typed retention admission and exact configured-platform lookup through trusted configuration op10 |
| Record construction | `request_retention.hepta` | Original Record transitions, typed payload serialization, Base64 and SHA-256 through native children |
| Storage JSON | `request_storage_json.hepta` | Record, directory identity, anchor and marker typed parsing and serialization |
| Record integrity | `request_record_validation.hepta` | Identity, payload-length, Base64 and digest checks |
| Record IO | `request_record_io.hepta` | Descriptor-based read, staging cleanup, new-file save and replacement save |
| Directory lease | `request_store_directory.hepta` | Private directory admission and retained descriptor leases |
| Archive metadata | `request_archive_metadata.hepta` | Anchor/marker reads, identity-sensitive validation and bounded FIFO cache |
| Archive publication | `request_archive_publish.hepta` | Anchor publication and marker creation with actual file operations and original cleanup order |
| Archive store | `request_archive_store.hepta` | Held archive and shard descriptors; creation and verification of all 256 shards |

Each owner has an adjacent `_abi.md` and `_composition.json`.
`result_storage_profile.json` declares **30 HIA images and six static executable
graphs**. The current profile SHA-256 is
`13cc2db561ed13ba9b063872d689c345465f51468982a630828d2b1ce95f6737`.
The compiler is Hepta `d3e2c90173cf733e42b299d0c4274df4b593a12f`, with fixed-point
image `bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`.

`result_storage_child_rebinding.json` retains the previous lineage and records
the current Value and four regex images. Safe DTO and retention import the
same four client-context function instances from the canonical dual-ABI owner;
the imported function bodies and complete call relocation are unchanged.
All 48 inherited configuration functions remain checked by canonical IR hash.
The original Rust source pin is unchanged. Historical observations are not
relabeled as executions of the new graph.

Python orchestrates compilation and reference tests. Runtime executable graphs
contain HIA images and fixed native effect boundaries. They have no Python or
Rust semantic fallback. Public `call_tool` admission, audit ordering, global
mutex/poison behavior, root-path preparation, restart and cancellation remain
separate contracts. All complete-runtime and production flags remain false.

## Native qualification

`scripts/hia_native_result_storage_qualification.py` provides the production
build and independent evidence readers. `build_storage(hepta, build, root)`
launches the actual source builder under its 180-second deadline and retains
its complete output and process receipt. `build_evidence` checks source bytes,
compiler observations, full compiled images, packer requests and all embedded
ELF bytes. Its default requires the actual build-process receipt.

`commands` returns the exact thirteen native processes. The four pure domains
are `storage_json`, `record_validation`, `safe_dto` and `retention`. The others
are `record_io`, `record_io_faults`, `directory`, `archive_metadata`,
`archive_metadata_faults`, `archive_publish`, `archive_publish_faults`,
`archive_store` and `archive_store_faults`. Each keeps its existing 180-second
limit. `domain_evidence` and `native_evidence` read every completed corpus and
its bound images and streams without executing a semantic owner.

The aggregate registers the nine components in an independent `storage`
native partition. It preserves the existing eight other native partitions,
including the complete ordered public View producer/consumer chain. The
standalone `run_result_storage_native.py` entry accepts `--root`, `--build`,
`--hepta` and `--output`. A new result directory is required for every attempt.

The typed JSON reader loads an independent case-generator instance on every
admission, preserving the original 4,221 rows even after archive generators
change their own `ANCHOR` fixture. The complete old typed-input SHA remains
`949851be2cdb1fa8e8b158c508b4dc4b1eabdab70cda292827b4bfc099da6cac`.

## Reachable RawValue behavior

The shared Value child is the current HIA implementation, including private
RawValue parsing. The safe-DTO text field is a real generic Value boundary;
retention consumes that decision. Each of these two native suites appends a
separate **104-case** segment after its complete earlier corpus. Each segment
contains **41 accepted and 63 refused** cases: first-key and escaped markers,
nested documents, wrapped fields, non-string and malformed contents, extra or
duplicate marker entries, numeric range boundaries and numeric overflow before
duplicate pruning. The original case generators and historical fixture streams
remain unchanged.

The extra fixed inputs and actual locked Rust observations live under
`tests/hia_native/fixtures/result_storage_reference/raw_value`. Their manifest
SHA-256 is `ca54a3fba9539c53a59fcac0280736fb45b4922fadb8e672ee2b103efc685d34`.
Native evidence retains the full canonical owner requests, complete native
responses and actual configuration-child traffic. Readers check those bytes
against every source-generated case. Historical reference loading always
records zero fresh Rust executions. The two corresponding original recipes
must also replay every added request using their newly compiled executables.

## Fresh original comparison

`compare_result_storage_original.py` accepts the root, build and native result
paths, output directory, native evidence path and external SHA-256, Rust and
Cargo executables, and one domain. Its process group must be owned. The nine
recipes preserve the following complete earlier domains:

| Recipe | Earlier processes | Earlier requests | Added RawValue processes / requests |
| --- | ---: | ---: | ---: |
| `safe_dto` | 9 | 5,591 | 1 / 104 |
| `retention` | 13 | 6,315 | 1 / 104 |
| `storage_json` | 1 | 4,221 | 0 / 0 |
| `record_validation` | 1 | 9,361 | 0 / 0 |
| `record_io` | 282 | 666 | 0 / 0 |
| `directory` | 121 | 347 | 0 / 0 |
| `archive_metadata` | 1,672 | 3,550 | 0 / 0 |
| `archive_publish` | 1,694 | 3,378 | 0 / 0 |
| `archive_store` | 160 | 1,455 | 0 / 0 |
| Total | 3,953 | 34,884 | 2 / 208 |

Startup refusals and deliberately killed fault cases are included; these
counts do not imply that every entered request produces a response. Held
filesystems are independent, and inode/device projection occurs only after
checking the live descriptor. Complete response bytes, filesystem observations,
short writes and recovery traces remain retained.

The reference helper checks 144 unchanged original blocks, the exact runtime
lock, Rust 1.95.0, complete registry members before and after compilation,
retained crate archives, executable bytes, argv, cwd, input and every response.
Each recipe has its own writable Cargo target, temporary and output directory.
All nine keep their separate 180-second process limits. Native captures are
fully checked before and after each original replay; those reads execute no
native owner. The independent `storage` original partition joins the existing
seven original groups. Every CI job retains its existing 15-minute limit.

## Evidence controls and retained failures

`check_result_storage_evidence.py` requires a quiescent, exclusively owned
completed result and its external native and original seals. It preserves all
**25 earlier corruption controls** and appends **five RawValue controls** for
complete native input/output, completion, original output and a consistently
rewritten original command. The full native and all nine original admissions
run before and after the thirty refusals. Every mutation receives an external
restoration copy before writing; exact bytes and modes are restored in
`finally`. Evidence admission does not substitute for an actual execution.

The aggregate requires source-bound actual process receipts, every complete
stream, both original RawValue replays and the corruption controls. Partial
results, failed attempts, raw diagnostics and regression inputs remain retained
outside Git. Local observed graph rebuilds may use an independently byte-checked
cached bootstrap and must say so. The repository's complete fresh cold and
combined native/original CI gates remain required for an integration commit.

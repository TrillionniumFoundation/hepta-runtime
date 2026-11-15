# X230 R16 / R17 publication evidence policy

The active working plan is `packaging-plan-v3.json`. The original `packaging-plan.json` and revision 2 are retained. A later change after a real inventory is frozen requires a new plan/inventory revision; original evidence and failed packaging attempts remain intact.

## Packages and layout

Each completed native, configuration, boundary, recovery, or qualification campaign has its own archive. R16 diagnostics and R17 candidate source evidence are separate packages. The final R17 launcher/selection gate is a separate control-evidence package. An entry marked `pending` cannot be packed.

Publication destinations are `tools/x230/20261104/r16/` and `r17/`. Each package produces three files: `<stem>.tar.gz`, `<stem>.manifest.json`, and `<stem>.archive.json`. The manifest inside `_publication/<package-id>/manifest.json` is byte-identical to the external manifest. It lists every original member's size, SHA-256, source root/relative path, archive path, and frozen file identity. It excludes itself from its own file list; the archive receipt records its exact hash and the archive's hash. The source-to-member mapping supplies relocation provenance without rewriting original JSON.

Archive members retain source byte content. Tar ownership, mode and timestamp are normalized to uid/gid 0, mode 0644 and mtime 0; source metadata is preserved in the manifest. Gzip uses mtime 0, an empty filename and compression level 6. Original test-log gzip files are included without recompression or modification of their own bytes.

## Closed selection

Campaign raw files are selected from the original report's explicit size/hash references. Native and configuration packages contain all four ABBA rounds, including both first and restart controller generations. Config includes the exact selected NUL-delimited worker environment entries and their JSON receipts. Whole process environments are excluded.

Boundary includes only the six `controller/state/jobs/<job_id>.json` records named and fingerprinted by `report.six_originals`. Recovery enumerates canonical native replies and both SSH streams from `native_calls` and `ssh_calls`; sequence gaps and empty stderr files remain intact. Six original request JSON files are retained. The original 12 measurement scripts accompany each campaign; config and boundary add their original extensions and freeze/policy files.

Qualification includes the original report, source map, isolated audit, commands/tests indices, summary, Cargo metadata/events, retained binary metadata, and raw stage/test logs. Stage stdout/stderr hashes are checked. Both `tests.jsonl` and `commands.jsonl` are used to enumerate gzip logs, including list/ignored-enumeration commands. Ignored, unexecuted test rows remain in the original index and do not create fictitious log files. Expanded gzip lengths are checked against original byte counts. Qualification tool sources come only from `report.harness_before`, which must equal `harness_after`.

Diagnostics retain positive and negative findings, the failed initial hash build, the failed manual profile attempt and its successful successor, openat2 counterexamples, independent source reviews, patches, and the probe's source/lock/feature graph/verify/oracle/raw timings. Probe fixtures are reconstructed by the preserved preparation script. Target directories, ELF/test binaries, fixture FIFO/symlink/hardlink/mode000 objects, sockets, Cargo caches, SSH configs, private profiles and keys are excluded. Binary identities remain in original metadata with their remote paths and hashes.

## Filesystem and content guards

Every selected source path is canonical and relative to a declared absolute root. Each directory component is opened with `O_DIRECTORY|O_NOFOLLOW`, and the final file with `O_NOFOLLOW|O_NONBLOCK`. Selected files must be regular and have one hard link. The packager never follows a symlink, chmods a fixture, or walks an undeclared subtree. Pattern selectors have a narrow named base and bounded depth; root metadata patterns are top-level only.

Content checks reject executable signatures, private-key markers and recognized credential assignments. These checks supplement the closed selection; they are not a universal secret detector. Suspicious evidence causes failure and is preserved remotely for review, rather than silently redacted or omitted. The archive process changes no original bytes.

An inventory binds size, SHA-256, inode, device, mode, link count, mtime and ctime. Packing opens every file again, verifies that identity, streams and hashes the bytes, checks EOF and rechecks metadata. A changing source aborts the attempt. Existing outputs are never replaced. Preserve stdout/stderr and return code of every failed inventory/pack attempt, then fix the specific issue in a new recorded attempt.

## Verification and offline scope

Every archive is independently streamed through gzip/tar after creation. Member names, regular-file type, normalized metadata, membership, sizes and SHA-256 must match the manifest. The verifier drains tarfile's own buffered stream, requires the second zero block, rejects nonzero trailing data, and validates gzip EOF. No extraction is needed for this check.

Native offline entry point: `analyze_native_observation.py --report ... --output <new-path>`. `audit_native_evidence.py` is an imported helper and has no standalone CLI. Config and boundary use their verifier with `--harness-root` pointing to the extracted sibling `measurement-tools`. Recovery uses `verify_cancel_recovery.py --report ... --output <new-path>`. Original reports remain unchanged.

Qualification's original audit and exact logs are inspectable. The archive excludes ELF files, so it does not promise that `audit_isolated_tests.py` can repeat every original check in an arbitrary extracted directory. A source hash, retained binary hash or test log is not a fresh execution of the binary.

## Execution and transport

The root agent owns measurement windows. Use sequential `nice -n 19` inventory/pack jobs only after the root releases the window. Packaging never invokes a runtime workload, Cargo compilation, qualification, service operation or GitHub write. Report archives over 50 MiB before transport so package boundaries can be reconsidered.

`publication_transfer.py` creates a transfer index with repo path, absolute remote path, planned local path, bytes, SHA-256 and Git blob SHA-1 (`SHA1("blob " + decimal-size + NUL + exact-bytes)`). Pieces contain at most 45,000 raw bytes / 60,000 base64 characters, with no added newline. Each piece has independent raw and encoded hashes and an exact offset. Reassembly refuses to overwrite a differing staged file and verifies the whole SHA-256 and Git blob SHA-1.

The final local index verifies actual staged bytes, retains remote provenance, and adds the root-owned Mac holder evidence from its explicit local directory. Local-only artifacts have a null remote path with an origin explanation; their own manifests retain original Mac paths. The root agent alone performs GitHub writes.

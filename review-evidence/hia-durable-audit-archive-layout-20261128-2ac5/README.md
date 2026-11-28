# Native audit v12 physical layout and restart

The HIA actor owns original flat versus sharded selection, bounded physical layout checks, the 256-shard initialization transaction, restart from durable intent, and retained-directory fences. It uses the same borrowed audit root for actual metadata, PinnedAnchor and publication children. No caller-supplied descriptor enters the public request. The fixed descriptor capability retains actual root, legacy, shard root and all shard directories; pending child request and action bytes remain frozen until one exact ACK. Its HIA packer emits the actual sealed executable bytes. The assembler is a byte oracle, not a runtime policy broker.

## Actual qualifications

The complete paired filesystem run passed all 12 cases and 48 original/native stateful operations in 73.012610 seconds. The cases are flat open and fence, complete initialization of all 256 shards, existing complete layout, and restart at Intent, RootCreated, RootBound, ShardCreated(0), ShardBound(31), ShardCreated(255), ShardBound(255), Anchor and IntentRemoved. Every original checkpoint callback and complete existing legacy record are preserved.

The second full boundary run passed 88 controls in 37.380724 seconds: 53 real paired filesystem scenarios, 19 HIA actor/input/ACK controls, 13 descriptor capability controls, and three damaged-header controls after one real metadata, PinnedAnchor or publication child. The filesystem set contains 49 refusals and four admitted recovery paths. Rejected physical operations preserve complete before/after snapshots and existing legacy file bytes/stamps. The three child response controls retain the real already-completed effect and reject its altered reply; they do not claim kernel fault injection.

The frozen original observer and the original 29 archive-store methods were rebuilt and executed using the original complete Cargo.lock/default features/release profile. The evidence includes all 360 locked registry archive pins, actual compiled dependency/source manifests, the full oracle and original 59,449,184-byte unit executable, and all method results. The observer is SHA256 7f646c7af4b36387639e165f0291d5300ceb4a1c6a6b64aedab8b1594b717833. The original 29 bodies remain a Rust reference domain; this checkpoint does not call those full bodies HIA passes.

Nine complete actual compiled HIA modules were copied with full source/image/manifest verification from the declared d3e2 native compiler domain to ROG. No different compiler or old cold authority is inferred. Every source, manifest, image, original binary and proof was checked before and after each qualified run. Complete stdout/stderr, requests, responses, all HIA actions, actual physical snapshots and all source predecessors are retained.

## Preserved attempts and corrections

The first smoke preparation failed because one already-qualified anchor QA file had the same bytes but a different physical mode after transfer. Its source capture was corrected explicitly; no policy was changed for that preparation.

The next smoke exposed a new qualifier bug: the default absent checkpoint and the absent result field were both None, causing an unintended cut. The qualifier now injects a cut only when explicitly requested. The subsequent actual native run exposed a product bug in the PinnedAnchor response offsets. The actor now reads the declared format field, the complete root/legacy identity and the exact reserved suffix at their actual offsets. The complete old actor and failing workspace/output remain available.

On Desktop ext4, the original Rust initialization exceeded the new qualifier's 10-second per-command ceiling after visibly constructing part of the 256-shard directory. That failed attempt and full partial physical state are preserved. No timeout was increased. The original tests use tempfile::tempdir(); on ROG the actual original /tmp is tmpfs. The complete qualification therefore uses an explicit fresh fixture directory on that original filesystem domain, retaining both the 10-second new QA command ceiling and the 180-second full gate.

The first boundary run passed 39 actual refusals, then the new qualifier's general intent-prefix branch swallowed its specific intent-reappeared fixture and failed while creating the fixture. The exact predecessor is retained. The successor excludes only that label from the general branch; product HIA and capability bytes are unchanged. The complete successor 53+19+13+3 run passed.

## Full original custody

originals-index.json lists ordered archive shards with exact length, offset and SHA256. Concatenating these shards reconstructs one tar.gz whose whole hash is recorded. Its manifest maps every original logical path to its complete byte object, mode and physical capture. All members and the concatenated archive were read back. Physical fixture records retain unreadable modes, symlink targets, special-file type and real read refusals without chmod or repair; readable bytes and authored inputs are retained separately.

The shared archive registry, content watch, record namespace, redb persistence and the ten public Durable Requests handlers continue in following work. This physical layout qualification does not claim those public paths complete.

The publication whitespace check reports one final blank line in the already-qualified layout author input. That exact whole file is intentionally retained; the formatting finding and initial checkpoint assertion are recorded in publication-checks.json, and no formatting PASS is claimed.

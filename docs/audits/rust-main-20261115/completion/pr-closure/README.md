# Rust PR closure completion evidence

## Completed scope

The fixed 93 Rust PRs were closed in 19 batches against merged main `737acf6f901e46c57b0b4374e323e0d1132e0d49`, with candidate `e425d92b6a0dedf13eb3e484e76419ee756804c0` and audited tree `76652098f4b5bcad487071f2eaefd82d7fed219c`. All 93 outcomes are `CLOSED_AND_VERIFIED`; there were no already-closed skips and no uncertain v2 outcomes. Each completed batch revalidated the exact merge proof and each PR's head/base/draft identity.

The PR-closure agent made no branch-ref, default-branch, HIA PR, workflow-setting or comment mutations. PR121/122/124 remain outside the closure set. PR120 was closed while its frozen HIA dependency head remained protected.

**This package proves PR closure and records pre-cleanup observations. It does not establish completion of branch deletion or default-branch migration. Root owns those separate operations and their final receipts.**

## Per-item custody

`closure-journal-v2.tar.gz` is the original sealed archive, SHA256 `842bb1ac8e82a4b53d4974c7ff4c485dc244b5e0345ccc276376020a90f42d2e`. Its 357 files include all 93 before receipts, all 93 exclusive/fsynced close intents, all 93 after-state outcome receipts, and all 19 completed batch records plus merge/readback and operation bindings. `closure-journal-manifest.json` supplies every archived file's SHA256 and byte count. Packaging independently reread every archived file and checked its hash.

The initial v1 attempt stopped while parsing the first read-only PR125 response, before any PR before/intent/outcome receipt or close call. Its zero-mutation STOP journal was retained. The complete postclosure snapshot archive includes that prior stopped-journal archive and evidence; no STOP record was reset to continue v2.

## Readable records

- `exact-93-closed-verification.json`: independent full-REST postclosure observations for all 93 fixed identities.
- `closed-pr-relationships.md` and `.json`: exact PR list and head/base relationships; the JSON retains full SHAs.
- `pr-close-exact-identities.json`: unchanged reviewed identity set, SHA256 `7de95f9fb6f72218d87e469f801bfacf5ff9bb8ffd849a88679f1fced3d26b31`.
- `closure-operation-summary.json`: caller/helper/executor/proof/authorization bindings and operation counts.
- `postclosure-readiness.json`: 109 PRs, only 121/122/124 open, no open deletion dependency, 157 refs, unchanged original149 leases, merged-main source custody149/0 rewrite/42 archives/5244 paths and exact45 standalone files.
- `precleanup-readiness.json`: later independent refs/open-PR refresh before root's dry-run. The HIA native tip had externally advanced to `7c4ef433be617341107cebc23e8cda8a39e55fe3`; the preservation observation was refreshed without moving any HIA ref.

## Complete snapshots

`postclosure-readonly-snapshot.tar.gz` and `precleanup-readonly-snapshot.tar.gz` contain their respective source snapshot directories in full, including raw REST pages, ref readbacks, plans, validation receipts, prior plan copies and empty isolated Git-read directory structure. Each has an accompanying per-file SHA256/size/mode manifest and a verified archive SHA256. Neither snapshot contains Git object files, symlinks or fetched repository object databases. The package contains no authentication credentials.

These are time-bounded observations. HIA work may advance externally, and root's cleanup script must still read fresh refs/PR dependencies and enforce the exact deletion leases. `MANIFEST.json` and `SHA256SUMS` bind this prepared evidence package.

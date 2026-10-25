# A27 follow-up reproduction sources

Runtime source stays at qualified A26. The CString candidate is rejected; the archive r02 comparison is invalid after the baseline 64K/C4 failure. No script here installs or restarts a runtime.

## Recompute public CString arithmetic

From the repository root:

```bash
python3 tools/x230/a27-followup/recompute_prepared_path_public.py
```

This reads the exact published compressed operation ledger and analysis, checks all 2,176 original rows and 32-cell order, both sets of 17 semantic cases, and independently recomputes the eight ABBA block CPU/thread/wall values and original gates. It does not reconstruct private authority identities or independently verify the original binaries. The archived public arithmetic receipt records the actual execution of this tool.

## Reconstruct the private evidence workflow

`recompute_prepared_path_result.py`, `build_prepared_path_publication.py` and `test_prepared_path_publication.py` are byte-exact provenance sources from the private experiment workspace. They require the original private archives, original source bundles and frozen A25/A26 publisher dependencies at the relative paths declared in their constants. Restore that original workspace layout and place the publisher and its test together in a tools directory one level below its root. Those private inputs are deliberately absent from this public repository. These are not standalone public-fixture tests.

The public-only arithmetic tool above is the supported reproduction path using repository files alone. The full publisher refuses changed private inputs, non-identity numeric changes, incomplete original ledgers and unapproved schema-key transformations. Its complete public package, package verification and independent review are retained in `docs/evidence/x230-a27-followup/`.

The archive interrupted publisher is separately retained with its own complete public evidence and inventory. It preserves incomplete execution and missing cleanup witnesses. Later completed-shape values in the failed r02 analyzer must not be used to turn an incomplete experiment into a valid comparison.

Frozen source bundles under `docs/experiments/x230-a27-followup/` retain rejected candidates and probe-only code. These are not production source selections; compilation, qualification and measurements belong on the authorized x230 development environment.

# Recover the original Kaggle artifact collection without inventing provider evidence

This change lets an already acknowledged, fixed Kaggle notebook version reuse
recovered local payload bytes after a fresh remote manifest, source and terminal
status check. It is intended to finish the original NDU mastery collection whose
2,336 payloads had already been recovered, while the router reservation remained.

The original identity is `ndu-repair-mastery-20261120-aa42a9-v1`, provider request
`hc-301097a07c1fb980f74152da554a52be6339c371`, account `qiqian`, kernel
146145883/version 1. Payload plus manifest is 7,002,550 bytes under the original
8 MiB cap. Source/kernel/version/request/manifest identity cannot be established
by caller receipts or local cache. Each payload must match the fresh remote
manifest's exact size and SHA-256; cache payloads do not acquire fake HTTP receipts.

## Two exact sources

The main feature changes the ordinary adapter and CLI while preserving main's
strict inventory readiness and base submission behavior. The deployed snapshot
keeps the separately observed CreateOnly CLI/targetless readiness behavior. The
deployed file did not exist on the inspected public main; its prior provenance is
a version-bound host read, not an invented GitHub commit. `BASELINE_DIFFERENCES.json`
records each exact original hash. Main jobs and transport are byte-identical to
the observed deployed originals. The independently pinned deployed CLI and actual
router fixture keep the production collect argv and state-transition test honest.

## Evidence and remaining operational step

The frozen deployed snapshot passed 77 tests, including 29 adversarial cache tests
and four tests using the actual deployed router body, actual CLI and temporary
ledgers with provider transport mocked. The main-compatible full Kaggle suite
passed 109 tests, and the shipped manifest equals its generated contract. A first
full-suite attempt against the deployed CLI retained two incompatible main
readiness expectations; its failures are preserved, not silently removed. The
local offline SDK check initially reported missing SDK packages. A single check
in the original ROG venv then passed all ten official serialization cases with
socket connections blocked, no attempted connection and no provider/auth call.

The independent entry-switch review covers native version CAS, wrong hashes,
concurrent version changes and rollback without ledger changes. Activation and
real provider import/normal router collection remain distinct operations until
their exact live receipts exist. Tests and prepared source do not establish
COLLECTED or release of the original reservation.

## Execution and rollback

`DEPLOYMENT_PLAN.json` contains exact allowed commands, paths, caps and stable
operation keys. Preparation scripts run with `/usr/bin/python3.12 -I -B`, never
`-O`. Rebuild the external cache from original immutable archive, manifest and
summary; do not accept the adapter's old staging directory as cache input. Stage
the five complete modules in a new private release, retaining every old byte.
Only then switch the single existing account entry using the reviewed native
expected-version CAS controller. The fixed compute bootstrap, its manifest,
router, account OAuth guards, session and interactive paths remain intact.

After official import, the original router's normal collect path must make its
own observations, recheck output integrity and execute its existing
`finish_collection` transition. Unknown write/status outcomes must remain unknown.
Do not edit SQLite, record JSON, locks, reservations or provider receipts to force
success. Rollback restores only exact original entry bytes; it never rewrites
new cache provenance into fictitious HTTP provenance. The old adapter cannot
independently verify the newly introduced cache receipt, so retain the new
release and all original/imported evidence even after entry rollback.

No new science, submission, account substitution or resource lease is created by
this recovery. The separate sunfo request still lacks a server acknowledgement
and is not closed by this fix.

## Reproduce offline gates

From repository `tools/cloud-compute/kaggle`, run
`python3 -B -m unittest discover -s tests -v`. The original Cloud Compute workflow
already runs this suite; no Rust runtime change is made. The deployed snapshot's
77-test gate uses its preserved three test files and exact router fixture.
`verify_contract.py` requires the original SDK environment and makes no network
request. All prior failed gate output, final receipts and raw-evidence hashes are
retained under this qualification directory.

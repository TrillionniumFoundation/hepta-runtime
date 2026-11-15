# R33 exact Rust CI: unsealed preparation

This package prepares one future external Rust CI attempt for
/home/qian/hepta-runtime-optimization-20261106-r33. It has not been sealed or
executed. The first qualification job was reported as 1a1ae8ce865-fc05-603f
while still running; that observation is not a successful terminal receipt.
No final source hash, test count or successful qualification result is assumed.

## Scope and immutable reference

The reference is the already published R31 attempt-02 exact CI package at
commit b9cea9e4295280900b77514947fd02fedb8acdb7, directory
tools/x230/20261105/r31/exact-ci/attempt-02-tools. All six exact original files
are retained under reference/r31-attempt-02. Their bytes and SHA-256 are
checked by verify_unsealed.py against reference-identities.json.

R33 is a fresh attempt-01. Its materializer omits R31's historical preflight
failure/recovery chain. It binds R33 preparation.json and 220 actual formatted
compiler inputs, and derives the full test counts from the actual original
isolated summary and its independent audit. R33's Git parent is the accepted
R24 commit baab4def80be7af015b2e7a594cb302f66c4130e. No R31 pidfd candidate or
R30 router code is introduced by this CI package.

The two original workflow commands remain exactly:

    cargo check --locked --all-targets --all-features
    cargo nextest run --locked --all-targets --all-features --test-threads 1 --retries 0 --no-fail-fast

The separate unfiltered nextest JSON inventory command also remains exactly:

    cargo nextest list --locked --all-targets --all-features --message-format json

The nextest 0.9.137 auditor and canonical workflow are byte-for-byte copies.
The pinned nextest binary, receipt, CI manifest, Rust 1.95.0 environment,
offline Cargo/cache/target settings, single test thread, timeouts, zero retries,
full original logs, exact-case/ignored-set checks and original child-group
cleanup are retained. No command has been run by preparing this package.

## Workflow binding

The qualified private source retains its historical workflow file:
7235 bytes, SHA-256 5574840f604a3c7963a274592ac2468a43fdd04cdaa7122851c271188a11065d.

The external canonical workflow is 7631 bytes, SHA-256
b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51,
Git blob 34afc29edffd3130df158601c6a14fee5efbf79c. Its identity must agree with
the original fixed CI manifest. The original publication provenance
c039688312ceb09b3d26d1cdd50f9118eb11129f is retained separately from R33's
actual accepted-R24 Git parent. The private qualified source is not edited
to obtain a workflow hash match.

## Independent qualification binding

The CI materializer imports the exact frozen, self-contained
ROOT/tools-01/r33_campaign.py under a non-main module name and calls only
bind_r33_candidate_preparation. This does not start a campaign, monitor or SSH
command. The same reviewed parent binder checks the completed R33 preparation,
two-file source transition, formatter-adjusted map, original qualification
evidence and closed prior cache owner.

CI uses ROOT/rust-ci-qualification-bindings-01.json with exactly six keys:

- qualification_launcher
- qualification_input
- candidate_patch (ROOT/combined.patch)
- qualification_preparation (ROOT/preparation.json)
- qualification_terminal_status (original native job ID and full identity)
- qualification_reports (the original qualification report, qualified flag)

It does not require campaign-inputs-01.json or any observation campaign to have
run. Install the exact bound parent script before running this CI launcher;
the CI tools directory itself keeps its original six-file inventory.

## Unsealed files and fail-closed behavior

templates/materialize_rust_ci_plan_01.py leaves JOB_ID, all actual qualification
hashes, parent/bindings hashes and FROZEN_COUNTS as None. Its first main action
rejects that state before creating a plan. The runner calls the same guard
before making an output directory or launching a child. The launcher has
SPEC = None and rejects it before any materializer or command submission.

actual-pins.example.json intentionally contains null future identities.
seal_package.py cannot accept it as actual evidence. The generator requires
real local copies of ten inputs with their actual remote path, byte count and
SHA-256. It verifies the successful native terminal, all eight qualification
stages, matching 220-input source maps, complete unfiltered isolated counts
and independent audit before writing a fresh sealed directory. The detailed
preparation/owner/source contract remains the shared parent binder's job on
x230. The generator performs no subprocess, network, CI or benchmark action.

The generator derives counts; callers do not supply anticipated test totals.
It re-reads the receipt copies before publishing the seal and refuses to
replace an existing output directory. An earlier failed or partial seal is
preserved; it is not silently overwritten.

## Future sealing and execution

After the original qualification completes successfully and its actual
receipts plus parent binder have been reviewed, fill a new actual-pins.json.
Each local_path must be an absolute direct path to the original copied bytes;
path is the fixed x230 path already shown in the example. Do not alter the
unsealed templates to insert future results.

The only future local generation command is:

    /usr/bin/python3 -I -B seal_package.py --pins /ABS/actual-pins.json --out /ABS/new-sealed-directory

The output contains tools/ with the four bound inputs, launcher and manifest,
the independent six-key qualification binding file, the exact supplied
actual-pins.json, and a seal-manifest.json. It remains sealed_not_executed.
The parent script is an external separately pinned dependency, not a newly
invented checker.

On x230, the owner can then install the six tools into absent
ROOT/rust-ci-tools-01 and the bindings into absent
ROOT/rust-ci-qualification-bindings-01.json, and run the launcher with its
actual SHA-256. The launcher creates only fresh ROOT/rust-ci-plan-01.json and
ROOT/rust-ci-01. No automatic resubmission or retry is included. This document
does not authorize or report a future execution.

## Validation and limits

verify_unsealed.py performs AST parsing and exact text/constant checks only.
It never imports or runs the CI templates. It checks the original runner and
launcher transformations, unchanged pure materializer helpers, original argv,
retained fixed inputs and explicit unsealed pins. These are preparation
checks, not Rust tests, compiler results or runtime qualification.

The external CI report schema will be hepta-r33-external-rust-ci/v1, attempt 01.
A completed external command run still does not mark hosted GitHub Actions
passed, prove a prospective-merge tree, or adopt a performance candidate.
No measurement or deployment is part of this package.

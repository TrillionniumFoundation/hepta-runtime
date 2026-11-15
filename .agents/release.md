# Hepta Runtime — CI and private release validation

The checked-in workflows under `.github/workflows/` define this fork's current
behavior. README links the original Octofs installation and distribution material as
upstream reference; it does not describe a Hepta publishing pipeline.

## Runtime CI

`.github/workflows/ci.yml` runs on pushes to `main` and the development branches
listed in its filters, on pull requests targeting its listed base branches, and
on manual dispatch. It cancels superseded runs for the same branch or PR.

- The source job checks out the exact PR head or pushed commit. A second job on
  pull requests checks the prospective merge with the base branch.
- Both jobs use GitHub-hosted Ubuntu 24.04, Rust **1.95.0**, and
  **cargo-nextest 0.9.137**. Rust checks, Clippy, and tests cover all features and
  `--no-default-features`; the latter validates library use without `remote-fs`.
- The full runtime tests use nextest with `--test-threads 1 --retries 0
  --no-fail-fast`. Some tests change process-global state, so each test needs a
  separate process; running the complete suite with `cargo test` is not the
  equivalent gate.
- Additional steps check descriptor-relative file safety, frozen REA mapping,
  evidence and control-plane regressions, release binaries/examples, and
  controlled local MCP/parser behavior. Preserve failures and skipped platform
  capabilities as such; a source mapping check does not requalify old evidence.
- Repository permissions are `contents: read`. This workflow does not write a
  coverage badge branch or publish packages.

Path-filtered REA workflows obtain public reference dependencies and run fixtures
on GitHub-hosted runners. The cross-host preview transfers an artifact between
two such runners. `cloud-compute.yml` runs offline unit tests when its paths
change; it does not submit Colab or Kaggle jobs. Their individual path and branch
filters remain significant when changing CI.

Historical `operator-parity.yml` retains source-specific evidence pins and its
original branch filters. It is not a `main` gate. Do not replace an expected
source digest solely to make a historical qualification pass. The historical
ROG SMU workflow requires its dedicated ops branch and actor before using its
self-hosted runner; it is not a `main` deployment workflow.

## Manual private release artifact

`.github/workflows/release.yml` has only `workflow_dispatch`; pushing a version
tag or a normal commit does not trigger it. It uses `contents: read` and checks
out `github.sha` with persisted Git credentials disabled.

On the selected source revision it:

1. Installs Rust 1.95.0, cargo-nextest 0.9.137, and the integration test tools.
2. Runs the locked all-target, all-feature Rust suite in isolated processes and
   the descriptor-relative file capability checks.
3. Builds the Linux `hepta-runtime` and `hepta-runtime-jobctl` release binaries
   with the default features and records their SHA-256 digests.
4. Packages both binaries and the tracked `deploy/` files. The manifest binds
   the artifact to the source commit and tree, Cargo.lock digest, compiler/Cargo
   versions, build command, and each staged file's digest, byte count and mode.
   A tar archive preserves executable permissions.
5. Retains the tar archive and manifest as the workflow artifact
   `hepta-runtime-linux-<source SHA>` for seven days.

This is source-bound packaging on one Linux runner, not a six-platform release
matrix or a deployment receipt. It does not publish to crates.io, npm, the MCP
registry, GitHub Releases, or a Homebrew tap. It does not install the artifact on
an operator host or change active services.

## Documentation and version metadata

Use the Hepta build and deployment instructions at the beginning of README and
the source/binary qualification receipts under `docs/qualification/`. Linked upstream Octofs packages, bundles and registry entries are upstream
references. Neither `server.json` nor a Cargo.toml
version change enables a publishing workflow.

Describe any new packaging or distribution behavior in the same change that
implements it. Preserve the identity and stated scope of historical receipts;
new source, current source-mapping checks, and qualification of an installed
service require their own evidence.

## Source package identity

The supported Git checkout uses a local `[patch.crates-io]` decoder under
`vendor/ruzstd`. Ordinary registry packaging omits nested packages and does not
apply the root patch to consumers. Its file list is not a supported release
contract. Historical retirement reduces that list without changing the manual
release workflow's tracked `deploy/` payload.

`src/mcp/weight_guard_journal.rs` embeds the complete Cargo manifest in persistent
request identity. Packaging-only manifest edits can therefore change journal
selection after rebuilding. The repository cleanup preserves `Cargo.toml` and
`Cargo.lock` byte-for-byte; future packaging changes need their own identity
compatibility assessment.

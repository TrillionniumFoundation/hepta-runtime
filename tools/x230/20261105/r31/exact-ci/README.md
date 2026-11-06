# R31 exact Rust CI attempt 02

This is a fresh materialization after a zero-Cargo preflight failure. It retains
the original attempt and changes no qualified source, qualifier, binary, test
selection, concurrency, retry, timeout, or output-audit rule.

## Original failure

Job `1a1ae4b6679-fc05-5ec3` failed with exit 1 while materializing the first plan.
The original native terminal has complete, durable, synchronized, untruncated
stdout (854 bytes) and stderr (1,071 bytes). The two stdout records are tool
installation and materialization; the old launcher never reached its executor.
Neither `rust-ci-plan-01.json` nor `rust-ci-01` was created. The corrected binder
requires both to remain absent and verifies the preserved old tools.

The private qualified source's `.github/workflows/ci.yml` is 7,235 bytes, SHA256
`5574840f604a3c7963a274592ac2468a43fdd04cdaa7122851c271188a11065d`.
It predates the published workflow's additional `20261029` and `20261030` Python
discovery commands in each of the two jobs. Rust command lines are unchanged.
This private workflow is preserved and explicitly bound as a historical input.

The published canonical workflow is 7,631 bytes, SHA256
`b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51`.
Its recomputed Git blob is `34afc29edffd3130df158601c6a14fee5efbf79c`, exactly the
original CI manifest's `workflow_git_blob` and unique workflow `input_files` row.
The corrected materializer binds this file outside the qualified source tree,
at `rust-ci-tools-02/canonical-workflow.yml`.

This does not claim the private source directory is an exact full Git checkout
of the published commit. The 222 qualified compilation inputs remain separately
bound to their actual original source map and full eight-stage qualification.

## Frozen deployment

Copy the six files in `tools/`, without changing their bytes, into the fresh
operator-owned private directory:

`/home/qian/hepta-runtime-optimization-20261105-r31/rust-ci-tools-02`

Copy the five existing original files from the sibling `failed_attempt_01/`
directory into the fresh evidence directory:

`/home/qian/hepta-runtime-optimization-20261105-r31/rust-ci-preflight-attempt-01`

Those five originals are `terminal-original.json`, `read-envelope.json`,
`stdout.log`, `stderr.log`, and `remote-source-workflow.yml`. Their exact paths,
sizes and SHAs are listed in `deployment-manifest.json`. Preserve the original
`rust-ci-tools-01` directory; the materializer requires its original five files.

| Frozen artifact | Bytes | SHA256 |
|---|---:|---|
| `launch_exact_rust_ci_01.py` | 6,393 | `fb6fbbaaa7ddeded4d2acdb637ac8ecceb48fc8b3350ac8c81d5733f07194ff8` |
| `package-manifest-01.json` | 2,827 | `dbf43466e09c4c11002aac1e31d6b63c9cc8d7d8cb9a7750924a44905c1235c1` |
| Canonical workflow | 7,631 | `b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51` |

Only after file installation and with no overlapping compiler or measurement:

```sh
/usr/bin/python3 -I -B /home/qian/hepta-runtime-optimization-20261105-r31/rust-ci-tools-02/launch_exact_rust_ci_01.py \
  --launcher-sha256 fb6fbbaaa7ddeded4d2acdb637ac8ecceb48fc8b3350ac8c81d5733f07194ff8
```

The launcher creates `rust-ci-plan-02.json` once and runs the original executor
against the fresh `rust-ci-02` output directory. The `01` filenames inside
`rust-ci-tools-02` refer to the reused tool protocol, not the evidence attempt.

## Retained execution contract

The runner differs from attempt 01 at exactly three namespace/attempt literals.
The nextest auditor is byte-identical. The existing qualifier/terminal/reader
functions in the materializer are AST-identical; the added functions bind the
failed preflight and the canonical workflow. Original qualification job
`1a1ae1c32b8-fc05-5d7a`, `qualification-01`, `preparation-02.json`, seven actual
qualification hashes, 222 compilation inputs and the actual complete test
inventory all remain required.

After recording Cargo/Rust 1.95.0 and nextest 0.9.137 versions, the executor runs:

```sh
cargo check --locked --all-targets --all-features
cargo nextest list --locked --all-targets --all-features --message-format json
cargo nextest run --locked --all-targets --all-features --test-threads 1 --retries 0 --no-fail-fast
```

The original offline environment, existing `target-build`, jobs 2, umask 022,
reporting options and bounded process-group cleanup remain unchanged. The
structured nextest inventory must match all actual qualified cases, original
ignored cases and retained qualified test ELF identities. Original commands
and every bound file are rechecked before and after stages. No fmt, Clippy,
release build, isolated qualification suite or Python CI gate is scheduled by
this package.

## Local checks and result limits

`local-check-01.json` records six limited groups of checks: invariant constants,
three-literal runner difference and unchanged auditor, existing function ASTs,
the actual original failed native streams and five invalid variants, canonical
Git-blob/manifest agreement and three invalid variants, and all original/new
file identities and Python syntax. No remote call, Cargo command, test suite or
CI runner was executed by this package-preparation work. Root separately read
the complete key diff and launcher arguments before deployment.

Future results must come from the actual new job. This package does not report
CI success in advance. `hosted_actions_passed` remains false: private external
exact-command evidence does not establish GitHub exact-head or prospective-merge
Actions success. The first failed preflight remains part of the public history;
attempt 02 is the first opportunity to execute these R31 Cargo stages, with zero
automatic retries.

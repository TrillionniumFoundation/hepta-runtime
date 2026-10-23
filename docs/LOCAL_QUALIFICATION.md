# Local exact-source Rust qualification (non-authorizing)

Use this when GitHub Actions cannot start an actual job (see runtime issue #29).
This tool collects **local** source and test evidence; it never grants Hepta
FinalUse, authority, deployment, or target-host production qualification.

## Prerequisites

- Linux or macOS with Python 3, Git and enough disk for two Cargo builds.
- Install Rust **1.95.0** with `rustfmt` and `clippy` (the verifier pins
  `RUSTUP_TOOLCHAIN=1.95.0` and checks both `rustc` and `cargo` versions).
- Use a trusted local clone of `hepta-runtime`, and fetch the **exact
  candidate PR head and GitHub-generated PR merge**. Do not substitute a
  locally constructed merge tree for GitHub's merge SHA.

Example for PR `N` (replace `N` with the real PR number):

```bash
git fetch origin "refs/pull/N/head:refs/qualify/N-head"
git fetch origin "refs/pull/N/merge:refs/qualify/N-merge"
SOURCE="$(git rev-parse refs/qualify/N-head)"
MERGE="$(git rev-parse refs/qualify/N-merge)"
python3 scripts/local_qualification.py \
  --repo . \
  --source-sha "$SOURCE" \
  --merge-sha "$MERGE" \
  --output "$HOME/hepta-runtime-qualification/N"
```

The output directory must be **outside** the repository. The checker reads the raw SHA-addressed merge commit and requires exactly two
parents, with the provided source SHA as its second parent. This rejects linear,
unrelated or wrong-head commits masquerading as GitHub's PR merge. It does not
authenticate the GitHub origin of a caller-supplied SHA; retrieve the actual
`refs/pull/N/merge` from GitHub using a trusted remote.

The checker creates
separate detached worktrees for both exact SHAs, refuses hidden index source
flags, missing/modified tracked bytes, replacement refs, non-POSIX execution,
non-pinned Rust, missing tests, or any failing check.

It runs Python source-contract and self-regression suites, then Cargo fmt,
check, Clippy, tests, and release build using locked dependencies on **both**
commits. Output is bounded to 8 MiB per command, command trees have wall-clock
deadlines, and JSON plus SHA-256-digested logs are retained even on failure.

`qualification.json.status` values:

- `BLOCKED`: at least one gate did not complete successfully. Never promote.
- `LOCAL_CHECKS_PASS_NOT_PRODUCTION`: **both** local SHA lanes passed. Still
  require independently reviewed runtime/host/FinalUse evidence and a real
  production acceptance decision before deployment.

If the PR head or base changes, refetch both refs and rerun; receipts for an
earlier exact SHA are not transferable to a new SHA or PR merge.


### Execution environment preflight (source-only, fail-closed)

The local verifier refuses inherited **execution-affecting environment variable names** before any Git or Cargo child process, including Git configuration/object redirects, Rust toolchain/compiler/flags, Cargo source/target/runner, Python import/startup overrides, dynamic loader injection, build/linker wrappers and OpenSSL/pkg-config overrides. Only reviewed diagnostic controls such as `RUST_BACKTRACE`, `RUST_LOG` and `CARGO_TERM_COLOR` are exempt. Denial receipts include **names only**, not values. Use a clean, controlled shell and rerun rather than passing tests under an unreviewed environment; no automatic allowlist expansion or gate bypass.

This closes an environment-inheritance false-positive in the local evidence harness. It **does not** attest the executable files reachable through `PATH`, installed Rust binaries, kernel, devices or signed operator authority. Two genuine pinned Git commits and real Cargo/host evidence remain mandatory.

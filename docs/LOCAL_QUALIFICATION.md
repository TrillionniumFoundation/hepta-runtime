# Local exact-source Rust qualification

`scripts/local_qualification.py` collects local source and build evidence for
an exact pull request head and its exact GitHub-generated merge commit. Its
successful status is `LOCAL_CHECKS_PASS_NOT_PRODUCTION`; every receipt sets
`production_authority` to `false`. This tool does not issue FinalUse grants,
authorize deployment, or qualify a remote host.

## Required inputs and tools

Use a trusted Linux or macOS host with Python 3, Git, a complete local clone,
and enough disk for two separate Cargo target directories. The verifier requires
Rust **1.95.0**, including `rustfmt` and `clippy`, and cargo-nextest **0.9.137**.
Install these tools before starting the verifier. It checks their reported
versions in each lane and pins `RUSTUP_TOOLCHAIN=1.95.0` in child processes.

Obtain both commits from the intended GitHub remote. For pull request `N`:

```sh
git fetch origin "refs/pull/N/head:refs/qualify/N-head"
git fetch origin "refs/pull/N/merge:refs/qualify/N-merge"
QUALIFICATION_SOURCE_SHA="$(git rev-parse refs/qualify/N-head)"
QUALIFICATION_MERGE_SHA="$(git rev-parse refs/qualify/N-merge)"
python3 -B scripts/local_qualification.py \
  --repo . \
  --source-sha "$QUALIFICATION_SOURCE_SHA" \
  --merge-sha "$QUALIFICATION_MERGE_SHA" \
  --output "$HOME/hepta-runtime-qualification/N" \
  --timeout 5400
```

Replace `N` with the actual pull request number. The output directory must be
outside the repository. `--timeout` is a per-command wall-clock limit; its
default is 1,800 seconds. Choose a sufficient bound for the actual resource
envelope and preserve failed receipts when a limit is exceeded.

Both supplied SHAs must be distinct, full lowercase 40-character Git commit
identifiers already available locally. The raw merge commit object must have
exactly two parents, with the supplied head as its second parent and a different
first parent. This rejects a linear commit, a wrong head, or displayed ancestry
altered by graft metadata. It does not authenticate GitHub as the origin of the
object. A locally manufactured merge is not a substitute for fetching the
actual GitHub merge ref. Refetch and rerun whenever the head or base changes.

## Checks in each lane

The verifier creates separate detached worktrees for the head and merge. Before
executing toolchain checks it compares every tracked regular file with its Git
blob, rejects hidden index flags and untracked nonignored files, and requires
all four qualification regression suites to exist. A missing suite cannot pass
through unittest discovery as a zero-test result.

Each lane checks the pinned tool versions, then runs:

1. The workflow contract, source-byte boundary, executable PATH fence, and local
   qualification regression suites.
2. `cargo fmt --all -- --check`.
3. Locked all-target `cargo check` and strict Clippy with both `--all-features`
   and `--no-default-features`.
4. Locked all-target nextest with both feature modes, one test process at a time,
   zero retries, and `--no-fail-fast`.
5. A locked all-feature release build of binaries and examples.

The index must also agree with the HEAD tree: staging a source modification or
deletion cannot hide it from byte qualification. Tracked source bytes and the
exact commit identity are checked again after each listed check. The local helper
covers this stated set of checks. The GitHub workflow
also contains runtime-specific Python regressions and release smoke tests;
this local receipt is not a substitute for those additional gates or a hosted
CI result. Both current CI lanes run the four qualification helper suites.
The source-contract suite checks workflow configuration only; it does not
execute Rust or prove native runtime behavior.

## Execution and source guards

Before any Git or build child process, the verifier refuses inherited
execution-affecting environment names. These include Git configuration/object
redirects, Rust compiler and toolchain overrides, Cargo runners and source
configuration, Python import/startup overrides, dynamic-loader injection, and
build/linker wrappers. `GIT_PAGER` is also refused. Reviewed diagnostics such as
`RUST_BACKTRACE`, `RUST_LOG`, and `CARGO_TERM_COLOR` remain allowed. Refusal
messages include names rather than values. Review the environment and rerun in
a controlled shell instead of weakening the guard for a particular runner.

Every PATH entry must be nonempty and absolute. Its physical path must remain
outside the source root, including aliases through symlinks. This prevents a
checkout from supplying a substituted `git`, `cargo`, or compiler through PATH.
It does not pin or authenticate the bytes of installed executables.

Before each Git command, the verifier reads effective Git configuration as data
and refuses executable configuration such as fsmonitor, custom hooks paths,
checkout filters, external diff/merge drivers, credential helpers, aliases, and
pagers. Git children ignore global/system configuration and replacement
objects. Repository replacement refs are refused. Worktree creation also
refuses include directives, including conditional includes that might become
active only inside the new worktree. Partial-clone configuration is refused:
qualification must not obtain missing objects through an unreviewed helper.
Disabling hooks alone would not stop a smudge/process filter from executing
before byte inspection.

Source intake opens the worktree directory and walks each tracked relative
pathname component with `O_NOFOLLOW`. It reads bytes, file type, executable mode,
and before/after metadata through the same regular-file descriptor. It refuses
tracked symlinks, intermediate symlinks, noncanonical components, FIFOs and other
nonregular files, hard-linked files, files larger than 64 MiB, and changes in
observed inode metadata during the read. Unsupported platforms fail closed.

Commands run in isolated POSIX process groups with bounded output capture
(default 8 MiB per command). A wall-clock timeout, output overflow, or failing
exit blocks qualification. If the immediate process exits while a descendant
retains a capture pipe or remains alive with closed pipes, the verifier kills
the remaining process group and records failure. A parent exit code of zero
alone is insufficient.

## Evidence and limits

`qualification.json` records exact SHAs, tree identities, tool versions,
per-command outcomes, log sizes, and SHA-256 log digests. Logs and a blocked
receipt are retained on failure. The final status is one of:

| Status | Meaning |
| --- | --- |
| `BLOCKED` | A required gate failed or did not complete. |
| `LOCAL_CHECKS_PASS_NOT_PRODUCTION` | Both local SHA lanes completed the stated checks. No production authority was granted. |

These guards assume a trusted local host and verifier. They do not attest the
kernel, executable contents, dependencies, hardware, or independently issued
operator authority. Byte checks do not make the worktree immutable between
inspection and execution. Process groups are not an OS sandbox; a descendant
that creates a new session can leave its original group. Production acceptance
requires the appropriate independent authorization, host confinement, runtime
recovery evidence, and exact binary/source binding.

## Source provenance

The active helpers retain the executable Git-config protections from
`108f27bd` and the later descriptor source-intake, environment, PATH, and
descendant guards from `efd53796`. Their old Rust implementations and old CI
layout are not imported by this helper integration. The current workflow and
library implementation remain the authority for their respective behavior.

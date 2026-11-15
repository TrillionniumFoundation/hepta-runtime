# Durable native guard journal and explicit interruption recovery

The Rust guard now retains a durable request intent and completion record in an
independent private journal. An identical retry authenticates current content
and reruns the guard. If the original evaluation stopped before a durable
completion, the retry conservatively rejects the unknown result and attempts a
verified inverse publication. This closes a process-interruption and receipt
gap in the isolated weight editor; it does not add live model activation or a
new model-quality result.

The implementation is `src/mcp/weight_guard_journal.rs`, with native subprocess
tests in `src/mcp/weight_guard_journal_tests.rs`. The public
`weight_guard_evaluate` entry point uses the journal wrapper; the existing full
guard remains the underlying evaluator. The final combined implementation was
qualified together with the Bellman planner. Its exact all-feature binary is
SHA-256 `a576b51e3fcb3d3a657e9d723bf2a9bfa579a3f6912178ee6e71a14c4ccd9854`
(380,407,976 bytes).

## Actual qualified behavior

Both all-feature and no-default-feature runs passed **75 focused weight-library
tests, with zero failures and two ignored tests**. The ignored entries are the
crash worker invoked explicitly by its parent test and an independently supplied
actual-head fixture test. The top-level ignored marker does not mean the crash
worker was skipped: each configuration contains eight actual subprocess
SIGKILL/restart records. These are real process terminations, not simulated
exceptions. Clippy with warnings denied, an all-feature binary build and final
format checking also passed. This local qualification is not the complete
repository test suite.

A separate **11-call actual MCP qualification** passed on the exact final
binary. Four fresh invalid requests preserve the existing `isError=true`
contract and original error family. Their identical retries return explicit
unverified rejection without publishing artifacts. A valid synthetic edit
accepts, an identical completed retry revalidates, and subsequent alteration of
the owned accepted artifact makes the retry reject instead of using its old
acceptance. Source bytes remain unchanged. Details and exact costs are in
`QUALIFICATION.md`, `qualification/mcp_receipt.json` and
`qualification/outer_receipt.json`.

No live Trader or Qwen checkpoint is loaded by this journal qualification. Its
synthetic guard fixture demonstrates compatibility, file authentication and
recovery behavior, not out-of-sample capability, trading value or a comparison
against gradient training.

## Request identity and bounded persistence

The canonical envelope binds the full typed guard request, ordered canonical
workspace roots, canonical private state directory and an explicit guard
semantic version. Non-finite or non-round-trippable values are refused. The
request envelope is limited to 1 MiB.

The explicit semantic version is
`hepta.guard.f32-linear.exact-l2.v2.journal.v1`. A named fingerprint additionally
binds the guard, exact norm checker, forward evaluator, tensor patcher, artifact
store, weight configuration, relevant REA file/model/evidence modules, this
journal, and Cargo manifest/lock. It is deliberately not described as a
complete execution closure: compiler, standard library, operating system and
every transitive implementation dependency are not all represented by that
fingerprint. Qualification records separately identify the compiler, lockfile,
tested sources and binary. A changed semantic fingerprint cannot silently
inherit an old journal acceptance.

The Linux journal is separate from the model artifact root. It requires owned
0700 directories and owned, regular, single-linked 0600 files. Directory
components are opened without following symlinks. Reads and writes use pinned
descriptors and recheck directory/file identities. Publication uses exclusive
creation, `renameat2(RENAME_NOREPLACE)`, file fsync and directory fsync. A
directory flock covers the entire evaluation; the wait deadline is 10 seconds.
The journal limits itself to 128 entries and 64 MiB, including abandoned staging
data. It does not silently overwrite or evict prior evidence. The artifact
store keeps its independent 128-artifact cap and authentication requirements.

These quotas are intentional availability limits. Repeated distinct rejected
requests can consume journal entries. At exhaustion the system refuses further
publication; this implementation does not introduce automatic retention or
garbage collection. Same-UID and privileged actors remain within the trusted
host boundary. File permission checks do not provide cryptographic protection
from an administrator or a malicious process with the same authority.

## Evaluation and recovery rules

The ordinary successful sequence is:

1. Exclusively publish and sync a complete intent before running the guard.
2. Run the existing full guard, including exact L2, label/source checks, content
   authentication, candidate publication, scoring and constraints.
3. Publish and sync the candidate reference.
4. Publish and sync the completion receipt before returning its result.

Every identical completed retry reruns the full guard and authenticates current
source and candidate bytes. The comparison covers source/candidate/restoration
hashes, objective and preservation scores, constraints, actual update budgets,
and acceptance. It excludes only wall-time and idempotent artifact-reuse display
fields. A saved `accepted` field is never sufficient on its own.

An incomplete identical request follows a different result rule. It reruns the
**full guard**, then forces inverse artifact publication and verifies the
restored file's full SHA-256 against the original expected source SHA. The outer
result is always `accepted=false`, even when the replayed guard internally
would accept. The replay therefore cannot bypass the current norm budget or
bad-label checks by calling the patcher alone. If no candidate existed at the
time of the interruption, reconciliation can publish an isolated candidate
solely to restore it; that extra work and artifact use are disclosed.

If the source is missing or altered, a required artifact is unauthenticated, or
the store has insufficient capacity, the result remains
`rejected_recovery_unverified`. It does not claim restoration. A first failure
can be retained immutably; this does not claim that every later retry attempt
has a separately durable failure receipt. Malformed, replaced or insecure
journal state fails closed.

This recovery occurs when a caller explicitly retries the **same request**. It
is not a background recovery daemon, an instantaneous rollback at crash time,
or a change to a production model pointer. The original source is never edited;
candidate and inverse files are immutable artifacts. Real process-kill tests
qualify the interruption boundaries described below, not abrupt power loss,
storage-controller behavior or all possible filesystem failures.

## API compatibility and preserved unsuccessful attempt

The first implementation converted a fresh core-guard error into an ordinary
JSON rejection. Review found that this would break existing MCP clients relying
on `isError`. The initial compilation was stopped before any test executed.
Its exact formatted source snapshots, partial receipt, sanitized log and
review-abort record are retained in `attempt_1_source/` and
`qualification/attempt_1/`. It is not counted as a test failure or a success.

The revised implementation keeps fresh core-guard errors as errors after
attempting durable first-failure retention. Its error includes the journal
identity and original reason. Retries of an already recorded intent have
explicit recovery semantics. The actual MCP qualification tests both sides of
this distinction instead of changing the test to accept a regressed contract.

The successful wrapper preserves the prior top-level candidate, acceptance,
score, constraint and budget fields and adds journal/recovery metadata. In an
unknown-interruption outcome, only the outer `accepted=false` is eligibility;
an internal replay result is evidence about the replay, not permission to deploy.

## Reproduction and evidence use

From the repository root, the focused native qualification commands are:

```sh
cargo test --locked --all-features --lib weight_ -- --test-threads=1 --nocapture
cargo test --locked --no-default-features --lib weight_ -- --test-threads=1 --nocapture
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo build --locked --all-features --bin hepta-runtime
cargo fmt --all -- --check
```

The captured qualification used `--offline` for Cargo and two build jobs with
one test thread. A new build on another environment will generally have a
different binary hash. Bind the hash of the new binary explicitly and report a
new execution; do not describe it as the original qualified binary.

The exact shared qualification protocol and driver are in the sibling package
`../native_bellman_20261105/LOCAL_PROTOCOL.json` (SHA-256
`becd6660335b264052d59ae13275ab2afe5294d3083997269a3f622cfbebfb33`) and
`../native_bellman_20261105/run_local_qualification.py` (SHA-256
`bc9d96d16baabf34181c515211ccec5661ff77ea7b040ba0c472795e1f530eca`).
This package retains an identical copy of the shared qualification receipt;
the duplicate record does not represent another build or cost.

For the actual MCP contract run, use `run_mcp_contract_outer.py` with the
frozen `qualify_mcp_contract.py`, `MCP_PROTOCOL_V2.json`,
`MCP_OUTER_PROTOCOL.json`, a full binary hash and a new output directory. The
outer wrapper copies nothing into a production state root. The inner driver
creates private synthetic fixtures, disables host execution and makes a new
owned mode0500 binary copy. The final binary copy and source/protocol hashes
are rechecked. Raw runtime responses and stdout/stderr remain private; public
receipts contain an explicit aggregate projection and raw hashes.

`python3 -B verify_records.py` checks this package's file manifest, receipt
bindings, crash-record invariants, the actual MCP contract outcomes and their
cost scope. It performs no model evaluation or new SIGKILL experiment. The
combined qualification used a local checkout with an explicitly verified source
overlay; its actual local HEAD is recorded separately from public parent
`e7a2688acc5504412d45160a08d2bf864be6b650`. The published integration must preserve
those qualified source hashes rather than mislabeling the checkout's Git identity.

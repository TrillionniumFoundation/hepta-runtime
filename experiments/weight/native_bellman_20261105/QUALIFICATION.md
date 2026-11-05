# Qualification: finite-DAG Bellman and durable guard integration

The actual Rust MCP replay and the independent engineering comparison passed.
All 320 exported worlds completed, with 246,160 graph nodes and 928,200 legal Q
values compared. Legal masks and selected actions match exactly. Maximum
absolute error against both the frozen own-law reference and an independent
scalar graph recurrence is zero; all 320 replayed J utilities also match
exactly. These are previously exposed worlds. This is an implementation
migration result, not a new scientific holdout or a new model improvement.

## Source and executable identity

The declared public parent is PR #92, commit
`e7a2688acc5504412d45160a08d2bf864be6b650`. The isolated qualification checkout
retained local HEAD `2809dc57a6ec393e4ab8e9935a047c79e66c679b`, tree
`84f79718dda7ce1f976e6d21ad041031f4fd5c7f`, with explicit, SHA-checked source
overlays. That older checkout identity is recorded, not represented as the
public parent. Publication must reproduce the qualified files atop the public
parent, and new official CI belongs to the resulting new commit.

The change contains seven Rust paths: `src/mcp/mod.rs`, `server.rs`,
`weight_guard.rs`, `weight_guard_journal.rs`, `weight_guard_journal_tests.rs`,
`weight_bellman.rs`, and `weight_bellman_tests.rs`. The qualification binds all
14 affected or directly related Rust files, including unchanged trust-region
and budget components. The guard's public entry point now calls the durable
journal wrapper; its private evaluator retains the prior gates.

| Identity | SHA256 |
| --- | --- |
| Fourteen-source manifest | `29549e735bce935cc7efab22b40c79d2eccc3633eb09313a5504f0bfb351493f` |
| Local qualification receipt | `c2953b97c8ba515a9c2fe6f768a206274b3bced285bd82cd558f16a78ca6beab` |
| Final actual executable, 380,407,976 bytes | `a576b51e3fcb3d3a657e9d723bf2a9bfa579a3f6912178ee6e71a14c4ccd9854` |
| Frozen native execution protocol | `8b6d771876f175670cc03fa32806f5f82bc66d09cd4e4863aae3fdfe7e70d3fe` |
| Final native corpus manifest | `929592dab6ab205f87fbd6eff356ab1eb13c79298f85194c9bc1879c8ae6f4ef` |
| Independent result | `8114cd5b01f2015f780619c613325c7f645af2eab72759aeda31d8bfe748eb0e` |

Each execution phase used a private pinned copy of this executable and checked
it after execution. Separate post-phase checks also verified the shared built
binary, Cargo.lock and all 14 Rust sources after trust regression, journal MCP
contract testing and Bellman corpus execution. These are stable individual
file reads, not an atomic snapshot of the entire filesystem. All passed.

## Completed gates

| Gate | Recorded outcome |
| --- | --- |
| Formatting, first and final checks | PASS |
| All-features focused `weight_` tests | 75 passed, 0 failed, 2 ignored; 1,696 filtered |
| All-features/all-targets Clippy, warnings denied | PASS |
| No-default-features focused `weight_` tests | 75 passed, 0 failed, 2 ignored; 1,681 filtered |
| All-features CLI build | PASS |
| Prior trust protocol under the final executable | Seven plans, 60 exact-norm cases, four negative controls, two public TRAIN-head cases; PASS |
| Durable journal actual MCP contract | 11 calls; PASS |
| Bellman actual MCP corpus | 320 attempted, 320 completed, zero RPC errors or missing worlds |
| Independent known-world replay | All Q/masks/actions and 320 J utilities pass; maximum compared errors zero |

The two ignored test entries are the pre-existing opt-in head fixture and the
journal subprocess worker entry point. The latter is invoked by the crash
tests: eight real SIGKILL/restart or lock scenarios ran under each feature
configuration, for 16 recorded scenarios in total. The journal contract tests
also check four fresh MCP error families, four conservative retries, positive
acceptance, completed retry revalidation and rejection after artifact tampering.
The neighboring `native_guard_journal_20261105` package contains the full
contracts and crash evidence.

The first, separate journal compilation was intentionally stopped after review
found a fresh-error contract defect. It did not run tests and is not a pass.
Its partial source, logs, cancelled exit `-15`, approximate 420-second observed
interval and accounting limits remain in the journal package. Compilation CPU
for that cancelled attempt is unknown, not zero. The subsequent unified attempt
passed on its first execution. The 75-test subsets are not full-repository CI;
the publication workflow must run full CI on the new exact commit.

## Independent acceptance and provenance

The comparison gate was frozen before the native corpus was read:
`abs(Q_native - Q_reference) <= 2e-12 * (1 + abs(Q_reference))`, with exact
legal masks and exact first-maximum actions. No tolerance was adjusted after
execution. The independent verifier freeze at 01:57:23 UTC preceded native
execution at 01:58:25 UTC. The native solver received only graph states and
branches, without reference Q, action tables, or world truth.

`qualification/independent_replay` contains byte-identical small receipts and
the research-package link. The complete frozen verifier, original references,
per-world comparisons and replay trajectories are in
`hepta-private-ci/tools/hcsn/wsp_followup_20261105/native_bellman_replay`, whose
`PACKAGE_SHA256.json` hash is
`b02dd6dbce89f0b9a7dec46c72d5661ce236e6f158c9950b8723defe79660c0d`.
Runtime's ten input groups and ten full output groups are included here for
independent native re-execution. Typed-Serde commitments, canonical Python
parameters, transmitted arguments and complete JSON-RPC request hashes remain
separate identities; they are not assumed to have the same serialization.

The J replay uses native query-node Q values with the frozen own-law export's
belief/state mapping. It does not authenticate the original checkpoint law in
Rust, execute real packet I/O, demonstrate economic net value or qualify a
production policy. It also does not run an online Rust call at every trajectory
decision. The earlier scientific J result remains the task-efficacy evidence;
this migration introduces no new statistical sample.

## Measured costs

| Phase | CPU seconds | Wall seconds | Accounting scope |
| --- | ---: | ---: | --- |
| Unified six-command local qualification | 2665.505785 | 1486.703156 | Waited Cargo commands and descendants; compile, tests, Clippy and formatting |
| Old trust MCP compatibility replay | 13.027080 | 29.400584 | Whole driver and waited MCP child |
| Journal MCP contract | 4.180270 | 19.563341 | Whole driver and waited MCP child |
| Export the 320 graph requests | 138.206351 | 138.278052 | Complete Python export worker, including startup/final writes |
| Native 320-world MCP execution | 37.789511 | 75.133058 | Complete driver and waited Rust child, including startup and final driver writes |
| Independent comparison and J replay | 52.947453 | 52.973096 | Complete verifier worker, including startup/final writes |

These phase intervals are separate; internal timers overlap the corresponding
outer rows and must not be added. The outer native interval excludes the small
supervisor setup and its own receipt publication, which the receipt identifies.
Its maximum descendant process RSS is 948,220 KiB, not an aggregate of all
concurrent processes. The cancelled journal compile, original scientific
training, LLM usage, file transfer and energy costs are not silently included
or treated as zero. Export plus native execution alone costs about 175.996 CPU
seconds, before independent verification and compilation. This package makes
no end-to-end speedup claim over the preceding Python planner or gradient
training.

The native corpus download encountered one OS argument-size rejection before
any destination file was written; bounded, version-pinned chunk transfer then
completed with all hashes checked. This transport failure is retained in the
research download receipt and is not a native experiment failure. Routine
source transfers also used bounded chunks. Raw local build-log hashes remain
in the qualification receipt; published log copies replace only isolated
checkout/target path prefixes, as declared in `logs/LOG_REDACTION.json`.

## Scope and independent inspection

The implemented objective is risk-neutral additive expectation on a finite
acyclic graph. It does not implement entropic/exponential-moment or log-sum-exp
value control, general NDU/FBSDE optimization, or a general risk-sensitive
recurrence for correlated random fees. Explicitly enumerated cost/successor
dependence is expressible under additive expectation; correlated-cost task
generalization was not qualified here. The two-worker Bellman pool is separate
from other Runtime pools, not a global shared execution ceiling. The journal
tests normal durable file recovery after process SIGKILL; they do not certify
power-loss behavior or a transaction that promotes a live model pointer.

From a full checkout, the following commands inspect committed records and
source identities only. They do not execute a new runtime or model experiment:

```sh
python3 experiments/weight/native_bellman_20261105/verify_records.py --repo .
python3 experiments/weight/native_guard_journal_20261105/verify_records.py --repo .
```

For a new native run, follow `README.md` and create new output/protocol paths.
Never overwrite these frozen receipts. Re-run the independently frozen research
verifier against the new native outputs before accepting numerical or task-value
equivalence. All production, new-scientific-efficacy, checkpoint-law-authentication,
packet-I/O and full-economic-value qualifications remain false.

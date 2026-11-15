# D1: minimal real qualification and phase-cost diagnostic plan

This is an unsealed execution recommendation, not a modified launcher or an
executed qualification. Accepted runtime remains R24. Use the diagnostic identity
D1, not an optimization/version label such as R36.

Proposed parent-owned branch:

    experiment/x230-r24-phase-cost-20261106

Proposed fresh host root, to be checked by the parent before use:

    /home/qian/hepta-runtime-phase-cost-20261106-d1

No host call, Cargo invocation, diagnostic fixture or benchmark has been executed
for this package. The source map, actual formatter result, ELF hashes, job IDs,
test outcomes, host freshness and measurement pins must be sealed from real
receipts later.

## 1. The unchanged qualifier already selects the diagnostic feature

The accepted R24 qualifier was independently read from Git:

- Path: tools/x230/20261028/qualify.py.
- Git blob: 9e0224291058d67740f603db982fa9220fca92b1.
- 7,661 bytes; SHA256:
  95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d.

Its actual Cargo selections are:

    /home/qian/.cargo/bin/cargo +1.95.0 clippy \
      --offline --locked --all-targets --all-features -- -D warnings

    /home/qian/.cargo/bin/cargo +1.95.0 test \
      --offline --locked --all-targets --all-features \
      --no-run --message-format=json

    /home/qian/.cargo/bin/cargo +1.95.0 build \
      --offline --locked --all-features --release --bins --examples

The parent independently observed these same selections in the real R35
qualification report. The final D1 preparer must still bind the actual original
nineteen harness files and their hashes, rather than rely on this statement.

The eight original stages are format, fmt-check, harness-tests, clippy,
test-build, isolated-tests, audit-isolated-tests and release. Keep their actual
commands, order, timeouts, source/monitor checks, auditors, test isolation,
zero-retry rules and pass criteria unchanged.

**With this candidate, those original --all-features commands compile and test
phase-cost-diagnostics and produce the D1 feature-enabled ELF.** Do not describe
that ELF as a feature-absent ordinary build. Do not add a redundant new feature
qualification because of the earlier assumption that the original gate omitted
the flag.

All three diagnostic environment variables must be absent during qualification
and exact CI. A feature-enabled runtime with mode unset does not initialize the
collector/output. This is still a feature-enabled build; runtime mode is not
Cargo feature selection.

Materialize the exact R24-to-recovery-02 patch into a new source root, with the
complete 220-to-222 map and only thirteen changed/added paths allowed. The other
209 compile inputs remain byte-identical. Preserve the pre-format map, all
formatter outputs, actual final 222-input map, original stage logs and actual
native terminal/read evidence. An unexpected source change is failure, not a
reason to broaden the allowed set afterward.

The real feature-selected test enumeration must include the six new sibling
tests and the selected existing tests. Counts remain dynamic: neither R35 counts
nor six static function names are a substitute for actual selected/passed/
ignored/failed/retry/enumeration evidence.

Keep the original exact Rust CI protocol as well. Bind its actual argv and Cargo
feature selection, canonical workflow, nextest binary/auditor and real outcomes;
do not infer its feature set from the ordinary/diagnostic label. If its real
commands include --all-features, they likewise exercise this diagnostic feature.

## 2. Verify ordinary cfg with the original feature set minus only the diagnostic

Cargo TOML gives a precise selection boundary:

- Accepted R24 Cargo.toml has no [features] table.
- The candidate adds only phase-cost-diagnostics = [].
- No dependency is added/changed, Cargo.lock is unchanged, and all six release
  settings are unchanged.

The original package-feature set is therefore empty; the candidate all-feature
set is the single diagnostic feature. The ordinary configuration is the original
feature set, not an invented alternate collection of defaults. **Do not use
--no-default-features**, which could change dependency/root default behavior in a
future or differently described baseline.

For this exact TOML, a separate ordinary-cfg supplemental invocation removes only
the --all-features selector and supplies no --features selector. Dependency
defaults, target set, toolchain, lock, environment, profile and all other original
options stay the same. The distinction is justified by the parsed TOML and must
be captured in the actual build binding.

This supplemental check is explicitly separate from the unchanged eight-stage
qualifier. Do not edit qualify.py or claim these are its original commands.
Use the same frozen Clippy/test-build methodology and existing isolated
execution/auditor for the ordinary selection, then preserve a separate ordinary
release ELF. The source-only format/header/embedded-Python checks already apply
to the same unchanged final tree; there is no need to reformat between selections.

For the exact original commands above, the ordinary selections are:

    /home/qian/.cargo/bin/cargo +1.95.0 clippy \
      --offline --locked --all-targets -- -D warnings

    /home/qian/.cargo/bin/cargo +1.95.0 test \
      --offline --locked --all-targets \
      --no-run --message-format=json

    /home/qian/.cargo/bin/cargo +1.95.0 build \
      --offline --locked --release --bins --examples

Freeze the supplemental invocation producer and complete isolated-test/audit
bindings before executing them. Do not switch to an aggregate ad hoc cargo test
run or omit original cleanup/enumeration checks for convenience. Ordinary cfg
does not compile phase_cost.rs or its six tests; its actual selected set/counts
must reflect that and be recorded separately. This supplemental source branch
check is not a throughput experiment.

Static token erasure supports this check: ten modified original Rust paths return
to the R24 token stream, mod.rs's original tail is unchanged, and no new
synchronous wrapper contains await. It does not replace compilation/type/borrow
checks, Clippy or execution of the existing tests under ordinary cfg, nor prove
bit-identical ELFs.

## 3. Seal two actual ELF identities without overwriting either

Both build selections use the same already-formatted final 222-input source map
and exact lock, Rust 1.95.0 toolchain and R24 release settings. Do not edit,
reformat, add debug instrumentation flags, change target triple, or override
release settings between them.

The original qualifier copies release hepta-runtime, hepta-runtime-jobctl and
examples/native_process_driver into its output directory. Bind those original
copies, not only the mutable target/release paths. The D1 feature ELF must have
its real copied bytes/SHA and original successful build/native closure before an
ordinary supplemental build can overwrite the shared target outputs.

After the ordinary build, immediately preserve its own independent create-only
ELF copies and bindings. Record the actual source map, lock, Cargo feature set,
Cargo/rustc identity, argv/environment, original native job, complete logs,
actual wait/cleanup, bytes/SHA and copied-path identities. A current shared target
file copied after the second build cannot be relabeled as the first ELF.

Build sequentially with one explicitly assigned project target/cache only after
its previous owner is really closed under the existing preparation policy.
Do not run Cargo concurrently or duplicate the entire dependency cache.
The current proposed cache owner is R35, whose real failed lifecycle receipt and
cleanup must be bound; its state must not be copied from R34's different
"lifecycle not executed" case. This plan does not supply missing R35 receipts or
relax existing disk/owner guards.

| Identity | What it establishes | Use in phase-cost cells |
| --- | --- | --- |
| Original accepted R24 ELF/map | Accepted baseline and prior gate context | Remains accepted reference |
| D1 --all-features ELF, actual original qualification/CI | Explicit diagnostic configuration's correctness | Same exact ELF for every OFF/ON cell |
| D1 original-feature-set ELF, supplemental checks | Ordinary cfg compilation/correctness and exact bytes | Not one of the OFF/ON cells |

Runtime OFF versus ON is a mode change on the **same diagnostic ELF**, not a
comparison between the two build selections. Both modes allocate the same fixed
slots and write a header/footer. ON adds recording and final event output.
Measure that perturbation; do not assume the OFF feature build is cost-free.

## 4. Seal the smallest diagnostic campaign separately

No campaign launcher is changed or executed by this package. Before the parent
schedules D1, freeze:

- Exact final source map, package/entry/parser, original qualification and exact
  CI, supplemental ordinary configuration receipts, and both real ELF identities.
- The original six-host topology/configuration, credential/profile pins, original
  controlled fixture identities, status/read mix and call sequence.
- Original held-agent recipe, compiler monitor readers/validator/policy, quiet
  duration, source/input checks and original owner-closing controls.
- Fresh controller state, private sidecar output parents, modes and cell names;
  native request identities and the original controller PID/start ticks.
- Identical controller CPU counter endpoints for every OFF/ON cell, explicitly
  stating whether setup/warmup/final JSON-sync/shutdown are included.
- Any optional C8 decision rule. Future job IDs, counters, outputs and successes
  must remain null until actual originals exist.

Then use the original held-agent/compiler monitor and 90-second quiet pattern
without changing its thresholds or resetting quiet opportunistically.

The first stage is fixed: C1, six hosts, existing status/read sequence, 192 calls
per cell, order OFF1 / ON1 / ON2 / OFF2. Use the same diagnostic ELF and original
fixture sequence; only mode and fresh ownership/output identities differ.

Stop on the first error, retain it and leave later cells explicitly unrun.
There is no automatic retry, replacement key/job, deletion of partial evidence,
or favorable-run selection. Finish actual original controller/SSH/agent custody,
close the independent monitor and source/input postflight, and keep the original
native status/read/log evidence. Process absence does not replace original wait
or remote-job custody.

The smallest future harness adaptation passes only the three explicit diagnostic
environment values to its original exact controller launch and binds/collects
the sidecar. Its ordinary request/deadline behavior, agent, profile, helper,
identity checks, cleanup and performance thresholds remain unchanged.

diagnostic-entry.py is available only where its fd-exec transition fits the
reviewed harness contract. It preserves the final PID/session/stdio and verifies
the ELF descriptor, but briefly starts Python before exec. If the original
startup identity verifier requires a direct ELF birth, retain that direct launch
with independently verified ELF bytes and explicit environment; do not silently
replace the verifier's contract with the wrapper.

The sidecar parent is new, owned mode 0700. Runtime creates a mode-0600 file
exclusively. Never clean/reuse a normal observation socket, old campaign,
existing controller state or previous sidecar to make preflight succeed.

C8 is an optional separately predecided second stage using the same four-cell
order and call count, only if a sealed rule calls for concurrency queue/lock
evidence and C1 closed without error. C16 is outside the initial scope. Do not
add levels or repeat a cell after seeing results.

## 5. Publish only what the measured scopes support

Keep raw trace bytes/SHA, original request/harness rows, native envelopes/reads/
logs, controller counters, source/ELF postflight and actual monitor/agent/owner
closure. Run the parser on exact original bytes, and retain that actual
invocation/result as another receipt.

The parser verifies a raw trace structure and synchronous CPU nesting. It does
not verify Cargo feature selection, native request success, remote-job cleanup,
exact controller lifetime, or campaign acceptance. Bind those independently
before interpreting phases.

Report OFF/ON perturbation using actual original intervals and samples. Report
synchronous controller CPU/wall by phase/native request, including all original
worker/owner validation and audit write/sync. Report queue and overlapping
capture/I/O spans with their actual scope.

Leave unmatched controller CPU unattributed, including negative/mismatched
residuals. Local SSH child CPU, remote helper CPU and network-only latency remain
unavailable in this first stage. A long ChildWait/capture interval is not proof
of pure network or Python startup cost. A microsecond leaf does not justify
another full optimization campaign by itself.

Existing optimization ABBA acceptance thresholds remain unchanged. Only a
material absolute cost, supported by this separately closed diagnostic evidence,
should motivate another narrowly frozen optimization against an explicitly
accepted baseline. D1 itself is not an adopted optimization.

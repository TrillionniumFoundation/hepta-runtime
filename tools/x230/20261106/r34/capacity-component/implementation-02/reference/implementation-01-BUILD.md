# Future offline build and evidence contract

No command in this document has been executed for this package. No component Cargo lock, resolved metadata, formatted source, compiler result, ELF, performance result or adopted candidate is prefilled. Actual R34 qualification and exact Rust CI are owned by the parent experiment and must close before its scheduled component build/run.

## 1. Freeze the formatted component revision first

`implementation-01` is a source-preparation milestone. Preserve it. Copy only this component preparation to a new named revision; use a temporary standalone component manifest with the actual read-only runtime path and format **only package `hepta-direct-capacity-component`**. Do not pass `--all`, format the runtime dependency, or run a Cargo build during this source-formatting step. Preserve the formatter command and exact resulting difference, then replace the new revision's source manifest with the actual final byte identities. The original source-preparation manifest must not be silently updated.

The new revision must retain the same component logic and fixtures. Any non-formatting fix is a named revision and must be reviewed. Future `fmt-check` is a real gate, not a substitute for this refreeze. Until this has happened, the current package must not be described as formatter qualified.

## 2. Bind the actual qualified runtime dependencies

Copy `build-inputs.unsealed.json` to a new actual input path, filling only retained actual identities, then set `status` to `sealed_actual_inputs` after review. A bound file is exactly `{ "path": absolute_path, "bytes": actual_length, "sha256": actual_sha256 }`. Use the final component source manifest from step 1.

For A, the entire 220-input map must equal `reference/r24-compile-inputs.json`; the original qualification report must have SHA256 `bf0c5814d28b163e4a90405026cd4d90e399370d1f910f8ac48cb580af1e4971`. For B, use the actual successful original R34 qualification report and its formatter-final `source_tested`/`source_after` map. Its `source_input` must equal the separately frozen original R34 input map. The source key set remains exactly 220 and exactly the four R34 paths differ from A. Supply and check the complete Python include-input closure separately. No R31 pidfd, R33 path cache, router, JSON deferral or global-12 change belongs in B.

Set absolute `cargo` and `rustc` paths, the actual Linux GNU target triple, and the **existing** original `cargo_home`. Never infer a new Cargo cache from a default native `HOME`. `compiler_jobs` is fixed at 1. The preparation output must be a fresh private path and its parent must already exist; no runtime source or cache is moved or copied.

The following is the future preparation interface, not an executed command:

```text
python3 -B prepare_build.py --input /absolute/path/actual-build-input.json
```

It performs all input checks before creating the output, then creates `arms/A`, `arms/B`, their own standalone manifests, copied component source/fixtures and **seed** lockfiles. The production trees remain path dependencies. The seed lock is not called a resolved component lock.

## 3. Resolve offline, then bind both actual graphs

Use the same explicit controlled environment for both arms. `seal_arm.expected_environment` is the canonical mapping:

```text
PATH=<actual cargo parent>:/usr/local/bin:/usr/bin:/bin
RUSTC=<actual absolute rustc>
CARGO_HOME=<actual existing original cache>
CARGO_TARGET_DIR=<prepared root>/target-component
CARGO_BUILD_JOBS=1
CARGO_NET_OFFLINE=true
CARGO_INCREMENTAL=0
```

Keep other build-affecting controls identical to the original qualified release procedure, record their actual values, and reject unexpected compiler wrappers, Rust flags, target linker overrides or Cargo release-profile overrides. The six profile declarations are checked by the tools; that declaration check alone does not prove an arbitrary inherited environment or Cargo configuration harmless. A future invocation producer must bind the actual effective control context, not merely fill the expected environment map after the fact.

For each arm, run the initial lock update sequentially with offline metadata (without `--locked`, because the new local root must be added). After the lock exists, capture the actual second metadata command using both `--offline` and `--locked`. A representative exact argument vector, with actual paths substituted, is:

```text
<cargo> metadata --offline --manifest-path <prepared>/arms/A/Cargo.toml --format-version 1 --filter-platform <target>
<cargo> metadata --offline --locked --manifest-path <prepared>/arms/A/Cargo.toml --format-version 1 --filter-platform <target>
```

Repeat for B serially. Preserve every original command/native receipt/stdout/stderr, including an initial failure. No registry download, `cargo update`, dependency upgrade or automatic retry is authorized. A registry version/checksum outside the accepted lock fails the graph gate even if it happens to be cached. The root's new local component package is the only new package identity; production package/version and all registry identities remain bound.

Validate the two retained **locked** metadata outputs:

```text
python3 -B check_graphs.py --prepared <prepared> --metadata-a <actual A metadata JSON> --metadata-b <actual B metadata JSON> --output <fresh graph receipt>
```

The tool rechecks actual runtime qualification/maps, original production locks, component source identities and each selected lock. Every registry package in metadata must belong to both its own selected lock and the accepted lock. A/B normalized features/dependency edges must match. This is a graph receipt; it reports neither a compilation pass nor an ELF identity.

## 4. Build A, seal A, build B, seal B

There is exactly **one new shared target**: `<prepared>/target-component`. Do not copy an entire runtime target/cache, run concurrent Cargo processes, or reuse a target from an earlier component attempt. Preserve only the actual final driver ELF for each arm plus the original build receipts and logs. This supersedes the earlier design sketch with separate arm targets.

For each arm, use the three canonical vectors in `seal_arm.expected_commands`, in this order:

```text
<cargo> fmt --manifest-path <arm>/Cargo.toml --package hepta-direct-capacity-component -- --check
<cargo> clippy --offline --locked --release --manifest-path <arm>/Cargo.toml --bin hepta-direct-capacity-component --target <target> --jobs 1 -- -D warnings
<cargo> build --offline --locked --release --manifest-path <arm>/Cargo.toml --bin hepta-direct-capacity-component --target <target> --jobs 1
```

All commands use `<arm>` as cwd. Preserve the native terminal and full raw stdout/stderr for every stage; a timeout, cancellation, truncation, sync error, output error or nonzero exit fails. No hidden retry is permitted. The invocation record is a separately retained record of the actual submission and effective controls, **not a claim that the native process-status API echoes argv**.

`arm-seal-input.unsealed.json` shows the binding interface. Each `invocation` file has schema `hepta-r34-capacity-recorded-build-invocation/v1`, actual `command`, `cwd`, controlled `environment`, `automatic_retries: 0`, actual native `job_id`, and actual `submitted_monotonic_ns`/`completed_monotonic_ns`. Its `clock` is `{ "kind": "linux:CLOCK_MONOTONIC", "boot_id": <actual x230 /proc/sys/kernel/random/boot_id> }`.

**Those timestamps must be obtained on x230 in the same Linux boot as `seal_arm.py`.** MCP client, Mac, UTC or browser timestamps cannot be substituted or mixed into this ordering. The actual invocation-record producer is not implemented by this source-preparation package; it must be bound to the parent's retained native submission procedure before any build is claimed closed. That remaining adapter must preserve the original process cleanup and failure behavior, rather than invent successful envelopes from a later ELF's presence.

After A's three real successful stages, run the sealer using A's actual input:

```text
python3 -B seal_arm.py --input <actual A arm-seal input>
```

The sealer rechecks sources/qualification/graphs/lock, verifies complete original native logs, and copies the actual ELF to fresh `artifacts/A/hepta-direct-capacity-component`. It fsyncs that file and directory, records the x230 monotonic preservation time, and writes a create-only arm report. It does not invoke a compiler or ELF.

**Only after that completed A seal** may the first B build command start. B uses the same target and environment. B's sealer requires the original A report and still-identical A ELF and proves `A.binary_preserved_monotonic_ns < B.first_build_submitted_monotonic_ns`, in the same boot. It preserves B separately and closes the pair. Every cell, including an A cell, requires this completed B pair report and the separately pinned selected arm ELF. An A artifact copied after B reused the target cannot satisfy the ordering.

Actual partial outputs are retained. An interrupted preparation, metadata command, compiler or sealer is not retried in the same names. A new reviewed recovery revision would have to bind the original failed attempt.

## 5. Single-cell execution remains subordinate to the outer campaign

`cell-inputs.unsealed.json` is not executable as distributed. A future sealed cell must bind actual separate ELF/build pair, runtime qualification/source closure, new private controller config/state namespace, original SSH profile/config/known-hosts/SSH binary, exact private wrapper, six original source job records and fixed environment. The Python coordinator validates these before creating outputs or issuing a private helper.

`coordinate.py --input <actual cell input>` is the implemented one-cell interface. Do not use it to manually choose/retry favorable cases. Before formal component measurement, implement and review the separate outer campaign indicated by `campaign-inputs.unsealed.json`: original held-agent control, compiler monitoring, 90-second quiet, the exact eight serial cells, first-failure stop and full original-evidence aggregation. The outer program, its original process cleanup, actual control bindings and final results summary are still unsealed.

The intended final delivery therefore has three distinct states: frozen source preparation; actual offline build/ELF closure; and complete frozen/executed capacity campaign. This package establishes only the first state.

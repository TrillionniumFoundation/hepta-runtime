# Original shell semantics reference

This directory is a test oracle for two HIA components. It is not linked into
the runtime and never runs a user's shell command.

`source_manifest.json` binds the complete current original `shell.rs`,
`shell_tests.rs`, production `Cargo.toml`, and production `Cargo.lock`. The two owner files are also
bound to their exact Git blob identities from the original runtime baseline.
Materialization copies the original terminal cleaner, regex, shell preflight,
stash detector, and all their helper bodies without rewriting their semantics.
The nine original pure tests are copied unchanged. Async process execution
tests are outside these components and are not claimed.

The independent Rust executable uses the same five registry packages as the
production regex dependency, with every package version, checksum, source, and
dependency list checked against the complete production lock. The original
regex dependency's default-feature declaration is checked as well. A fresh isolated
build and the nine original tests are mandatory before any aggregate replay.

## Exact inputs and outputs

Native semantic corpus files are ordinary binary streams. Each record is a
little-endian `u64` byte length followed by that many bytes. Terminal inputs
are complete UTF-8 strings. Shell inputs use the documented `HSHGATE1` frame;
the command is UTF-8, while a present workdir retains arbitrary Unix bytes
through `OsStr::from_bytes`. The six operations return the original full
message or original borrowed byte offsets, including empty slices.

`cases.py` independently regenerates the complete corpus in a stable order.
It provides `semantic_cases(mode)` and `control_specs(mode)` for evidence
readers. The native suite records every case ID, category, input hash, return
length, output hash, and invocation capacities. The aggregate refuses missing,
extra, reordered, truncated, or changed semantic input bytes, then compares
every original/native output byte. A captured native corpus alone is not an
original Rust comparison.

Malformed transport, invalid command UTF-8, and inadequate buffer capacities
are recorded separately with full before/after output and workspace bytes.
They are native ABI controls, not original Rust semantic observations.

## Execution

Native shards set `HIA_TERMINAL_MANIFEST` and `HIA_TERMINAL_CORPUS_DIR`, or
`HIA_SHELL_GATE_MANIFEST` and `HIA_SHELL_GATE_CORPUS_DIR`, then run the
corresponding `test_shell_native.py` or `test_shell_gate_native.py`. A new
corpus directory is required. The suite performs actual `NativeModule` calls;
there is no host semantic fallback.

The separate aggregate invokes:

```sh
python scripts/hia_native_shell_reference.py \
  --runtime /absolute/runtime \
  --output /absolute/new-original-run \
  --rustc /absolute/pinned/rustc \
  --cargo /absolute/pinned/cargo \
  --corpus /absolute/native-corpus \
  --mode terminal
```

Use `--mode gate` for shell semantics and `--offline` only when the exact
locked dependencies are already available. Rust 1.95.0 is required. The output
contains physical source and dependency receipts, executable identity, all
process commands/deadlines/statuses/full stdout/stderr, independently
regenerated input, complete original output, and `result.json`. Inherited
build override variables are removed and their names are recorded without
disclosing values. Failures remain failures with their complete process bytes.

For development only, `HIA_SHELL_ORACLE_BIN` can point at an already built
original executable to compare native and original bytes immediately. The
aggregate still requires its own fresh locked build and original tests.

These components do not qualify process spawning, cancellation, background
promotion, output publication, SSH execution, production tool routing, or
removal of the original shell owner.

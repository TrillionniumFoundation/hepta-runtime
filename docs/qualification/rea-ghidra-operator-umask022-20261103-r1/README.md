# Ghidra import-only qualification with explicit umask 0022 - 2026-11-03

This record qualifies the actual copied runtime binary
`290fa949b7744c85018f9f26b32fbdd1884cce1c31ff202a9f076bc3d6a89c63`
(391,141,088 bytes), built by focused job `1a1a18da495-96a-6fb4`.
It includes the shared state-root bootstrap permission fix in
`src/mcp/runtime/config.rs` with SHA-256
`836b9a85a74dc84f2a82063f164ac5c0343696b68774962eb0e677ee2630b9e0`.

The subsequent change to `config_tests.rs` corrected only a test fixture.
Its recorded SHA is
`9c4ab8beb1641605804822dbbcf572621b060aa930dbbfc22c513cb5bc2591de`;
this record does not claim that later test-only edit was linked into the
production executable. The root full qualification records cover the wider
Cargo test result separately.

## Exact run and result

- The original frozen harness was invoked once for this new workspace.
- Wrapper job `1a1a19bc3c2-96a-7018` was authoritatively
  `succeeded` with exit 0; `qualification.json` records `qualified: true`.
- The original successful MCP job was `1a1a19cd14c-3b6045-1`.
  Same-key replay and controller restart returned its original job and report.
- Cancellation addressed original job `1a1a19d52b9-3b7d72-1` and
  the owner confirmed `cancelled`.
  Frozen admission retained observation/cancellation; replay after thaw did not
  relaunch the operation.
- Artifact hashes were unchanged, and no inspected fixture target was executed.
- The harness removed one private scratch directory after terminal cancellation.
  Normal worker completion removed its own private scratch.

## Explicit permission conditions

The preserved `launch-wrapper.py` sets `os.umask(0o022)` and passes an
explicit `umask=0o022` to the original unmodified harness. It records
`/proc/.../status` observations for the outer process, harness, both MCP
controllers (before/after restart), and direct native worker. All observed
runtime processes had `Umask: 0022`. `launch-environment.json` retains their
PID/start identities, exact executable paths and permission observations.

The newly created workspace, controller-state, jobs and authority directories
were 0700; the config, owner lock and owner fence were 0600. Source files were
hash-identical before and after the run. The harness precreates state_dir as
0700, so this engine lifecycle run does not prove missing-root creation.
Separate focused real-MCP/bootstrap tests cover that runtime behavior.

This is operator-mode qualification on the stated host. It is neither a GitHub
CI run nor isolated-host qualification. The remote SSH/systemd job umask was
not independently measured; the explicit 0022 observation applies to the
listed local wrapper/harness/controller/native-worker processes.

## Evidence and preserved attempts

`binary-snapshot.json` records a single-held-FD copy, source identity checks
before/after copying and a second hash through the destination FD.
`qualified-source-files.json` includes the changed runtime config plus engine,
bridge and original harness hashes. The earlier 680edd... and faadf842...
qualification directories remain unchanged.

The two initial outer-wrapper preflights used an incorrect source inventory
path (`src/config.rs`). Both failed before launching either harness or creating
its workspace. Their authoritative exit-1 statuses are retained in
`launch-preflight-failures.json`. Only the external wrapper path was corrected;
no source/harness check was disabled and no engine operation was retried.

Raw semantic results, requests and original owner/cancellation evidence are
retained beside this file. `evidence-files.json` hashes the copied run records.
No runtime/engine binaries, state databases or credentials are included.

## Actual Ghidra observations

Ghidra 12.2 / Temurin 25.0.5+8 imported the harness-authored ELF as
`x86:LE:64:default` / `gcc`, returning 12 memory blocks and four imported
symbols including the authored function and external symbol. The native
operation took 19,290 ms. All 3,078 installation files / 678,364,159 bytes
matched the complete manifest and passed before/after installed-path checks.
The read-only official installation and its preparation receipts are retained.

The native and live-cancellation Java children had NoNewPrivs 1 and Seccomp 2.
The original cancellation child PID/start identity was confirmed gone.
These are observations of active filters, not independent BPF decoding or a
network connection challenge. The bridge did not run auto-analysis,
decompilation, external-library loading, project saving or the input program.
The pinned Ghidra API emits the retained getDomainObject deprecation warning.

## Scope and reproduction

JADX/Ghidra remain installed mature engines; full REA capability parity is not
claimed. Installed JRE/Ghidra paths are verified but not sealed executable
closures. Aggregate scratch usage is sampled every 250 ms, not a hard quota.
Owner interruption can leave the logged private scratch directory.

The preserved launch-wrapper contains the exact command, binary/harness pins
and environment assertions. Reproduction requires an explicitly new workspace
and a separately verified engine installation; an existing workspace is
rejected. Use the original repository harness with the same documented
arguments, and retain the wrapper environment receipt for the new run.

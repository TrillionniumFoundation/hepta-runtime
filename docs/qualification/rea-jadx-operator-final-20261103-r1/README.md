# Final JADX native and operator qualification — 2026-11-03

The real native worker and stdio MCP → localhost SSH → existing user-systemd
owner qualified with JADX 1.5.6 and Java 21 using the copied runtime
`680edd4d3252f7d39d771de81c66eb02222c65e6d14e16f5458c1e5480111cc7`.
This is the same frozen binary as the final Ghidra qualification and includes
the Ghidra provider and shared JavaLaunch refactor.

The successful preflight build was job `1a1a14e3dab-96a-6e33`.
Qualification wrapper job `1a1a1597018-96a-6e6f` was confirmed succeeded with
exit 0. The build used base `f9756508462ebc72e814a12f5dbba1b067edabe4`
plus the frozen implementation. `binary-snapshot.json` and
`qualified-source-files.json` retain the exact copied binary and relevant
frozen source/harness scope. The earlier qualification for binary
`faadf842c842572ff6b20ad0dad118571cf8476c0b84ec3021a0366d1e18cf32`
remains separately retained and was not overwritten.

## Recorded results

- `qualification.json` records `qualified: true`, exact runtime, Java launcher,
  selected JRE, fat-JAR and upstream archive identities, and zero target
  executions.
- `native-worker-report.json`, `classes-result.json` and `sources-result.json`
  retain actual class/method observations, bounded reconstructed source,
  source SHA-256 and successful normal scratch cleanup.
- The original classes job was `1a1a15a0a80-342df9-1`. Same-key replay and
  controller restart returned that original job and report.
- Changed payload/profile bindings and observations of never-submitted
  requests were rejected.
- The cancellation job was `1a1a15a943d-344422-1`. Frozen admission preserved
  observation and original-owner cancellation. The owner confirmed
  `cancelled`; thawed same-key replay returned the original job. One private
  scratch directory was removed by the harness after terminal confirmation.
- Both inspected fixture artifacts retained their original hashes. Fixtures
  were compiled only from the harness's own Java source and never executed.

This record qualifies `execution_mode: operator` and explicitly does not
qualify an isolated host. The earlier isolated attempt and its unchanged
`launch_unknown` investigation are retained in
[the earlier record](../rea-jadx-operator-20261103-r1/README.md).
The native fixed Java child installs the shared network-denying seccomp filter.
This final JADX lifecycle harness does not independently observe kernel flags;
the [Ghidra qualification](../rea-ghidra-operator-20261103-r1/README.md)
observes real Java children on the same frozen runtime, while the earlier
JADX-specific kernel observation is bound only to its earlier runtime.

The inspected input, engine JAR and fixed bridge are sealed memory snapshots.
The installed JRE is checked by selected pinned paths and remains a trusted
installation rather than a sealed executable closure. Aggregate scratch usage
is sampled every 250 ms; it is not a hard disk quota. Decompiled source is an
engine observation without independent semantic equivalence validation.

## Recipe

Use an independently verified JADX 1.5.6 distribution, pinned Java 21 and
existing localhost SSH/user-systemd support. Choose a new workspace:

```sh
python3 tests/rea_java_external.py   --runtime /absolute/path/to/the/exact/binary   --java-home /usr/lib/jvm/java-21-openjdk-amd64   --jadx-home /absolute/path/to/jadx   --workspace /absolute/new/private/qualification-directory   --allow-local-ssh --execution-mode operator
```

The frozen harness SHA-256 is
`39d0f80ff09b6647c030cab4a0a80afa43e91253c07b4e5eff701f50b4728e07`.
`evidence-files.json` hashes the copied raw records. Runtime/engine binaries,
state databases and credentials are excluded. Full upstream REA parity is not
claimed.

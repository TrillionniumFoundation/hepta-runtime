# JADX operator-mode native qualification — 2026-11-03

This record qualifies the exact copied runtime binary
`faadf842c842572ff6b20ad0dad118571cf8476c0b84ec3021a0366d1e18cf32`.
Its build used base commit `f9756508462ebc72e814a12f5dbba1b067edabe4` plus the
then-current implementation, including atomic private scratch and re-admission
of pinned JRE paths. It predates the later Ghidra provider and JavaLaunch refactor.
The record makes no claim that later source changes were present in that binary.

The real native worker and stdio MCP → localhost SSH → existing user-systemd
owner both used JADX 1.5.6. The inspected class/JAR came only from Java source
authored by the harness. No fixture target was executed.

## Recorded results

- `qualification.json` contains the actual runtime, Java launcher, selected JRE,
  fat-JAR and archive pins. `qualified` is true.
- `native-worker-report.json` retains the actual bridge observation and scratch
  outcome.
- `initial-job.json`, `classes-result.json`, `sources-result.json` and
  `cancellation-result.json` retain owner/job and semantic evidence.
- The original classes job was `1a1a12de222-313930-1`; replay and controller
  restart returned the same job and report.
- The cancellation job was `1a1a12ee40e-31495f-1`; the owner confirmed
  `cancelled`. Frozen admission preserved observation/cancellation; a later
  same-key start returned that original job. One cancelled-job private scratch
  directory was removed by the harness only after terminal confirmation.
- Source preview content and its SHA-256 were checked. Inspected bytes retained
  their original hashes.

The host explicitly used `execution_mode: operator`. Operator host policy
permits networking and does not claim a filesystem sandbox. The fixed Java child
independently installs the runtime's network-denying seccomp filter and
NoNewPrivs; its success path and report retain that fact. The lifecycle result is
**not** isolated-host qualification. Any separate kernel-flags observation
records only what it actually observed; no external network challenge is sent.

## Earlier isolated-mode attempt

The `isolated_unqualified` directory retains the failed qualification summary and
read-only transport investigation. The persisted original record remains
`launch_unknown`. The exact configured helper
`/usr/local/libexec/hepta-runtime-jobctl` was absent, the fixture's remote job
directory was empty, and its system/user unit names were not found. That
configuration and request were preserved without relaunching or rewriting the
owner record. The operator qualification used a separate fixture workspace.

## Recipe

Run only with an installed, independently verified engine/JDK and existing
localhost SSH/user-systemd support. Use a new workspace for a new qualification:

```sh
python3 tests/rea_java_external.py \
  --runtime /absolute/path/to/the/exact/binary \
  --java-home /usr/lib/jvm/java-21-openjdk-amd64 \
  --jadx-home /absolute/path/to/jadx \
  --workspace /absolute/new/private/qualification-directory \
  --allow-local-ssh --execution-mode operator
```

The harness copies the binary before recording its SHA. It never overwrites an
existing workspace. Binary files, credentials and state databases are excluded
from this documentation directory.

## Observed Java child kernel state

A separate direct native-worker probe using the same pinned runtime observed the
fixed Java source child while it was alive. The worker had Seccomp 0,
Seccomp_filters 0 and NoNewPrivs 0. Its actual Java child had Seccomp 2,
Seccomp_filters 1 and NoNewPrivs 1. The report and observation retain PID/start
identity, exact Java executable path, runtime SHA and native report identity in
`native-kernel-observation.json` and `native-kernel-probe-report.json`.

This demonstrates that a filter and NoNewPrivs were active in the observed child.
The specific network-denying syscall set is established by the fixed runtime
implementation and its successful filter-installation path. The probe does not
independently decode BPF rules and sends no network connection challenge.

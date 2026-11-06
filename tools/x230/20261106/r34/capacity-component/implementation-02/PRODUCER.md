# Actual build invocation producer: unexecuted preparation

This revision adds `record_build_invocation.py` and its still-unsealed input.
It changes the `seal_arm.py` consumer to require the original producer evidence
and complete native read pages. No entry point, Cargo command, formatter, test,
component binary or fixture was executed to prepare or statically review this
revision. `implementation-01` is preserved.

R34's original normal observation has now rejected the candidate at its C8
throughput gate. The parent has explicitly stopped capacity builds and cells.
These files are source preparation only. They establish no build, capacity,
performance, resource improvement or adopted candidate.

## Fixed future interface

Before any independently authorized future execution, create a new formatted
component revision and bind its actual source manifest. Preserve the current
unsealed templates. Fill a fresh `build-stage-input` from actual files and the
actual native jobs directory; no job ID, backend, process identity, output,
native terminal state or timestamp is supplied as a future success pin.

The original native `process_start` would have this exact command vector:

```text
/usr/bin/python3 -B /absolute/frozen/record_build_invocation.py --input /absolute/actual-stage-input.json
```

Its explicit cwd is `<prepared_root>/arms/<arm>`, request `env` is empty, and
there is no stdin payload. Its outer timeout must exceed the stage timeout by
at least 240 seconds, and be at most 7,200 seconds. The producer rechecks the
remaining margin immediately before Cargo. Maximum requested Cargo timeout is
6,600 seconds. These are timeout/cleanup budgets, never performance samples.

The stage input binds exactly three executable Python source files through
`programs`: this producer, `prepare_build.py`, and `seal_arm.py`. The actual
runtime qualifications, both source maps, Python include maps, prepared source,
Cargo locks and closed graph receipt are rechecked before and after a build.
No runtime source or runtime target is copied, deleted or built by preparation.

## Environment and actual toolchain identities

The Cargo environment is constructed from an empty mapping. It contains only
the seven controls from `seal_arm.expected_environment` plus explicit `HOME`,
`RUSTUP_HOME` and `RUSTUP_TOOLCHAIN`. HOME must equal the native job's actual
HOME. Ambient flags, wrappers, linker variables, profile overrides and
credentials are not inherited into Cargo.

`RUSTUP_TOOLCHAIN` must name an actual installed directory under the supplied
RUSTUP_HOME. A CI short name such as `1.95.0` does not prove that directory
exists: the installation may use a host-qualified name. Future input must use
the observed complete name. Absolute cargo/rustc paths must identify the actual
intended tools. The producer records their resolutions and the selected
toolchain's cargo, rustc, rustfmt, cargo-fmt, cargo-clippy and clippy-driver
files. All must satisfy the existing stable ordinary-file/nlink-one reader;
an unobserved multi-hardlink rustup shim is not called verified. Direct real
toolchain paths avoid ambiguity when actual retained stat evidence supports
them. No present runtime toolchain identity has been filled in this template.

Cargo configuration and rust-toolchain files along the arm/source ancestor
paths, and Cargo-home config files, must be absent. Existing rustup settings
are hash-bound. This intentionally refuses an unreviewed effective build
configuration; it does not edit configuration. These inputs and tool bytes are
checked again after the stage and by the arm sealer.

## Original native identity, not a reconstructed envelope

The producer reads its supervisor-provided `HEPTA_RUNTIME_JOB_ID`. It binds
that exact job directory's original `request.json`, `child.json` and
`launch.json`. It checks the actual command, cwd, job ID, launch nonce,
request fingerprint, timeout and the original child's PID plus Linux
boot/start-ticks identity against itself. There is only a five-second bounded
wait for those same metadata files to be published; this is not a Cargo retry.

It preserves exact original metadata bytes, actual cgroup membership and its
own birth identity. A real systemd backend must match the whole unit path
component (including the optional `.service` suffix); the Cargo child must
remain in the same observed cgroup. A real detached backend is retained as
detached and cannot claim the systemd control-group safeguard. The original
native implementation's systemd backend uses `KillMode=control-group`; this
producer does not change the native supervisor or infer a future backend.

An fsynced create-only `invocation-intent.json` precedes Cargo. It binds the
actual command, cwd, full environment, original native identity and Linux
CLOCK_MONOTONIC timestamp. `cargo-child.json` records the subsequently created
child's actual PID/start ticks/process group/session. Cargo is a child of this
native workload, not a newly invented native job.

## Ordering and partial failures

All producers and both arm sealers hold the same nonblocking `build.lock`.
Stage directories are fixed, create-only and non-replayable. The sequence is:

1. A metadata-seed, A metadata-locked, B metadata-seed, B metadata-locked.
2. After actual `check_graphs.py` closes both retained locked metadata outputs,
   A fmt-check, A clippy-release, A release, then A arm sealing.
3. Only after the A ELF and arm report are fsynced: B fmt-check, B
   clippy-release, B release, then B arm sealing.

The first metadata stage requires a new, absent `target-component`. Both arms
then use this one independent target. Seed metadata is offline without
`--locked`; subsequent metadata is offline and locked. The graph checker must
consume the exact retained `build-stages/<arm>-metadata-locked/stdout.log`.
It is not allowed to substitute a separately reconstructed metadata document.

Every earlier stage must have its original successful final invocation and
closed cleanup before another stage can begin. Preflight failures after a
stage is reserved retain the original input, native metadata, empty or partial
streams and a failed JSON report. Earlier identity failures may have no stage
directory and no Cargo launch; their original failed native receipt remains
necessary evidence. A partial intent or missing final invocation never means
success and blocks later stage creation. No retry, failed-output deletion or
automatic recovery is implemented.

The first B build requires the original successful A report and unchanged A
ELF, with `A.binary_preserved_monotonic_ns < B.submitted_monotonic_ns` in the
same Linux boot. A cannot build or seal after any B build attempt. The sealer
and producer lock prevent an ELF copy from racing target reuse.

## Cleanup and stream boundary

The producer is a Linux child subreaper. Cargo starts a separate session with
PDEATHSIG(SIGKILL), protecting the direct Cargo process if its parent disappears.
That signal does not prove that grandchildren were reaped. Normal, timeout and
handled SIGINT/SIGTERM paths retain the original leader through non-reaping
`waitid(WNOWAIT)` observations, then use the existing INT/120s, TERM/10s,
KILL/10s escalation only against the birth-bound original group. The group
leader is not reaped before the last possible group signal, preventing a
reused PGID from being signalled.

Only an actual `waitpid` return for the original child establishes its exit
and reap. The producer also checks the original group and adopted children;
dead adopted children are actually waited. A remaining live or escaped
descendant leaves cleanup unknown/failed. No unrelated process or group is
signalled. Hard SIGKILL or another producer loss can prevent its finally path:
without its final original wait/closure receipt the arm cannot seal and no
later build can start. Detached mode has no asserted cgroup fallback. Neither
cgroup emptiness, a parent-death signal nor process absence is substituted for
an owner wait. There is no claim of general system idleness.

Cargo stdout and stderr are retained in separate create-only files and fsynced.
Each accepted stream is at most 32 MiB. Oversize or unstable streams fail the
stage; existing raw files remain. The wrapper forwards only those raw bytes to
the corresponding native stdout/stderr. It prints no status JSON or traceback
into them. Producer errors and actual return codes remain in `invocation.json`;
wrapper failure exits nonzero. An interrupted/unfinished file is not labelled
a complete immutable stream.

For each of the three build stages the arm-seal input must include `invocation`,
`native_terminal`, `native_reads` (the complete ordered list of original read
pages), and raw `stdout`/`stderr` file bindings. The sealer verifies original
terminal success, exact job/nonce, durable/untruncated/synced output, contiguous
hex read pages, exact Cargo stream bytes, original intent and child birth,
actual successful wait and complete cleanup. Length equality alone is
insufficient. The native terminal remains a subsequent original receipt; the
producer cannot pre-publish its own supervisor's successful terminal status.

Only source parsing and static inspection are permitted for this rejected R34
preparation. The entire actual execution chain remains unexecuted and unsealed.

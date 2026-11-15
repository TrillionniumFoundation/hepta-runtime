# Finite desktop + x230 recovery profile

This profile is executable preparation for the selected **final** Runtime. It is
not a completed qualification result. Run it only after the final artifact path
and SHA-256 have been supplied by the frozen-combination qualification run.

The runner is `scripts/rea_multihost_recovery.py`. It uses Python's standard
library, authenticated OpenSSH, the actual final Runtime HTTP MCP server, and
the Runtime's original durable process owner. It does not replace the Runtime
with a test server or a mocked job implementation.

## Exact scope

One private HTTP controller runs on **desktop**. Its two configured operator
hosts are desktop through its existing `localhost` SSH binding, and x230 through
the existing `x230-ts` binding. Each original durable job executes a distinct
private copy of the **same final Runtime bytes**. Each worker serves a loopback
HTTP MCP endpoint with a minimal Runtime profile, a separate token, and its own
state directory. Runtime configuration requires at least one declared host, so
the worker declares one `disabled-fixture-host` with execution, PTY, file writes
and read roots disabled. The fixture checks its `host_list`, verifies the exact
disabled configuration, and requires a host `file_info` request to be refused.
It never submits another job through that host.

The profile exercises:

1. Actual native startup and `--version` on both Linux hosts, after byte identity,
   ELF architecture, GLIBC requirement and dynamic-loader checks.
2. One acknowledged, original durable native Runtime job per host.
3. A real open MCP SSE TCP connection, its socket shutdown, and a new TCP
   connection using the original MCP session while the controller remains live.
4. A new MCP session on the same controller and an exact idempotency-key replay
   that must return the original job ID.
5. `SIGKILL` of the runner's own private desktop controller group, followed by a
   new controller process using the same private token, configuration and state.
6. Recovery of the original live jobs, original owner/child bindings and original
   log prefixes, with another exact-key replay.
7. Cancellation through `process_cancel` for the original job IDs. Both output
   streams must have authoritative complete and durable terminal publication.
8. A second cold desktop controller startup, followed by byte-identical,
   paginated reads of the original cancelled jobs and unchanged terminal files.

This does **not** exercise a controller restart on x230. It does not inject a
host reboot, a network partition, disk failure, acknowledged-data loss, arbitrary
PID reuse, replacement services, or an engine/device workload. TCP disconnect is
reported separately from controller exit and worker termination.

The receipt always leaves `public_gates = 0`, `capability = 0`,
`replacement_qualified = false`, `full_multihost_matrix = false`, and
`full_cost_comparison = false`. A successful finite run sets only
`limited_profile_passed = true`.

## Read-only preparation observations

Observed on 2026-11-05 through the configured operator-host tools:

| Property | desktop | x230 |
|---|---|---|
| OS | Ubuntu 24.04.5 LTS | Ubuntu 24.04.5 LTS |
| Machine ABI | x86_64, GLIBC 2.39 | x86_64, GLIBC 2.39 |
| Kernel | 7.0.0-38-generic | 6.8.0-142-generic |
| Login UID | 1000 | 1000 |
| Home | `/home/qian-qi` | `/home/qian` |
| CPU | Xeon E5-2673 v3 | Core i5-3230M |
| Python | 3.12.3 | 3.12.3 |
| User systemd bus | present | present |
| Strict localhost SSH | authenticated | refused: localhost host key not known |

The source observations are retained in durable read-only jobs
`1a1aa4b4d22-fc05-4085` (desktop) and `1a1aa4c1759-fc05-4095` (x230).
The installed connector also authenticated both configured hosts in its bounded
SSH health challenge. These are preparation observations, not final-binary runs.

x230 lacks AVX2, FMA and BMI features available on desktop. Equal architecture
names alone cannot establish artifact compatibility. The final build must retain
its reviewed baseline target configuration; the runner additionally records ELF
notes and required GLIBC versions, resolves shared libraries, and actually runs
the selected final bytes on each host. ELF notes and exercised paths do not
attest every instruction or the complete dynamic-library closure.

The x230 localhost refusal is not repaired by lowering host-key verification or
changing a global SSH file. This is why the prepared profile uses one desktop
controller across the two hosts. The script refuses failed existing SSH trust or
authentication and retains its partial preparation.

On desktop, `x230-ts` is an existing configured transport alias and the actual
strict authenticated challenge returned zero (`1a1aa60eb61-fc05-420a`). The
connector-side name `desktop-ts` is not a desktop-local alias and is not reused.
The existing localhost binding is used for the desktop job.

## Commands

These commands are run on desktop from a reviewed checkout. `plan` starts no
Runtime, copies no Runtime artifact, and contacts no host:

```sh
python3 scripts/rea_multihost_recovery.py plan
```

After the final qualification artifact is identified, substitute its exact path
and SHA. Both output paths must be **new, absent directories** whose parents
already exist. The source binary is read-only and is never replaced:

```sh
python3 scripts/rea_multihost_recovery.py run \
  --runtime /ABSOLUTE/FINAL/QUALIFIED/hepta-runtime \
  --runtime-sha256 EXACT_64_LOWERCASE_HEX_SHA256 \
  --desktop-root /home/qian-qi/work/hepta-rea-multihost-final-UNIQUE_RUN \
  --x230-root /home/qian/hepta-rea-multihost-final-UNIQUE_RUN \
  --x230-ssh-alias x230-ts
```

The script must not be invoked with a previous candidate merely to produce a
green result. The final SHA is a required input; no search for a convenient
binary, fallback executable, implicit rebuild, or artifact substitution exists.

The private desktop profile uses the existing Runtime HTTP options:

```text
hepta-runtime mcp --path PRIVATE/workspace
  --runtime-config PRIVATE/controller-config.json
  --bind 127.0.0.1:OWNED_PORT
  --auth-token-file PRIVATE/controller-token
```

The original jobs use the same command with each host's private worker profile.
The operator controller profile does not set `allowed_cwd_prefixes` or pretend
to provide a command sandbox; every request explicitly selects its private
fixture cwd. Workers have a 600-second original-owner deadline, a 768 MiB memory limit, 50% CPU
quota and nice adjustment 5. These are finite-fixture limits, not general REA
performance measurements. Every `process_start` has one saved request and one
stable idempotency key. An unknown acknowledgement is retained as unknown; the
runner does not submit a different key to obtain a convenient new job.

## Identity and transfer

The runner hashes the caller-selected final file before effects. It copies from
one held regular single-link file descriptor into a create-only private file,
checks the source identity again, and verifies the expected SHA before execution.
The x230 transfer uses the existing authenticated OpenSSH/SCP binding with strict
host-key checking. Both destinations are newly created private namespaces.

Publication first verifies the transferred file's total size and SHA. A
create-only link publishes its name, then the incoming name is removed before
execution. Subsequent checks require a regular **single-link** binary. Existing
destinations are never overwritten. Both staged copies and the selected source
are checked again at the end.

Actual controller and worker images are independently read through their
kernel-provided `/proc/PID/exe` descriptors. PIDs are coupled to boot IDs and
start ticks; the runner also records process groups, original owner launch
nonces, supervisor identity, and the original `child.json` binding. Same-key
recovery must preserve the original binding files, not just return a similar
status string.

The connector's bounded `binary_read`/`binary_upload` tools are also available
for verified transfer, but the script uses the existing SSH binding for the
large final artifact. It does not silently switch transport, disable trust
checks, or obtain another credential when this path is unavailable.

The existing localhost SSH configuration enables automatic `UpdateHostKeys`.
To keep global trust files untouched, only the private controller's `Popen`
environment prepends a private `bin` directory to `PATH`. Its exact `ssh`
wrapper is:

```sh
#!/bin/sh
exec /usr/bin/ssh -oUpdateHostKeys=no "$@"
```

The wrapper preserves every Runtime-supplied argument, address, credential
selection and `StrictHostKeyChecking=yes` policy. It is a declared fixture
component. The receipt includes its original bytes/SHA, the actual `/usr/bin/ssh`
and shell identities, observed aliases and effective options, and before/after
hashes of configured public trust files. It does not attest an unwrapped
production transport. No global SSH config, alias or known-host entry is edited.

## Cleanup and failure custody

Only runner-created controllers are signalled directly. Their original leaders
remain unreaped during process-group signalling and observation (`WNOWAIT`),
then are actually reaped after the original group is confirmed stopped.
Controller PID reuse cannot confer authority to signal another process.

Remote jobs are cancelled only through the same final Runtime's `process_cancel`
using saved original host/job identities. The runner never uses an arbitrary
remote `kill`, restarts an installed service, changes a global SSH file, or
removes a test tree. It requires complete `/proc` visibility before making a
positive group-cleanup assertion. Unsupported visibility remains an error.

After cancellation, the original PGID must have no live member, and descendants
actually observed before cancellation must no longer have their original live
identities. This is a limited observation: it does not prove that arbitrary
previously unobserved descendants could never escape the original group.

Failed or successful namespaces are retained in full. On failure, known original
jobs receive a best-effort owner-mediated cancellation. A lost admission
acknowledgement, unavailable controller, unproven process exit, incomplete output,
or changed identity keeps cleanup incomplete. The original bounded job deadline
is retained as a fallback, never reported as a completed cancellation without an
observation. No positive result is inferred from disappearance alone.

The profile assumes the configured operator account and its private directories
are not being manipulated by a hostile same-UID process. It does not claim a
separate-user sandbox or protection from privileged concurrent writers.

## Receipt structure

`PRIVATE/receipt.json` is updated after each completed phase and retained on
failure. It contains:

- Selected source artifact identity, SHA, runner SHA, per-host ABI/loader/version
  observations, and final identity rechecks.
- An explicit topology and the controller restart host list.
- Original process-start arguments and keys, acknowledgement state, job IDs,
  remote job directories and raw Runtime replies.
- Controller PID/start identities and actual kernel-image SHA; HTTP
  initialization, session IDs and tool-schema digests.
- The real SSE connection's local/remote socket endpoints and the exact
  disconnect/reconnect phase, without authentication tokens.
- Original owner/child JSON bytes' hashes and parsed values before/after cold
  recovery, cancellation and final readback.
- Per-stream lossless byte cursors, complete captured bytes' hashes, durable
  terminal status, process-group observations, and cleanup errors.
- Phase elapsed times and staging byte counts. These are observations for this
  profile; they are not a complete cost comparison.
- An explicit failure description and `limited_profile_passed`, with all public
  qualification counters kept at zero.

Raw MCP requests and responses are kept in `evidence/mcp-wire.jsonl`; transport
authentication headers and token contents are excluded. Controller stdout/stderr
and each final worker stream are saved alongside it. Every token is newly
generated in a private file, and no deployed controller token is read.

Preparation syntax/plan checks do not count as runtime acceptance. The final
same-binary execution and its receipt must be reviewed separately.

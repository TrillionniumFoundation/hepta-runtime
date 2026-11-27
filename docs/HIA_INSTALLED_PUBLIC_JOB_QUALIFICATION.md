# Installed native v26 public-job qualification

`tests/hia_installed_public_jobs_integration.py` is an external qualification
driver for the ordinary public `process_start` and `shell_start` routes after
an actual HIA Worker installation. It is separate from the existing
`hia_native_helper_mcp_integration.py` campaign. That original campaign and its
hosted Worker, language, lease and replay gates remain required and unchanged.

## Inputs and real installation

The administrator supplies a fixed Runtime source and binary, a fixed Hepta
source, the corresponding native `hia-worker-install` entry, actual B3 compiler,
completed cold report and native Store package. Every binary/data input has an
explicit SHA256 argument. Source and qualification scripts must match their
selected complete Git commits; imported Python caches and extension shadows
remain subject to the existing source-admission controls.

The driver invokes the ordinary native installer once. It does not offer an
option to accept a preassembled controller directory, an existing installation,
a synthetic sealed receipt, or a Python installation implementation. The native
owner remains responsible for source and cold admission, complete Store
reconstruction, package equality, installation, Worker construction, all
nineteen controller roles and the mode-3 configuration binding. The driver
retains the original command, stdout, stderr and actual execution trace. The
installer runs with an empty `PATH`; the trace admits its one initial pathname
execution and at least one successful descriptor execution. Failed descriptor
attempts are counted separately; unfinished syscalls must match their process
identity and syscall on resumption, and unknown results remain HOLD.

Successful external reading requires the native owner's typed success receipt
for the selected Store digest, a private `runtime-config.json`, exactly the
nineteen named v26 members, exact catalog bytes, the five installed `native_jobs`
paths and pins, and the native Worker's installed entry/profile. Unrelated host
and runtime policy must remain unchanged. Receipt and hash consistency alone
is not installation provenance: this driver requires the actual pinned owner
invocation in the same campaign before it reads those bytes.

## Public observations

The campaign uses a fresh private controller and original ordinary request
keys beginning with `public-native-`, without the reserved HIA key prefix.
Its cases are:

| Case | Required observation |
| --- | --- |
| Ordinary ELF | Original `argv[0]` and physical inherited entry descriptor, exact stdin, exit 17, 131,109 binary stdout bytes and 8,193 binary stderr bytes |
| Safe final executable alias | The same physical entry and output contract while preserving the selected alias as `argv[0]` |
| Default `shell_start` | The public default `/bin/sh`, actual built-in stdout/stderr, and exit 7 |
| Native installed Worker | Its real installation-manifest query through the public process route, matching the native configuration's four identity pins |
| Cancellation | The original child first emits `ready`, then the public native cancellation owner terminates that same child and publishes a confirmed cancelled result |
| Reconnect | The completed original START is reused without launch, the job inventory remains identical, and public reads/status retain the exact original bytes and witness |

Output is read through actual MCP byte cursors, beginning with a seven-byte
page. The reader checks independent stdout/stderr offsets, complete EOFs,
terminal byte counts, and exact binary payloads. Terminal exit codes, stream
offsets and byte counts must be exact JSON integers; booleans, floating point
values and null cannot stand in for them. It independently captures the
original remote request, terminal JSON and witness from the same physical
filesystem, checks their original job/nonce/protocol binding and the witness's
digest of the actual terminal bytes, and retains those raw files.

An existing SSH endpoint must prove the same effective identity, exact private
sentinel inode/bytes and kernel boot. The driver does not change that endpoint's
credentials, service or SSH configuration. Alternatively,
`--allow-disposable-sshd` uses the original disposable SSH helper only on an
explicit GitHub-hosted runner. That helper's original platform restrictions
remain intact. Detached fallback remains disabled.

## Live refusals and retained failures

The campaign deliberately changes only its own completed job's terminal
witness digest. Public STATUS must then withhold terminal confirmation and
automatic retry. The original witness inode and bytes are restored before
checking the original terminal result again.

A separate private controller selects an incorrect pin for the otherwise
unused cancel role. A new public process must refuse before remote execution;
its external workload marker and remote state directory must remain absent.
An incomplete nineteen-role inventory and a wrong controller-manifest digest
must each prevent startup from serving MCP.

Lost or timed-out calls remain HOLD. The driver never invents a replacement
START key or reruns the installer. Cleanup observes the fresh controller's
actual original identities, including identities whose START acknowledgement
was lost, and cancels only those owned jobs when necessary. Raw failure files,
partial native installation output and unknown operations are retained.

`tests/test_hia_installed_public_jobs_integration.py` contains synthetic reader
controls for incomplete/mixed identities, modified roles, unsafe files,
incorrect native selection, policy changes, forged witnesses, ambiguous JSON,
foreign or unsuccessful execution traces, mismatched syscall continuations,
boolean/integer aliases and an actual timed-out owned child. Those controls
qualify the reader's refusal behavior; they cannot publish a passing native
installation or public campaign.

## Invocation

All paths should refer to private, stable, single-link ordinary artifacts.
The output directory must be absent and outside both source checkouts. Run the
driver from the selected complete Runtime checkout with Python `-I -B`:

```sh
python3 -I -B tests/hia_installed_public_jobs_integration.py \
  --runtime "$RUNTIME_BINARY" --runtime-sha256 "$RUNTIME_BINARY_SHA256" \
  --runtime-source "$RUNTIME_SOURCE" --expected-runtime-source "$RUNTIME_COMMIT" \
  --hepta "$HEPTA_SOURCE" --expected-hepta-source "$HEPTA_COMMIT" \
  --native-installer "$NATIVE_INSTALLER" --native-installer-sha256 "$NATIVE_INSTALLER_SHA256" \
  --compiler "$B3_COMPILER" --compiler-sha256 "$B3_SHA256" \
  --cold-report "$COLD_REPORT" --cold-report-sha256 "$COLD_REPORT_SHA256" \
  --package "$NATIVE_STORE" --package-sha256 "$NATIVE_STORE_SHA256" \
  --ssh-target "$EXISTING_SAME_HOST_SSH_TARGET" \
  --output "$NEW_EVIDENCE_DIRECTORY"
```

Replace the SSH target option with `--allow-disposable-sshd` only for an
authorized disposable GitHub-hosted-runner campaign. The native installation
deadline defaults to 3,600 seconds and is explicit in the retained command.
The separate original cold qualification budget is never changed by this
driver.

Run the reader controls with:

```sh
python3 -I -B tests/test_hia_installed_public_jobs_integration.py -v
```

## Scope and remaining gates

A passing report qualifies the specific installed source/binary/input tuple
for these public process, shell, observation, cancellation and native Worker
identity-query cases. It does not qualify all eleven HIA public tools, pooled
observations, foreign platforms, retirement of the Rust controller, removal of
the legacy source tree, or unrelated branch functionality. The existing full
Runtime CI, complete native cold and Store gates, hosted common campaign,
native Worker functional parity and final source regression suite remain
independent obligations.

The initial implementation's local eighteen reader controls and compiled C
workload controls passed. The actual installed public campaign remains OPEN
until the matching complete cold/Store products are supplied and the ordinary
installer and public calls finish successfully. No synthetic test result is
substituted for that remaining execution.

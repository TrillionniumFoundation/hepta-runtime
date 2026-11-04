# Native static provider adapter

This increment runs an admitted GNU readelf, GNU objdump, fixed JADX or bounded
Ghidra provider through the existing Hepta Runtime durable process owner. It
inspects owned build artifacts without executing them. The optional JADX profile
and its precise boundary are described in [ELF_AND_JAVA.md](ELF_AND_JAVA.md).

Legacy Ghidra profiles omit `ghidra_engine.bridge_revision` and retain the
original inventory bridge bytes and serialized identity, with automatic analysis
disabled. An explicitly admitted revision `2` profile can allow `inventory`,
`functions`, `function`, `xrefs` and `decompile`. The analysis operations use a
fixed, partial analyzer profile and bounded selected-function observations.
Ghidra 12.2 and JDK 25 remain installed engine dependencies; its Java/native
decompiler is not rewritten in Rust. See [GHIDRA_ANALYSIS.md](GHIDRA_ANALYSIS.md)
for versioned bridges, selectors, budgets and real-engine qualification.

Full Ghidra/IDA/Hopper workflows, arbitrary commands, general disassembly,
runtime instrumentation and complete REA 6.8.0 behavioral parity remain outside
this implementation. Decompiled text is an engine observation, without a claim
of general source equivalence.

## Configuration and admission

`rea_static_profiles` is a default-empty runtime configuration map. With no
profiles, the static provider tools must remain absent from MCP discovery.
A profile fixes the host, runtime executable and SHA-256, backend executable
and SHA-256, exact `LC_ALL=C --version` first line, input roots, operation list,
working directory and resource limits. The caller cannot change any of them.

Example shape; the deployment owner fills in actual independently observed pins:

```json
{
  "rea_static_profiles": {
    "owned_elf": {
      "host": "configured-linux-host",
      "runtime_executable": "/opt/hepta/hepta-runtime",
      "runtime_sha256": "REPLACE_WITH_ACTUAL_RUNTIME_SHA256",
      "provider": "gnu_readelf",
      "backend_executable": "/usr/bin/readelf",
      "backend_sha256": "REPLACE_WITH_ACTUAL_READELF_SHA256",
      "backend_version": "REPLACE_WITH_EXACT_GNU_READELF_VERSION_LINE",
      "working_directory": "/srv/owned-builds",
      "input_roots": ["/srv/owned-builds"],
      "allowed_operations": ["headers", "sections", "symbols", "notes", "relocations"],
      "max_artifact_bytes": 67108864,
      "max_output_bytes": 32768,
      "timeout_seconds": 30,
      "memory_max_bytes": 536870912
    }
  }
}
```

The profile must fit the configured host's read/cwd/execution policy. An input
under a nested protected root remains denied. Linux sealed memory snapshots
are required; other platforms are not qualified by this implementation.

## Request and original-job recovery

`rea_static_profiles` returns `profile_sha256` computed from the complete admitted
profile. Preserve it with every request. The six execution-facing fields are
`profile`, `profile_sha256`, `idempotency_key`, `operation`, `artifact_path` and
`artifact_sha256`. (The two identities serve different purposes: profile pinning
prevents host/backend rebinding; artifact pinning selects the exact input bytes.)

```json
{
  "profile": "owned_elf",
  "profile_sha256": "EXACT_PROFILE_DIGEST_RETURNED_BY_PROFILES",
  "idempotency_key": "owned-build-17-headers",
  "operation": "headers",
  "artifact_path": "/srv/owned-builds/program.elf",
  "artifact_sha256": "EXACT_ARTIFACT_SHA256"
}
```

- `rea_static_start` calls `native::execute_or_observe` using a stable owner key.
- `rea_static_status` calls `native::observe_request`; it cannot start work.
- `rea_static_read` calls `native::observe_terminal_output`; pending or unknown
  status is preserved. Completed output is checked against the admitted input,
  profile, backend, runtime and complete durable-job output witness.
- `rea_static_cancel` calls `native::cancel_request` for this exact request;
  cancellation acknowledgement is followed by status observation.

The full original request is the recovery handle; no separate registry or
supervisor is created. A changed payload retains the same owner key, so the
existing owner rejects an attempted substitution. If the profile changes, the
adapter rejects the old profile pin instead of submitting a job on a new host.
Historical jobs remain accessible through the original stored owner job reference
returned by `start`; changing deployment profiles does not rewrite that history.

## GNU worker execution

The execution details in this section apply to GNU readelf/objdump. Fixed Java
providers use the installed-launcher checks and private scratch lifecycle
specified in [ELF_AND_JAVA.md](ELF_AND_JAVA.md); their installed runtime is not a
sealed executable snapshot, and owner-level cancellation can leave scratch.

The ordinary owner starts the same runtime binary with the hidden
`rea-static-worker` command and supplies one bounded JSON request on stdin.
The worker verifies its running `/proc/self/exe` bytes, snapshots and hashes the
configured backend, and checks its exact version. The selected artifact is opened
by descriptor-relative traversal under an admitted root, with symlink descendants
refused. It is streamed into a memory file and compared with the caller's required
SHA-256. The worker checks ordinary source changes during capture.

Both backend and input snapshots are sealed against writes, growth and truncation
before use. The backend executes from its pinned memory snapshot and receives the
artifact through an inherited `/proc/self/fd` descriptor. It never executes the
artifact. No temporary directory or disk snapshot is left behind after cancellation.
Backend children retain the durable owner's process group and are subject to its
resource and cancellation mechanism; there is no detached child or new daemon.

Only these fixed argument sets exist:

| Operation | GNU readelf | GNU objdump |
| --- | --- | --- |
| headers | `--file-header --wide` | `--file-headers` |
| sections | `--section-headers --wide` | `--section-headers` |
| symbols | `--symbols --wide` | `--syms` |
| notes | `--notes --wide` | unsupported |
| relocations | `--relocs --wide` | `--reloc` |

Every invocation adds `--` followed by the internal descriptor path. The caller
cannot supply flags, plugins, scripts, commands, destinations or output files.
The backend environment is cleared except `LC_ALL=C`. Parent job policy continues
to govern network and account access.

Each output stream has a hard live byte bound. Overflow or deadline kills and
reaps the backend, and no partial report is represented as a complete analysis.
A nonzero backend exit is retained as a failed analysis with its complete bounded
diagnostics. The worker itself then exits nonzero. Its structured report remains
available through the original durable output.

## Evidence and capability boundary

Reports use `hepta.rea.static-report.v1` and a `hepta_rea_static_v1_` digest. They
retain unmodified UTF-8 backend stdout/stderr plus their byte counts/hashes,
backend/runtime pins, input snapshot identity and the exact operation. They remain
`rea_evidence_compatible=false` and explicitly partial in scope. A successful
process or parse does not establish full format correctness or decompiler parity.

For GNU providers, the Rust summary maps selected readelf header labels and GNU
build-id hex strings. Every fact points to its line in the retained stdout. It preserves
duplicate observations, bounds retained facts at 64, labels truncation and leaves
unsupported operations unmapped. `rea_static_read` independently recomputes this
mapping from the retained text before returning it. This is not independent ELF
validation: there are no inferred physical ranges, note descriptor hashes,
complete table coverage, GPU ISA conclusions or upstream Evidence compatibility.

An ELF GPU object can be inspected only to the extent supported by the exact
admitted GNU backend. A synthetic ELF with a GPU machine identifier is a structural
fixture; it is not a real CUDA/ROCm compiler output, GPU ISA validation or proof
that the backend understands every GPU object format. Dynamic system-library
contents are not pinned by the executable SHA/version contract.

## Verification to run

Sibling Rust unit tests cover fixed argv, path/profile admission, profile changes,
same-key changed-content identity, report substitution, immutable memory snapshots
and symlink rejection. Two explicit owned-host tests cover real GNU readelf on the
test suite's own compiled ELF, version mismatch, actual output overflow and deadline
cleanup. These tests do not install packages or analyze an external target.

`tests/rea_static_external.rs` is an ignored, explicit opt-in Linux/remote-fs test
for the actual stdio MCP → native durable owner → localhost SSH → worker chain:

```bash
HEPTA_REA_STATIC_REAL_SSH=1 cargo test --test rea_static_external -- --ignored --nocapture
```

It compiles its own Rust object, checks actual GNU headers, sections, symbols and
relocations, and retains the exact original job/result across controller restart.
It verifies same-key reuse, changed-operation/profile rejection and observation
without submission. A separately compiled and pinned synthetic backend provides
a deterministic live job for cancellation: restart recovers the original job,
the original backend PID/start-time identity disappears, and the attempt counter
remains one. This synthetic backend is lifecycle evidence only; it is explicitly
excluded from GNU semantic coverage. The test provisions only its own temporary
fence/state/artifacts and does not edit the active service's admission authority.

The host needs already working authorized localhost SSH and the existing jobs
isolation mechanism, GNU readelf and rustc. The test installs nothing. Passing
unit tests, adding the ignored test, or spawning readelf is not an E2E pass.

`scripts/rea_static_fixtures.py --output-dir /absolute/new/qualification-dir`
adds independent semantic checks on an owned Rust object and cdylib. It verifies
all five fixed readelf operations and four objdump operations, including a known
GNU build-id, while recording executable hashes, versions, input hashes and raw
output hashes. It also constructs an ELF with an AMDGPU machine ID and checks its
header, section and note structure. That object has no valid GPU instructions.
The output directory must be new, and the script never executes any inspected
artifact. These direct backend checks supplement the MCP lifecycle test.

## Frozen upstream comparison

The comparison baseline is REA 6.8.0 at
[`93b8b82db70279e40f484114cff9dc1958dc14ee`](https://github.com/morluto/rea/tree/93b8b82db70279e40f484114cff9dc1958dc14ee),
published archive SHA-256
`8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb`.

| Selected fact | This adapter/fixture | Frozen REA scope and remaining gap |
| --- | --- | --- |
| ELF header, section names | Actual fixed GNU operation text and source identity | Not a replacement for complete `inspect_binary_layout` or loader behavior |
| Rust exported symbol and external relocation | `hepta_static_fixture` and `puts` on the owned Rust object | Does not reproduce full export visibility/version normalization or infer behavior |
| GNU build-id | Known build-id observed by `readelf --notes` on an owned cdylib | REA also retains physical table/entry ranges, note descriptor hashes, owners/types and independent PT_NOTE/SHT_NOTE coverage |
| GPU object structure | Synthetic AMDGPU ELF machine/section/note facts | Does not qualify real CUDA fatbin/CUBIN/PTX, HIP/CCOB, AMDGPU MessagePack metadata, kernel parameters, GPU ISA or actual CUDA/ROCm compiler outputs |

For a real selected-field oracle, the fixture script accepts both
`--rea-package /installed/rea-agents` and `--rea-archive /frozen/rea-agents-6.8.0.tgz`.
It verifies the fixed archive hash and the installed package's archived bytes
before invoking its read-only `inspect-elf-notes` CLI on the owned cdylib. The
comparison asserts only the known `gnu.build_id_hex`; it does not compare entire
Evidence envelopes. If the reference package/archive is absent, the JSON report
records `rea_reference.executed=false`; source review is not reported as a run.

The scope distinctions follow the pinned upstream
[`docs/elf-notes.md`](https://github.com/morluto/rea/blob/93b8b82db70279e40f484114cff9dc1958dc14ee/docs/elf-notes.md),
[`src/domain/native/elfNotes.ts`](https://github.com/morluto/rea/blob/93b8b82db70279e40f484114cff9dc1958dc14ee/src/domain/native/elfNotes.ts),
and [`docs/gpu-code-objects.md`](https://github.com/morluto/rea/blob/93b8b82db70279e40f484114cff9dc1958dc14ee/docs/gpu-code-objects.md).

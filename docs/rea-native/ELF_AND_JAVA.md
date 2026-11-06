# Native ELF and fixed Java engine observations

This increment adds native ELF inspection and fixed Java-engine adapters. None
executes an inspected program. Native ELF parsing runs in Rust within the existing
artifact inspection worker. The optional JADX 1.5.6 and Ghidra 12.2 providers run
installed analysis engines under the existing static job owner. They are not Rust
rewrites of those mature engines.

## ELF facts and limits

The ELF reader validates ELF32/ELF64 headers in either byte order, section and
program table ranges, section-name tables, symbol-table links, symbol strings,
extended section indexes, and bounded note records. It returns actual sections,
symbols and GNU build-id bytes when present. A build-id is an observed byte
string, not an authenticity proof. It handles NOBITS without treating virtual
storage as file-backed bytes.

Resource ceilings are 32 MiB input, 65,536 section headers, 16,384 program headers,
262,144 scanned symbols, 16 MiB scanned symbol-name bytes, and 4,096 scanned notes.
Returned detail is separately bounded to 256 rows per inventory and a 192 KiB
report. Exceeding a detail budget preserves summary/counts and marks omission;
it does not silently turn a partial inventory into a complete result.

GPU observations come from ELF machine identity and ABI/flag bytes. Machine 224
identifies AMDGPU and machine 190 identifies NVIDIA CUDA. Exact target ISA and
kernel inventory remain absent unless a parser establishes them. File names are
not evidence of a GPU architecture. This reader does not decode instructions,
relocations, vendor kernel metadata or every ELF semantic rule.

## Optional JADX provider

Use the existing `rea_static_profiles/start/status/read/cancel` family with
provider `jadx`. Operations are `classes` and `sources`. The fixed bridge loads
only the bundled Java and DEX input plugins. It accepts class, DEX or ZIP/JAR/APK
byte carriers, suppresses resource saving, automatic deobfuscation and external
dependency loading, and never loads inspected classes for execution.

Class observations include raw class identity, a bounded method-name inventory
and observed counts. Sources additionally include bounded reconstructed source
previews and SHA-256 of the full source text returned by JADX for each selected
class. The result always says `source_semantics_validated: false`. Decompiled
source is an engine observation and is not proof that the original program has
the same semantics.

At most 64 classes are detailed, at most 16 methods per class are named, and
source previews are capped at 1,024 UTF-16 code units without cutting surrogate
pairs. The final serialized observation is reduced to the configured output
budget and reports omitted class counts. Resource and bytecode-level parity
with the full upstream REA/JADX surface is not claimed.

## Installation identity

Existing GNU profiles keep exactly the same serialized identity: the new
`java_engine` field defaults to absent and uses `skip_serializing_if`.

A JADX profile additionally fixes:

- `java_home`: canonical Java 21 installation directory.
- `jar_path` and `jar_sha256`: installed JADX 1.5.6 fat JAR.
- `engine_version`: exactly `1.5.6`.
- `release_archive_sha256`: deployment provenance of the independently verified
  upstream distribution; the worker hashes the installed JAR, not that archive.
- `runtime_files`: relative JRE file paths and their SHA-256 values. Required
  entries are `release`, `lib/modules`, `lib/server/libjvm.so`,
  `lib/libjava.so`, `lib/libzip.so`, `lib/libnio.so` and `lib/libjli.so`.

The original profile fields still pin the runtime binary, Java launcher inode
and SHA-256, exact first version line, input roots and resource bounds. Each
runtime component is re-admitted by its canonical installation path and checked
against its held inode before and after Java runs. The engine JAR, compiled-in
bridge source and inspected input are sealed memory snapshots.

Java's launcher requires its installed JRE layout. Its installation and system
shared-library closure therefore are not sealed executable snapshots. Selected
manifest checks detect observed replacements and do not prove that a privileged
concurrent writer could not race a check. Deployment owners must maintain their
trusted engine installations accordingly.

## Job and resource boundary

There is one durable native owner. A retry uses the original complete request,
profile digest and idempotency key. Status and reads only observe it; cancellation
addresses the original job. No additional scheduler or service is introduced.

JADX profiles admit at most 32 MiB artifacts, 64 KiB output per stream, 120 seconds
and 768 MiB–2 GiB owner memory. Java is fixed to one active processor, a 256 MiB
heap, bounded metaspace/code cache, and one JADX analysis thread. A seccomp filter
denies network syscalls in the Java child and blocks ptrace, process_vm and
io_uring operations. The Java child remains able to read its trusted runtime
installation and use its private scratch; this is not a full filesystem or
namespace sandbox.

Scratch directories are created atomically with mode 0700. A 16 MiB per-file
RLIMIT applies. A monitor samples aggregate scratch usage every 250 ms with
64 MiB / 1,024-entry budgets. The aggregate limit is a monitored budget, not a
hard filesystem quota; writes may exceed it between observations. Normal
completion or handled failure removes scratch. Owner-level interruption can
leave the private directory whose path is retained in worker stderr. The owner
may remove that directory after confirming the original job is terminal.

## Qualification

Unit tests cover malformed ELF tables and semantic identities, a real object
compiled from test-authored C source (never executed), legacy GNU identity,
provider/operation admission, report bindings, canonical installation path
replacement and scratch permissions.

`tests/rea_java_external.py` is an explicit real-engine qualification harness.
It requires an installed verified JADX/JDK, an already working localhost
SSH/systemd owner, and `--allow-local-ssh`. It compiles only its own Java fixtures
and checks the native worker, MCP classes/source results, exact replay,
controller restart, frozen-owner observation, original-job cancellation and
unchanged fixture bytes. It writes the actual pins, reports and qualification
outcome to its new private workspace. A successful API-only probe does not
qualify that native lifecycle.

## Qualified operator-mode lifecycle and versioned Ghidra adapter

The first real JADX native-worker/MCP/SSH lifecycle qualification is retained in
[the dated qualification record](../qualification/rea-jadx-operator-20261103-r1/README.md).
It binds one exact copied runtime SHA and explicitly qualifies operator mode.
Its earlier isolated-mode attempt remains unqualified because the required
system jobctl was not deployed. Successful operator lifecycle checks do not
establish isolated-host deployment.

A `ghidra` profile with no `ghidra_engine.bridge_revision` retains the original
inventory bridge bytes and serialized profile identity. This legacy route
admits only `inventory`. Its fixed Java 25 bridge uses Ghidra 12.2 `ProgramLoader`
with `ElfLoader`, disables loading external libraries and linking project
libraries, and does not invoke the auto-analysis manager, decompiler, target
program or project save operation. It returns bounded language/compiler,
memory-block and imported-symbol facts.

An explicitly admitted `bridge_revision: 2` selects distinct bridge bytes and a
new profile identity. It can allow `inventory`, `functions`, `function`, `xrefs`
and `decompile`. Revision 2 inventory retains import-only semantics and repairs
the named-byte-provider failure observed on a dynamically linked ELF. The four
analysis operations use a fixed, partial analyzer profile; `decompile` invokes
Ghidra's native decompiler for one canonical function entry. Target-library
loading, project linking, target execution and project saving remain disabled.
Ghidra 12.2 and JDK 25 are external engine dependencies. These observations do
not establish full analyzer coverage, general source equivalence or REA parity.
See [GHIDRA_ANALYSIS.md](GHIDRA_ANALYSIS.md) for migration, selectors, analysis
budgets and qualification. This is an engine adapter, not a Rust rewrite of
Ghidra.

The optional `ghidra_engine` field preserves existing GNU/JADX serialized
profiles when absent. It specifies `java_home`, `installation_root`,
`manifest_path`, `manifest_sha256`, fixed `engine_version: "12.2"`,
`release_archive_sha256`, and the same seven required relative JRE file pins.
Its optional `bridge_revision` is omitted when absent; only explicit value `2`
admits the new bridges. Legacy profiles are not silently upgraded.
The separately pinned manifest has schema
`hepta.rea.ghidra-installation.v1`, engine version, archive SHA, and a
`files` map of relative paths to SHA-256 values. The complete actual
`Ghidra/` subtree must match it. At most 20,000 files / 8 GiB are admitted;
the manifest itself is limited to 8 MiB.

Only manifest-pinned JARs in Framework, Configurations, Features and Processors
lib directories enter the explicit classpath. Their installed paths are checked
before and after use. The manifest, bridge and inspected ELF are sealed memory
snapshots; the installed Ghidra/JRE files and system shared-library closure are
not sealed. Privileged concurrent writers can race path observations.

Ghidra profiles admit at most 8 MiB ELF input, 2–64 KiB output per stream,
1–2 GiB owner memory and 120 seconds. The inventory details at most 128 memory
blocks and 128 imported symbols while scanning at most 4,096 symbols. Counts and
scan-completeness fields distinguish omitted rows from unobserved symbols.
The shared private scratch/child network boundary and its limitations apply.

`tests/rea_ghidra_external.py` retains the legacy inventory qualification. It
creates and compiles only its own C object files, checks actual import facts,
same-owner retry/restart, kernel flags on the fixed Java source child, and
cancels an observed live Java child through the original owner job.
`tests/rea_ghidra_analysis_external.py` qualifies the revision 2 dynamic-ELF
inventory and all four analysis operations, with independent fixture facts,
original-job replay/restart and cancellation of an observed native decompiler.
A successful record for the exact runtime and installation is required before
claiming that route qualified; the earlier records below describe their frozen
inventory implementation.

### Ghidra installation must be read-only to the engine identity

Prepare a verified official distribution with its original file timestamps, and
keep the installation directories and files non-writable to the actual JVM
identity. Do not admit first-use `*.sla.lock` files into the official installation
manifest. Ghidra 12.2 normally creates these locks and writes/truncates lock
contents even when it does not need to compile a language. If it cannot open a
lock for writing, its documented code path directly reads the existing compiled
SLA instead. This permits the worker's strict file-set and metadata checks to
remain unchanged.

In the recorded preparation, all 5,324 release files matched the official ZIP
bytes; ZIP timestamps were restored, and 135 empty locks created by the initial
API-only probe were removed before the tree was made read-only. A repeat under
UID 1000 returned the expected import facts with all 3,078 `Ghidra/` files and
their identity/metadata unchanged. This is an installation prerequisite verified
for that identity, not a claim that chmod constrains a root or capability-bearing
process. The exact preparation and read-only API observation are retained with
the dated Ghidra qualification evidence.

Official implementation references:
[SleighLanguageFile read-only lock handling](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/app/plugin/processors/sleigh/SleighLanguageFile.java)
and
[SleighLanguage compiled-SLA loading](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/app/plugin/processors/sleigh/SleighLanguage.java).


## Earlier qualification on the frozen runtime

Both [JADX](../qualification/rea-jadx-operator-final-20261103-r1/README.md)
and [Ghidra](../qualification/rea-ghidra-operator-20261103-r1/README.md)
passed their real native-worker and operator-mode MCP/SSH lifecycle harnesses on
the same exact runtime SHA-256
`680edd4d3252f7d39d771de81c66eb02222c65e6d14e16f5458c1e5480111cc7`.
The retained evidence includes actual semantic observations, original job
identity through replay and controller restart, frozen-owner cancellation and
unchanged self-authored artifact bytes. Ghidra cancellation also observed the
live Java child and confirmed its original PID/start identity disappeared.

Ghidra returned the expected x86-64/gcc import, 12 memory blocks and four imported
symbols from the harness's own ELF object. Its complete 3,078-file installation
manifest and before/after path checks passed with the read-only distribution.
Actual direct-native and MCP Java children had NoNewPrivs 1 and Seccomp 2; this
observes active kernel filters, without separately decoding their rules or
making a network connection attempt.

These records qualify the named operator-mode deployments and bounded static
operations. They do not claim isolated-host deployment, a fully sealed installed
engine/JRE closure, full REA capability parity or execution of any inspected
target. Exact source/harness hashes and reproducible invocation recipes are
retained beside the raw records.


## Qualification after the runtime bootstrap fix with umask 0022

The shared state-root bootstrap fix was followed by one new run of each original
frozen engine harness. Both
[JADX](../qualification/rea-jadx-operator-umask022-20261103-r1/README.md) and
[Ghidra](../qualification/rea-ghidra-operator-umask022-20261103-r1/README.md)
qualified on exact runtime SHA-256
`290fa949b7744c85018f9f26b32fbdd1884cce1c31ff202a9f076bc3d6a89c63`.
The outer launch explicitly set 0022; actual harness, direct native worker and
both MCP controller instances had observed `Umask: 0022`. Config/fence files
remained 0600 and their fixture directories remained 0700.

The runtime config SHA-256 was
`836b9a85a74dc84f2a82063f164ac5c0343696b68774962eb0e677ee2630b9e0`.
The retained source inventories include that file and the unchanged engine and
harness sources. Source hashes matched before and after the runs. Previous
exact-binary records are preserved separately.

These are operator-mode lifecycle results, not GitHub CI or isolated-host
qualification. The fixtures precreate their state directories as 0700; separate
focused runtime tests cover creation of a missing state root. The remote
SSH/systemd owner's umask is outside the independently observed 0022 scope.

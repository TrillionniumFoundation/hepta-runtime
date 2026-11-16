# Isolated SDK 3.9 CI recipe, version 3

This is an additive CI source overlay on the frozen 185-file recovery bundle.
All 185 original file hashes remain unchanged. The overlay supplies the missing
Rust modules, retained component sources, five exact fixture lock seeds, and the
CI orchestration. It has not been executed with Rust or native code.

Use `scripts/run_full_public_recipe.py` for this recipe. The older
`scripts/run_public_recipe.py` and README.md are retained as historical recovery
inputs. The v2 source-only check covered hashes and Python syntax; it omitted
the G4 Rust module closure. That preparation gap is recorded in
`preparation-history/v2-missing-rust-module-closure.json`.

## Installation and workflow

Place the complete source bundle at a repository path chosen by the root agent.
The supplied `ci/workflow.sdk-target.yml` is a complete manual workflow. Its
`source_path` input defaults to `tests/hia_native/sdk_target_ci`; set it to the
actual installation path. Root controls tree, commit, branch, and dispatch.
This package creates none of them.

The workflow checks out three exact inputs: the candidate containing this bundle,
Hepta commit d3e2c90173cf733e42b299d0c4274df4b593a12f, and current original
Rust target d3d75c30719db966b004756f610007a7c723729e. It compares original
Cargo.toml, Cargo.lock, and src/mcp/server.rs with the bundled copies.
Historical public58 owners remain bound to v9
e3c7342325b2260be1459ac2a8c4e7c8d219e4f6.

The worker needs Linux x86-64, Python 3.11 or later, git, binutils, a C linker
toolchain, and Rust 1.95.0. This recipe uses no third-party Python packages.
The workflow installs the native build tools and exact Rust toolchain.
All Rust/native execution belongs on the authorized CI worker.

The machine-readable dependency list is `ci/dependencies.json`. It lists all
five projects, literal Rust module/include closures, lock seeds, expected normal
domain counts, generated-input pins, and compiler/target identities.

## Source-only checks

These commands parse and hash source files without running Rust, HIA, or inputs:

```sh
python3 -I -B /path/to/bundle/scripts/ci_source_dependencies.py \
  --source /path/to/bundle
python3 -I -B /path/to/bundle/scripts/run_full_public_recipe.py \
  --source /path/to/bundle --check-only
```

The additional checker verifies each `mod name;` and literal `include!` edge
in the five fixed fixtures, every source/image pin used by retained components,
all exact direct dependency versions, all registry versions/checksums in the
frozen subset locks, and the unchanged 185-file base.

## Cache preparation and execution

CI first fetches the exact fixture closures into its dedicated Cargo cache:

```sh
python3 -I -B /path/to/bundle/scripts/prepare_ci_cargo_cache.py \
  --source /path/to/bundle \
  --output /path/to/new-cache-preparation \
  --rust-bin /path/to/rust-1.95.0/bin
```

This step runs `cargo fetch --locked` in separate projects created from the
fixed source files and subset lock seeds. It performs no compilation. The later
qualification starts from the complete current target Cargo.lock in fresh
projects, resolves offline, verifies every retained package against the target,
checks cached crate archives and their extracted source files, and then builds
with `cargo build --locked --offline`.

```sh
python3 -I -B /path/to/bundle/scripts/run_full_public_recipe.py \
  --source /path/to/bundle \
  --output /path/to/new-qualification-output \
  --hepta /path/to/pinned-hepta \
  --rust-bin /path/to/rust-1.95.0/bin
```

Both output paths must be unused and outside the source bundle. All input files
remain unchanged. A failed attempt retains its process records, stdout, stderr,
partial observations, and summary. A corrected attempt uses a new output path.

## Five actual original Rust fixtures

| Fixture | Actual SDK boundary | Native comparison |
|---|---|---|
| Catalog/request | Nonempty typed catalogs and CallTool/ReadResource extraction | 654 ordinary cases |
| Context | RequestContext capability selection plus typed ClientCapabilities | 104 contexts and 11 typed capability values |
| Response | CallTool/ReadResource result extraction, typed serialization and cache policy | 215 response cases, 119 typed emitter cases, 3 cache sessions / 15 responses |
| Transport/message | Actual AsyncRwTransport, separate codec.decode_eof, shutdown observations and message types | 197 G1 projections, 25 native transport cases, 4 separate codec EOF cases, 12 native shutdown-policy calls |
| Connection | Actual normal bootstrap, discovery, version negotiation and request context | 67 sessions through components and the packed four-image fixture |

The G3 generated input files are produced only in the CI output directory.
The generator and every resulting file are checked against the original frozen
manifest before the actual SDK runs. The original normal JSONL and manifest
bytes must remain identical after generation. Large fixture inputs are not
downloaded from ai395 or shipped as prebuilt artifacts.

The shutdown component compares the bounded ordering policy. Its inputs are
trusted queue/send observations. It does not implement a scheduler, task token
registry, or native future cancellation. Those qualification flags remain false.

## Native construction and actual public loop

The runner starts a fresh Hepta development fixed-point bootstrap from the pinned
compiler source. It recompiles every historical public58 owner, all G5 owners
and controller, and the retained component owners. Reuse inside this one run
requires identical source SHA and buffer profile. No prior image or ELF is an
input. Copying the just-built bootstrap into separate pack roots avoids module
name collisions; it does not claim an independent cold qualification.

The retained four-image fixture must reproduce ELF SHA256
bc1c0b930c1b723d1692f5ff1d68b6e8fb0137b20d5d5dad43a6a0264b540a8d.
The historical public58 and new public62 ELF hashes must match their frozen
receipts. The new controller is regenerated from its preserved authoring source
and must match its previously qualified source and image pins.

After the bounded G5 frontend and 2,213-invocation controller domains, the runner
executes four real public stdio processes: historical and target-request graphs,
each in legacy and modern sessions. The ordinary workflow covers all eight
registered tool routes. It compares complete response bytes and complete owned
filesystem snapshots, checks move identity preservation, and compares four
ordinary ID projections and 32 actual target result bodies with fresh SDK
oracles. No handler result is synthesized by the harness.

The expected route set is host_list, effective_config, execution_shadow_admit,
view, workdir, directory_create, file_move, and directory_move.
The synthetic configured host is not contacted.

## Evidence and result interpretation

`evidence/recipe-summary.json` is the aggregate. A bounded success requires
five fresh original SDK fixtures, all retained G1/G2/G3/G4 domains, G5 catalog and
frontend/controller domains, exact public62 packing, and the actual eight-tool
loop. The workflow checks these flags and rejects broad completion claims.

`scripts/export_ci_evidence.py` archives source, cases, process records,
observations, native build artifacts, actual public ELFs, and the five observed
Rust executables. It excludes other Rust target-directory build-cache files.
Every archive member is read back and hash checked. The workflow retains
successful and failed evidence.

The public62 graph still uses historical connection identity, transport, and
response owners. Their target equivalents are qualified in the retained fixture,
not connected to the public graph by this recipe. Current original Rust tool
handler bodies are not all independently qualified; historical native body
equivalence remains a separate result. Later canonical-path changes and the
ninth TextEditor route are separate work.

Full SDK, all 136 routes, full async runtime, native task registry, native future
cancellation, independent cold qualification, production activation, and old
path removal all remain false. A prepared recipe or source-only PASS supplies
no runtime qualification.

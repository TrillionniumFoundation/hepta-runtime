# G5 public eight-tool source rebuild

This recovered source bundle prepares an isolated Linux x86-64 CI run. The input
contains source, ordinary fixture inputs, source/image pins, and historical build
receipts. It does not contain compiled HIA images, ELFs, Rust executables, or a
compiler bootstrap.

## Current status

The complete recipe has not been executed. Python parsing and source/hash checks
are the only checks available in the recovery workspace. Historical evidence is
kept separate: the 62-image public graph and its 2,213 native controller invocations
passed before the environment interruption, while the actual eight-tool public
stdio loop remained unexecuted. No earlier RMCP 3.4.1 qualification is promoted
to a complete RMCP 3.9.0 qualification.

The original 185-file source bundle was lost with ephemeral storage. Its recorded
manifest SHA256 was
`4726a0328f3f19a6e7c1e1b8bd21e805ca985248671145cd334890e1f266e0ea`.
This directory is a new, independently hashed recovery bundle. Its README is new;
its recipe and exact Rust helper were reconstructed from complete prior patches.
The frozen G5 owners and cases were read back and checked against the original
362,435-byte review manifest, SHA256
`57804409ceb0f57c0033623bdbf06b68d98ae3aeac8cb98f2b729d724d20970a`.
The new manifest records recovery provenance and does not assert byte identity
with the lost original bundle.

## Pinned sources

The historical public graph comes from
`TrillionniumFoundation/hepta-runtime@e3c7342325b2260be1459ac2a8c4e7c8d219e4f6`.
Its own source-closure manifest is verified before building.

The current original Rust target is
`TrillionniumFoundation/hepta-runtime@d3d75c30719db966b004756f610007a7c723729e`.
The copied Cargo.lock SHA256 is
`1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631`.
The fixture uses the exact RMCP 3.9.0, serde 1.0.229, serde_json 1.0.151,
Tokio 1.53.3, and schemars 1.2.2 packages retained from that lock.
Historical commit 737acf6f901e46c57b0b4374e323e0d1132e0d49 is not the current
target identity.

The Hepta checkout must be commit
`d3e2c90173cf733e42b299d0c4274df4b593a12f`, with source tree
`8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49`.
The expected development fixed-point bootstrap SHA256 is
`bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`.
Rebuilding that bootstrap does not establish an independent cold qualification.

## Run

First perform the source-only check. This does not execute Rust, Hepta, native
images, or any tool bodies:

```sh
python3 /path/to/bundle/scripts/run_public_recipe.py \
  --source /path/to/bundle --check-only
```

On the authorized CI/build worker, provide an unused output path, the pinned
Hepta source checkout, and the Rust 1.95.0 toolchain bin directory:

```sh
python3 /path/to/bundle/scripts/run_public_recipe.py \
  --source /path/to/bundle \
  --output /path/to/new-output \
  --hepta /path/to/pinned-hepta \
  --rust-bin /path/to/rust-1.95.0/bin
```

Python 3.11 or later and the native build dependencies required by the pinned
Hepta toolchain must be installed. The Cargo registry cache must already contain
the exact fixture closure. Normal Cargo environment settings, including
`CARGO_HOME`, are honored. The runner performs offline metadata resolution,
checks every retained package version/checksum, checks the registry archive
against the target lock, compares extracted source files with each archive, and
runs a fresh `cargo build --locked --offline`. It records each process result.
A failure remains in its output directory; use a different output path for a
corrected rerun.

## Execution scope

The recipe rebuilds three original SDK fixtures from source, all 58 historical
native owners, the G5 typed request/catalog components, and the new controller.
It compares the rebuilt historical and 62-image public ELF hashes with their
historical receipts, then runs ordinary public stdio workflows over an owned
temporary filesystem. All eight registered routes must execute real tool bodies.
The harness compares complete response bytes and filesystem snapshots against
the historical native graph and compares selected request/result serialization
against the actual current SDK fixtures.

The public catalog is slot 0 and the controller is slot 19. New SDK leaves occupy
42 (message), 43 (request), 44 (bridge), and 45 (historical protocol).
Slots 33 through 41 stay reserved for the separately developed TextEditor graph.
This bundle does not register a ninth tool or adopt the later target canonical
path owner.

The graph still uses the historical connection/identity, transport, and response
owners. G1/G2/G3/G4 retained component domains are not all rerun by this recipe.
A successful run may qualify the bounded eight-tool loop and selected SDK data
contracts; it does not qualify all original current-target tool handlers, the
full SDK, full async runtime, native task/future cancellation, independent cold
builds, production activation, or old-path removal. The generated summary retains
those false flags.

The filesystem fixture is local and owned by this run. Its synthetic configured
host is never contacted. This recipe performs no external target operation.

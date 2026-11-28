# Public registry qualification and integration

The new owner is the actual HIA `public_tool_dispatch` module and its fixed
17-image connection/configuration composition. The profile binds the current
shared regex syntax, Unicode, HIR and NFA images. The other thirteen member
sources, the native adapter and the HIA packer remain unchanged. The compiler
remains pinned to d3e2c901; this component does not introduce another cold gate
or replace the existing full compiler qualification.

The current profile SHA-256 is
`e41371914278c6e2b0dcd45ccdd1328d085981fb5fa9579c9c7d8609203ccdc7`.
Its actual HIA packer produces a 4,629,489-byte ELF with SHA-256
`24f03090c0d5b8b2de0d063142c9545876cee46f976397378c09d05cc760fc38`.
Member positions and the complete packer input are derived from the newly
compiled images. The normalized kernel prefix is unchanged. Qualification
must repeat every existing native and fresh original case against this graph;
historical observations do not qualify the changed regex children.

`scripts/build_public_registry.py` compiles all 17 member images and the HIA
packer from source. Final builds need no assembler. Its retained files include
each actual compiler request, source, complete bounded output buffer, stdout,
stderr and receipt, plus the complete packer input, process completion and
native ELF. The build verifier checks extracted image bytes and every fixed
call displacement. It rejects an empty compiler observer even if a surrounding
receipt is internally rehashed.

`hia_native_public_registry_qualification.build_public_registry(hepta,
build_root, source_root)` returns `build/public-registry-build.json` after an
actual bounded build. The build process retains the existing 180-second and
three-second cleanup limits. Timeout cleanup kills its owned process group.
Parent-SIGKILL cleanup of this build wrapper is not qualified; no claim is made
that a killed external supervisor executes the wrapper's cleanup path.

The remaining qualifier API is `build_evidence`, `test_commands`,
`native_evidence(..., completed_test_summary, create=False)` and
`original_evidence`. Evidence admission is read-only and never executes a
semantic owner. Native collection creates the compatibility result only from
the three complete, actually executed test records. Every later admission
reconstructs and compares that result.

The three independent native suites are:

- `run_public_registry_cases.py`: 152 actual processes, 1,038 input events and
  1,036 response frames through the fixed ELF and installed configuration.
- `test_public_registry_controls.py`: 119 actual router calls, including 48
  malformed receipts, 12 child-envelope refusals, 28 private-input refusals and
  8 output-capacity refusals. Its six child completions are explicit fixtures;
  three preserve original error text with a nonzero owner diagnostic category.
- `test_public_registry_elf.py`: 12 additional actual processes and 34 replies,
  including maximum raw lines, final EOF, huge escaped IDs, real configuration
  locks, immutable startup, regex first-error behavior and real execution joins.

The original recipe is `compare_public_registry_original.py --repo ROOT
--build BUILD --output OUTPUT --cargo CARGO --rustc RUSTC --rustfmt RUSTFMT`.
It requires actual Rust 1.95, all 100 original locked dependencies and all 175
installed rmcp 3.4.1 crate files, including its complete 65-file source directory.
Ten server blocks, one HIA catalog predicate
and 54 config/execution blocks are compared directly to the original repository.
The full wrapper is source-pinned; only that test wrapper replaces outer audit
dispatch with the declared fixed route set. Rust is a reference process, never
a runtime fallback.

The recipe builds one new original executable, observes the actual catalog,
and reruns all 152 native and 152 original sessions. It compares the complete
2,372,013-byte result streams, not just parsed JSON values or selected fields.
Every process command, request digest, stdout digest, exit status and empty
stderr is retained. All earlier compilation and observer failures remain in
their private evidence directories; a new successful run does not relabel them.

The completed `public-registry-rust-compare` wrapper must be admitted through
the existing aggregate completion API. The integrity-control script must run
only after writers stop. It damages source/build/corpus/completion evidence,
requires rejection, restores bytes and mode, and re-admits the complete native
and original result after every control. It adds no native or Rust calls.

The next real integrations are per-request trusted Workdir connection state,
shared SessionWorkdir/context/statx cache, additional implemented handlers and
the global request owner/audit/result lifecycle. Repeated initialize can replace
legacy peer capabilities after a typed-parameter failure; a future Workdir bridge
must not reuse a stale fixed startup snapshot. Canonical arguments can exceed
the raw 8 MiB frame length, so no new route may silently reapply that raw limit
to the expanded serde Value representation.

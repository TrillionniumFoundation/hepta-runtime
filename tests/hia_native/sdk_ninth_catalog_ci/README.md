# Exact TextEditor declaration and independent ninth catalog CI recipe

This is a new, reviewable source recipe. It preserves the recovered metadata fixture and adds the missing native catalog qualification path. It is separate from the frozen 246-file public eight-tool v3 recipe. It does not claim byte-for-byte recovery of the earlier lost 23-file preparation directory.

At preparation time only source identities, Python syntax, literal Rust include closure, local workflow YAML/shell syntax, and original source fragments are checked. No Rust compiler, HIA compiler, native image, or tool method has been executed locally. A successful source check is not a runtime qualification. Local YAML and shell checks do not validate GitHub expression-context availability; the initial draft with job-level `runner.temp` references is preserved under `preparation-history`. The active template instead derives temporary paths from `RUNNER_TEMP` in its first step and writes them to `GITHUB_ENV`. GitHub workflow-service validation still awaits publication by the parent.

## Exact inputs

The original application is `TrillionniumFoundation/hepta-runtime` commit `d3d75c30719db966b004756f610007a7c723729e`. The included `target/Cargo.toml`, `target/Cargo.lock`, and `target/src/mcp/server.rs` bind this recipe to that current original. Historical commit `737acf6f901e46c57b0b4374e323e0d1132e0d49` is not used as the identity of the current target.

The fixture uses RMCP 3.9.0, schemars 1.2.2, serde 1.0.229, and serde_json 1.0.151, with exact versions in `oracle/Cargo.toml`. Its own lock is freshly derived from the full application lock in CI. Every retained registry version and checksum must occur in the original target lock. Before the fresh offline build, each downloaded crate archive and its extracted source files are checked against the target checksum.

Hepta is pinned to commit `d3e2c90173cf733e42b299d0c4274df4b593a12f`, tree `8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49`. The recipe builds and verifies the development fixed point B1 = B2 = B3 with SHA-256 `bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`. This is not a new independent cold-bootstrap qualification.

`source-pins/metadata-fragments.json` binds the exact command enum, parameter struct, and `#[tool]` attribute plus method signature to unique byte spans in the current original source. The metadata fixture retains those bytes. Its method body is a panic sentinel and is never called. Two leading inner documentation comments were converted to plain comments to permit `include!`; the actual metadata fragments remain unchanged.

The SDK source audit files come from the official `modelcontextprotocol/rust-sdk` release commit `5596a8a0bba2a1ec5519cc855cdadf23e4dcecdc`. In that source `#[tool]` generates `text_editor_tool_attr()`, and `schema_for_input::<TextEditorParams>()` returns `Result<Arc<JsonObject>, String>`. The fixture checks their actual runtime results after compilation in CI.

## What CI does

1. Verify the complete source manifest, exact original source fragments, dependency pins, retained HIA sources, and the literal Rust include edge. Check the exact original and Hepta Git revisions independently through fresh checkouts.
2. Populate a dedicated Cargo cache. The smaller macro fixture requires pruning the full application lock. The cache preparation uses Cargo metadata without compiling or executing crates, then rejects any retained version or checksum outside the original target lock. The subsequent fixture build begins again from the original full lock, resolves offline, verifies archived and extracted sources, and builds with `--locked --offline` into a new target directory using Rust 1.95.0.
3. Invoke the actual original macro metadata accessor. Assert name `text_editor`, title `Text Editor`, the exact schema accessor result, and the four explicit annotations. Save the complete declaration. The filesystem method remains uncalled.
4. Append that declaration to the eight retained public declarations. Ask actual RMCP 3.9.0 to deserialize and serialize all three normal result policies: unchanged typed result, legacy type stripping, and modern cache hint defaults.
5. Build the pinned HIA serde, SDK catalog, and eight-item public catalog owners from source. Canonicalize the same catalog input in native serde and compare the native SDK catalog output against the original Rust result for all three policies.
6. Produce both public list suffixes from the actual native SDK catalog output. Those native bytes become the new catalog literals. Expected serialized Rust output is used only for comparison, never as the HIA implementation.
7. Add a ninth-list entry to the existing catalog source. The previous entry is cloned exactly; only function `f0` changes, and every other original function AST must remain exact. Compile the generated catalog into a fourth native module. Compare its two ordinary list modes to the native-produced suffixes, check that the first eight declarations and all result metadata remain unchanged, and compare all 18 existing non-list operations byte for byte against the baseline owner.
8. Preserve the original Rust executable, four native modules, generated HIA source and composition, process logs, all inputs and outputs, and successful or failed summaries in a read-back-verified archive. The completed Rust build receipt is written before the first oracle invocation, so a metadata assertion failure still leaves the original executable eligible for archival.

The intended comparison count is three typed catalog policies, two public list modes, 18 retained non-list operations, and 46 actual native calls. Counts become evidence only after CI completes.

## Execution interface

Static checks need only Python and may run locally:

```bash
python3 -I -B SOURCE/scripts/run_ninth_catalog_recipe.py --source SOURCE --check-only
```

Rust and HIA execution are explicitly restricted to CI. Both execution entry points require `CI=true`. The complete workflow template is `ci/workflow.ninth-catalog.yml`. Parent integration may install it as a temporary workflow and choose the repository source directory; the frozen source template is not a branch trigger by itself.

The workflow uses these commands, with fresh output directories and a dedicated `CARGO_HOME`:

```bash
python3 -I -B SOURCE/scripts/prepare_ci_cargo_cache.py \
  --source SOURCE --output CACHE_PREPARATION --rust-bin RUST_BIN
python3 -I -B SOURCE/scripts/run_ninth_catalog_recipe.py \
  --source SOURCE --output OUTPUT --hepta HEPTA_SOURCE --rust-bin RUST_BIN
```

The runtime entry point has the portable parameters `source`, `output`, `hepta`, and `rust-bin`. It consumes no `/home/qq` directory and no precompiled image. Recorded recovery paths in `source-pins/reused-sources.json` document provenance only; they are never opened during execution.

## Future integration boundary

The generated source is `generated/native/runtime_mcp_catalog_ninth.hepta`, with its generated composition beside it. It accepts the existing slot-0 `HRMCD002` catalog request ABI and returns the `HRCATR02` header plus suffix. The ABI entry returns the 32-byte header length; the payload length is the word at offset 16. The qualifier reads and checks that full extent explicitly.

This recipe does not install that owner in a public graph, does not add a TextEditor dispatcher case, and does not invoke the original or native TextEditor body. It does not select any older private 75-image graph. Later integration must use the parent's final TextEditor source, caller, adapter, and slot allocations, and must prove the public request-to-body-to-response path separately.

The public eighth-tool v3 loop, the nine-item metadata/catalog boundary, the parent's private TextEditor body qualification, and a future public ninth route are separate claims. `public_route_registered`, `public_text_editor_body_qualified`, `full_sdk_qualified`, `full_136_route_qualified`, full async/task/future flags, production activation, old-path removal, and cold-bootstrap qualification remain false here, including after a bounded catalog PASS.

# Repository layout and language boundaries

## Current ownership

Hepta Runtime is a Rust application with explicit helper and engine boundaries.
A native implementation for one route does not replace another route's Python
or Java implementation.

| Area | Current role and retention rule |
| --- | --- |
| `src/**/*.rs` | Cargo/module closure; all 429 Rust source files are connected |
| `src/mcp/runtime/*.py` | Seventeen live Rust-embedded document, file, process, search, stream, terminal and checkpoint helpers |
| Python strings in `jobs.rs` | macOS/operator launch, status, read and cancellation paths |
| Nine Java sources in `src/mcp` | Active revision-specific Ghidra/JADX bridges |
| `workers/weight/` | Optional resident model computation; Rust native client supplies transport |
| `tools/cloud-compute/` | Colab/Kaggle dispatch, recovery, version binding and offline CI |
| `deploy/`, `config/` | Supported installation, gateway, service and operator interfaces |
| `scripts/`, `tests/`, `.github/` | Regressions and independent Python/JavaScript references |
| `vendor/ruzstd/` | Required pinned Rust decoder, local fixes, license and provenance |
| `experiments/`, `qualification/` | Retained standalone research with separate stated scope |
| `docs/qualification/`, `tests/evidence/` | Retained evidence and current consumers |
| `archives/` | Exact inventories of original content retained in reachable history |

Document routes need their configured Python interpreter/libraries; model routes
need the worker's declared dependencies; Ghidra/JADX need their engines/JDK. Native
artifact routes have different boundaries. See [unified runtime](rea-native/UNIFIED_RUNTIME.md)
and [weight owner](weight-runtime/RUST_OWNER.md).

## Historical material and recovery

The complete pre-cleanup snapshot remains at
[`a404d4f1bf540fb94f65ef3707145eed07eef183`](https://github.com/TrillionniumFoundation/hepta-runtime/tree/a404d4f1bf540fb94f65ef3707145eed07eef183).
The [Rust branch index](../archives/rust-branches/README.md) and
[repository history index](../archives/repository-history/README.md) record original
commit/tree/path/blob/mode identities. Historical failures and partial attempts
retain their original bytes and classifications. Current documentation points to
immutable evidence URLs.

```bash
git worktree add --detach /your/isolated/hepta-runtime-history \
  a404d4f1bf540fb94f65ef3707145eed07eef183
python3 scripts/verify_rust_consolidation.py
```

Use the verifier from the cleanup checkout and the separate historical worktree
for original reproductions. Shallow or incomplete clones need an explicit history
fetch first. Verification checks ancestry, source identities, complete retired
subtree inventories and local object availability; it never fetches or executes
archived code. Those checks establish custody, not runtime performance.

The X230 October 28–30 harnesses remain in CI. `tools/x230/a27/` remains because
the throughput runner loads its pinned resource sampler by a relative path.
The `v9-harness-drafts` input remains because current tests/workflows pin it.

## One bridge implementation

`deploy/readonly-bridge/bridge.py` is the canonical standalone bridge; copy that
file to the installed service location. `deploy/chatgpt_mcp_bridge.py` delegates
to it in the checkout, preserving CLI behavior and module globals. Both entries
retain stdio/HTTP regression coverage.

## Package and release boundaries

Build from Git with the local `ruzstd` patch. Ordinary Cargo registry packaging
omits the root override and nested crate; its current file list is not a supported
release contract. Historical retirement reduces that list while the private
release still packages the supported binaries and tracked `deploy/` assets.

Cargo metadata remains unchanged. `weight_guard_journal.rs` embeds the entire
manifest in persistent request identity, so even package-only metadata changes
would affect journal selection after rebuilding. Any future packaging redesign
needs a separate identity compatibility assessment. See
[release validation](../.agents/release.md) and [the cleanup audit](audits/repository-cleanup-20261115/README.md).

## Maintenance

Keep active source with its owner and entry point. Keep independent reference
implementations while tests depend on them. Store routine build output, caches
and logs in workflow artifacts; commit evidence only for a documented maintained
consumer or reproducibility requirement. Retire complete historical collections
with exact inventories and reachable originals, then redirect current links.

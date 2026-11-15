# Contributing to Hepta Runtime

Use a Git checkout, including the patched `vendor/ruzstd` crate and embedded
helpers. See [repository layout](docs/REPOSITORY_LAYOUT.md) for ownership and
archive rules. CI pins Rust 1.95.0 and cargo-nextest 0.9.137.

## Build and validation

```bash
cargo +1.95.0 fmt --all -- --check
cargo +1.95.0 check --locked --all-targets --all-features
cargo +1.95.0 check --locked --all-targets --no-default-features
cargo +1.95.0 clippy --locked --all-targets --all-features -- -D warnings
cargo +1.95.0 clippy --locked --all-targets --no-default-features -- -D warnings
cargo +1.95.0 nextest run --locked --all-targets --all-features \
  --test-threads 1 --retries 0 --no-fail-fast
cargo +1.95.0 nextest run --locked --all-targets --no-default-features \
  --test-threads 1 --retries 0 --no-fail-fast
cargo +1.95.0 build --locked --release --bins --examples
```

The complete suite needs isolated processes because some tests change global
state. Workflows also run Python/JavaScript references, deployment checks and
native integrations; see [CI validation](.agents/release.md). Preserve failures
and report unavailable host capabilities explicitly.

For local MCP development:

```bash
RUST_LOG=debug cargo +1.95.0 run --locked --bin hepta-runtime -- mcp
```

## Changes and reviews

Use focused branches and describe the problem, changed behavior and actual
validation. Preserve copyright notices, hard-tab formatting and sibling Rust test
modules. Read [tool authoring](.agents/tool-authoring.md) and
[remote SSH](.agents/remote-ssh.md) guidance for those areas.

Python/Java helpers embedded by Rust are source dependencies. Keep independent
oracles that active tests use. Routine generated logs, binaries and run outputs
belong in workflow artifacts unless a maintained consumer requires them in Git.
Preserve each experiment's original result.

Retired historical files must remain in a reachable original commit with complete
path/blob/mode inventories under `archives/`. Verify those records using
`python3 scripts/verify_rust_consolidation.py` from a full-history clone. The
Repository Hygiene workflow exercises archive refusals and active bridge, X230
and REA regression paths.

## Reporting and license

Include source commit, platform, command and complete error in bug reports. Follow
[SECURITY.md](SECURITY.md) for vulnerabilities. Contributions use
[Apache-2.0](LICENSE); original Octofs copyright and attribution remain.

# Native runtime qualification repair

Base: PR #70, d4d48189d03b8ff8dfe8d82652b749fb44cd9d50.

The previous CI combination failed 176 tests. This change creates private test fixture roots that satisfy the existing native audit/state-root policy and installs ripgrep in CI. Production permission validation is retained, including a new refusal regression for a wide state root.

The native library now exposes observe_request(ProcessStartParams). It resolves the original host/idempotency-key/full request digest and physical host/state-root binding, then observes the existing record without issuing a launch. None means only that the local original binding was not found; it is not proof of non-admission and does not authorize replay. Revoking new execution does not prevent read-only observation of an old original request.

## Actual validation

On Linux, under umask 022:

- cargo fmt --all: completed.
- cargo clippy --locked --all-targets --all-features -- -D warnings: passed.
- cargo nextest run --locked --all-targets --all-features --test-threads 1 --retries 0 --no-fail-fast: 1,179 passed, 21 skipped, zero failures; nextest elapsed 1,526.825 seconds.
- Earlier focused gate: 255 passed, including original audit archive and new observation regressions.

The 21 skipped tests remain skipped; this is not evidence that their platform/external prerequisites were exercised. The raw final gate stdout/stderr and authoritative process completion are retained here. The full gate used this worktree's locked dependency graph.

New lost-ack observation tests preserve original identity, reject changed payload/physical bindings and duplicate idempotency records, observe after execution revocation, and never call launch. Qualification host integration separately exercised this API against an actual loopback runtime job; that evidence belongs to the native-agent research branch.

No deployment, production configuration change, or runtime service restart is included.

# D1 ordinary supplement: original launch preflight failure

Native job `1a1b03a9d15-fc05-6f3f` failed once with exit 1, complete durable streams of 0 stdout bytes and 910 stderr bytes, no automatic retry, no cancellation and no timeout. The raw start, terminal status and complete read response are preserved verbatim. Its preceding create-only installation job `1a1b03a1cc4-fc05-6f3b` succeeded.

The failure occurred at the full Q-plus-CI prerequisite binder before the ordinary plan was written and before the launcher could exec the five-stage qualifier. No ordinary Cargo or Rust test stage was reached. The original qualification and native exact CI remain successful independent jobs.

The actual CI plan binds the original manifest `/home/qian/hepta-runtime-optimization-20261105-r25/ci-gates/ci-gate-manifest.json`, 45,857 bytes, SHA256 `bf0df5f7d19ebd149854fbf75887fb0fb136f18a63a0c240abf8420655fb195e`. The full binder's generic declared-input allowlist covered the D1, R24, R35, and nested nextest roots, but not that distinct original manifest path. It consequently rejected its first real full-CI use. Prior metadata sealing and static review did not prove this runtime branch.

The installed ordinary-tools-01 and original rust-ci-prerequisites-01 binder are retained unchanged. Any corrected launch requires a separately reviewed binder with that exact path, byte count and hash, explicit provenance for the original CI binder, a new ordinary namespace, and preserved failure history. It must not widen all input roots, overwrite the original CI plan, claim the revised binder was used in the successful CI, or rerun CI to remove this record. No ordinary or C1 success is claimed here. Accepted runtime remains R24.

# R22 integrated runtime source-closure candidate — 2026-10-17 UTC

**DRAFT / NOT DEPLOYED.** This Git branch is a reviewable source snapshot, not proof that the running R22 native binary was built from this commit.

## Provenance

- Branch parent: `cb999f6cfb1f8a68d83d970cf3c33d5a14df9849` (PR #14 streamed idempotency).
- Imported Rust/localhost test implementation from isolated `hepta-runtime-r22-perf-streamed-20261016-r2`, itself derived from a previously qualified unversioned R22 integration tree.
- Of 166 source Rust/Python paths in the isolated candidate, 164 have identical bytes in this versioned branch. The two deliberate differences are `deploy/chatgpt_computer_http.py` and `deploy/runtime_registry_page.py`, replaced with verified **installed live R22** release bytes.
- All 42 eligible Python/JSON/JS control-plane release assets were verified against the live `latest-r22` release SHA256 manifest at initial import. The current source branch preserves **40** byte-identical; `runtime_registry_page.py` has a **deliberate isolated LRU fairness patch** and `chatgpt_computer_http.py` has a **read-only pager sharing across stateless HTTP lanes** patch. Original and candidate SHA256 values for both files are retained in `docs/R22_CONTROL_PLANE_SOURCE_IMPORT_20261017.json`. The installed R22 file remains untouched.
- Installed R22 native binary SHA256 is `6d4d182b2fa50cc79f921f1a8fb3b7da0dc1456d8d5feddf14d031fb044a079f`. No matching source Git commit or bit-identical native rebuild is proven.
- Prior local source delta was restricted to `src/mcp/runtime/jobs.rs` and `src/mcp/runtime/jobs_tests.rs` across 166 Rust/Python files; `effect_owner_fence.rs` remained byte-identical.
- Prior isolated source closure SHA256 (sorted source path/content digests): `f26f194ceee6c8a5f4b783296a2049927cb9d139dda7256a66ffbd6a2b203870`.

## What is verified, and what is not

- The unversioned source predecessor retains two **historical** disposable-localhost 35-check two-controller V4/V11 owner-fence receipts. They are NOT a fresh acceptance of this Git branch and do not qualify a production owner cutover.
- The integrated candidate completed **38 passing Rust jobs tests** (one explicitly ignored manual benchmark), including host-bound launch locks, positive-cache inode restrictions, streamed exact-key search and paged inventory. After importing **39** Python test files and applying both isolated control-plane patches, a real Git-worktree run of seven control-plane suites completed **171/171 passing tests**, including previously reproduced active-cursor-churn and stateless-HTTP-lane pager-share failures. The original failing runs were retained and not declared green.
- This Git branch contains R22's owner-fence logic and full API/history source together with the performance candidate. It is not installed as an active tunnel or controller.
- All tests and benchmarks on real six-host dispatch, legacy identity replay, CPU/GPU scheduling and operator/DC-off recovery remain subject to independent qualification.
- Do not merge, switch runtime owner, restart tunnel/production control-plane, or retire original Desktop Commander based on this source snapshot alone.

## Safety boundaries

- No private SSH keys, auth tokens, signed host config, actual process history, raw output logs or secrets were imported. A scan of source literals found no recognized PEM/GitHub/Slack/AWS/OpenAI key patterns; this is not exhaustive secret certification.
- No target-host action, broker/trader execution, host reboot, or production mutation was used to create this branch.
- Files included are reviewed source, tool contracts and unit fixtures, not binary installers or connection-specific runtime state.

## Further qualification

1. Complete locked whole-source tests at exact Git commit, including native jobctl, client contracts, and original V4/V11 owner-fence requalification where permitted.
2. Pin reproducible Rust toolchain/build flags and distinguish installed R22 binary equality from new candidate release identity.
3. Perform a single-controller isolated 1/4/8/16/32-way A/B with authoritative job IDs, original stdout/stderr hashes, P50/P95/P99 and rollback. Do not replay uncertain effects.
4. Reconcile original V4 job/PTY/stream retention and single-effect-owner authority before any production promotion.

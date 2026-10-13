# Work handoff — Full Hepta Runtime replacement for Desktop Commander

## Goal and execution scope

The user asks Work to continue implementing, testing, reviewing and deploying **user-authorized** Hepta Runtime capabilities until Desktop Commander can be retired **for the user's actual workflows**, without faking equivalent product/vendor features or weakening the security posture. This is a substantial multi-host software engineering task. The user must select **Work** in the ChatGPT mode picker; this file cannot programmatically change ChatGPT modes.

Use the authorized qian-qi computer and connected GitHub/Hepta tools, with other hosts accessible through existing configured channels. Do not assume new Work instances inherit a shell, privileges or a particular GUI session: verify connected tools and service identities first.

## Work continuation — 2026-10-13 native v5 candidate

The priority-2/3 native implementation work below has advanced. See
docs/DC_FUNCTIONAL_V5_NATIVE_CANDIDATE.md and the immutable
docs/qualification/dc-functional-v5-native-candidate-20261013.json for exact
source/binary fingerprints and retained failures. Installed/runtime/app
baseline remains v4 with 50 tools; candidate source/catalog has six additive
native tools with every original definition unchanged.

Native candidate acceptance passed strict lint, 446 Rust tests (11 conditional
tests remain ignored by default), 19 batch helper tests, 7 search worker tests,
12 gate tests and 31 facade tests. The same debug candidate passed six-host
health (10 checks), batch reads (108), durable search (54), and actual
operator/PTY/stdin/cursor/cancel/temporary-controller restart regression (81).
These are native/local-facade proofs, not new-tool model-origin acceptance,
production recovery, production rollback, DC-off or full replacement.

Fixed defects include omitted pinned evidence in Git, acceptance of unrelated
cutover receipts, batch transport diagnostic leakage, abandoned search-session
quota lockout and Mac case/Unicode protected-directory aliases. All failure
logs/receipts are retained. Mac cancellation's detached-backend return is
term_sent/kill_sent; the canonical cancelled terminal/output evidence is
required rather than a Linux-only launch-result assumption.

Next work must resolve truthful private caller scope, secure session/restart
resume where required, request-level audit/history and redacted effective
configuration. Qualify an optimized release and preserve active native jobs
before any controlled native installation; then require legitimate
administrator app Refresh/Review and genuine model-origin acceptance. Keep
the historical installed-v4 crosswalk intact until actual installed/model
evidence changes. Do not repeat the implementation as if the native candidate
were absent, or silently promote it to the installed/ChatGPT baseline.

## Current qualified baseline

- Private repo: `TrillionniumFoundation/hepta-runtime`, worktree `/home/qian-qi/hepta-runtime-operator-20261006`, branch `feat/operator-parity-20261006`, Draft PR #3.
- Installed source baseline: native Rust multi-host runtime, existing 50-tool pinned catalog at `deploy/contracts/hepta-runtime-full-operator-v4.json`. Private Full Operator ChatGPT app currently loads **50** tools: 19 declared read-only, 31 declared non-read-only. Review latest HEAD, remote branch and exact-head CI before changes: other legitimate work may have advanced this branch.
- `docs/qualification/dc-parity-v4-model-origin-tool-ledger-v3-20261013.json` records **30 distinct non-read-only tool names with successful bounded invocation**: 29 with positive bounded action evidence and `process_checkpoint` with **read-only inspect** success only. `privileged_action` has no configured admin-pinned action; no arbitrary grant was invented. Tool-name count does not imply all parameters, safety categories or runtime states passed.
- Existing model-origin six-host evidence covers bounded normal-user shells, PTYs, file creation/edit, document/PDF operations, kill/cancel of **disposable identity-pinned processes**, and limited sudo `id -u`. Native tests are separate from ChatGPT-origin results.
- Desktop Commander is a distinct app with **31 exposed tools** and its own blocked command list. It remains installed, running and serves as recovery path; never uninstall/disable it merely because Hepta lists more tools.
- Existing measured DC core modify/execute category coverage is **9/10** for bounded workflows. The remaining `set_config_value` changes vendor-specific application settings. Do **not** add a generic unaudited Hepta policy writer in order to tick this box.
- Cloud Gateway policy/OAuth/JWT/mTLS implementation is **offline candidate work** only. It is not a deployed public HTTPS tenant/device SaaS, and private parity does not automatically authorize publication.

## New source-of-truth capability gate

- `docs/qualification/dc-functional-parity-crosswalk-20261013.json` maps all **31 DC tool names** to available Hepta operations and exact SHA256-pinned existing evidence.
- `deploy/dc_replacement_gate.py` prints a strictly bounded acceptance summary without touching machines, policy, execution, credentials or DC. `tests/dc_replacement_gate_tests.py` exercises tampered receipts, catalog drift, missing tools and false cutover flags. The report intentionally states `full_dc_replacement_qualified=false` until actual gaps and final cutover evidence close.
- Baseline distribution: **14 bounded** (one or more limited demonstrated workflows), **9 partial**, **3 unimplemented**, **5 vendor-specific**. “Bounded” is not universal parity, approval for arbitrary tool arguments or host security coverage.
- The private cutover gate is **separate** from public Cloud Gateway shipping criteria.

## Priority engineering order

1. **P0: integrity & regressions.** Confirm latest exact-head CI green; run new crosswalk, existing 50-tool frozen schema, Rust, native 6-host, model-origin and recovery suites. Do not modify the live catalog without a new version and explicit tool refresh. Keep the source clean of unrelated generated intermediates.
2. **P1: safe functional omissions.** Add a genuinely bounded `read_multiple_files` equivalent with per-path authorization, UTF-8/native file handling, total response size and multi-host tests. Add real configurable-host `ping` health/RTT probes, without letting user input arbitrary network targets. Both operations should have accurate read-only annotations.
3. **P1: durable search lifecycle.** Add cancellable bounded file/content search with `start_search`, result pagination, `list_searches` and `stop_search`-equivalent semantics. Use authenticated session ownership, stable snapshots, resource caps and cancellation of **only** the session's own job. This must not become a shell runner or leak paths across configured workspaces. Never claim synchronous `view` ranges fully replace background search cancellation.
4. **P1: asynchronous sessions and audit.** Qualify Hepta request/job status versus DC remote-call IDs, persistent PTY resume, independent process output cursors, target health and client reconnect. Implement redacted, caller-scoped Hepta history/usage if needed, not counterfeit DC account billing.
5. **P2: safe configuration UX.** Offer an audited, redacted effective Hepta configuration read surface and reviewable, admin-authorized, version-controlled changes with rollback when genuinely required. Do not let a general model tool modify sudoers, the command blocklist or arbitrary runtime policy. Document vendor-only DC actions as retired-by-design or replace them with truthful Hepta-specific operations, after user/admin review.
6. **P2: adversarial lifecycle.** Stress target disconnects, SSH credential expiry, UID changes, stale tool schema, fail-closed workspaces, symlinks and hardlinks, job replay, signal identity reuse and broken pipes. Verify recovery after native service/tunnel restart. Do **not** claim arbitrary memory/GPU/socket migration or retroactive DC Node buffered stream ownership.
7. **P3: independent DC-off cutover gate.** Once the above is qualified and the user authorizes this risk-bearing action, arrange an out-of-band recovery route. Test a controlled temporary stop of only DC agent with an explicit rollback, while Hepta independently performs real required workflows on six hosts. Preserve user business tasks, active PTYs and native jobs. Recover and verify DC until the final replacement decision; uninstall only upon a separate explicit user request.
8. **P4: separate public product.** Continue tenant-isolated OAuth/JWT/mTLS, per-user device routing, revocation, enrollment, server authority and independent public security review. Do not place the existing local bearer token in a shared public gateway. App Store approval and billing are independent of private DC replacement.

## Evidence and progress discipline

After **every** accepted source change: write tests/receipts, run relevant regression, commit and **push to remote GitHub**; inspect the exact-head hosted CI before declaring green. Keep PR #3 Draft until the user explicitly authorizes merge/release. For work that changes the installed 50-tool contract, build and freeze a new catalog, compare original 50 definitions exactly, install via controlled rollback, request legitimate ChatGPT administrator tool refresh, and record model-origin calls. Do not relabel write/sudo/shell functionality as read-only to seek platform approval.

**Completion is not tool-count parity**. Close every applicable functional row (or explicitly agree to retire vendor-specific DC functions), pass six-host model-origin and native acceptance, satisfy a real DC-off and recovery drill, and show no business service regression. If a boundary is untestable without user/admin approval or independent hardware, leave it HOLD with exact evidence rather than asserting replacement. Remain within Work's execution session; do not promise background execution outside scheduled/authorized tools.

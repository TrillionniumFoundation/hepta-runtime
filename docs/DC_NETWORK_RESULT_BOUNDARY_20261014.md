# Network result boundary repair — 2026-10-14

## Failure and evidence scope

The earlier X230 operation `1d27597702ab60f39bb2c46cd1e4e560f6640f1a267af56972ef78e9e0b0d57e`
remains unknown, without a payload. Its original audit says completed in 669 ms;
its terminal outcome says unknown. No original state, used key or outcome is
rewritten or replayed by this work. The bytes lost in that historical event
cannot be inferred from a later sample.

A separately identified read-only sample from the same compiled network helper
returned 855,140 bytes. Exact Rust serialization measured a 1,453,542-byte legacy
native SDK envelope, above the unchanged 1,048,576-byte retention ceiling.
The complete compact envelope is 914,507 bytes. A frozen-byte replay through
the original f20a7aa8 binary reproduces successful direct reading followed by
unknown async completion and no retrievable payload. It performs no real SSH
network operation. This is a deterministic causal reproduction of the defect,
not recovery of the missing historical bytes.

The legacy causal report's `source` field identifies its harness worktree; it
must not be mistaken for the legacy executable's compile source. An immutable
clarification binds that report to the independently preserved f20a7aa8 binary
and previous eb9e13f5 compile-source fingerprint. New reports call the field
`harness_source` explicitly.

## Product change

`inspect::network_inspect` now serializes through `inspection_result` before
forming its native response. Ordinary small observations keep the exact legacy
pretty JSON. For a larger observation, only JSON formatting whitespace changes;
every field, route, value, error and Unicode character is preserved. Admission
is measured against the actual `CallToolResult` envelope, including JSON string
escaping. Both text production and envelope accounting are bounded.

If even the complete compact observation exceeds the ceiling, return a small,
explicit native tool error. Do not truncate route arrays, return a partial
success, raise the limit or mark the result completed without retrievable bytes.
That error can itself be encrypted, paginated and recovered by `operation_result`.
This is not unbounded network snapshot support. The representation of a large
response changes, so equivalence is complete JSON value equality, not equality
to the old oversized pretty-output bytes. Each newly formed original SDK result
must still be retained byte-for-byte within its own operation.

No tool names, input schemas, annotations, credentials or host policies change.
No effectful operation is concealed inside a read-only endpoint. Live V4, the
already installed 8791/f20a7aa8 canary, DC and business services are not switched.

## Validation entry points

```sh
cargo fmt --all --check
cargo test --locked --all-features --all-targets
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo build --locked --release --bin hepta-runtime
```

The private captured-sample Rust check is separately ignored by ordinary CI:
set `HEPTA_PRIVATE_NETWORK_SAMPLE` to the frozen private sample and execute
`exact_rust_current_network_sample_retains_complete_json -- --ignored --nocapture`.
Never copy the private network sample into Git.

`tests/network_result_boundary_acceptance.py` compares old and new actual native
HTTP binaries using only a fixed-source local SSH adapter. It verifies exact
catalogs, unchanged small results, full captured large data, retained explicit
oversize errors, restart reads, independent byte cursors and no redispatch when
a key repeats. Its role and executable SHA are mandatory evidence distinctions.
`tests/service_scope_native_acceptance.py` supplies the separate actual configured
six-host file/job/PTY/search/read-operation and owned-controller recovery matrix.
Passing a local adapter is not six-host or ChatGPT-origin acceptance.

## Inventory and cutover

The read-only snapshot saw 7,542 controller registry entries: 7,541 parsed records
passed bounded descriptor/path/owner/link checks and basic ID/host matching.
One zero-byte publisher-temporary-shaped entry remained unresolved. This is not
full JobRecord-schema validation, atomic global inventory or an admission/queue
freeze. The unknown entry is not ignored or removed to manufacture completeness.

Both previously registered DC SSH PIDs, 2267056 and 2950449, still existed with
stable identities. They were in a GNOME Terminal scope, not proven drainable by
checking only the remote-agent systemd unit. No stdin/stdout/stderr content was
read, no input was sent and no signal was delivered to these sessions. Their
business ownership and graceful completion/explicit handoff remain open.

Full Desktop Commander replacement and production rollback qualification stay
false. The existing 128-per-owner permanent asynchronous-key cap, option-level
parity, model-origin catalog review and independent DC-off acceptance are not
closed by a successful bounded read matrix.


## Final executed result

Release SHA256: `26f8cda8f9bd57362c17b6b78e0854402fff1f8b2b51feb57ad31336ca12f4af`.
Compile-source fingerprint: `05344112c324296530260ffbd07650a53769369045698def611e9ab1085df7b1`.
651 ordinary Rust tests passed; a separately selected private captured-sample
Rust test also passed. The eleven pre-existing conditional tests remain unrun.
All 25 service-scope Python regressions, format check, strict Clippy and Release
build passed. The original fifty V4 definitions remain exact inside the pinned
sixty-six-tool catalog.

The frozen-byte old/new native comparison passed: the old release loses the
large result as unknown, the new release retains all 914,507 original SDK bytes
in 56 pages, and a genuinely oversized result produces a small recoverable tool
error. All fixed cases survive the owned controller restart; same-key repeats
do not dispatch again. Small native text is byte-identical across versions.

The new Release then passed all sixty host/read-operation cells on actual main,
Pocket4, ROG, Mac, X230 and AI395. All six native HOME searches and owned PTYs
passed. The full cohort has 27 grouped checks and confirmed terminal owned jobs,
closed PTYs and exited temporary controllers. Restart evidence preserves the
runtime job identity and exact logs/results; it is not arbitrary OS memory or
production rollback qualification.

A private immutable release copy is staged but unactivated. The existing V4,
DC agent and 8791/f20a7aa8 canary retain their earlier PID/start identities and
executable hashes. The original X230 outcome/audit hashes are unchanged; its
missing historical payload is not reconstructed or relabelled as passing.

The later DC native session snapshot contains three live registered sessions,
not just the two earlier SSH processes. None was read as an I/O stream, signalled
or adopted. Registry and live-session changes reinforce the remaining admission
and ownership gates. Full replacement remains false. No commit, push, merge or
new hosted CI is claimed; the earlier blocked publication was not retried.

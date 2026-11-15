# Native runtime qualification evidence

Source: `dd7bf97f4cbe9b77d35c117ef1584e541129f041`. This record validates retained report consistency; it does not rerun the experiment.

| Check | Result | Evidence |
| --- | --- | --- |
| Format, all-target/all-feature strict Clippy, native example build | Passed | Job `1a16cc27e56-1b6abb-46bd`; root execution record |
| Real localhost SSH native canary | Passed | Original report SHA256 `4868644068756417162a40e4e3e316dbcecf3561ea4d93568c15bd2a75889d33` |
| Full process-isolated correctness suite | passed | Summary [1790.418s] 1177 tests run: 1177 passed (4 slow), 21 skipped |
| Existing hosted CI | Not established by this record | Existing workflow is a distinct gate |

Binary SHA256: `c792efcaa3a712acbaeb61e20d99fdf408e5df5c7cad15374cd5a700fb40717a`. Source-input manifest: `f62d93ca41f509604e4f3ba1557bdd945dcf545fffdcb6843aacdbf7c76b9fbc` (355 files). The source snapshot and binary hash are recorded separately; their correspondence depends on the build record.

Original job `1a16ccc71e4-3d0906-1` survived controller exit -9, reused the same key/job with no launch retry, rejected a changed payload, and completed with exact output and a publication witness. Recorded worker entry: `4000087` exactly once.

Cancellation job `1a16ccc7e8c-3d0af9-1` recorded worker `4000607` exactly once. The request response was `stop_requested` with termination_confirmed=false. The later authoritative state was cancelled, exit `-15`, with a publication witness. Request acceptance and terminal proof remain distinct.

The earlier shared-process Cargo run is retained: 1,142 passed, seven failed, 21 ignored, 2,595.71 seconds. Two semantic failures were repaired; five metadata-deadline failures occurred under shared-process contention. The production three-second budget is unchanged. Nextest uses one process per test, one active test, zero retries, two CPUs, 8 GiB and nice 10; the host is not exclusive. It preserves concurrency inside each test and is not a load SLA.

Scope: owned temporary-directory workloads after an acknowledged receipt. No production deployment, FinalUse admission, Codex OS sandbox parity, target reboot, pre-ack power loss, general business exactly-once or whole-agent performance claim is established.

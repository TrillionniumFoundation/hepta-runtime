# Native semantic certificate: targeted qualification, 2026-11-06

The candidate source in commit
`66eb0811bb8784d13666d269c470e0ea810bdd89` passed the targeted engineering gates
below. It is based on PR #96 at
`f9c121fa54c470cd001c891faaf439ac66bba23f`. Subsequent evidence-only commits do
not change the compiled source. This is a draft implementation, with no merge
or production deployment.

The isolated ai395 checkout kept its baseline Git HEAD while the candidate
files were compiled. Those exact formatted bytes were uploaded as Git blobs,
checked against their locally calculated Git blob identities, and used to
create the published source commit. The original source footprint, commands,
tool identities, logs and terminal records are retained in the evidence below.

## Executed gates

Every command used the pinned Rust/Cargo 1.95.0 toolchain, an isolated target,
`CARGO_BUILD_JOBS=1`, no incremental compilation, no debug information, and
the existing Cargo.lock. Test profiles inherit optimization from Cargo.toml.

| Command | Result |
| --- | --- |
| `cargo fmt --all` followed by `cargo fmt --all -- --check` | Passed |
| `cargo test --locked --offline --lib --all-features weight_semantic -- --test-threads=1` | 32 passed, 0 failed, 0 ignored |
| `cargo test --locked --offline --lib --all-features weight_certificate -- --test-threads=1` | 12 passed, 0 failed, 0 ignored |
| `cargo test --locked --offline --lib --no-default-features weight_semantic -- --test-threads=1` | 32 passed, 0 failed, 0 ignored |
| `cargo test --locked --offline --lib --no-default-features weight_certificate -- --test-threads=1` | 12 passed, 0 failed, 0 ignored |
| `cargo clippy --locked --offline --all-targets --all-features -- -D warnings` | Passed |
| `cargo clippy --locked --offline --all-targets --no-default-features -- -D warnings` | Passed |
| Final `cargo fmt --all -- --check` | Passed |
| `cargo test --locked --offline --lib --all-features weight_semantic -- --test-threads=4` | 32 passed, 0 failed, 0 ignored |

The two feature configurations overlap: 44 distinct targeted tests were run
in each. The last command repeats the 32 semantic tests with concurrency to
exercise the shared worker test isolation corrected during review. It is not
an additional set of independent scientific samples.

The semantic filter includes the 11 new composition tests and the actual rmcp
discovery, delivery, rejection and recovery test in an isolated child process.
Its synthetic host cannot execute, write or open a PTY and is never contacted.
This validates the MCP API path in the test executable; it does not test an
installed production Runtime instance. No full repository test run, release
binary build or original 21,458-row corpus replay was performed for this new
source. The old #96 CI and corpus results do not transfer to this commit.

## Executable and resource identity

Only binary identities were collected; ELF contents are not included.

| Test executable | Bytes | SHA256 |
| --- | ---: | --- |
| All features, `hepta_runtime-2ab9d12294fbbb61` | 71,530,976 | `78883e1fcfea51bbbba6f017dac3859c9540bd64d996b8b0a43343097583924b` |
| No default features, `hepta_runtime-3c5eb2f20f34981d` | 65,243,712 | `6082962a314c96a75496c3888f33641a72401017c8821f434104b4cb6bd22bea` |

The main qualification job used a 200% CPU quota, 6 GiB memory limit, nice 15
and one Cargo job. Its nine commands completed in **827.811780 wall seconds**
and **830.925799 child CPU seconds**. The final cgroup sample recorded
**832.072134 CPU seconds** and **4,501,061,632 bytes peak memory**, with no
memory-limit or OOM event. CPU throttling occurred six times for 0.526686 seconds;
this is not a failure or an unreported unlimited run. The four-thread repeat
used 0.180613 wall seconds, 0.274275 child CPU seconds and 102,051,840 bytes peak
cgroup memory.

Measurements stop after the source checks and before receipt writing and
interpreter exit. The independently read durable records confirm terminal
success/exit 0 for both jobs. Cgroup CPU, child rusage CPU and wall time are
different measures; they are not model inference or training benchmarks.
Source hashes remained stable across qualification, the tool binary hashes
matched before and after, and Cargo.lock remained unchanged.

## Preserved failed attempts

Attempt 1 failed at `cargo fmt --all` before compilation because the rustup
proxy selected a default stable toolchain without cargo-fmt. The later run
explicitly selected the already installed 1.95.0 toolchain. Its original failed
receipt and 144-byte error log remain in the archive.

Attempt 2 passed formatting, then failed before compilation because the offline
cache lacked the locked `russh-sftp` package. A single
`cargo fetch --locked --target x86_64-unknown-linux-gnu` succeeded and the
before/after Cargo.lock SHA256 was unchanged. The failed receipt, 370-byte error
log and successful fetch receipt are retained. Neither failure is relabelled
as a passing attempt.

## Evidence and remaining boundary

- [Machine-readable summary](evidence/weight-semantic-certificate-20261106.json).
- [Original receipts, protocols, command logs and normalized durable records](evidence/weight-semantic-certificate-20261106.tar.gz): 42 files, 64,047 bytes; SHA256 `22db70c7e657eb7ce1c1990c071a88c59617fef3b4899f85659f6f77d11b61cb`.
- [Independent static review](evidence/weight-semantic-certificate-review-20261106.json): SHA256 `68c06adfaf8ed22767e546d7cc32c968f0a5faccab52fa21d670500bec38ea85`. The reviewer checked source/identity and the earlier deadline/test-isolation fixes; this review is separate from execution results.

The main receipt SHA256 is
`50698fba34274e9f7afe66c000cc7c9fa0c3c4e8a633969a48c06478c9094164`;
the four-thread receipt is
`6c0b77f304e264dba8308b4e80ac3e0b8605d146a4cec4999aad4d3497596e2c`.
The archive contains exact stored Cargo logs and qualification JSON. Controller
terminal records are normalized parsed JSON, not raw JSON-RPC transport bytes.

The original exact arithmetic and target contract are byte-identical. The
semantic numerical recurrence is unchanged, while its earlier-deadline entry
point changes its source identity. Source pins do not by themselves identify a
complete executable or authenticate an external model/data producer.

New PR full CI is separate and was not awaited for this targeted qualification.
Consult the current PR for its exact-head status. No production model,
held-out scientific evaluation, training, weight edit, deployment or measured
task-value improvement is part of these results. They qualify the bounded
native semantic-to-certificate path under synthetic engineering fixtures.

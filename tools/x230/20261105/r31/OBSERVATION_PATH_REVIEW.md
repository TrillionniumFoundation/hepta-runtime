# R31 timed observation path review

This is a static source and existing-receipt review. The comparison is accepted
R24 `baab4def80be7af015b2e7a594cb302f66c4130e` against qualified R31
`c039688312ceb09b3d26d1cdd50f9118eb11129f`. No new benchmark or build was run.

## Finding

No direct path was found by which the cancellation script change adds payload
bytes, construction work or full-file checks to the timed status/read requests.
This does not invalidate the original failed C1 gate: B/A remains
**0.9498379221405816 < 0.95**. It does not establish causality or prove the
new binary cannot affect timing indirectly.

Apart from the CANCEL_CODE literal and its new test-module declaration,
`jobs.rs` is byte-identical between the two source snapshots. CANCEL_CODE grows
from 5,026 to 6,346 bytes (+1,320). Shared directory validation, shared request
binding, START_CODE, STATUS_CODE and READ_CODE remain unchanged. The sibling
Rust/Python test fixture does not enter the normal release path.

| R31 entry | Relevant production route |
| --- | --- |
| status_job → status_observation | PythonStatus; the legacy status_record also uses STATUS_CODE only. |
| read_job | PythonRead; the legacy route uses READ_CODE only. |
| start_job → launch_record | START_CODE; same-key reuse follows the original status route. |
| list_jobs_async → list_jobs | Local durable inventory; does not construct remote Python. |
| cancel_job | Only its non-system-jobctl branch uses bound_remote_code(CANCEL_CODE). |

`jobs.rs::observation_script` has only Status and Read branches.
`ssh.rs::job_observation_command` retains separate OnceLock instances for
those commands. prepare_observation copies the selected command and serializes
that request; it does not bundle all jobs.rs constants. The complete ssh.rs,
ssh_observation_pool.rs and ssh_observation_profile.rs files match R24.

## Timed work and checked files

The frozen R16 benchmark runs 192 measured calls per cell: 96 status and 96
read, distributed over six hosts with 16 of each per host. Its balanced
24-call warmup is separate. Timed cells contain no start, cancel or list calls.
Controller initialization, prelaunch ELF hashing and initial full output
reads are outside cell timing.

Profile loading and repeated file verification cover the profile, SSH config,
known_hosts, /usr/bin/ssh, /usr/bin/false and fixed shell. They do not include
the controller ELF or CANCEL_CODE. R31 adds no file, byte or verification pass
to that hot path.

These facts exclude the specific direct mechanism of placing the new
cancellation payload into observation construction or full-file verification.
They are not a reason to round the result into a pass or replay the workload.

## Evidence

The original R31 patch SHA-256 is
`743701d44a9cef52c6cb04115bd8a8d7671c32e7fc0e52459c38ca63ff70ea21`.
The unchanged R16 run_native_observation.py SHA-256 is
`7606648c99b2ff2bbf0bba58384e8cab609ac3899f838c0b80ba54d6288d20bb`;
x230_observation_benchmark.py is
`4d96f0bf2da2562e788f48be7c37589ab3a513be5f9d8b2d741afe5c08ea9eed`.
The [rejection report](OBSERVATION_REJECTED.md) gives original parent, summary
and full-archive identities.

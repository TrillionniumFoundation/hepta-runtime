# Hepta Runtime security policy

This private fork follows the operating contract in `docs/HEPTA_RUNTIME.md`.
Upstream Octofs compatibility mode is not the hardened deployment: production
must specify `--runtime-config` and loopback HTTP authentication.

The controller has no unrestricted root shell. Linux jobs run as systemd
DynamicUser workloads under a reviewed root-owned policy and aggregate limits.
The root helper accepts only owned-job operations, not arbitrary PIDs or unit
names. A restricted SSH identity and strict known-host verification are required.

File capabilities use descriptor-relative traversal and nofollow opens for
remote operations. User home directories, trading state, runner credentials and
Desktop Commander are outside runtime workspaces. HTTP rejects browser Origin
headers and requires its per-installation token.

macOS does not have the Linux sandbox; its explicit fallback is suitable for
trusted jobs under a dedicated account, not untrusted multi-tenant execution.
Program output is untrusted input, and neither local JSONL audit nor per-job
result files are tamper-evident attestations. Do not expose this runtime publicly,
forward operator credentials into jobs, or grant general-purpose sudo actions.

Report issues privately to the repository maintainer. Never include live keys,
SSH material, trading identifiers or sensitive output in public reports.

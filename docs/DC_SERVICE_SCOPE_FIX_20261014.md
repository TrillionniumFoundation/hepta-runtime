# Desktop Commander successor: service-manager scope correction

This change is a bounded correctness repair, not approval to retire Desktop
Commander. Production V4 and the current private tool catalog must not be
silently relabelled as the candidate tested here.

## Reproduced defect

The installed `service_status` queried only the system manager. Consequently an
active login-user `hepta-runtime-operator.service` or
`desktop-commander-remote.service` could be reported as `LoadState=not-found`.
The new helper queries systemd's system and current-login-user managers
independently. It does not stop, restart, enable, disable or reload any unit.

The input remains `{host, services}`. No MCP tool name, input definition or
annotation is changed. The exact V10 catalog still requires native verification.
The returned text JSON gains scope, resolution and observations. Consumers must
handle an ambiguous or incomplete observation rather than infer absence or pick
an arbitrary PID.

| Resolution | Meaning |
|---|---|
| `unique` | Both managers answered; exactly one contains the unit. |
| `present_other_scope_unknown` | One manager proves presence; the other could not be observed. |
| `ambiguous` | Both managers contain the exact unit name; top-level properties are intentionally empty. |
| `not_found` | Both managers independently prove the unit absent. |
| `unknown` | Absence cannot be established. |

For a selected unit the existing top-level `properties`, `exit_code` and `stderr`
remain available, with `scope=system` or `scope=user`. Every individual probe is
retained in `observations`. Timeout, missing manager and malformed manager output
are not converted into `not-found`. A shared 15-second helper budget and bounded
three-second probes limit waiting. Description/diagnostic caps have explicit
`properties_truncated` / `stderr_truncated` markers; UTF-8 is not split.

The current user's runtime directory is checked for directory type and UID;
the user-bus address is constructed from that UID rather than inherited from a
foreign login. The helper is not an OS privilege boundary or a service mutation
interface. The existing macOS system-domain inspection is preserved and marked
`system_domain_only`; GUI/user launchd parity is not claimed by this repair.

## Verification commands

```sh
python3 -B tests/service_scope_tests.py
cargo fmt --all --check
cargo test --locked --all-features --all-targets
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo build --locked --release --bin hepta-runtime
```

`tests/service_scope_native_acceptance.py` creates an independent loopback
controller, fresh private credential and per-host HOME fixture namespaces. It
uses the installed host aliases, but never reads the installed runtime token or
restarts an installed service. File-tool roots are narrowed to the fixtures;
operator command execution continues to have the configured login user's OS
authority and is not misrepresented as a path sandbox. Other host policy fields,
including paired checkpoint pins, are preserved.

The native harness covers the exact V10 catalog, real user/system observations,
ten asynchronous read-operation arms per selected host, original result byte
reconstruction with SHA256, process idempotency, ordinary PTY input/output,
owned search and an owned-controller restart. It records launch identities
before later observation. Failed or uncertain starts are not replayed. Only
acknowledged test PTYs and direct child controllers are eligible for cleanup;
unknown or pre-existing work is never signalled. Private credentials, runtime
state and raw host responses must not be included in publication bundles.

Local HTTP origin is deliberately recorded as local HTTP, not as ChatGPT's
new-catalog authorization or model-origin proof. Fixture directories and failed
receipts are retained rather than deleted by an unqualified inventory sweep.

## Replacement gates not waived

Complete production job/session inventory and classification, exact installed
catalog review, genuine model-origin tests, real business recovery/rollback,
and independently authorized Desktop-Commander-off acceptance remain separate.
Existing arbitrary DC sessions are not silently adopted by this code. The
full-replacement gate remains false until those actual acceptance conditions
are met; successful unit tests or the number of tools do not override it.


## Observed results for the local canary

The source-code fingerprint is `eb9e13f5ec3f54294994b725677ecc6c95683d859337f78e139d50189e72fc5e`.
The release binary SHA256 is `f20a7aa866c2784a6320eebfa57bd35889c7cc312db958dbfb2cb9e44cd2545b`.
Local validation passed 25 Python tests and 644 Rust tests (11 Rust tests remain
ignored), formatting, strict Clippy and the release build. The candidate's
native 66-tool catalog exactly matches the pinned V10 catalog.

Real native HTTP plus configured SSH tests verified all ten asynchronous read
arms on main, Pocket4, ROG, Mac and AI395. X230 verified nine arms. Its original
`network_inspect` operation is `unknown` with no retained payload; only its
original status/result identity was queried during diagnosis, with zero new
network dispatches. The underlying cause is not yet established. These are
59 of 60 narrowly defined host/read-arm cells, not a replacement percentage.

The separate main/AI395 recovery run passed eleven grouped checks, including a
restart of the owned test controller, preservation of the original process job
identity, exact output and encrypted result bytes. This does not qualify a
restart or rollback of production services.

The main-only `hepta-runtime-successor-canary.service` is running on
`127.0.0.1:8791` with the pinned binary and fresh private state/credential.
It was not enabled at boot and no existing transport was repointed. Installed
Hepta and Desktop Commander PID/InvocationID/ActiveState observations were
unchanged across the accepted canary installation. The initial new-unit parse
failure and its corrected receipt remain private, unmodified evidence.

Desktop Commander still had two registered blocked sessions in the observed
snapshot; their streams, input and lifecycle were not touched. No complete
production inventory or general adoption of these sessions is claimed.

See `docs/qualification/service-scope-20261014.json` for the compact sanitized
receipt. Raw host responses, state, tokens and failure evidence stay private.
`full_dc_replacement_qualified` remains **false**. New branch CI is a separate
result from the base commit's successful run and must be observed independently.

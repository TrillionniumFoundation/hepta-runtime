# Candidate Mac GUI HIA configuration transition

**Status: source candidate with offline protocol tests. Production activation
is not qualified.** No installed configuration or service was changed while
developing this helper. The tests use temporary files, inert binary bytes and
fake service observations; subprocess execution is disabled.

`deploy/mac_hia_activation.py` fills a specific implementation gap in runtime
source `4cd85c99c5f5a480832c48fbde8561bb365f67a9`. That revision's existing
operator upgrade and parity activation helpers use Linux systemd. They do not
implement a macOS GUI LaunchAgent transition or a persistent transaction owner
across uncertain calls.

The new Python helper has its **own source identity and qualification**. It
does not modify compiled runtime code, inherit the existing binary's build
qualification, publish a release, or claim that the original runtime source
already contained this deployment protocol.

The loaded-full-configuration requirement below is an applicability condition
of **this new, stricter activation protocol**. It is not a retroactive change to
the scoped v9 installation-identity readback recorded in
[Hepta PR #820](https://github.com/TrillionniumFoundation/Hepta/pull/820).
That passed manifest observation remains valid within its recorded subject and
limitations.

## Deliberately limited change

The only live file eligible for replacement is the selected runtime JSON
configuration. Its only permitted differences are these HIA worker fields:

| May change | Must remain identical |
| --- | --- |
| Worker source directory, Python executable, worker SHA, backend SHA | Worker host, catalog SHA, worker state root, artifact roots, timeout, memory budget |
| The resulting whole configuration's bytes and inode | Every non-HIA configuration value, controller state directory and host policy |

The runtime executable, executable pointer, LaunchAgent bytes, label, login,
credentials and tunnel are not updated. Only the existing GUI service can be
restarted, using a fixed `launchctl kickstart -k` invocation. The helper does
not execute a candidate binary, execute an arbitrary validation command, read
referenced credential files, or call HIA.

This limited scope still needs real state compatibility evidence. Keeping the
same state directory is not a compatibility proof. New source can change the
service, context/lease behavior, request handling or rollback interpretation
while retaining the storage module. Unknown schema or in-flight operation
compatibility is a refusal, not a reason to relax the configuration guard.

## Reused code and separate helper pin

The helper executes the exact source bytes of two existing 4cd Python modules:

| Module | SHA-256 |
| --- | --- |
| `stage_dc_successor.py` | `80fb34a7d55157032a5a8da007d31f289eb2862746ea16747de7b3cb305f0582` |
| `mcp_tool_contract.py` | `e2b29f987d3aaa863d7bf6879d0d6a835a807c133c5c355b6a4e69bce9c3e216` |

It reuses descriptor-relative path walking, trusted publication-parent checks,
single-link regular-file admission and the whole-tool-contract implementation.
Existing `.pyc` files are not selected in place of those pinned source bytes.
The new helper's own SHA is recorded alongside those pins. A changed helper
invalidates a previously prepared operation plan.

`helper-identity` only prints those source identities. It is not a native
runtime build attestation.

## Whole candidate and preflight binding

Preparation consumes the following explicitly SHA-pinned inputs:

- The live configuration, existing LaunchAgent, resolved installed binary,
  current original release lock, and proposed whole production configuration.
- The original `check_hia_online_readback.py` source bytes. This revision fixes
  their SHA-256 to
  `ff9669c365b4056de643129376a3e4868396745f542adf90ef1fb4c114014542`.
  Preparation stores the source snapshot in the plan and later commands recheck
  it. A different checker requires an independently reviewed helper revision.
- The candidate's original release lock, `candidate.json`, complete probe
  configuration, successful `release-preflight.json`, and complete whole-server
  tools/list contract.
- The original `native-tools.json`, `worker-manifest.json` and
  `stdio-transcript.json` captures named and hashed by that preflight.

It verifies both entire configuration hashes, source-pair identity, candidate
qualification, original lock and capture bindings, runtime binary hash and
the complete supplied tool definitions. A HIA-only contract is refused. All
seven runtime owner tools and the eleven HIA tools must be represented; those
presence checks do not replace the exact supplied full-contract comparison.

The isolated probe may differ from the proposed production configuration only
in its controller state directory and worker state root. Both must be distinct
from production. All other policy, source, interpreter, artifact and resource
values must agree. The resulting plan separately binds the proposed whole
production configuration. It explicitly records that the probe did not prove
production-state compatibility or binary build provenance.

Preparation rechecks the process and file snapshots before creating a new
private operation directory. It copies the original and candidate config bytes
there, plus `plan.json`. It does not create a live deployment lock, replace a
live file, or restart a service.

## Required external maintenance admission

Preparation is not admission. `apply` and `rollback` require a separately
reviewed, pinned `hepta.mac.hia.maintenance-admission.v1` receipt. The helper
does not generate a positive admission from its own observations.

The receipt binds the operation ID, exact helper identities, entire baseline,
whole proposed configuration, original release lock and whole-server contract.
It has a finite interval of at most 900 seconds. Its required facts are:

1. All actual authorized writers participate in this deployment lane; no
   unexplained competing writer remains. The canonical lease path is fixed by
   the live configuration path, not selected independently per invocation.
2. Live state schema compatibility, in-flight operation compatibility or an
   admitted drain boundary, and rollback compatibility have been reviewed.
3. Recovery is owned independently of the target service. Losing the h
   connection during its service restart cannot become a new restart request.
4. The baseline loaded configuration is independently bound to the actual
   process identity and configuration SHA by a verified startup receipt or a
   runtime loaded-configuration attestation. Disk bytes and a cached manifest
   are not accepted as this evidence. The admission contains an explicit
   path/SHA reference to the receipt bytes, whose actual hash must also appear
   in the reviewed evidence list.
5. The reviewed supporting evidence hashes are retained.

These are technical evidence requirements, not a new user permission prompt.
The receipt's factual authenticity and the competence of its producer belong
to the independent operator review. This helper checks exact bindings and
refuses unknowns; it cannot infer that every real writer has joined a protocol
merely because a JSON boolean says so. Supplying fabricated positive admission
would violate the protocol.

### Current 4cd observation gap

The native adapter can inspect the exact GUI service, actual argv, same-login
PID/start identity, `proc_pidpath`, loaded text device/inode and measured binary
bytes. The argv executable may be a pointer while the loaded image is the
resolved release path; those are different relationships.

The adapter explicitly returns `loaded_configuration_sha256: null`. Existing
4cd `effective_config` exposes an allowlisted capability/count projection; it
does not expose the original entire loaded configuration SHA. The readback of
the selected disk path does not fill that gap.

Consequently, the available disk/profile observations alone cannot admit a
production transition through this candidate. A real deployment needs either
an already valid startup receipt for the exact current process or a separately
implemented and qualified producer of loaded-configuration identity. A future
runtime producer would retain the loaded input identity at `RuntimeConfig::load`
and `init_runtime`, then expose a read-only identity bound to its process or
controller instance. Such a runtime change would require its own source,
macOS binary and contract qualification. This document does not add that API or
transfer the Linux release build's provenance to a macOS executable.

### Minimal identity-producer interface still needed

The helper consumes an independently authenticated receipt or normalized runtime
attestation with schema `hepta.mac.hia.loaded-configuration-attestation.v1`.
It reads the SHA-pinned original bytes and checks these subjects:

| Field | Required meaning |
| --- | --- |
| `status`, `basis` | `verified`, with `guarded_startup_receipt` or `runtime_loaded_configuration_attestation` |
| `configuration_scope` | `entire_runtime_configuration` |
| `configuration_sha256` | SHA-256 of the exact raw bytes consumed by the successful configuration load |
| `process` | PID, login UID, start identity, loaded binary SHA-256, device and inode matching the observed process |
| `service_target` | The exact observed GUI service target |
| `producer_source_sha256` | Reviewed source identity of the receipt or attestation producer |

A producer must obtain the digest from the same bytes that the runtime parsed
and installed, not from a later path read or an allowlisted worker projection.
For a runtime implementation, capture the identity during `RuntimeConfig::load`
and carry it into the initialized configuration held by the process. A
canonical-JSON identity may also be provided, but cannot silently substitute
for the raw-byte identity. Publish the identity only after successful parse,
validation and initialization, bound to the process incarnation and loaded
image. An additional incarnation nonce may strengthen that binding.

A startup receipt needs an enforceable connection to those consumed bytes.
Hashing a path before `exec` alone is insufficient: the file can change before
the runtime opens it. The startup producer must bind the successful load to
the measured process and service, retaining its original evidence bytes and
source identity through an independently reviewed custody channel.

The helper checks receipt bytes and subject bindings. It does not authenticate
a producer merely because the receipt says `verified` or includes a source
hash. Authenticity and custody remain explicit external trust requirements.
The existing observation package does not provide this producer. No positive
production receipt is generated by the candidate or its tests. If implementing
the producer changes the runtime binary or launch contract, that change needs
separate source, macOS build and contract qualification; it falls outside this
unchanged-binary/unchanged-LaunchAgent transition. None of these future gates
changes the previously recorded scoped v9 installation-identity result.

## Persistent ownership and journal

The deployment lane has two distinct mechanisms:

- A private `flock` file serializes current calls from cooperating writers.
- A create-only active-operation record binds the plan, helper, operation ID
  and private bundle. It remains after the helper exits or loses its caller.
  Another operation cannot displace it just because the transient lock is free.

Neither mechanism is a security boundary against uncooperative code with the
same UID. Configuration replacement is a serialized check-and-replace under
that cooperative contract; it is not an OS-level compare-and-swap. A writer
outside that contract invalidates admission. The helper does not steal or
unlink the runtime's controller liveness locks.

The operation directory contains an append-only, SHA-linked journal. Each
event is create-only, private and synchronized before the next effect. The
journal has a finite event budget. A partial, corrupted or exhausted journal
refuses further effects.

Each event includes a SHA-linked `reserved_slots` value. Under the same operation
lock, every configuration/restart intent checks that its own event and the
required continuation fit in the 128-event limit. Configuration admission is
checked before staging and again when recording the intent. Reading the journal
reconstructs and verifies this reservation ledger. Unclassified events refuse
to consume it.

The finite continuation budgets include the step's receipt, a necessary later
observation, and the already implemented compensation or release path:

| Checkpoint | Slots reserved after that event |
| --- | ---: |
| Ownership intent | 15 |
| Activation config intent / installed receipt | 12 / 11 |
| Activation restart intent / result | 10 / 9 |
| Observed activated config and new process | 8 |
| Observed candidate config with original process and no restart intent | 7 |
| Rollback config intent / installed receipt | 6 / 5 |
| Rollback restart intent / result | 4 / 3 |
| Restoration config intent / installed / returned receipt | 5 / 4 / 3 |
| Observed rollback or restoration ready for release | 2 |
| Guarded owner-release intent / receipt | 1 / 0 |

The ordinary activate → observe → rollback → observe → finish path fits in
16 durable events. This is a finite control-path allowance, not an unlimited
retry budget. Repeated identical observations return the existing observation
sequence without appending. A read with no actionable progress preserves the
continuation reserve, including room for a later actionable observation. If a
new observation would consume protected slots, the read returns explicitly with
`journal_recorded: false`; it cannot authorize a subsequent effect. Mutations
still require a retained observation and fresh state guards.

Logical event slots do not reserve disk space or guarantee I/O success. Partial
writes, corrupted records, unbounded process/state changes and indefinite
UNKNOWN states can still require separate recovery review. Retain the original
bundle in those cases. No guaranteed convergence under every failure and no
live journal-exhaustion incident is claimed.

The ordering is:

1. Verify admission, baseline process/image and file guards while holding the
   deployment lock; claim the persistent operation record.
2. Stage candidate bytes privately in the live configuration's directory.
   Record the expected original guard and exact staged inode before rename.
3. Recheck ownership, unchanged configuration and immutable inputs; replace
   the configuration and record the resulting inode and bytes.
4. Recheck the original service and the installed file; synchronize a restart
   intent before calling the fixed OS service primitive once.
5. Record success-returned or unknown. A successful command return is not
   proof that the new process loaded the intended configuration.

The actual process and file guards are repeated immediately before each
configuration replacement and after the durable restart intent, before
dispatch. The admission clock is checked after those potentially blocking
reads and journal synchronization, immediately before the corresponding effect.
If the interval expires after a restart intent has been synchronized, a
`RESTART_NOT_DISPATCHED` event records the refusal. That intent is retained; it
does not authorize replay or config-only compensation. These checks do not
turn the cooperative protocol into an OS compare-and-swap.

An interruption after rename but before its receipt can be observed using the
recorded staged inode and hash. An interruption after the owner record was
created but before acknowledgement can recover only that exact original claim,
before any live effect. Neither recovery repeats a configuration/service effect.

## Observation and conditional rollback

`observe` reads the original operation. It never restarts the service or rewrites
the live configuration. It distinguishes owned config, foreign/unknown config,
the predecessor process and a new observed process. Original UNKNOWN events
remain in the journal. A rollback's predecessor is the candidate process,
not the original pre-activation PID; otherwise a timed-out rollback could
mistake the still-running candidate for a newly loaded rollback.

An explicit `rollback` is admitted only after a separate observation of the
operation's candidate config and new process. The current config must still
match this operation's full post-state guard, including inode; identical bytes
in a replacement inode do not qualify. The process, executable, LaunchAgent,
active owner and fresh maintenance admission must still match. Rollback then
records its own config and restart intents and invokes the service primitive
at most once. It is never an unconditional exception handler.

If a restart is uncertain and the predecessor is still present, only observation
is available through this protocol. It does not synthesize a new restart or
pretend the original operation failed without an effect. Further recovery
requires a separately reviewed maintenance decision, preserving that unknown.

`abort-before-restart` can release a claimed operation only if no restart intent
exists and the exact original config inode/bytes and original process remain,
or a separate observation has established this operation's explicit restoration.
It cannot erase a restart intent or restore a changed live config itself.

`restore-before-restart` covers the determinate interruption after this
operation installed its candidate configuration but before any restart intent.
It requires a fresh maintenance admission, a separate observation of the exact
owned post-state inode and the original process, unchanged immutable inputs,
and the same persistent operation owner. It writes an explicit restoration
intent, restores only the original bytes and never invokes a service primitive.
It cannot be repeated. After a separate `observe` confirms the owned restored
inode and unchanged original process, `abort-before-restart` can release the
owner. A lost restoration receipt is observed using the recorded staged inode,
not repaired by another rename. Any restart intent or foreign inode refuses
this path; further recovery requires a separately reviewed maintenance decision.

## Completion does not bypass the original checker

`finish` releases only this operation's persistent record. It requires a pinned
external completion receipt bound to the same observed process and entire final
configuration. It also requires independently reviewed loaded-configuration
evidence, the original online checker's output and an execution receipt binding
its exit code, unchanged checker source SHA and exact stdout hash.

The loaded-configuration reference is read and its complete configuration,
process and service subjects must match this final observation. A caller's
`verified` label or an unattached evidence hash does not satisfy that check.
The checker execution SHA must equal the fixed original source snapshot in the
prepared plan, not merely have the shape of a SHA-256 string.

The checker output must be a successful `PASS_CURRENT_INSTALLATION_READBACK`
for the selected original lock and all three installation identities. For a
rollback it must match the original installation. This helper does not execute
an arbitrary caller-supplied checker, substitute its own checker, or create new
HIA calls. The original capture/provenance boundaries still apply.

An absent active-operation record after a recorded release intent is separately
observable; it does not authorize adopting later state or replaying an effect.

## Offline checks and remaining qualification

The tests exercise positive fake transitions, explicit rollback, pending and
unknown operations, same-byte inode replacement, competing owner records,
flock contention, expired/unknown admissions, whole-config/contract drift,
interrupted owner and config acknowledgements, path/link refusal, source helper
pins, actual receipt subjects, fixed checker binding, expiry at effect boundaries,
config-only compensation, and mocked macOS path/inode/process parsing. They also ensure referenced
credentials are not read and a native adapter cannot run on the Linux test host.
Capacity-boundary checks refuse an insufficient journal before ownership/live
effects, finish the complete rollback path with exactly 16 slots, preserve
UNKNOWN and duplicate-read reserves, and retain interrupted-owner recovery.
The unit tests patch the checker pin only around inert fixture bytes; they
separately assert the production pin and never execute that fixture. This is
protocol testing, not an execution of the original online checker or proof of
receipt authenticity.

The reproducible test command is:

```sh
python3 -B tests/mac_hia_activation_tests.py
```

Before considering production use, independently review this helper and qualify
the actual Mac adapter against a dedicated, owned test LaunchAgent and temporary
configuration. Exercise command/connection loss and the journal windows while
preserving all unknowns. Then supply actual state/writer/recovery admission and
loaded-configuration evidence for the intended production instance. No fixture
receipt or success label in this document satisfies those gates.

The command surface is `helper-identity`, `prepare`, `apply`, `observe`,
`rollback`, `restore-before-restart`, `abort-before-restart`, and `finish`. Mutating commands are never
called by the local validation workflow. Operation bundles and admission or
completion receipts contain private paths; publish only explicit sanitized
projections with hashes of retained originals.

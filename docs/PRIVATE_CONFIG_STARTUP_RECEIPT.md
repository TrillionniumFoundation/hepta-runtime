# Private configuration startup receipt — experimental source candidate

This opt-in producer records which complete JSON buffer was parsed and which
normalized immutable RuntimeConfig was successfully installed by one runtime
initialization. It is a source candidate. No production activation, new live
configuration observation, Mac binary qualification, or state migration is
established by this change.

The previously captured v9 public installation and immutable-manifest readback
PASS remains valid in its original scope. This new protocol does not add a
retroactive requirement to that result.

## Opt-in behavior

The new MCP startup flag is `--runtime-private-config-receipt`. It requires an
explicit `--runtime-config` and defaults to false. When absent, the original
RuntimeConfig loader, search-interpreter initialization and runtime installation
sequence is retained. In-memory initialization remains available and carries no
claimed file-origin provenance.

With the flag present, LoadedRuntimeConfig reads one buffer, parses and validates
that buffer, and retains its length and SHA-256. It offers only an immutable
configuration reference; installation consumes the wrapper. Search-interpreter
setup receives that same parsed value. The raw identity is never calculated by
reopening the source pathname.

Initialization validates again, canonicalizes the state directory, acquires the
existing controller locks, prepares the existing state directories, and sets both
the immutable configuration and controller ownership. Provenance lives beside the
installed config, outside RuntimeConfig serialization. Existing policy/durable
request identity remains unchanged.

Only a successful return from the entire installation path can publish a receipt.
A failed second OnceLock set cannot create one. A failed/repeated initialization
does not fabricate provenance for an older installed value. This change does not
roll back the pre-existing partial-initialization semantics; startup returns an
error and must not be treated as ready.

## Private artifact and exact meaning

On Unix, the producer writes beneath the initialized private controller state
directory into an owned mode-0700 `startup-receipts` directory. Each instance uses
an unpredictable 128-bit identifier and a `config-<pid>-<instance>.json` name.
Each receipt is limited to 4,096 bytes and has mode 0600 and one hard link.
Existing directories with unsafe ownership/modes or aliases are refused.

State and receipt directories are opened with directory/no-follow flags. Entry
creation and publication use the pinned directory descriptor. An exclusive
`.pending` file is written completely and synced before a no-replacement hard
link creates the final name. The pending link is removed and directory durability
is requested. A collision never overwrites an old receipt. Failed pending files
are retained for private operator inspection and are not accepted final records.

An I/O error after linking can leave a complete final file. The producer reports
failure and does not automatically retry. Such an outcome requires observation
of the original attempt; a final filename alone is not a success acknowledgement.
No guarantee covers disk exhaustion, filesystem durability failures, adversarial
same-UID modification, or unlimited retention.

The schema is `hepta.runtime.private-config-startup.v1`. Its stage is deliberately
`configuration_initialized`. The payload contains:

- The original input buffer length and SHA-256.
- A separately labeled SHA-256 of `serde_json::to_vec(RuntimeConfig)` after
  installation normalization. Defaults and canonicalized paths can make this
  identity differ from the original JSON bytes.
- PID, effective UID, a random instance identifier and receipt creation time.
- Device/inode identities of both held controller lock files.

The receipt includes no raw configuration values, source pathname, SSH target,
credentials, binary hash, service label, or `verified` assertion. Digests remain
private because even a digest of hidden policy can disclose low-entropy values.
Ordinary MCP `effective_config`, its allowlist, and all tool schemas are unchanged.
The producer does not log receipts or digests on stdout/stderr.

Opt-in publication requires Unix ownership semantics and a serializable normalized
configuration. Failure is an explicit startup error. The existing default path
continues to defer policy serialization, including the existing non-UTF-8-path
behavior. Production Mac behavior has not been exercised by this source change.

## Operator trust and activation boundary

This is not a signature, hardware attestation, listener-readiness result, native
worker execution certificate, or complete runtime-behavior certificate. PID and
receipt creation time are not OS process-start identity. A stale receipt must not
be accepted merely because a PID has been reused.

A separately qualified private operator adapter must bind the exact original
receipt bytes to the actual process start identity, loaded image device/inode and
hash, service target, held owner locks, and independently verified producer
source/build. Private ownership and a syntactically valid digest do not alone
authenticate the currently running producer. No such adapter, LaunchAgent
exercise, build receipt, or deployment is supplied here.

The new source changes runtime binary identity. It needs independent exact-source
qualification, a measured Mac build/loaded image, and a new unified release lock.
It cannot be inserted into the fixed-runtime4cd qualification of PR111 or used to
retroactively certify an already-running old process.

The receipt covers the selected full RuntimeConfig input and installed value.
CLI credentials, remote worker state, and other runtime behavior remain outside
this claim. The controller liveness locks remain liveness locks; they do not
establish that every deployment writer or request consumer has been fenced.

## Focused verification scope

The sibling Rust tests cover input replacement after loading, raw-versus-normalized
identity, defaults, unchanged policy serialization, invalid input, in-memory
origins, reinstallation, lock acquisition and second-set failures, namespace
aliases/permissions, no-replacement publication, retained pending attempts,
non-UTF-8 normalization, and private file ownership/link checks. CLI tests cover
default-off behavior and explicit selection requirements.

At preparation time, these are source tests awaiting exact-candidate CI execution.
The local editor environment has no Rust toolchain; no new native/loader
experiment, local Rust target, operator call, production configuration write, or
service restart was performed. Later qualification must cite the actual source
and run. Existing Linux CI does not establish a real Mac startup or transition.

Before any pin change, compatibility still needs a consistent private inventory
and a real admission boundary. Old native artifacts, active slots and leases are
installation-bound; identical SQLite DDL or no running process is insufficient.
Unresolved request intents must retain their original durable identities.

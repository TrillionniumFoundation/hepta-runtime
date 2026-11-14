# Installed administrator configuration owner

This is the internal ABI of `config_owner.hepta`, SHA-256
`5f9e4cbaf8b8652a3a9eb05bdeccb90149258c9851a5fd8095465ea6cd12e5eb`.
The five-image static executable has executed actual configuration reads,
normalization, validation, two retained locks, immutable installation, lazy
digest caching, host lookup and cached public summaries. This document freezes
the query and host-lookup contract for composition. The MCP transport is a
separate controller. The full original configuration domain is not closed:
Rust regular-expression compilation, unconstrained source resources and the
original general concurrent installation API remain outside this profile.

## Authority and lifetime

The administrator supplies the configuration pathname through the process
argument `--runtime-config FILE`. The fixed adapter obtains the original
environment values from the initial process environment. The HIA owner selects
defaults, reads the file, decodes its exact typed schema, validates twice in the
original load/init order, normalizes `state_dir`, and retains both controller
lock descriptors before publishing the private configuration arena.

The production adapter invokes startup exactly once. A separately identified
fixture executable can exercise trusted reinstallation to compare the original
`OnceLock` failure ordering; that fixture entry is absent from production.
Ordinary query frames cannot install, replace or choose configuration. The
configuration, successful public summaries, and the first digest result remain
owned by the installed process. Changes to a configuration file or pathname do
not trigger reload. EOF releases the retained descriptors and ends the process.

The fixed native call bridge invokes this owner with a private 256 MiB workspace
under the existing `history.v1` byte-buffer allocation profile. This profile
name confers no authority. Startup/output/child buffers are disjoint. Only the
filesystem leaf may request its enumerated system calls. The JSON, validation,
identity and MCP controllers have no system-call capability.

## Query frame

All integers are little-endian unsigned 64-bit values. The source length must
equal `24 + payload_length`.

| Offset | Size | Value |
|---|---:|---|
| 0 | 8 | ASCII `HRCFGQ01` |
| 8 | 8 | Operation |
| 16 | 8 | Payload length |
| 24 | payload length | Operation-specific bytes |

| Operation | Payload | Success payload |
|---:|---|---|
| 1 | Empty | Original `inspect::host_list` pretty JSON text |
| 2 | Empty | Original redacted `effective_config` pretty JSON text |
| 3 | Empty | 32 raw SHA-256 bytes of the exact installed typed serialization |
| 4 | Exact UTF-8 configured name | Internal host-lookup record below |
| 5 | Exact UTF-8 name or SSH alias | Internal host-lookup record, or empty if absent |
| 6 | Empty | Canonical installed state path as raw Unix pathname bytes |

Operations 3–6 are internal composition operations, not advertised MCP tools.
Their presence in this byte ABI does not authorize a public caller to use them.
Only the public controller's explicit tool routes are reachable from stdin.
Operation 4 preserves exact `RuntimeConfig::host` behavior. Operation 5 preserves
the original BTree iteration order and first match of `name == input ||
ssh_target == input`; an earlier SSH alias can precede a later exact name.
Neither lookup grants execution, filesystem, network or write permission.

## Response frame

| Offset | Size | Value |
|---|---:|---|
| 0 | 8 | ASCII `HRCFGM01` |
| 8 | 8 | Status |
| 16 | 8 | Native diagnostic category |
| 24 | 8 | Payload length |
| 32 | payload length | Exact result or error bytes |

Status 0 is success; status 1 is an original error string; status 2 reports the
explicit unimplemented regex dependency; status 3 reports a finite native
resource bound. Diagnostic categories are not original Rust values. A successful
name lookup is observable only as status 0 plus a well-formed internal record.
Consumers must retain the original first-error ordering: resolve the configured
host before validating a shadow execution record. They must not resolve an SSH
target or grant a local filesystem profile in place of an unknown name.

An unknown operation-4 name returns status 1 and exactly
`unknown host \`NAME\`; call host_list for configured names`, with the original
name bytes inserted without normalization. Configuration unavailability returns
`runtime tools are disabled; start with --runtime-config <file>` (operation 2
uses the original redacted unavailable error).

Native return `0xffffffff` rejects an invalid internal ABI/receipt;
`0xfffffffe` reports insufficient buffers; `0xffffffe0` yields a closed child
call. No ordinary result is a continuation. The response payload is published
only after its output capacity is checked.

## Internal host-lookup record

| Offset within payload | Size | Value |
|---|---:|---|
| 0 | 8 | ASCII `HRCFHOST` |
| 8 | 8 | Installed generation, currently 1 |
| 16 | 8 | Opaque node identity in this owner's private installed arena |
| 24 | 8 | Configured name length |
| 32 | name length | Exact configured UTF-8 name |

The record length is exactly `32 + name_length`. The opaque node identity is
process-local, is not a pointer to caller memory, and must not be dereferenced
outside this owner. It is not a secret bearer credential and must not be accepted
from untrusted tool arguments. A consumer such as the shadow-execution handler
needs only successful lookup, before its own record validation; it may discard
the opaque identity. Future host-policy actions must resolve their permissions
through this installed owner and a fixed trusted call route. This ABI does not
yet export a general host-policy accessor.

## Observed original comparison

The actual unchanged original `config.rs` module and original host/effective
cache functions were compiled on ai395 with the exact 100-package Cargo closure.
The native and original processes ran 62 fixture scenarios and 490 total
requests against identically reconstructed absolute fixture paths. Complete
result/error payloads, digests, installation ordering, lock custody and filesystem
snapshots matched. Native diagnostic categories and process-local opaque host
node identities are explicitly excluded from original-value equality.

Report: `probes/owner-v1-observed/report.json`, SHA-256
`a0d893e30c416a76c555b1abdf760ee4bc44b0a478380a285db8d4238b5e1446`.
Original job: `1a1dbb74964-392-1a8b`, observed exit 0. Original binary SHA-256:
`60e116966eae0a47a1c662646c32b42e69d375da77523a421b13fface276df7e`.
This is original execution evidence, not fresh aggregate/cold qualification.

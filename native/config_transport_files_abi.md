# Native file transport installation binding

The administrator may add a named HostConfig property named native_files containing executable and sha256, or null. It binds one installed hia-file-entry. Its presence is Linux-only. The path must be absolute, normalized, at most 4096 bytes, contain no control characters, and have the exact basename hia-file-entry. The digest is exactly 64 lowercase hexadecimal bytes.

This is a distinct installation authority from native_jobs. No job role or permission implicitly supplies a file entry. Absent and explicit null omit the field from canonical identity. The old positional HostConfig representation remains limited to its original twenty fields; the added field is admitted only by name. All previous semantic checks and their error priority remain before the new profile check; privileged actions retain their following order.

## Installed operation 12

The actual configuration owner accepts HRCFGQ01, operation 12, host-name byte length and exact UTF-8 name. The common HRCFGM01 response is unchanged: status, diagnostic, payload length and complete payload. Unknown or invalid installed hosts retain the original failure.

A successful HRCFFL01 payload has a 64-byte little-endian u64 header:

| Offset | Value |
| --- | --- |
| 0 | HRCFFL01 |
| 8 | Version 1 |
| 16 | Installed generation 1 |
| 24 | Present: 0 or 1 |
| 32 | Host-name byte count |
| 40 | Role count: equal to present |
| 48, 56 | Zero |

The exact host name follows. An absent profile ends there. A present profile has one row: role ID 1, executable byte length, digest byte length 64, then the exact executable and digest. Readers must check the complete extent, reserved words, host and generation; an absent profile cannot create a native permission or choose a fallback.

## Actual qualification

The unchanged original 20,231-call differential and fifteen installed configuration controls pass on the four new native images. An independent named-field domain executes 121 typed cases, 78 semantic and digest cases and 39 actual installed operation-12 cases: 316 native calls, zero differences. All inputs and native artifacts remain bound to the actual pinned d3e2c90173cf733e42b299d0c4274df4b593a12f compiler graph.

The initial 21-field positional acceptance is preserved as a failed observation, then rejected by the corrected named-only model. The first independent reference placed the new check before the original path-prefix check; the original HIA error was correct. The reference now restores the original ordering, with a complete byte inverse to its original source. All failed preparation and differential observations remain in qualification/config-native-files-20261128.

These results qualify the installed configuration binding. The separate SSH transport, remote file implementation and public handlers require their own actual gates.

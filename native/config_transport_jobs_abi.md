# Installed configuration transport and native job accessors

This candidate extends the installed native configuration graph. It does not accept a host policy or native role supplied in a tool's JSON arguments. The existing configuration filesystem capture, typed parser, semantic validator, canonical identity and configuration owner remain in the actual call graph.

## Query and common envelope

A request is `HRCFGQ01`, followed by little-endian u64 operation, host-name byte length and exactly that many UTF-8 host-name bytes. Operation 10 returns the transport policy. Operation 11 returns the five native job role bindings. The selected name must exist in the installed host map.

The common response is `HRCFGM01` followed by u64 status, diagnostic and payload length, then exactly that payload. Nonzero status is a refusal, never an empty successful host.

## Operation 10: HRCFTR01

The fixed header is 128 bytes. All numeric fields are little-endian u64.

| Offset | Field |
| --- | --- |
| 0 | HRCFTR01 |
| 8 | Version, exactly 1 |
| 16 | Installed generation, exactly 1 in this owner |
| 24, 32, 40 | Host name, SSH target, remote state directory byte lengths |
| 48 | Platform: 0 Linux, 1 macOS |
| 56 | Execution mode: 0 isolated, 1 operator |
| 64 | Flags: execute, PTY, write, job network, detached fallback at bits 0 through 4 |
| 72 through 120 | Seven list counts |

The strings follow the header, in name / SSH target / state-directory order. Seven lists follow: allowed cwd prefixes, allowed read prefixes, allowed write prefixes, protected paths, protected argument substrings, denied executables, allowed dangerous executables. Each list member is u64 byte length followed by those exact UTF-8 bytes.

The reader must reject an unknown version, platform, mode, flag bit, non-exact extent or malformed string/list length. No path or execution permission is implied by the existence of the host.

## Operation 11: HRCFJB01

The fixed header is 64 bytes.

| Offset | Field |
| --- | --- |
| 0 | HRCFJB01 |
| 8 | Version, exactly 1 |
| 16 | Installed generation, exactly 1 in this owner |
| 24 | Present: exactly 0 or 1 |
| 32 | Host-name byte length |
| 40 | Role count: 0 when absent, exactly 5 when present |
| 48, 56 | Reserved zero |

The exact host name follows. A present configuration then has exactly five rows, in this order: entry, submit, observation, cancel, launcher. Each row has u64 role ID (1 through 5), executable-path byte length, SHA256 byte length (exactly 64), then the path and the lowercase hexadecimal SHA256.

The Rust source field is `executable`, not `path`. The complete `NativeJobEntries` and `NativeJobPin` structures reject unknown and missing fields. Absent and explicit-null native job configuration have the same canonical identity and produce present=0; neither grants a fallback native role. A present profile is Linux-only. Paths obey the original absolute, normalized, non-control-character, 4096-byte limit and exact role basename rules. Every role's digest participates in the installed configuration identity.

## Qualification boundary

The original 6,491 typed cases, 7,666 current typed cases and 3,131 current semantic cases execute against a Rust 1.95.0 reference built from the exact original 100-package lock. The final actual HIA run makes 20,231 native calls with zero differences. The eight required positive cases and seven independent configuration-identity checks are explicit requirements, not inferred from a large negative corpus.

The installed ELF separately passes fifteen real filesystem/configuration startup controls, including the old ignored-`native_jobs` counterexamples. This qualifies the configuration accessors. It does not qualify SSH transport, remote job execution, the public file tools or the complete 136-handler runtime. The complete original failures and subsequent passing artifacts are preserved in `qualification/config-native-jobs-20261128`.

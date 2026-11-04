# Ghidra analysis candidate qualification — 2026-11-04

All eight real-provider gates passed for the isolated development candidate. This receipt does not qualify a later combined/release binary or a production deployment.

## Candidate identity

- Worktree: `/home/qian-qi/hepta-runtime-rea-next-ghidra-20261104-r1`
- Branch: `work/rea-next-ghidra-20261104-r1`
- Source base: `310add6db47bcfbed3545432eb528a72f5eb6dcd`; candidate changes were intentionally uncommitted.
- Runtime SHA-256: `26f6c1f92499f0c012548c13bfb0c9f8e96ccb7658b8db967a21778c74b228c8`
- Build: locked Rust 1.95 development profile, debug information disabled, incremental disabled, `-j4`. The Cargo development profile itself retains its configured optimization.
- Analysis bridge SHA-256: `1b20b872258f26ba75ac463afd1c35a544f76efd3f0bcc05e29515eb940fdf21`
- Revision 2 inventory bridge SHA-256: `a4d166231a4eade27ae1e403b85718da9729c4d752822e9bf9a7ff7fe37878f4`
- Unchanged legacy inventory bridge SHA-256: `47de6f614c94983f6042adff41bb188a545599ca5ca4ac249480171ffaedc127`

The exact build source manifest is in `build-final-r2-receipt.json`. `mcp-native-r2-launch.json` contains source hashes before/after, the runtime hash, command, successful exit and 326.4427-second duration. Its launch also checked that both new bridge source byte strings were actually embedded in the candidate binary. Returned provider reports independently match those bridge hashes.

## Gates and independent observations

| Gate | Result | Evidence |
| --- | --- | --- |
| Formatting | Pass | `build-final-r2-0.log` |
| Locked binary build | Pass | `build-final-r2-1.log` and build receipt |
| Clippy, all targets/features, warnings denied | Pass | `build-final-r2-2.log` |
| Focused Ghidra contracts | 11 passed, 0 failed, 0 ignored | `build-final-r2-3.log` |
| Real MCP and original durable owner | All 8 checks passed | `mcp-native-r2/qualification.json` |
| Independent finite C differential | 141 of 141 inputs matched authored C and independently calculated arithmetic | `finite-c-differential-r1/receipt.json` |
| Same C in API and real-provider runs | Exact 63-byte C SHA matches | `finite-c-provider-link.json` |

The real provider imported the dynamically linked owned ELF, repaired the previous importer failure with a named byte provider, ran four fixed analyzers and discovered function entries matching independent GNU `nm`. Incoming call site `0x401134` matched GNU `objdump`; the selected leaf entry was `0x401106`. Ghidra reported 95 instructions, 13 total functions and 12 returned internal function rows on this fixture.

Actual native decompilation returned:

```c
int hepta_leaf(int param_1)
{
  return param_1 * 7 + 0xb;
}
```

The raw C retains its original whitespace in the report and `finite-c-differential-r1/recovered.c`. Its full SHA-256 is `f5cfb8e45b727b130ef92c6511118695d2454bf9be1b340c66170611d125d029`. The provider itself executed zero targets. The separate differential harness executed only its own authored/recovered fixtures for these finite values; universal source equivalence is not claimed.

## Original jobs and cancellation

| Operation | Original durable job |
| --- | --- |
| Inventory v2 | `1a1a4e1ba43-ac9d-1` |
| Functions | `1a1a4e232d3-ac9d-2` |
| Function | `1a1a4e2b3fe-ac9d-3` |
| Cross-references | `1a1a4e34996-ac9d-4` |
| Decompile | `1a1a4e3e5a8-ac9d-5` |
| Live native cancellation | `1a1a4e52f9e-14b2c-2` |

Controller restart returned the identical original decompilation result and job. Same-key changed payload and invalid/extra selectors were refused. A function-interior address was admitted as a bounded request but failed in the real backend with no successful mapped facts.

Cancellation was requested while the actual native decompiler was observed in the original owner's cgroup. The harness observed Java PID 93886/start 84552134 and native decompile PID 98811/start 84554846, both with `NoNewPrivs=1` and `Seccomp=2`. It then froze admission, cancelled the original job, verified durable terminal `cancelled`/exit -15, and verified that both original PID/start identities disappeared. Re-admitting the identical request retained the same terminal original job; it did not relaunch. The single retained cancellation scratch directory was removed only after that confirmation.

Raw original request, initial job, live-child and terminal records are in `mcp-native-r2/`. External qualification launcher job was `1a1a4e10348-fc05-1525`; the build/test launcher was `1a1a4ddae89-fc05-14ec`. Durable terminal statuses are preserved in `launcher-terminal-status.json`.

## Failed attempts retained

Failures remain separate from the successful candidate evidence:

1. `api-preflight-r1/` records the anonymous ByteProvider null-name failure on the owned dynamic ELF.
2. `old-inventory-executable-r1/` independently reproduces the same failure in the unchanged legacy importer. The original receipt's bridge-hash metadata mistakenly referenced the analysis bridge because a wrapper replaced only its command path. `receipt-correction.json` records the original receipt hash, correct executed legacy bridge hash and the correction. The original receipt and stderr are unchanged.
3. `mcp-native-r1*` records a failed provider run whose runtime still embedded the first, unfixed analysis bridge (`df1559…`). Source before/after equality alone did not establish correspondence to that earlier binary. The successful r2 build/run added explicit build/source/binary and embedded-bridge checks.
4. `focused-r1-1.log` records the first all-targets compile failure from an older test literal missing the new optional request field. The literal was repaired before the successful r2 Clippy and contract tests.

Standalone Java preflights establish Ghidra API behavior only. They do not qualify provider policy, system-call restrictions, owner recovery or cancellation. Those claims rely on the real r2 provider run.

## Scope and environment

Qualification used the Linux x86-64 `desktop` development host, local SSH and user-systemd `operator` mode. The installed Ghidra release was 12.2; the actual backend was `openjdk 25.0.5 2026-10-20 LTS`. Installation manifest, selected JRE hashes, raw observation reports and commands are retained.

The evidence does not establish isolated-host mode, all architectures, all Ghidra analyzers, arbitrary address expressions/scripts, complete upstream REA contract/Evidence parity or production readiness. Engine observations continue to declare partial coverage and `source_semantics_validated=false`. Ghidra and Java remain installed dependencies. Read [the operation and migration contract](../../rea-native/GHIDRA_ANALYSIS.md) for the fixed limits and legacy profile handling.

The evidence manifest binds every retained file except itself. Source and raw output were not edited to hide an earlier failure.

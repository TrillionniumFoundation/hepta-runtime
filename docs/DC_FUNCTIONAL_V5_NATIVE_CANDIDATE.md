# Desktop Commander replacement — v5 native candidate

This candidate adds real missing private-runtime functions. It is not a full Desktop Commander replacement, a deployed catalog, a public gateway, or proof of ChatGPT-origin approval. The installed runtime/tunnel stay on v4, and Desktop Commander stays enabled as the rescue channel.

| Capability | Implemented behavior | Boundary |
| --- | --- | --- |
| read_multiple_files | 1–16 complete UTF-8 regular files, per-path read authorization, independent identity/SHA256, shared escaped MCP response budget | 64 KiB/file maximum, 256 KiB serialized result maximum; no symlinks/hardlinks or atomic multi-file transaction |
| host_health | Fixed authenticated SSH challenge to an administrator-configured host, bounded output and redacted failure | SSH invocation timing includes auth/startup; does not measure ICMP RTT |
| search_start | Fixed native background literal path/content scanner, durable private receipts and bounded resources | No arbitrary shell/target; literal only, no regex/gitignore parity |
| search_results | Stable terminal snapshot pages with independent row cursors | Running output is not a mutable page stream; response wire bytes capped |
| search_list | Native-session-owned persisted metadata, pagination, terminal status reconciliation | Does not authenticate individual ChatGPT callers sharing one facade backend session |
| search_stop | Cooperative own-job marker and retained terminal snapshots | Never signals arbitrary PIDs; cancellation must be confirmed by terminal results |

The v5 contract has six additive definitions. Every original v4 definition is compared byte-for-byte as a canonical JSON object. Operation annotations are explicit: batch reads, health, result pages and listing are read-only; creating and cancelling search state are not read-only. More tool names do not establish functional parity or approval of every parameter combination.

Search traversal refuses symlink components, hard-linked regular files and special files. Linux protected-prefix comparison is exact; Darwin comparison conservatively uses Unicode normalization and case folding to protect the same resource on case-insensitive APFS. Traversal, read bytes, result count, file size, CPU/FD limits and cooperative wall budgets are bounded. Darwin does not claim the Linux OS address-space resource limit. Blocking kernel filesystem I/O can delay termination. A hard worker failure reconciles as interrupted, never as a complete snapshot. Persisted active receipts are internally refreshed before quotas/listing, so abandoned completed sessions do not permanently lock out new searches. Other owners' metadata stays private during this reconciliation.

New native sessions cannot take over an old session's searches. A private controller restart preserves a fail-closed interrupted receipt, without a secure session-resume protocol. The Full Operator facade currently shares its internal native session across modern calls; native session isolation is not evidence of separate ChatGPT-caller isolation.

## Evidence

The immutable v5 candidate receipt and failure index in docs/qualification/ bind binary/catalog/source fingerprints, per-host results and retained logs. They separately identify direct native MCP tests, local facade tests and historical model-origin evidence. No new-tool ChatGPT-origin success is claimed.

Real six-host fixtures cover main, Pocket4, ROG, Mac, X230 and AI395. Fixtures are disposable; production services, business files, old PTYs and Desktop Commander are not stopped. Temporary controller restarts in these tests do not qualify restarting production services or a production rollback drill.

Existing frozen crosswalk remains the installed-v4 baseline. The gate now rejects valid-hash but unrelated receipts for positive cutover flags and requires dedicated business-workflow qualification before a full replacement conclusion. Past bounded success is not silently promoted to universal parity.

## Optimized release

The optimized stripped release was independently exercised on all six hosts and staged without installation. The immutable stage receipt is docs/qualification/dc-functional-v5-release-staged-20261013.json. Its source HEAD b02e45f99ddb05cfeb3b14ddb0d55c91b6eebc1b passed exact-head hosted CI. A release startup failure had its detailed response discarded by the old harness; all available evidence is retained. SSH pre-auth saturation at the same time is strongly correlated but does not identify the failed client. Three strict main diagnostics and a main-first coordinated full-six rerun passed. The harness now records phase/error evidence; no SSHd policy change or uncertain write retry was added. Uncoordinated auth-burst resilience remains unqualified.

## Remaining gates

- Isolate real ChatGPT callers or explicitly review a truthful single-principal private scope; implement secure reconnect/resume where required.
- Qualify caller-scoped asynchronous request history and redacted effective configuration; agree on vendor-specific retirement rather than invent a DC billing/configuration clone.
- After controlled native installation of a reviewed successor, the ChatGPT administrator must Refresh/Review the new tool catalog and use a fresh conversation for genuine new-tool model-origin acceptance.
- Complete business-workflow acceptance, production failure/recovery and exact rollback with preserved active native jobs/PTYs.
- Only after these close, obtain explicit authorization for a temporary DC-only stop drill with a working out-of-band recovery route. Restore and verify DC. Uninstallation remains a separate explicit user decision.

PR #3 stays Draft/unmerged. Public OAuth/device SaaS qualification is separate.

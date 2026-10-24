# Jobs-only large inventory draft

Latest reviewable revision: `required-pin-r3`. It is isolated from ACTIVE and has not been wired, committed, pushed, or used for production collection.

The observer proves job membership and status layers separately. The record cap is 16,384, and each complete HTTP response body has a fixed 32 MiB cap. Every requested host listing must exactly match that host's independent private registry membership before any status RPC. All expected IDs receive a status RPC; launch records never supply a terminal default. Missing state is `unknown`, and authority/nonce/supervisor flags require explicit boolean `True`.

Every client has an independent host/session/sequence. Its required credential inode pin is checked using metadata only, before and after the audited token reader and before every RPC. Full stat changes, replacement and rotation block new HTTP. No credential digest is created. Registry fingerprints contain only ID, host and stat identity; launch argv/env/output stays in RAM and is excluded from reports and exception text.

The direct endpoint is fixed at `127.0.0.1:8790/mcp`; proxy variables, redirects and mutating methods/tools have no authority. Each connect/send/actual receive checks remaining time. The standard HTTP parser reads through the same deadline adapter for status lines, headers, chunk sizes, bodies and trailers. Deadline expiry stops new submissions and returns partial unknown rows/HOLD. This is not a claim that Python can forcibly kill an already in-flight system call or preempt bounded JSON/CPU work.

| Source lines | Review focus |
| --- | --- |
| 1–207 | Fixed schema/caps, private FD ancestry, current UID and metadata-only credential pins |
| 208–306 | Full bounded registry snapshot and stable metadata proof |
| 307–337 | Actual receive deadline adapter for standard HTTP framing |
| 338–540 | Required credential custody and fixed read-only transport |
| 541–648 | Reviewed native DTO, strict JSON equality and public sanitizer |
| 649–823 | Six-host scheduler and separate completeness/HOLD |

Run only the owned offline fixture from the revision directory:

```sh
/usr/bin/python3 tests/dc_successor_inventory_tests.py --results-dir results/new-run-name
```

The results destination must be new, so existing failures are preserved. The final main-host run is `results/run-main-011`: 55 tests passed, 0 failures/errors, 7.1391 seconds. Source/test SHA256 values before and after are identical. The local final run is `results/run-local-010`.

The failed run `../results/run-009` and its exact source/test inputs are preserved. Its chunk-size fixture initially used a framing line too short to consume the test budget; the corrected fixture uses a longer legal hexadecimal size. `../results/review-0c262c-rejection.json` records that the first 36 passing fixtures did not overcome the source audit's High working-bound rejection.

Caller API: `observe_inventory(jobs_directory, factory, credential_identity=pin)`, where `factory(host, deadline, pin)` returns a matching independent `LoopbackReadClient`. The client requires `token_reader`, `host`, `deadline` and `expected_credential_identity`. Production selection remains a future root-controlled import of a caller-validated manifest directory and the audited private-token reader. A None pin is refused; only low-level `read_registry(..., fixture=True)` permits a None pin for explicit fixtures.

PTY, stream and native/facade dispatch/freeze fields remain false, and decision remains HOLD. This jobs-only draft is not a complete successor preflight replacement. No production registry/token/profile, real HTTP endpoint, SSH, signal, service control, adoption, replay or repair was exercised. Same-UID concurrent writers are not an atomic snapshot security boundary. See `../manifest.json` for complete hashes, source references and limitations.

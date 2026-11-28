# Native read bootstrap and successful worker retirement

This change adds a source-owned HIA bootstrap for the existing seven-image Linux read service and repairs a real successful-worker retirement race in the shared HIA composition packer. It has actual isolated loopback SSH evidence for binary_read, read_multiple_files and file_info. The current default public graph remains at 136 registered tools, 13 routed tools and 123 unrouted tools.

## Successful result ownership

A ready file_info worker had committed its full result and notified its private pipe. The old parent sent cancellation and made one specific-PID wait4(WNOHANG) attempt, then published the result even when that attempt returned zero. The next normal inspection could therefore fail with EBUSY.

The deterministic control retains four legal WNOHANG zero results without supplying application output. The old actual ELF publishes a successful result while its owned worker remains a zombie. The repaired actual ELF retires the worker before publication and then completes the next original-result comparison. A separate control interrupts one bounded poll.

The new 156-byte fragment is emitted by native/composition_packer.hepta. It calls the retained specific-PID reap helper and waits without descriptors for at most one millisecond between attempts. Each attempt uses the existing absolute CLOCK_MONOTONIC deadline. The fixed 30-second total inspection budget and the final pre-commit deadline check remain. Timed-out uninterruptible workers retain the existing bounded pending-worker policy.

The authoring transformation preserves f1 through f42 exactly. The original f0 becomes f43, with precisely eight metadata-address constants relocated; inverse reconstruction recovers the entire original function. The new f0 performs the original admission and output-capacity checks before emitting the handoff jump and fragment. The metadata offset moves from 8752 to 8912. Runtime execution does not use the authoring Python or assembler.

| Identity | SHA-256 |
|---|---|
| Current composition packer source | 60c081c08f4f1be4a2585f49ce3f6dffa1a50707df9e0b8383a0396b61589f63 |
| Normalized adapter prefix | b176ed119e3df573a47a05f546d1316bc66dcbcd41295833eebe932f2b19760a |
| Rebuilt seven-image read ELF | b3f8cfa8f27db8f829d5b5daf2b8562fa77e851662d6e8a6be24c3948b9f79d6 |
| Bootstrap HIA source | f62961dce03136c61cbc3ee9dbc6cb41cadaa745265b6effc345958d0ac7aa1c |
| Bootstrap native image | 753b0fcbc3014dc8056f6430c7eed2de3be36e354d9ccdcf125ad3e18c2139db |

## Trusted-root bootstrap

native/native_read_bootstrap.hepta accepts HLRBQ001, the exact helper image size and a trusted installed root. It validates complete framing, zero reserved words, the admitted size range, absolute root bytes, strict UTF-8 and absence of NUL. The root length is 1 through 4095 bytes.

The HIA owner emits HLRBR001 and the complete POSIX bootstrap command. It preserves root bytes through single-quote escaping, receives exactly the declared ELF extent with full-block reads, checks the received size, launches the private executable with --local-read-profile and inherits the remaining stream. Temporary files are owned by the invocation and removed on completion. Qualification includes quote, newline, tab, backslash and non-ASCII root names, fragmented transport writes, a truncated image and a complete invalid image.

The remote executable performs file semantics in HIA. OpenSSH and POSIX utilities provide transport and image installation. Python is used for authoring, building, fixture control and independent original-owner comparisons.

The SSH fixture creates its own loopback server, ephemeral client/host keys and strict known-host binding. It does not modify an existing SSH server configuration. It is an execution proof for this explicit profile. Configured-host alias selection, default public gateway/catalog wiring, SSH cancellation, remote parent death and complete runtime replacement remain separate work.

## Actual verification

The pinned compiler is Hepta d3e2c90173cf733e42b299d0c4274df4b593a12f. The B3 image is bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0.

| Domain | Complete executed coverage |
|---|---|
| Original local read suites | 6 + 5 + 5 tests; 415 actual ELF responses; 118 binary, 57 multi-read and 39 metadata exact original comparisons |
| Complete original suites through SSH | The same 16 tests and case counts; 413 responses through actual SSH and two retained direct EOF responses |
| Additional SSH controls | Five outer tests; three quoted-root sessions, 15 additional responses, nine exact original comparisons, truncated and invalid image refusals |
| Bootstrap byte owner | Three tests; 34 native calls, 20 accepted frames, 12 admission refusals and two capacity refusals |
| Successful worker retirement | Three tests; four original comparisons, eight controlled WNOHANG zeroes, an interrupted bounded poll and two observed retirements before success |
| Original fixed deadline | Four tests; two actual 30-second kernel holds/cancellations, 34 responses, resource/root custody, setup failures and recovery |
| Shared privileged packer | Six tests; 103 actual packer calls, 99 admission refusals, two capacity refusals, 37 rehashed ELF mutation refusals and seven exact SHA imports |
| Shared scope kernel | Eleven tests; 37 actual processes and 238 responses, including entropy ordering and cleanup |
| Scope receipt controls | Nine groups; retained original/native report controls, 49 receipt mutations and 25 classifier refusals |

The transport driver requires isolated, unoptimized Python. It clears inherited HIA and PYTHON overrides, materializes the unchanged original source at the declared commit/blob identities, and checks current and original sources after execution. Each added suite must report the exact 3/5/3/4 test count, zero errors, failures, skips, expected failures and unexpected successes, with isolated=1 and optimize=0. The complete original 6/5/5 suites retain every original counter and case requirement.

The successful first driver run is retained as v1. The final v2 run adds strict anomaly/isolation admission and passes the complete driver again. The old successful-result race, initial SSH failure and the initial relocation-authoring failure remain identifiable observations. They are not rewritten as passing evidence.

Reproduce the read component with a fresh output directory and a verified pinned Hepta checkout:

```sh
python3 -I -B scripts/hia_native_read_transport_qualification.py \
  --hepta /path/to/pinned/Hepta \
  --build-root /path/to/fresh/read-qualification
```

The SSH proof requires ssh, sshd and ssh-keygen on Linux. The ordinary common module registry also includes the bootstrap byte-owner suite and the successful-retirement suite.

## Current bindings and remaining boundaries

Current scope, record, cache, batch, history and request-scope composition bindings point to the new shared packer. Historical original Rust comparison receipts and prior packer provenance retain their recorded identities. The new bootstrap adds one source and one executable qualification entry to the common inventory, 195 to 196. The complete current native tree additionally contains the pre-existing 35 public-graph sources outside that older common inventory; this change does not claim to have reconciled that separate historical boundary.

The public build's existing source binding still validates. No default public route is added by this component. The full original Rust/Python paths remain until their actual public replacements, configuration behavior, permissions, errors, budgets and lifecycle are independently closed.

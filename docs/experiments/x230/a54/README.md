# A54 — borrowed compact rows, X230 qualification checkpoint

**Status: the full X230 qualification passed. Native, fault-recovery and fixed
archive acceptance for this executable remain in progress. Performance adoption
is not established by this checkpoint.**

A54 extends the published A53 commit
`b20bcf02cfe72b3873c5c03180e4028ea673067f` / tree
`84d5caea62cceaf41b59a354185c85439a6fa0e8`. Three existing source files change; the
other 172 compiler inputs retain their qualified A53 identities. The release
still includes A53's bounded direct SSH and original-child cleanup ownership,
the owner publication barriers and conservative unknown-owner recovery.

## What changed and why

The serial archive verifier previously decoded each compact derived ROW into
three owned strings, expanded binary IDs to hex, then parsed those IDs again to
validate its ROW/ORDER join. A54 keeps the original redb access guard alive for
one member and borrows the compact row's already validated fields. It constructs
the same 80-byte ORDER key and checks the same 32-byte ORDER value directly.

`view_if_compact` uses the complete existing compact parser. A malformed `HAR1`
row remains an error; it cannot fall back to the legacy JSON path. Legacy rows
continue through the existing decoder. Base-row encoding, identity and ORDER
checks precede pending replacements, so a valid pending completion cannot hide
a damaged base row.

The actual original JSON is still read completely and parsed by the original
record deserializer. A54 compares every record field and the complete file
stamp. The exhaustive record destructure makes future record fields require an
explicit comparison. Canonical identifier checks, escaped but valid JSON,
strict compact framing, legacy behavior, pending updates, off-owner membership
and corrupted ORDER bindings have regression coverage in the existing sibling
test file.

This change removes expected-row allocations and repeated encoding work. It
does not reuse a completed observation. The full namespace walk, all original
record reads, descriptor/path checks, pre/post layout fences, ROW/ORDER
transaction, pending accounting and final fences remain required. The serial
page path, original usage-reader path, eight metadata permits, one-millisecond
cohort cutoff and original three-second absolute request budget are unchanged.

## Actual X230 qualification

The original root job was `1a17893f8e9-96a-1245`, started on
2026-10-26 at 14:18:45 UTC and completed at 14:33:39 UTC with exit code 0 and
complete, untruncated operator output. Fresh source, entry and qualification
directories use the `a54-compact-view-r01` identity.

Rust 1.95.0, the original offline/locked commands, two Cargo jobs, two test
threads, two Tokio workers, disabled incremental compilation, stage umask 022
and the original stage timeouts were retained. No Rust build or test was run
on the local review machine.

| Original stage | Exit code | Recorded duration |
| --- | ---: | ---: |
| format | 0 | 2.504 s |
| fmt-check | 0 | 2.060 s |
| clean-package | 0 | 0.429 s |
| all-feature/all-target Clippy, warnings denied | 0 | 42.642 s |
| full test | 0 | 523.940 s |
| release | 0 | 316.523 s |

The original test summaries contain **1,332 top-level passed tests and 23
existing ignored tests**: 18 + 1,306 + 8. Two nested, filtered subprocess
summaries are retained and excluded from that total. The [complete original test log](qualification-test.original.log.gz) was
separately purpose-read in full: 429,389 bytes at the qualification-pinned SHA256
`9c4754e96493e65732ccb2a7d3ed59d0ee6a7026b41270623330841c4a39ad6e`.
The [download and parser receipt](qualification-test-log.purpose-verification.original.json)
and [seven-test coverage record](new-test-coverage.direct-log.json) verify that
each new fully qualified test name appears exactly once with `ok`, and that
all twelve original test declarations remain present. The subsequent full-source export also passed and independently agrees with
these direct source and original-log observations.

All six stage host gates passed. The guarded original worker retained its
identity, pidfd, GO decision and wait custody until reaping. Raw wait status
was 0, its process group was quiet and no cleanup signal was needed. The parent
source/input fences and the actual retained parent Git identities remained
unchanged. No service or authentication configuration changed.

| Object | SHA256 |
| --- | --- |
| [Original qualification](qualification-r01.original.json) | `49b0019ece7405d455ace8cb638080a203a24fca01c6985a6cdda6d51180a51c` |
| [Original guarded entry](entry-r01.original.json) | `a98b564f5db07c64b497b68098902192f71f7be6884e687e68b38e9e41f3e6c3` |
| [Original worker](worker-r01.original.json) | `b7ee93502f5ba0a3861e4578da8301ebac9af8ceb9e1b535ad2e5a8c6af73a90` |
| Release ELF | `d2134c1b2b1999f46f0808b0d523ae51f54821c09afa6ecbf8188c883bbf3d70` |
| Test ELF | `9ae6a1ca692bea236a09771e6b5ca58d7c99454f7f4d51ccf11f1d5f1cd161eb` |
| Complete tested/after map, 175 entries, compact JSON | `7d4143971feeb9b1fcbf1f3e567ba367c36770cdf050fe496b1e2778a1025176` |
| Original full test log | `9c4754e96493e65732ccb2a7d3ed59d0ee6a7026b41270623330841c4a39ad6e` |

Publication uses only the three actual formatted bodies read from their exact
qualified X230 paths and checked against the complete qualification map. The
[complete original source export](qualified-source-export.original.json.gz) is
79,175 compressed bytes at SHA256
`91d34de8a51d77121ac036a9044d393c40c5fe2c7614d9a92fe72dc19eea6274`.
Its actual job `1a179848f46-96a-1278` completed with exit 0 and complete output.
The export rehashed all 175 source inputs, retained their final fences, exported
the three changed bodies and six original host-gate bodies, and checked all
seven new test names against the original full log. Its 551,116 expanded bytes
have SHA256
`8e8b667afa9f58f392e4a753c32c9a110be3379a3aad34e741cc23a0a3c6c77c`.

The [download verification](qualified-source-export.download-verification.json),
[direct-read reconciliation](qualified-source-export.direct-reconciliation.json)
and [independent review](qualified-source-export.independent-review.json)
verify complete bytes, the exact 186 input-receipt membership, all 175 source
identities, the six embedded gate bodies and all seven unique successful test
names. The three exported source bodies are byte-identical to the earlier
direct capture. The export records ELF identities from the qualification; it
accurately makes no new ELF-body rehash claim. Each native/performance admission
still checks its exact executable under the original protocol.

Rustfmt changed the prepared content-verifier and test-file bytes. The three
qualified identities are:

| Source | Actual formatted SHA256 |
| --- | --- |
| `src/mcp/runtime/request_archive_codec.rs` | `8201e82a69debf0243f9145f2b6fac8dfac5ec417cbe4f3f14b35f1a8c3a6e94` |
| `src/mcp/runtime/request_archive_content.rs` | `d5be2c37d5544a870a7f64af210bfd9f512f7c7771f5501d13a6cd037071b768` |
| `src/mcp/runtime/request_archive_content_tests.rs` | `a5053ec2721dacff50ba965f0bfa49534dffce668acd23e6c292c3e94f8e9d3d` |

## Acceptance ledger for A54

| Gate | State at this checkpoint | Required evidence |
| --- | --- | --- |
| Full X230 qualification | Passed | Six original stages, actual source/ELF and original-worker custody |
| Fifteen Python commands plus dependency precheck | Actual bindings frozen; execution result pending | Unchanged 216-file combined copy and original sixteen command results |
| Native eight-job concurrency | Actual binding frozen; execution result pending | Nine same-source X230 checks, original 8/8/8/16/8 batches, complete raw reconciliation |
| Controller/reply/owner loss | Actual fresh plan prepared and independently checked; native execution results pending | Original three effects, actual exit witnesses or explicit unknown state, no retry |
| Small archive | Actual fixed protocol frozen; execution result pending | 8,192 measured / 8,848 total calls, two opposite ABBA blocks, all six gates |
| Large archive | Actual fixed protocol frozen; execution result pending | All 80 measured calls / 32 waves and all sixteen gates |
| Six-host native suite | Actual adapter and lease bindings frozen; execution result pending | All eight original stages on AI395, Mac, main, Pocket4, ROG and X230, including the 600-second trace-off soak |
| GitHub CI | Parent A53 passed its exact-head run; A54 result pending | Actual CI success for the newly published A54 commit |

The independent binding review rehashed every frozen archive source, reversed
the declared substitutions to the original A53 source, verified the source
exporter's four bindings, and checked the eight-job and six-host bundles byte
for byte. Runtime functions, fixed deadlines, business cardinalities,
authentication sources and custody code remain unchanged. Binding preparation
does not substitute for any execution result in this table.

## Earlier A53 results retained

The A53 eight-job native run and all three native owner-recovery cases completed
and passed independent raw-evidence audits. The small-archive comparison passed
all six fixed gates. Its complete 29,004,490-byte original archive is retained;
one independent audit implementation passed on both X230 and the fully
downloaded local original, with identical semantic results. These are A53
results and do not close the A54 rows above.

The A53 large attempt completed all four original controllers and all 80
measured calls. It passed 15 of 16 gates; candidate C4 correctness was **30/32**,
so the attempt remains failed. Both errors consumed the original three-second
metadata budget. All failure costs are retained. The comparison's successful
call-rate ratio is not a complete-acceptance speedup.

An independent same-ELF diagnostic reproduced one failure among 20 measured
calls. In that diagnostic, a late caller formed a new one-member cohort after
the original cutoff, waited 2.159 seconds on the store lock, then entered full
verification with about 0.839 seconds remaining and reached its original
deadline. The earlier three-member cohort's complete scan took 2.157 seconds.
Trace instrumentation can affect scheduling; this is direct evidence about
the diagnostic, not proof of the exact split in the preceding untraced run.

The complete A53 large-original collector subsequently retained 264,292 members,
including every one of the 264,192 original record bodies, in a 49,267,466-byte
gzip at SHA256
`55ab40111d71f1cf3781682147fc1cabf98989f0988e70d250df2762a62302f4`.
It checked complete before/after byte and namespace fences and preserved the
failed performance result. A successful capture is separate from the pending
independent full raw semantic audit.

A54 must demonstrate its effect under the original acceptance protocol. No
success from another executable, widened window, renewed deadline, successful
subset or automatic business retry can close a remaining gate.

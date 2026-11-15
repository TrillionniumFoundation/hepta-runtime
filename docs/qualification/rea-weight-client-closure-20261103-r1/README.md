# Weight client closure evidence, 2026-11-03

This directory accompanies
[the closure report](../../weight-runtime/BENCHMARK_CLIENTS_CLOSURE_20261103.md).
It retains completed cohorts and exact provenance. Documentation preparation
executed no benchmark/build and modified no Rust source or benchmark driver.

## Contents

| Files | Purpose |
| --- | --- |
| `identity-results.json` | Complete original 240-sample identity/large-response cohort |
| `formal-results.json` | Complete original 300-sample helper/socket/complete-MCP cohort |
| `derived-statistics.json` | Nearest-rank p50/p95 and means; CPU summed per sample |
| `runtime-receipts.json`, `*-original-job.stdout.log` | Original benchmark terminal states and retained output |
| `identity-launch.json`, `formal-launch.json` | Exact arguments, source labels and launch snapshots |
| `baseline-release-*.json`, `candidate-build-r*-*.json` | Build/source linkage, preserving R2's failure and R3's success |
| `candidate-prior-harness-correction.json` | R2 regex error and reuse of successful immutable compilation |
| `candidate-*-artifact.json`, `candidate-weight-native-*` | Artifact receipts and ten tests per feature configuration |
| `candidate-warm-store-turn.*` | Successful exact regression whose enclosing R2 summary failed |
| `source-manifest-selection.json` | Six changed paths, selected source rows and whole-manifest references |
| `semantic-validation.json` | Raw traces, scoped IDs, 100 query arrays, forward counts and worker terminals |
| `semantic-response-frames.json` | Ten bounded original formal semantic frames, preserving UTF-8 bytes |
| `documentation-input-recheck.json` | Explicitly later recheck, separate from original in-run checks |
| `external-trace-manifest.json` | Original paths/SHA-256 for 1,465 external files / 126,987,011 bytes |
| `external-build-artifacts.json` | Binary/test-library and whole-inventory references; no executables copied |
| `archive-provenance.json` | Byte-exact copy sources and original artifact identities |
| `SHA256SUMS` | Hashes for this archive and reports |

The baseline was clean commit
`23246a5313957e9e97e324303bc47a91808f1ea8` at build time. Candidate means that
base plus six modifications, inventory
`0d4d316c6ea9de52276e359e711749a404d3e60191c4d37d7fcd8dcb2c39a28c`,
diff `79cef8bff8213a1f159c310a98ce5fdf29505113745a93b07debd2f61ef651ec`.
It is not a clean base-commit build or an already-published new head.

## Recompute a CPU cell

This example reads retained data only:

~~~python
import json
import math
import statistics
from pathlib import Path

data = json.loads(Path("formal-results.json").read_text())
rows = [row for row in data["samples"]
        if (row["layer"], row["route"], row["operation"])
        == ("cold_helper", "native_rust", "inspect")]
cpu_ms = sorted(row["client_user_cpu_ms"] + row["client_system_cpu_ms"]
                for row in rows)
assert len(cpu_ms) == 20
print("p50", cpu_ms[math.ceil(0.50 * len(cpu_ms)) - 1])
print("mean", statistics.fmean(cpu_ms))
~~~

This yields p50 79.429 ms and mean 80.33375 ms. Adding independent user/system
p50 values is not this calculation. No recorded timed sample was filtered.
Explicit warmups and semantic checks remain outside the sample arrays.

## Verification and retention

From this directory, `sha256sum -c SHA256SUMS` verifies the archive and reports.
External traces can be verified by comparing byte count and SHA-256 at each
original operator-host path. These are retained sources, not replay destinations.
The manifest was created by reading/hashing files without resending requests.

Large frames, full RPC transcripts and executables remain outside Git. The ten
semantic frames are small: hashing `raw_frame_utf8.encode("utf-8")` reproduces
the original response hash, including its terminating newline.

The source-inventory digest recorded by a build runner and the SHA-256 of its
serialized inventory JSON are named separately. Monitored source/build linkage
is not a cryptographic compiler attestation. Test libraries retain recorded
artifact hashes and were not rehashed during documentation. R2's outer failure
remains visible although its compile and exact regression exited 0.

OS caches were warm. Helper RSS is lifetime `wait4.ru_maxrss`, potentially
including inherited pre-exec peaks; it is not post-exec memory. Identity exits
are cumulative paths. Large-response timings combine hashing/parsing changes.
MCP medians/tails remain mixed. Both compute routes retain the same
Python/PyTorch CPU backend, and native remains opt-in.

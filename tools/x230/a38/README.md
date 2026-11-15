# A38 reproduction tools

Run these tools on the isolated X230 workspace. They do not install or restart a
runtime service. Use a new output directory for every run, retain failed outputs,
and do not run compilation concurrently with a performance comparison.

## Build qualification

`qualify_runtime_candidate.py` takes `--source`, `--target-dir`, `--output`, and
optionally `--cargo`, `--toolchain` (default 1.95.0), and `--jobs` (default 2).
Set `CARGO_HOME` to the already provisioned offline dependency cache before
invoking it. It formats and freezes the source, cleans this package's artifacts,
runs strict Clippy/all-feature tests/release, and rejects stale compiler artifacts.
Dependency cache reuse is allowed; reuse of the candidate's test/release package
artifact is not.

## File observation comparison

Keep the Python files in this directory together. `x230_file_pool_benchmark.py`
imports the original native controller/profile/fixture helpers and the pinned
SSH wrapper from the six-running-job canary. Its public CLI is:

```bash
python3 x230_file_pool_benchmark.py \
  --candidate /absolute/qualified/hepta-runtime \
  --profile-template /absolute/profile.json \
  --frozen-jobs /absolute/six-original-job-records \
  --socket-parent /absolute/private-short-socket-root \
  --out /absolute/new-output-directory \
  --calls 96 --concurrency 1 4 8
```

The profile template and frozen records must be authorized synthetic fixtures
from the selected six hosts. The current SSH agent must cover those hosts;
expired historical agent paths are not reused. Preserve strict host checks.
The socket parent must be private and short enough for Unix-domain socket paths.

The script sends only `file_info` and `binary_read`; it never writes remote
fixture content. It fixes off/on/on/off order and checks every successful result
and every negative result. `--soak-seconds N` selects one pooled round that
repeats the requested cells until that duration has elapsed. A soak is a
candidate-only diagnostic and does not create another two-mode comparison.

`report.json` records completion, every cell, actual controller waits, sampled
resources and all sampler errors. `calls.jsonl` is written as calls finish,
before later resource sampling can fail. Complete round CPU uses waited child
accounting; per-cell CPU is explicitly controller-only.

The copied six-running-job recovery harness is included as a dependency and for
separate recovery work. A38's file comparison did not execute that harness.

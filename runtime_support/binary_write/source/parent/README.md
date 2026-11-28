# Binary parent owner — independent HIA candidate

See `ABI.md` for exact ownership, resource limits and qualification scope.
This source has no production graph or router activation. Generated HIA files,
the original sources and every author/reader belong to the full source manifest.
Build and evidence directories remain outside this source tree.

Use the exact compiler checkout named by `COMPILER_INPUT.json` and its retained
development B3 bootstrap. Use the original qualified CPython 3.12.3 executable
with SHA-256 `e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f`
for capture. The environment must permit the read-only ptrace observer and
export the real memfd seal constants needed by the existing HIA loader.
Do not substitute constants or disable the kernel observer.

The following commands take fresh, nonexistent output directories:

```sh
/usr/bin/python3.12 -I -S -B scripts/build_images.py \
  --hepta /absolute/exact/compiler-source \
  --retained-bootstrap /absolute/exact/bootstrap --output /absolute/run/images
/usr/bin/python3.12 -I -S -B scripts/link_callable.py \
  --images /absolute/run/images --output /absolute/run/linked
/usr/bin/python3.12 -I -S -B tests/test_parent_data.py
/usr/bin/python3.12 -I -S -B scripts/run_capture.py \
  --build /absolute/run/linked --output /absolute/run/suite
```

After natural completion, independently obtain the SHA-256 of the actual
`suite/capture/CAPTURE.json` and pass that exact value to the DATA-only reader:

```sh
/usr/bin/python3.12 -I -S -B scripts/read_parent_capture.py \
  --capture /absolute/run/suite/capture --capture-sha256 ACTUAL_SHA256 \
  --images /absolute/run/images --build /absolute/run/linked \
  --output /absolute/run/READBACK.json
```

Only a complete successful reader receipt can qualify the frozen domain. Build
success, a source-control test, an unobserved development smoke or a partial
capture is not that receipt. Preserve failed runs, timeouts and raw traces.
The old body-only 101-case authority remains a separate historical result.

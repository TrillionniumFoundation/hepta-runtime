# Install and capture with R36 evidence tools revision 2

This repairs evidence transport only. R36 remains rejected, original performance results stay unchanged, and no performance or qualification workload is replayed.

## Frozen inputs

| Input | Bytes | SHA-256 |
|---|---:|---|
| `r36-install-evidence-tools-02.py` | 10,715 | `6bbe5c925828ebf109cb8c8464eac671464db8216dcc9bc6452fee10128faca3` |
| `r36-evidence-tools-v2-install-payload.json` | 32,320 | `b26e8ef6f617c0c36e36f0f4d416b70964d51c2e8406597d826f141c77a3138f` |
| `r36-evidence-tools-v2-deploy.tar.xz` | 24,176 | `1511a4ba7c959eeaa8091e8c3f1bdaae47bd674c1642025ea0dcb3d8430c914c` |
| First-member `_export-manifest.json` | 8,705 | `02cd30bf3b01f267f66b10c33c99f6b21ef50a7d18363717c18cab1bfc94498f` |

`r36-evidence-tools-v2-deploy.json` contains the complete file pins, original tool pins, helper archive validation, and final installer/payload identities. There are 15 tool files plus the first manifest. The deployment manifest uses `files`.

## Native installation

Use the configured `x230` native process API with executable `/usr/bin/python3`, arguments `-B`, `-c`, and the exact UTF-8 contents of `r36-install-evidence-tools-02.py`. Provide the exact `r36-evidence-tools-v2-install-payload.json` contents as stdin. Allocate a fresh stable installation operation key, a finite timeout and bounded CPU/memory. The 32,320-byte stdin is below the native 1 MiB bound.

The installer validates the whole archive and every member before creating anything. It requires all three destinations to be absent:

- `/home/qian/hepta-runtime-optimization-20261106-r36/evidence-tools-02`
- `/home/qian/hepta-runtime-optimization-20261106-r36/evidence-tools-deployment-manifest-02.json`
- `/home/qian/hepta-runtime-optimization-20261106-r36/evidence-tools-installation-02.json`

It reads and verifies all twelve original tool files and the exact original failed-capture receipt before and after writing the new files. It never writes `evidence-tools-01`, `evidence-export-01`, runtime sources, or performance output. An installation error leaves the original error outcome and any newly created partial destination for review; it does not clean up or repeat itself.

Retain the native start, complete stdout/stderr, and authoritative terminal. Confirm exit zero, `output_complete`, `output_durable`, `terminal_publication_confirmed`, synchronized untruncated streams and matching byte counts before capture.

## Capture once in a fresh directory

Start the following exact executable/argv through the configured native process API, with a new stable capture operation key:

```text
/usr/bin/python3
-B
/home/qian/hepta-runtime-optimization-20261106-r36/evidence-tools-02/pack_r36_evidence.py
--out
/home/qian/hepta-runtime-optimization-20261106-r36/evidence-export-02
```

The archive retains the filename `r36-evidence-01.tar.xz` inside this new output directory. Capture requires the original `evidence-export-01/export-failure.json` body to match 2,129 bytes and SHA-256 `24ef364dc00258ad354ec5650950060ac8e91f823c6598d922b8a18452752332`. All other entries under that previous export directory remain metadata-only; arbitrary export trees are not traversed.

## Independent verification

Download the complete actual archive and `export-report.json` using version-pinned reads. Verify the observed export-report SHA-256; do not substitute a planned hash. Use the local frozen revision-2 verifier:

```sh
python3 -B r36-evidence-tools-v2/verify_r36_evidence.py --archive /absolute/download/r36-evidence-01.tar.xz --report /absolute/download/export-report.json --report-sha256 ACTUAL_OBSERVED_REPORT_SHA256 --out /absolute/new-verification.json
```

Verification binds all five revision-2 core files, the unchanged archive helper, every retained payload and omission, original failed-capture identity, holder copies, and original reported stage flags. Successful transport verification does not change R36 adoption or prove a performance improvement.

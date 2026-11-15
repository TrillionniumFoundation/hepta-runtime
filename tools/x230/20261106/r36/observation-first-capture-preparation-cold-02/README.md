# R36 validation-scratch cold02: first partial evidence capture

This package reuses the successful evidence capture implementation from the separate legacy R36 audit-cache experiment (PR106). It captures the current PR108 cold02 root and the original first observation failure. It does not replay a workload, run an auditor, infer an observation gate, or make an adoption decision.

Four executable source files are unchanged: pack_r36_evidence.py, verify_r36_evidence.py, scan_evidence.py and stable_xz_archive.py. Only evidence_policy.py changes. Its eight exact replacements and complete reverse reconstruction are in Git 0b9ac7c1540c13d724b7b6b6d55404cce572501d. The changes are fixed paths, one actual holder prefix, two current evidence directories, and removal of the legacy PR106 capture-failure prerequisite. There was no previous export attempt in this independent root. The current failed observation reports and native records remain original payloads; they are not passed to or replaced by that legacy capture-failure predicate.

## Deployment

Use the five exact entries in deployment catalog 68a6c448156073b966916fc5cf3fcbc7db7a094f. Install them create-only under:

/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02/evidence-tools-01

Do not modify the old R35, old R36 or original measurement tools. The four copied source bytes must remain exact because the verifier compares archived tools against its local copies.

## Original holder copies

Manifest Git dfd941e6d3aef69b634fc4adda8f6317d2158715 is 8477 bytes, SHA256 0b6e760743465a773259adf2922f023a7630850676769870000db9844e3233f2. It declares 22 actual originals totaling 101419 bytes: the 21 log_files from the completed original holder report plus that report.json itself. Its observed flag describes those actual original identities, not a completed transfer. No future lifecycle holder appears in the manifest.

Copy only the fixed 22 filenames from:

/Users/qianqi/work/hepta-runtime-r36-validation-scratch-cold-02-observation-holder-01

to:

/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02/holder-inputs-01/hepta-runtime-r36-validation-scratch-cold-02-observation-holder-01

The operator checks original regular-file ownership, exact bytes/SHA and before/after identity while copying. Preserve each empty original as an empty file. Do not copy directories recursively, sockets, configuration, credentials or unlisted files. The source report records 12 empty log files, eight other logs totaling 1257 bytes, and the already-bound 90946-byte remote-script.py. report.json adds 9216 bytes.

Place the manifest at:

/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02/holder-inputs-01/manifest.json

The existing holder validator requires exact membership throughout holder-inputs-01. A native binary_write sidecar there would be an extra member. Stage the manifest outside this directory and copy it with O_EXCL, or use a create-only raw-stdin write that leaves no sidecar. Do not delete or ignore unexpected files to satisfy the inventory.

Copy the two already-published original native JSON bodies without reserialization:

- /home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02/observation-holder-native-01.json
  Git c45fdf3b3da3df47779b1b12a2274f7dd824741c, 726 bytes, SHA256 72b287ed8474522845a46516c97df55dfa21ad365718f1a6d9ee9d3c1ed811f6.
- /home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02/observation-holder-read-01.json
  Git 2c7336a6d8001f88276bf75be83d7c21cf5fd20c, 1318 bytes, SHA256 b1dcd26c9a197be29f09d5d70e34832d9c32200df4960586d330cf84d47b100b.

The latter is the actual original offset-zero read covering the complete 325-byte stdout and empty stderr; it is not a joined or reserialized page.

## Capture

After original writers and in-scope receipt creation have stopped, use the original entry once with a fresh output:

/usr/bin/python3 -B /home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02/evidence-tools-01/pack_r36_evidence.py --out /home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02/evidence-export-01

Expected filenames, without predicting success:

- /home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02/evidence-export-01/r36-evidence-01.tar.xz
- /home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02/evidence-export-01/export-report.json
- On export failure: export-failure.json and any original partial new output are preserved.

The stable before/after namespace requirement is unchanged. Do not create other in-scope receipts concurrently with capture.

The original scope includes current source, candidate, full qualification logs/maps/case logs, current exact CI output/tools, campaign raw traces and resources, lifecycle directories when actually present, the recovered measurement fixtures, six copied historical owner originals, original root receipts and the exact external s36 cancel-recovery directory if it actually exists. Missing later-stage reports stay missing/unknown in the observed stage summary. Metadata-only exclusions are unchanged. The exporter does not follow outside-root references into other historical work.

## Download and verify

Download the archive and its actual export-report.json as immutable originals. Retain all five exact source files together locally. Use the real observed SHA256 of export-report.json:

/usr/bin/python3 -B /ABSOLUTE/LOCAL/TOOLS/verify_r36_evidence.py --archive /ABSOLUTE/DOWNLOAD/r36-evidence-01.tar.xz --report /ABSOLUTE/DOWNLOAD/export-report.json --report-sha256 ACTUAL_EXPORT_REPORT_SHA256 --out /ABSOLUTE/FRESH/verification.json

The original verifier checks all included bytes, canonical member order/types/modes, omissions, observed original report flags, exact holder copies, tool identities, XZ checksum and exact EOF. It never extracts the archive or executes archived workload/auditor code.

All original bounds stay unchanged: scanner file cap 32 MiB, decoded work cap 64 MiB, 100000 decoded nodes, 1000000 JSON visits, depth 3; inventory cap 30000, payload cap 384 MiB, helper manifest cap 16 MiB and expanded archive cap 512 MiB. No scanner rule or failure bound is weakened.

Five source files passed local AST parsing only. Preparation performed zero target imports, target entry calls, host calls, workload runs or archive runs. The actual archive and verification result remain unknown until root performs and records those original operations.

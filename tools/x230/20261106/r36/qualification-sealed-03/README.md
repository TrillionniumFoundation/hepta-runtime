# R36 validation-scratch qualification transport 03

This package prepares the first qualification of the two-file R24-based validation-scratch candidate (PR108). It does not contain a qualification result. The four future qualification/map/count/release fields remain null.

## Exact change

Relative to the preserved namespace02 package, prepare_qualify.py changes only CARGO_HOME from the missing 20261023 cache to /home/qian/.cargo. Reversing that one line reproduces the entire previous preparer. The independent validation-scratch ROOT remains /home/qian/hepta-runtime-validation-scratch-20261106-r36. The frozen 12-file candidate, 28 old-owner bindings, 19 original harness files, original 8 qualification stages, jobs=2, offline/locked selectors, deadlines, source checks, retained ELF checks and live cache scan are unchanged.

The archive has 22 files and 283139 selected bytes. Only prepare_qualify.py, qualification-input.json and qualification-package-manifest.json differ from namespace02. All six raw holder/native/read sidecars preserve their exact original bytes.

## Environment repair before qualification

Root preserved the initial offline metadata failure (job 1a1b1b4536d-fc05-7a5e: missing aead 0.6.1). The separate cargo fetch --locked environment repair completed with exit 0 (job 1a1b1b5ee01-fc05-7a65), followed by successful offline/locked metadata (job 1a1b1b6c529-fc05-7a6b; 280 packages and 280 resolve nodes). Root reports both pinned R24 Cargo files unchanged. These are cache-repair and dependency-resolution facts, not compilation, testing or qualification results. The precise reported identities and this agent's evidence scope are in amendment.json; root retains the original native receipts.

## Installation and qualification

Stage the exact decoded archive at /home/qian/r36-validation-scratch-qualification-deployment-03.tar.gz and the exact installer at /home/qian/install-r36-validation-scratch-qualification-03.py. Both are outside ROOT. The base64 companion has no trailing newline.

Use transport/installation-command.json for the create-only installer. It checks the complete pinned archive, requires the separately created ROOT to be empty and owned, then claims the installation exclusively. It never starts the qualifier. Use transport/qualification-launch.json for the separate original first qualification request: /usr/bin/python3, empty env, 7200 seconds, the exact two input hashes, and key x230-r36-validation-scratch-qualification-first-20261106-01. Neither operation was performed by this package-generation agent.

Original archive 01 and namespace02 remain unexecuted preparation history. The earlier optimization-20261106-r36 directory contains a different audit-cache candidate (PR106); this transport never targets or modifies it.

## Checks and limits

Local verification checked all 22 archive members and hashes, exact base64, bounded tar structure, the two Python ASTs, the candidate schema and the four future null values, without extracting members or executing a target entrypoint. The independent Cargo-home review covers only the one-line source change and derived identities. Actual original metadata outcomes remain separately attributable to root. No Rust, auditor, workload or host operation was performed here. Cache-owner measurement closure does not assert machine-wide idleness; the original live process scan still runs before the single cache rename.

# R36 validation-scratch: cold-only recovery 02

The first preparation wrapper (job 1a1b1bedd38-fc05-7a99) failed before running the original qualifier. Its expected D2 target-build release file was absent. Root's subsequent read-only inventory found no D2 target/cache directory and 42487177216 free bytes. The original failure directory and native receipts are preserved. The cause of the missing cache is not established; the earlier audit-cache R36 preparer contains no D2 cache-move operation.

This recovery uses a distinct ROOT, /home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02, and a new empty Cargo target. It does not reuse, read, copy, rename or claim ownership transfer of a D2 build cache. The 28 D2 historical workflow documents and the six genuine retained release copies remain checked as historical evidence. The cache path in the closure input is null, the former location is labeled historical_cache_path, and reuse/transfer-applicable are false.

## Preserved qualification behavior

The frozen R24-based candidate is unchanged: 220 compiler inputs, exactly two Rust source changes and two new tests. All 12 candidate package files are original bytes. The original 19 qualification harness files, eight stages, jobs=2, offline/locked arguments, time bounds and three source/qualifier subprocess call ASTs are unchanged. The source remains accepted R24 plus the frozen patch.

The preparer retains its exclusive create-only report claim and existing failure preservation. It verifies the historical documents, applies the original 3 GiB minimum free-space assertion and the original live process/compiler scan, then creates only the absent target directory with mode 0700 and checks it is empty. It continues with the original R24 source copy, exact patch checks and qualifier command. No migration success is substituted for cold construction. The source change is restricted to three functions, the ROOT constant and corresponding explanatory metadata; 17 other functions retain their exact bytes.

## Transport and operator inputs

The archive contains 22 members totaling 283156 selected bytes. Four metadata/tool members change from transport03: the preparer, qualification input, historical owner input and deployment manifest. The 12 candidate members and six raw sidecars are unchanged.

Stage the archive at /home/qian/r36-validation-scratch-cold02-qualification-deployment-01.tar.gz and installer at /home/qian/install-r36-validation-scratch-cold02-qualification-01.py. Stage both outside ROOT. The installer first validates the entire archive, then requires the separately created ROOT to be empty before claiming and installing fixed files. It does not run the qualifier.

Use transport/installation-command.json and transport/qualification-launch.json. The latter uses a new explicit cold02 idempotency key, empty env, the actual input/closure pins and the original 7200-second envelope. Do not reuse the failed root or its key.

## Evidence boundaries

This package generation executes only pure metadata sealing, local AST checks and one zero-extract archive check. It starts no host operation, compiler, test, auditor or workload. All future qualification, formatter map, counts and release identities remain null; the real isolated inventory decides counts. Local checks verify all member hashes and preserve original raw sidecar bytes. The successful dependency-cache repair reported before the first wrapper remains distinct from qualification.

The recovery record identifies which first-failure and filesystem facts came from root's actual native observations. Root retains those original receipts separately. Historical D2 workflow closure is not a machine-wide idle claim; the original live compiler/process check runs again for the new target.

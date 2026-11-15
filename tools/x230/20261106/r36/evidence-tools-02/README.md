# R36 bounded evidence capture — tool revision 2

These tools preserve original evidence and its original failures. A successful export or verification is a transport/inventory result, not candidate adoption, performance acceptance, or a hosted CI result. No command, benchmark, remote operation, or archived code is executed by the exporter or verifier.

`stable_xz_archive.py` is copied byte-for-byte from the verified R29 companion. Its SHA-256 is `8b7aa7ef3b3772da13ea4f7009d8c478e0c92bc207d65db3f45c23453097d7a2`. It supplies original-descriptor identity checks, streaming hashes, exclusive destination creation, canonical USTAR members, one SHA-256-checked XZ stream, exact archive EOF checks, and independent member verification without extraction.

## Why this separate revision exists

The original `evidence-export-01` stopped in its scan phase before archive creation. Its unmodified `export-failure.json` is 2,129 bytes with SHA-256 `24ef364dc00258ad354ec5650950060ac8e91f823c6598d922b8a18452752332`. Five telemetry files exceeded the pending decoded queue because the first scanner queued every repeated JSON key/value and deduplicated only when removing work from that queue. The failure reported queue/JSON-queue bounds, not a detected secret. The failed native capture and its original output remain separate evidence.

Revision 2 deduplicates pending bytes at enqueue time using SHA-256 and the shallowest pending depth. Processed depths remain separate, so content previously inspected at a deeper level is inspected again if a shallower route later permits more decoding. Every accepted unique byte sequence still receives every raw secret rule. A full queue records a failure; no payload is silently skipped or excluded to make capture succeed. The original 100,000 processed/pending-node bounds, 1,000,000 JSON-visit bound, 32 MiB file bound, 64 MiB expanded-work bound and three decoded layers are unchanged. JSON visits still count duplicate values.

The capture and verifier identify `evidence-tools-02`, retain all old `evidence-tools-01` files, and require the exact original failure receipt above. Only `evidence-export-01/export-failure.json` is eligible for a body read within that old export directory. Other files/directories there are metadata-only; other export directories remain outside the fixed scope. The new output directory is `evidence-export-02`; its archive keeps the canonical filename `r36-evidence-01.tar.xz`. Rejection of R36 and all original performance gates are unchanged.

## Scope

Only these original roots can be traversed:

- `/home/qian/hepta-runtime-optimization-20261106-r36`
- `/home/qian/hepta-runtime-optimization-20261104-r16/r36-cancel-recovery-01`

The second path is the one explicitly approved R36 recovery canary. The rest of R16 is never traversed. Top-level R36 directory allowlisting is in `evidence_policy.DIRECTORIES`; root-level regular receipts and scripts are also captured. Unlisted directories are recorded as metadata-only omissions. The fixed list includes complete qualification logs, source maps, isolated-test inventories and compressed case logs, current source, original patch, CI records/tools, observation RPC/resource evidence, lifecycle evidence and failed/partial outputs.

`target-build`, other declared build/VCS caches, `.ssh`, private profile trees, runtime/SSH configurations, credentials by declared filename, sockets, special files, symlinks, nonexclusive hardlinks and opaque container archives are metadata-only omissions. They are not followed, hashed, copied or recursively read. ELF detection uses only a four-byte header probe; its body is not read or hashed. Omission receipts retain `lstat` metadata, the reason, `body_included: false` and `body_sha256: null`. Existing hashes inside original qualification reports remain original claims, not new body verification.

The exporter records a stable namespace snapshot before and after capture. Fixed later-stage directories that are absent are labeled `not_executed_no_output_observed`; this means no output was observed in that controlled directory at capture, not a claim about deleted historical work. Existing but unreadable/omitted output directories and missing reports are marked unresolved. Original report flags, including false, are retained without promotion.

## Holder originals

Do not read or copy any live agent socket, `.ssh` directory or credential/configuration body. After observing the actual holder output, copy its approved evidence files into `ROOT/holder-inputs-01/` and create `manifest.json` with schema `hepta-r36-observed-holder-copies/v1`, `observed: true`, and `files` keyed by the copied relative path. Each entry must contain the observed original absolute `original_path`, byte length and SHA-256. Only these original path prefixes are accepted:

- `/Users/qianqi/work/hepta-runtime-x230-r36-20261106/observation-holder-01/`
- `/Users/qianqi/work/hepta-runtime-x230-r36-20261106/lifecycle-holder-01/`
- `/Users/qianqi/work/hepta-runtime-x230-r36-20261106/async-read-holder-01/`

For example, `observation-holder-01/receipt.json` must identify that exact original Mac path and match the copied bytes. The supplied example remains `observed: false` and cannot authorize capture. No future holder success is fabricated. If no copies exist, the manifest says `not_collected` and lists the three planned original directories. The approved `supplement-tools-01`, `async-read-abba-01` and root `async-read-protocol-01.json` are also captured. The supplement remains descriptive and supplies no adoption gate.

## Run once after original writers have stopped

Deploy this reviewed revision to the new `ROOT/evidence-tools-02` directory. Preserve `ROOT/evidence-tools-01` unchanged. Keep the five implementation files unchanged; the verifier compares their archived hashes with its local reviewed copies. Use an unused output directory. Existing output files are never replaced, including on failure.

```sh
/usr/bin/python3 -B /home/qian/hepta-runtime-optimization-20261106-r36/evidence-tools-02/pack_r36_evidence.py --out /home/qian/hepta-runtime-optimization-20261106-r36/evidence-export-02
```

The output contains `r36-evidence-01.tar.xz` and `export-report.json`. Every included member has an exact byte count and SHA-256 in the embedded first-member manifest. The report binds that manifest and the complete compressed archive. Original files and services are not modified. A failed run retains `export-failure.json` and any partial new archive; it does not overwrite originals or retry.

Use the SHA-256 of the actual observed export report, not a value inferred from a planned run, for independent verification. The archive/report paths may be local downloaded originals. The destination must be new and absolute.

```sh
python3 -B verify_r36_evidence.py --archive /absolute/download/r36-evidence-01.tar.xz --report /absolute/download/export-report.json --report-sha256 ACTUAL_OBSERVED_REPORT_SHA256 --out /absolute/new-verification.json
```

Verification checks all regular member bytes, canonical order/types/modes, inventory/omission reconciliation, original stage observations, observed holder copy bindings, tool identities, XZ checksum and exact archive end. It never extracts or executes archive contents. Original native-operation custody and qualification/performance gate adjudication remain separate evidence.

## Secret scan and limits

Every included file and the manifest are scanned before archive creation and again during verification. Checks cover raw token/private-key patterns, JSON/JSONL strings (including nested MCP text payloads), hex, standard/URL-safe base64 and gzip log bodies, with up to three decoding layers. PEM recognition includes traditional encrypted keys with `Proc-Type` and `DEK-Info` metadata. Findings expose only `path` and `pattern`, never excerpts, decoded bodies or matched values. A finding or decoding/resource bound refuses export; nothing is silently truncated or dropped to make a package pass. Source code that merely lists a PEM header is not treated as a PEM key body.

Bounds are 32 MiB per scanned file, 64 MiB decoded work per file, 100,000 decoded nodes, 30,000 inventory entries and 384 MiB total payload. The unchanged archive helper enforces a 16 MiB manifest and 512 MiB expanded archive bound. These are explicit fail-closed limits, not evidence completeness claims if a limit is reached. Opaque archive bodies are omitted because their expanded originals are captured separately; original gzip case logs are included and scanned after decompression.

Twelve local tests exercise repeated JSON/JSONL telemetry, later shallower decoding, unchanged failure bounds, exact prior-failure containment, and encoded-secret handling without disclosure, private/build-directory containment, retention of negative/unresolved outcomes, holder binding rejection and an actual archive/independent-verification roundtrip followed by rejection of a corrupted compressed archive. They operate only on fixtures inside this tool directory and do not run the R36 qualification or any workload. Run them with `python3 -B -m unittest -v test_evidence_tools` from this directory. The original R36 runtime candidate remains rejected; this transport repair does not run or change any qualification or performance workload.

# D1 qualification archive03

This revision fixes archive02's selection error while preserving the original content scanner. The old archive01 source contains its own detector literal and was accidentally selected as archive data. Archive02 stopped with the original 99-byte error before the archive write branch. The two original collector sources are preserved as separate immutable Git objects with exact raw file_info references. Their bodies are excluded from the evidence tar; no encoded substitute is included.

## Deployment

Read deployment.json (Git 8c01ce2b9423ba3a4aec592510116147e5d3a8ba), verify all eight entries by byte count and SHA256, and create the fixed destination files only if absent. It contains the seven additional provenance originals and the sealed collector. The existing archive01 and archive02 sources, failed receipts and qualification dataset remain unchanged.

Run once under the existing native owner:

```text
/usr/bin/python3 -B /home/qian/hepta-runtime-phase-cost-20261106-d1/archive_d1_qualification_03.py --kind qualification
```

The new output basename is qualification-evidence-03. No command in this preparation package has run that collector remotely. Preserve its original native start/status/read and real outcome.

## Evidence and limits

The actual qualification is the first original job 1a1aff8769c-fc05-6d26: 1651 passed, 0 failed, 34 ignored, 1685 selected and 0 retries. These results are bound through the original seven qualification files; they are not rerun. The full selected source222, original19 harnesses, eight-stage logs, isolated-test originals and compressed case logs keep the prior selection rules. ELF binaries, target caches and credential files remain excluded.

Bounds remain 32 MiB total selected bytes, 8 MiB per file, 2 MiB manifest and 8192 files. The original stable nofollow reads, create-only outputs, bounded decompression and zero-extraction verification remain unchanged. The candidate patch identity remains the original exact four fields, including its Git blob.

After the original archive03 run and transfer, local read-only verification is available from this exact sealed source:

```text
python3 -B archive_d1_qualification.py --verify /absolute/path/qualification-evidence-03.tar.gz --expected-sha256 ACTUAL_ORIGINAL_ARCHIVE_SHA256
```

That example's archive SHA must come from the real completed archive03 job. This preparation claims no archive03 success or performance acceptance.

## Original code and failure provenance

- Archive01 source: 55645 bytes, SHA256 e8d151daf83577367432d0913e0783ca2cce9bd62fdb8e8e3e156823b1baa444, Git 0a9c96080f43aee5c1aeb2b327b3f36f47a346b0.
- Archive02 source: 58076 bytes, SHA256 67e681a58af261c11d5de8d470ff25a0d43abf2a84613ebb0303c6df7d97944c, Git 7e46ad1ca5f3846e7a501f5bdb2c3c02d308dae8.
- Real failed archive jobs 1a1b01385a8-fc05-6df2 and 1a1b01cee00-fc05-6e22 remain preserved. They are archive-preparation failures; the qualification and optimization measurements were not rerun.

The local executor disconnected after source sealing. The archived builder, old source and exact original metadata reconstructed the sealed source byte-for-byte: 63482 bytes, SHA256 e7a0787a110c50a93e18bf951c02f195e62752c532ea3f649f956ca1b06d018f. The independent review is Git 87486472b4823fc89d43c288104bebe9be44242d. The recovery receipt distinguishes this exact source restoration from any future host execution.

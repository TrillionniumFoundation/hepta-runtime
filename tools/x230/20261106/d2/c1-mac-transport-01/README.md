# D2 C1: transport the actual sealed package to Mac

This transport preserves the actual original source seal. It stages 23 files: all 21 sealed payloads, the original seal-manifest.json, and the unchanged install_campaign.py. The optional operator-argv.json is omitted because the exact argv is already in the actual seal manifest. The original installer reads every sealed payload and installs only the two Mac programs.

## Exact delivery

| Item | Bytes | SHA256 | Git blob |
| --- | ---: | --- | --- |
| Transport tar.gz | 174945 | 523b4e1003eb1cd6f55764a64e4479fe9c4be37e706057fcecc0deed89d53565 | 0019ef3fcd22b551a47d6a890f7bcd607d9c3bb8 |
| Base64 companion, ending in one newline | 233261 | 27dff20b09a69cf99c9a49f062ef2bb0c86cdb97db649368ea413c1ed245bf71 | 6a9914f6ddb97656c747eff7420f8fe394da0b06 |
| Mac transport importer | 15014 | c1f59080befeba1b660ae7b6bb24ba1e2f4af083a2f60ce30ae37a785f255994 | 8bf6bd5154826e6da2f4558587f1886a0624468b |
| Actual original seal manifest | 325264 | 2f14f87be47957240dc54c99e64d98f346a44822b878936df05060950cd46b0d | 1ed0f4a3f1b1256356258faf146f57bd2a5017af |

All 23 uncompressed payloads total 709014 bytes. The 21 original runtime payloads total 371348 bytes. The original installer remains 12402 bytes / bd6e33588cb938a15ffc6ca68bed3f6e11c2df1a1e51da743202dd1a9941faba.

## Root operator sequence

1. Create these five directories as the Mac owner with mode 0700, with no files present:
   - /Users/qianqi/work/hepta-runtime-d2-c1-sealed-staging-01
   - /Users/qianqi/work/hepta-runtime-d2-c1-sealed-staging-01/x230
   - /Users/qianqi/work/hepta-runtime-d2-c1-sealed-staging-01/x230/c1-tools-01
   - /Users/qianqi/work/hepta-runtime-d2-c1-sealed-staging-01/x230/c1-tools-01/reference
   - /Users/qianqi/work/hepta-runtime-d2-c1-sealed-staging-01/mac
2. Stage and hash-check the tar at /Users/qianqi/work/hepta-runtime-d2-c1-sealed-payloads-01.tar.gz and importer at /Users/qianqi/work/hepta-runtime-d2-c1-importer-01.py. Both inputs stay outside the private payload staging tree. Upload lock files in the work directory are neither selected nor modified.
3. Execute the importer once using the exact argv below and preserve its original native terminal/read streams. Its success reports imported=true, files=23, payload_bytes=709014, target_code_executed=false, measurement_started=false.
4. After that successful import, execute the original Mac installer once using the exact argv below. It installs only d2_campaign.py and held_agent_campaign_02.py into /Users/qianqi/work/hepta-runtime-d2-launchers-01 and creates install-report-01.json. It starts no workload.
5. Root separately completes the unchanged Linux installer, which installs 19 payload files. Once both original installation receipts are closed, the original holder argv from the seal manifest is ready. No source or measurement protocol changes are part of this transport.

Importer argv:
```json
["/usr/bin/python3","-B","/Users/qianqi/work/hepta-runtime-d2-c1-importer-01.py"]
```

Original Mac installer argv:
```json
["/usr/bin/python3","-B","/Users/qianqi/work/hepta-runtime-d2-c1-sealed-staging-01/install_campaign.py","--sealed-dir","/Users/qianqi/work/hepta-runtime-d2-c1-sealed-staging-01","--target","mac","--manifest-sha256","2f14f87be47957240dc54c99e64d98f346a44822b878936df05060950cd46b0d"]
```

The importer accepts no arguments. It rejects any preexisting payload or unexpected staging entry. Every archive member is verified before the first payload write. Any partial failure keeps created files and the original native logs for reconciliation; it does not overwrite, remove, or retry.

## Narrow source adaptation and verification

The reference is the reviewed D1 importer01, Git bcaadb2cabce393182c465d84a04d052a5e26e74, 14918 bytes / deb82a9c072729208c1dc6ba1a2a009ad2faa78ea08fdb9ebff3ec72ec8a850e. The source edit ledger contains 13 explicit substitutions, including the fixed D2 identities and paths. Reversing those substitutions restores the full reference source exactly.

Seven functions are byte-identical: require, sha, stamp, directory_identity, read_regular, octal, and check_directories. parse_archive changes only its frozen payload-total literal. inventory removes the old in-tree transport-input allowance. main reads the fixed archive and importer through the already checked work-directory descriptor, and checks the external executing path. No lock allowlist, wildcard, new cleanup, or new target execution is added.

The original bounds remain: 1 MiB compressed archive, 1 MiB per file, 2 MiB total payload, and 23 fixed regular USTAR members. The original nofollow, owner/mode, stable-read, complete inventory, create-only, readback, and fsync checks remain. Source AST parsing and exact function/source comparisons passed. The deterministic USTAR/gzip was generated locally from exact originals and every member was compared in memory against those bytes and their SHA256/Git identities; no filesystem archive extraction occurred.

Only metadata/source packaging and static validation were run here. No importer, installer, holder, controller, workload, parser, or auditor was executed. Original runtime bytes and original 40-file preparation bytes were not changed.

## Measurement boundary

This transport is preparation only. Once root starts the original held-agent campaign, the existing measurement lock remains: root polls only that same Mac holder's original status/read until terminal and owned cleanup are closed. No other host reads, probes, transfers, builds, or new jobs are implied. The quiet interval, ownership rules, original auditors, and all measurement failure conditions are unchanged.

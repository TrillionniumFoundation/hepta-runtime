# D1 create-only deployment

The archive `deployment.tar.gz` is 334,455 bytes with SHA256 `eb6485c00d81803c2379982374ca6fdf4bf1665d58e5d2f2969ea520f2550e41`. It contains 51 regular files totaling 1,320,021 bytes. The sealed package manifest is 9,427 bytes with SHA256 `d13dcedb008d909073a5d5f60215aacd75ea64b63069722207ed2242bb702ebc`. The complete archive has been compared with all local members without filesystem extraction.

Stage the archive with binary upload/write and commit. Preserve the original staged file. Do not put the archive or its base64 body into `process_start.stdin`. Stage `install_qualification.py` separately; it is small enough for a short text installation request.

The installer reads one pinned staged archive, verifies its file identity, SHA256, bounded decompressed size, 51 regular members and all per-file manifest hashes, then exclusively creates `/home/qian/hepta-runtime-phase-cost-20261106-d1`. It writes regular private files with `O_EXCL` and verifies them. It does not invoke the qualifier, a compiler, an auditor, a workload, or any cache operation. A pre-existing D1 root is rejected. An interrupted or failed installation is retained for review and is not automatically deleted or retried.

Run the short installation argv after the two files have actually been staged:

```text
/usr/bin/python3 -B <staging>/install_qualification.py --archive <staging>/deployment.tar.gz
```

The following qualification argv is also recorded in the sealed package's `launch-command.json`:

```text
/usr/bin/python3 -B -u /home/qian/hepta-runtime-phase-cost-20261106-d1/prepare_qualify.py --input-sha256 6035b89808862402a49cb070e4d511dfbf4965ed16399c590ac035bb9690020a --owner-closure-sha256 cfb1f49ea5c9b15433c5411a9f3c9453fa7220d9e9b800a3aac44c2a0ab69601
```

Use the D1 root as the working directory and preserve the existing native qualification process custody, output collection and timeout arrangement. The three environment variables `HEPTA_RUNTIME_PHASE_COST_MODE`, `HEPTA_RUNTIME_PHASE_COST_OUTPUT` and `HEPTA_RUNTIME_PHASE_COST_ELF_SHA256` must be absent. The original eight stages use `--all-features`, so their preserved release ELF contains the diagnostic feature while its mode remains unset.

Neither command has been executed by the preparation agent. The installer was parsed and reviewed statically. The sealed inputs contain actual prior-owner evidence; D1 qualification, CI, final source map, binaries and measurements remain future facts. The original source package and original owner receipts are unchanged.

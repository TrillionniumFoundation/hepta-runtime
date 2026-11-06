# R30 qualification passed; observation failed; candidate not adopted

R30 isolated the shared unfiltered ToolRouter on the accepted R24 source. The
original eight qualification stages passed. The complete isolated inventory
reported 1,647 passed, 0 failed, 34 ignored, 1,681 selected, and 0 retries. The
qualified runtime SHA256 is
`9c30ec2a6b8299755184d6a91e4d6b694a384f8589eb3f4cb65f31d4c8b996c8`.

The original observation run completed all four ABBA rounds and all 12 cells.
Round index 2, candidate B, concurrency 1 completed 191 of 192 calls successfully.
One `process_status` call to `rog`, request ID 72, returned the native error
`observation transport deadline; no automatic retry` after 10,010.97226 ms.
The other 11 cells each completed 192 of 192 calls successfully. That is 2,303
successful calls out of 2,304 submitted cell calls, with one retained failure.

The parent exited 1, and the observation was rejected. The native audit,
boundary, cancellation-recovery and observation-summary stages were not reached;
normal lifecycle ABBA was not started. No rerun is planned. The four controllers'
normal shutdown and restart shutdown completed. Source, runtime binaries and
frozen topology remained unchanged. The compiler-monitor audit passed with 281
samples; it does not establish a cause for the failed RPC.

The data do not establish router causation or an environmental explanation.
Successful qualification and publication of the candidate do not constitute
performance adoption. R24 remains the accepted baseline. R31 is the separate
R24-plus-pidfd candidate and excludes the router change.

## Original evidence identities

| Artifact | Identity |
|---|---|
| Qualification native job | `1a1ade0d4f4-fc05-5b52` |
| Qualification report | 83,365 bytes; SHA256 `24cd58c6194ab94f1d5b7f33c409bd901a06ca5f39ad33d53aa0ec339dcb6a76` |
| Qualification terminal | 732 bytes; SHA256 `74a312bc03e765ac3883fac0f38c7c149ec2ec36870381c2c5452f052597e79a` |
| Observation raw report | 3,567,429 bytes; SHA256 `3b7ced2475a579f4a6c9f9f61605a7e4756c31884ec8cb505e74da176e8a0f5c` |
| Mac holder native job | `1a1adfc0c89-fc05-5c5e`; failed, exit 1, complete logs |
| Candidate publication | `dbedaf9be0bbb65812fa9dbfcd9d7c0fb13f1ffd`; draft PR 97 |

`archive_r30_evidence_v2.py --kind observation` preserves the raw report and transport
logs with a file-by-file SHA manifest. Its compact is recomputed from the original
round/cell/call rows and includes the complete failed call record. Profile and
credential configuration, ELF files and test executables are excluded explicitly
in the archive manifest. `observation-holder-native-01.json` is included when
present. The actual Mac holder directory and its forwarded stdout/stderr remain
on the Mac; the x230 archive does not claim to contain those host-local files.

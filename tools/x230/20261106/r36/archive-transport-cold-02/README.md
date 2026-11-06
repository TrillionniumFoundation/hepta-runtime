# Complete qualification and exact CI evidence

Both archives below were created once from the existing original reports and logs, then checked once by the original bounded zero-extraction verifier. Neither collection nor verification reran tests, target executables or auditors. Full immutable transfers verified every chunk and each complete SHA256 before creating the Git blobs.

| Evidence | Original job | Passed / failed / ignored / selected / retries | Files | Selected bytes | Archive bytes | SHA256 |
|---|---|---|---:|---:|---:|---|
| Qualification | `1a1b1cb4862-fc05-7ad9` | 1647 / 0 / 34 / 1681 / 0 | 3611 | 11138949 | 2492706 | `f5247fbce9ec7a6c69fcd1021afefb39b6839e1f307cc2dc07550e821cca08f8` |
| Exact native CI | `1a1b1fadfab-fc05-7bda` | 1647 / 0 / 34 / 1681 / 0 | 39 | 3445475 | 581561 | `a00c4e112b465259e3afe482156bfa9ddc21e698ab1982a1c39f80dd028ce57e` |

Qualification includes all eight stage logs, isolated-test compressed logs and audit, exact source inputs and frozen harness. CI includes its six original stages, full nextest inventory/output, independent audit, plan, original native receipts and frozen tools/qualification bindings. The original collector and verifier native records are adjacent to their archives; the immutable transfer ledger is in `archive-transport-cold-02`.

The full OBS candidate acceptance remains unresolved after the separately preserved baseline preflight failure. Neither archive success is a performance gain or adoption claim.

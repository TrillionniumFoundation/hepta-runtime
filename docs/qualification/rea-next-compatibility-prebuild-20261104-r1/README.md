# Prebuild compatibility snapshot preserved before final release observations

This directory retains the exact eight canonical compatibility files that existed before the final release capability observations were recorded. The historical cached/offline checks and PREBUILD_VALIDATION refer to these original bytes; later canonical regeneration must not replace this snapshot.

The original ledger SHA-256 is `9168c706521730de6b7747b94ed98f6c804df969a0ce3f96ac574769bdef1a0d`; the original environment SHA-256 is `8e9088d381b41fe8f6208e89f373be556dc3a0536ed1cce5867cf03555207d9c`. All eight files, including the earlier README, mapping, input pins, validation and interim/prebuild receipts, are retained under `compatibility/` without JSON reserialization.

This is an archival snapshot, not a new qualification result. Its historical paths and PENDING states remain as originally recorded. The canonical files may subsequently point to final release receipts while the full upstream parity gate stays OPEN.

The manifest covers every file except itself and identifies original-byte copies separately from this generated README. Archiving did not run tests, change the canonical files, or stage anything.

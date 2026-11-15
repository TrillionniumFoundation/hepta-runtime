# R35 lifecycle owner postflight

This separate script records the current state after R35's original normal lifecycle attempt completed and was rejected by its unchanged concurrent-cancel throughput gate. It leaves the earlier OBS postflight, which truthfully captured LC as not yet started, byte-for-byte unchanged.

The standalone script is 46387 bytes, SHA256 `6b03c0025b2bffc0f0552e53e95d7867a45fbb78ebf05d601172cddf91434c7e`, Git blob `dae4f73771eb24cf298477603e9e7d9fda40a52e`. Five original need/ident/read/create/native helpers are copied byte-for-byte from the reviewed R35 OBS postflight. The construction only parsed Python syntax and copied source; it did not import or execute the resulting postflight. Root performs the independent review and, if approved, one native invocation.

The 95 fixed identities come from existing Q/CI/OBS/LC originals, their bound round/phase identities and the completed LC archive receipt. Original stage streams and monitor tool sources are additionally read through their original fixed identities. The script verifies the original Q/CI successes and counts, OBS success, and the LC failed native result with complete stored bytes. The four LC reports and original audits, 44 phase records, eight normal shutdowns, 14 tool tests and 149 monitor samples remain original evidence; no auditor is rerun and no performance gate is recalculated.

Immediately before its sole output, it rechecks the current 220 compiler inputs including 17 embedded Python files, all 19 original harness files and the three independently preserved release programs. It retains the same cache-directory device/inode and records nanosecond metadata as decimal strings. It never moves/deletes the cache, changes source, launches workloads, or asserts that the machine is idle. The future preparer must still check live processes that reference the cache.

Install create-only as:

```text
/home/qian/hepta-runtime-optimization-20261106-r35/postflight_r35_lifecycle_owner_01.py
```

Run once with cwd at that ROOT:

```text
/usr/bin/python3 -B /home/qian/hepta-runtime-optimization-20261106-r35/postflight_r35_lifecycle_owner_01.py
```

The only new result is create-only `ROOT/lifecycle-owner-postflight-01.json`, schema `hepta-r35-rejected-lifecycle-owner-postflight/v1`. Its job ID, report size/hash and native terminal/read must come from that real invocation; none is predicted here. A failed check creates no success receipt, and the original native failure must be preserved without overwriting or silently retrying this output.

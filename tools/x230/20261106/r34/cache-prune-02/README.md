# R34 cache prune attempt 02: exact timestamp input correction

This package is prepared for a separately reviewed second attempt. The pruner
has not been executed during preparation. The R34 source, sealed qualification
launcher and original 3 GiB requirement remain unchanged.

## Preserved first failure

Original native job `1a1aeeea99f-fc05-6440` finished failed, exit 1, with durable
complete stdout/stderr and zero automatic retries. Its report records zero
deletions, no absent selected files, no postcheck errors, unchanged retained
programs and unchanged unselected cache entries.

The original error was `candidate fixed stat differs:
hepta_runtime-1b8b761b89392e3b`. Both complete before/after cache inventory
receipts are 1,645,029 bytes and have SHA256
`9fa4908281b0dcc03921272a7e63a0871f831c6daf3e0edb2377c07488255154`.
The before/after owner receipts also have identical bytes and SHA256. The
original 01 script, plan, native/read and report remain preserved.

## Exact cause and limited change

Preparation code parsed the original nanosecond integers through JavaScript
`Number`, which rounded values beyond its exact-integer range. Direct Python
parsing of the preserved 69,145-byte original inventory recovered these values:

| File | Incorrect 01 decimal value | Original exact decimal value |
|---|---|---|
| `hepta_runtime-1b8b761b89392e3b` | `1793930603038937300` | `1793930603038937265` |
| `libhepta_runtime-564505b54e9d81cd.rlib` | `1793930262097573600` | `1793930262097573724` |

The original failed-cache inventory was also compared with live stat by
read-only job `1a1aef15be1-fc05-6460`, which succeeded with exit 0. Its exact
stdout and native/read originals are included without reserialization; both
selected objects matched in every checked field.

All other fixed stat fields match. The two corrections are +35 and -124
nanoseconds in the old supplied values relative to the originals. Attempt 02
stores the original timestamps as canonical decimal strings and requires exact
equality with `str(os.stat(...).st_mtime_ns)`. It introduces no tolerance,
truncation or rounding.

The only executable-source changes are the new tool/output namespace, these
two timestamp literals and their exact string comparison. The full source is
byte-equal to attempt 01 after reversing those specific changes. Every other
owner, source, retained-ELF, process, file-type, link-count, full-hash, inventory,
durability and free-space check remains unchanged. The fixed two-file allowlist
does not expand.

Both candidate files must still pass all checks before either unlink. The test
ELF must match the separately retained original SHA256
`e2096aa99096233152ffbd11fd1d42aa145cbfa1ef9f4fa81b8191e9055ad3b1`.
The rlib's exact fixed-stat object is fully hashed and recorded before deletion,
then fully hashed again and required to match before unlink. No external rlib
SHA is invented. Other dependencies, fingerprints, results, source and retained
ELFs are preserved. Partial deletion remains visible if a later operation fails.

## Installation and entry point

The archive contains the tool and plan plus seven exact original files for
review provenance. Install the nine regular members under
`/home/qian/hepta-runtime-optimization-20261106-r34`; they all reside in the new
`cache-prune-tools-02/` directory. Runtime receipts use create-only
`cache-prune-02/`. The existing `cache-prune-01/` is not reused or overwritten.

```json
["/usr/bin/python3","-B","-u","/home/qian/hepta-runtime-optimization-20261106-r34/cache-prune-tools-02/prune_cache.py","--plan-sha256","1179668edde634ffba8307ca35c129652d9df15c0743c76b5bdc4e6fe8f7d62b"]
```

This new attempt is explicit. The tool performs no automatic retries and
requires R34 qualification to remain unstarted. Actual deletion and free-space
results remain unknown until the coordinating owner runs the approved command.

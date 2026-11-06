# D1 C1 sealed Mac staging transport

This package transports the exact 23 files already produced by the real D1 C1
source sealer. It does not change or execute the original installer, parent,
adapter, holder, verifier, auditor, or measurement. No host calls were made while
preparing this transport.

## Fixed destination and commands

The following directories must already exist, be owned by the current non-root
Mac user, have mode 0700, and contain no payload files:

```
/Users/qianqi/work/hepta-runtime-d1-c1-sealed-staging-01
/Users/qianqi/work/hepta-runtime-d1-c1-sealed-staging-01/x230
/Users/qianqi/work/hepta-runtime-d1-c1-sealed-staging-01/x230/c1-tools-01
/Users/qianqi/work/hepta-runtime-d1-c1-sealed-staging-01/x230/c1-tools-01/reference
/Users/qianqi/work/hepta-runtime-d1-c1-sealed-staging-01/mac
```

Upload only `sealed-payloads-01.tar.gz` and `import_sealed_payloads_01.py` into the
staging root. The base64 file is a transport alternative: decode its exact bytes
before saving the `.tar.gz`; do not save an additional base64 file in staging.
The importer rejects extra entries. It also rejects links, unsafe parent
ownership or modes, any existing payload, and any archive/member identity
mismatch before the first payload write.

Run the importer exactly once:

```
/usr/bin/python3 -I -B /Users/qianqi/work/hepta-runtime-d1-c1-sealed-staging-01/import_sealed_payloads_01.py
```

Only after a successful original native terminal and complete stdout/stderr,
run the unchanged original installer:

```
/usr/bin/python3 -I -B /Users/qianqi/work/hepta-runtime-d1-c1-sealed-staging-01/install_campaign.py --sealed-dir /Users/qianqi/work/hepta-runtime-d1-c1-sealed-staging-01 --manifest-sha256 4f0b9447c24788c856c1bbb4664c3ab483e27803ff09c84e9192424f34f69f6b --target mac
```

The importer does not create any benchmark or result directory, start a holder,
or authorize a measurement. The original installer selects its declared files,
so the two transport files can remain in staging. Root retains responsibility
for the actual installation and subsequent original holder invocation.

## Integrity and failure behavior

The deterministic USTAR/gzip package contains exactly 23 regular files with
692,705 original payload bytes. The archive is 174,654 bytes with SHA-256
`efe412bd28dd0e2fa6935f57a699e3742eb91c2d064bb1861f7c63a9282ac760`.
The importer binds this compressed identity and all 23 path/size/SHA-256 entries.
It uses a bounded gzip read and a manual USTAR parser, with no extraction API,
shell, subprocess, or imported package code. Limits are 1 MiB compressed,
1 MiB per file, and 2 MiB total selected payload; tar framing is separately
bounded to that payload limit plus 64 KiB.

All archive and output absence checks precede writing. The importer keeps
no-follow directory descriptors, writes only declared leaves using O_EXCL and
mode 0600, fsyncs files/directories, and reads each whole file back. It verifies
the final complete file set and archive/importer invariance. A failure leaves
any successfully created files untouched for inspection; there is no cleanup,
overwrite, automatic retry, or repair path.

Local preparation parsed the importer AST and verified every tar member against
the actual sealed source bytes entirely in memory, without extracting paths or
executing the importer. The original 23 files were not modified. The source
builder and its unsealed importer template are preparation provenance only.

`local-static-integrity-01.json` records the actual member map and local check.
`transport.json` records deployment paths and hashes. The Git catalog records
actual created blobs, including both binary and no-trailing-LF base64 tar forms.

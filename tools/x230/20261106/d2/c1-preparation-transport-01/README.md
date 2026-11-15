# D2 C1 original preparation transport

This transports the exact 40-file unsealed preparation catalog `7d96edc6fe3eb62603692834b83ce553ccc95a40`. The payload is 514,838 bytes; no preparation member was changed. The source manifest remains revision 02, with SHA256 `9fcf4d95387e5b5fdb124acaf273c807ca59cf8d78c4fdc9f73577166e6e44f7`.

The tar is 138598 bytes, SHA256 `78fb352cae7e77cc34cef6be84059a38c423668e48a0dc5014ea012ebad38cdc`. It contains only regular USTAR members in lexical path order, mode 0600, zero UID/GID/mtime and empty owner names. Gzip uses no filename, mtime zero and compression level 9. Every member was read back in memory and compared byte for byte with the frozen originals; no tar filesystem extraction was used. The base64 companion is the exact archive encoding plus one final LF.

## Fixed deployment

Upload the tar to:
`/home/qian/hepta-runtime-d2-c1-parent-preparation-01.tar.gz`

Upload the installer to:
`/home/qian/install_hepta_runtime_d2_c1_preparation_01.py`

Both staging files are outside ROOT. Do not create the installation leaf in advance. Upload-created lock files stay outside the destination and are neither copied nor removed by the installer.

Use working directory `/home/qian` and this single installation argv:

```text
/usr/bin/python3 -B /home/qian/install_hepta_runtime_d2_c1_preparation_01.py --archive /home/qian/hepta-runtime-d2-c1-parent-preparation-01.tar.gz
```

Destination:
`/home/qian/hepta-runtime-validation-cost-20261106-d2/c1-parent-preparation-01`

Original installation receipt:
`/home/qian/hepta-runtime-validation-cost-20261106-d2/c1-preparation-install-01.json`

The installer verifies the archive, all forty members, the exact source manifest, and destination absences before writing. It preserves the original 4 MiB file / 16 MiB payload / 128 member bounds, no-follow stable reads, exclusive writes, fsync/readback and partial-failure retention. Existing source, ordinary evidence, runtime tools and outputs are not destinations.

## Narrow source derivation

The installer derives from the already reviewed D1 source `b528256167ffb1e5bb278ad7aaba9982edd20838`. Thirteen exact replacements update namespace, first destination/receipt, outside-ROOT tar path, actual package identities, and the original D2 manifest's revision and source-package-only field. The eight IO/helper functions and main remain byte-identical. Reversing all replacements reconstructs the original source exactly; both sources passed AST parsing. See the exact ledger, unified diff, static checks, and independent review.

This transport does not run the sealer, binder, verifier, compiler, auditor, holder, campaign or any packaged code. It does not claim actual C1 readiness or a measurement result. Root must separately wait for the actual ordinary/postflight closure and use the already frozen operator plan. No host calls were made while building this transport.

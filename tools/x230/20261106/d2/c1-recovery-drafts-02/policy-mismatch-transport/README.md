# D2 C1 recovery02 preparation transport

This is preparation-only transport. It does not seal actual runtime sources, compile, execute a target helper, launch a holder, or claim a02 result.

## Exact payload

- Standard USTAR + gzip stored DEFLATE blocks: 614468 B / SHA256 802d7eae498a4945b45b04eb3afa06b40bc3d1cb50f4ddc498406aac2ef50950.
-55 regular source members /568655 B. Source manifest 14499 B /1fc96864278c7b1996aba3fba69bb3293d2c12d952d19bc0e8098fe5424dea90.
- All metadata fields are deterministic: file mode0600, uid/gid0, mtime0, empty uname/gname, gzip filename empty and mtime0.
- The installer writes55 files under ROOT/c1-parent-preparation-02 and separately mirrors the7 exact fixture bodies from that package into ROOT/c1-fixtures-02. The runtime sealed payload remains19Linux+2Mac.
- No profile/ssh_config/known_hosts body is in this transport.

## Staging and one installation

Upload the tar outside ROOT to:
 /home/qian/hepta-runtime-d2-c1-recovery-preparation-02.tar.gz

Upload the exact installer outside ROOT to:
 /home/qian/install_d2_c1_recovery_preparation_02.py

Do not precreate the three guarded destinations:
 ROOT/c1-parent-preparation-02
 ROOT/c1-fixtures-02
 ROOT/c1-preparation-install-02.json

Root's exact command:
 /usr/bin/python3 -B /home/qian/install_d2_c1_recovery_preparation_02.py --archive /home/qian/hepta-runtime-d2-c1-recovery-preparation-02.tar.gz

All tar members, fixed manifest and7fixture mappings are checked before mutation. Both new leaves must be absent. Original8 filesystem helpers and main CLI are unchanged: bounded stable reads, no filesystem extraction, nofollow, owned/private directories, O_EXCL0600 writes, readback and fsync. Partial failures are retained without cleanup or replay. Native upload lock files are outside the new destination leaves.

## Later actual seal and install

After successful preparation installation, root create-only places the existing successful full Q/CI JSON (original Git63a72647e6a920db1d633318e9fd5251792803b1,7538 B /39ee58937fdb05bd97bde4dc7c9ef1033b5744c7d52b6613bc0368f9af54ed63) at ROOT/c1-parent-preparation-inputs-02.json.

The unchanged CLI shape then reads actual Q/CI/ordinary01 and the new fixed seed/fixture identities:
 /usr/bin/python3 -B ROOT/c1-parent-preparation-02/seal_campaign.py --prerequisites ROOT/c1-parent-preparation-inputs-02.json --output ROOT/c1-sealed-02

This preparation has not run that command. Actual sealed manifest, runtime source identities, native installation receipts and holder result remain future. Install the eventual exact19Linux+2Mac package using its actual manifest SHA, finish all transfers, then root alone may run the original holder command from operator-plan.unsealed.json. Preserve every old01 file.

## Static scope

The source package had actual Python AST/byte checks before executor loss. A later Python packing call did not start; the artifact here was built with the documented pure JS USTAR+stored-gzip function, checked against every exact member and bound whole hashes. The new installer subsequently passed a separate Python ast.parse plus original8-helper/main byte comparison. No target module or installer was executed. Source-builder parse-error history is retained separately and is not a runtime failure.

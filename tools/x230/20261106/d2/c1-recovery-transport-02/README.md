# D2 C1 recovery02 preparation transport

This is preparation-only transport. It does not seal actual runtime sources, compile, execute a target helper, launch a holder, or claim a02 result.

## Exact payload

- Standard USTAR + gzip stored DEFLATE blocks: 624708 B / SHA256 6c9298dac0a1ca2633f5b70fab97b0ab64b0e5491e176947501d03288c936de7.
-55 regular source members /571661 B. Source manifest 14932 B /cade99b39f0e5ddfaff207efb50550a0ea58b7cc0ea407663b3d6a332979f613.
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

## Final preparation correction

The previous66-object source/transport catalog e87ffa10e45124dafbac6789443d159959d3ab2d remains the unexecuted first recovery draft. Independent review found its parent monitor-policy attempt literal differed from the retained original JSON. Final parent3d373419528ff1252346161ebae5a353d39612c7 restores only that policy literal to01 while outer attempt02 stays. The final source manifest is 22af08e2b6c878929810ca8801586823d318adcd; source count remains55. The new transport installer differs from064965 only in the three fixed identity declarations, with identical installation control flow. Its8IO helpers and main again passed actual parse-only byte comparison. No source/transport from the rejected draft was uploaded or executed.

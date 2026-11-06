# D1 C1 revision05 — source preparation transport

This is a create-only transport for the frozen unsealed outer source. It does not seal a campaign, import a target module, run a compiler, start a monitor or holder, or claim an ordinary result. The source package contains 43 regular files and 564,059 bytes. Its manifest is 13,228 bytes, SHA256 40693bc863122eff6c554aa18e4c4394e9a6c17a90753b2761deaa920382c38e.

## Exact transport

| Item | Bytes | SHA256 | Git blob |
| --- | ---: | --- | --- |
| c1-parent-preparation-05.tar.gz | 158613 | ad6778f31e7b10caaad3913e8c6368cc09fa6ef6b34c411cdf54a15d8a4e2faf | 61f0c57ab7e00d3b91ada9411d786e6c44881e36 |
| c1-parent-preparation-05.tar.gz.b64 | 211484 | b531f507d1ed0a5eb35dc7ac306b62c5b5b556500431444162ed683c42b07ca7 | f2481ddf173901ed42ce0a1af7f95016aa24370b |
| install_c1_parent_preparation_05.py | 9443 | 166f6f9df734065a6bc9fd1565da3c596de3c4d62c97b295309c87cd12b0af35 | b528256167ffb1e5bb278ad7aaba9982edd20838 |
| transport-manifest.json | 4056 | 59914524efc81465f8f42b0a4e8b317615a8be534cf14d352f15208a5fbce57c | 211e8c1c2bfd8c737b23b97fdc2aa430edf53373 |

The base64 artifact contains no terminal newline. Decode it as bytes and verify the tar identity above. Every listed Git object has actually been created. The source installer verifies the whole compressed archive and every declared member before making any destination.

The source installer retains eight filesystem helpers byte-for-byte from the reviewed sealed-payload installer: need, canonical, identity, stamp, regular, directory, sync_directory and write_new. It requires the original Linux operator UID1000 and a protected, owned ROOT. It uses bounded gzip/tar reads (16MiB total, 4MiB per member, 128 members), regular members only, stable nofollow reads, exclusive new files, readback and file/directory fsync. Its single intended root is:

    /home/qian/hepta-runtime-phase-cost-20261106-d1

## Source-only installation, allowed before ordinary completion

Create only these two new transport files, with the exact bytes above:

    ROOT/c1-parent-preparation-05.tar.gz
    ROOT/install_c1_parent_preparation_05.py

Execute once through the original native job owner:

    /usr/bin/python3 -B ROOT/install_c1_parent_preparation_05.py --archive ROOT/c1-parent-preparation-05.tar.gz

Here and below, ROOT is shorthand for the absolute directory above, not a literal argument. The machine-readable transport-manifest.json contains every fully expanded argv.

This operation creates the 43 files below ROOT/c1-parent-preparation-05 and writes ROOT/c1-preparation-install-05.json. It does not execute packaged source. Existing destination or receipt causes rejection. A partial or unknown outcome preserves all created paths and original native logs; it authorizes no automatic cleanup or replay.

The currently real Q+CI foundation may then be copied byte-for-byte to a new staged input:

    ROOT/c1-parent-preparation-05/actual-prerequisites-01.json

Its exact identity is 5063 bytes / SHA256 9d5ca9b3d4e276d8f7b830cf028eac9eded76ab3b0f560758279451989c966cb / Git f04bea128fd4f3b127ea269c6f7729e2d3a0a4be. It is an external actual input, not one of the 43 frozen source members. It contains Q+CI closure and does not assert ordinary completion.

Keep ROOT/c1-prerequisites-01.json absent until the later sealed-payload installation.

## Actual source seal, only after ordinary closure

seal_campaign.py must run on x230, because its bound readers inspect the actual absolute ROOT source, original qualification/CI/ordinary records and retained release programs. Running it against an unrelated local mirror is not an equivalent seal.

Before this step, the original ordinary02 five-stage job, all its native output pages, and the original readonly verifier job that writes ROOT/ordinary-postflight-02.json must have closed. Root retains that verifier job's original native/read evidence. All compilation and auxiliary owned work must be finished. No ordinary result is filled by this preparation.

Execute once:

    /usr/bin/python3 -I -B ROOT/c1-parent-preparation-05/seal_campaign.py --prerequisites ROOT/c1-parent-preparation-05/actual-prerequisites-01.json --output ROOT/c1-sealed-01

The sealer requires the reviewed verifier at ROOT/ordinary-tools-02/verify_ordinary_02.py, its real ROOT/ordinary-verification-input-02.json and real ROOT/ordinary-postflight-02.json. It rechecks the actual five stages, source maps, Q feature programs and ordinary release programs through the existing pure verifier. It writes fresh sealed payloads and a seal-manifest.json. The actual seal-manifest SHA256 is not known or supplied here.

## Later sealed installation

On x230, using the actual seal-manifest SHA256 produced above:

    /usr/bin/python3 -I -B ROOT/c1-sealed-01/install_campaign.py --sealed-dir ROOT/c1-sealed-01 --manifest-sha256 ACTUAL_SHA256 --target x230

Copy the whole resulting sealed package, preserving its exact bytes, to the fresh Mac staging directory:

    /Users/qianqi/work/hepta-runtime-d1-c1-sealed-staging-01

Then on Mac, with the same actual SHA256:

    /usr/bin/python3 -I -B /Users/qianqi/work/hepta-runtime-d1-c1-sealed-staging-01/install_campaign.py --sealed-dir /Users/qianqi/work/hepta-runtime-d1-c1-sealed-staging-01 --manifest-sha256 ACTUAL_SHA256 --target mac

The fixed Mac destination is /Users/qianqi/work/hepta-runtime-d1-launchers-01. The installer does not start a holder or measurement.

## Unique later holder invocation

After actual ordinary closure and both installation jobs close, root may run the original holder once:

    /usr/bin/python3 -B /Users/qianqi/work/hepta-runtime-d1-launchers-01/held_agent_campaign_02.py --remote-script /Users/qianqi/work/hepta-runtime-d1-launchers-01/d1_campaign.py --out /Users/qianqi/work/hepta-runtime-d1-c1-holder-01 --timeout-seconds 3600

The parent uses the fresh short socket parent /home/qian/hd1c01 and the original 90-second quiet and compiler-monitor workflow. The fixed protocol is C1 only, OFF/ON/ON/OFF, 192 measured and 24 warmup calls per cell with the original six preflight and twelve restart calls per round. Counts are planned protocol, not observed results. The mandatory pre-execution clarification preserves the original driver's measured-failure continuation and rejects the entire stage without successful cost interpretation. This preparation authorizes no C8 expansion, rerun, lifecycle or capacity stage.

## Verification scope and reviews

The local metadata builder parsed the generated installer, checked eight helper bodies, constructed a deterministic archive and compared all 43 member bodies in memory without extracting any path. It never imported or executed the installer, sealer, parent, binder, ordinary verifier, adapter, auditor, monitor or holder; it made no host request.

The independent source review is Git11965cd600d8dbcfdc1dd3b2d497b3b766866ffa (13218 bytes, SHA256 ff0b558b62f4a55151c20ac6a2f866c37533f8628ac0f1696387e45fd867e116).
The independent source-installer review is Git4f17cf94563bbe562a1f2a60e7300f28bd95864f (2700 bytes, SHA256 ecf8654bb7b39ac3c215e8be6038944e1cfa037706660eeadb3239eaa238478c). The reviewer checked source and helper equivalence; the binary tar roundtrip is the builder's separately recorded local check.

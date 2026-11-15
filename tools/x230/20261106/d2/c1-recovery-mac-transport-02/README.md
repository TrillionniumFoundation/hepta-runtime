# D2 C1 recovery02: exact Mac23 transport

This package transports the already sealed recovery02 runtime files. It does not execute the campaign, alter its inputs, or change the original runtime installer. The actual Linux seal is `be4d62eef1e30e9f6c6798998b76b0258257415c` (325264 bytes, SHA256 `a3009f021e4287d45d60099e613e4812ba04f17094b9a500ebe0c590cc7aaebe`). Its 21 files total 371324 bytes: 19 Linux and 2 Mac payloads. Adding the unchanged runtime installer and exact seal manifest produces 23 files and 708990 bytes.

## Inputs and fixed locations

Archive: `d0690bb0f5b677ed43d6fd30a39fa1e75650f8a8`, 737358 bytes, SHA256 `4a9d5af52aba5b030d8206fa0b03b1f5c60dfab5f90caf085ef69d79a80ed263`.
Base64 companion: `1f0eb7620bce6f11e5d265c689cf42e35177b45c`, with one final LF after the base64 text.
Importer: `dc48bdfd5df5ce7daf832c22ccb3cb01e3de3470`, 15014 bytes, SHA256 `c2fa1c88deb8ba446e76f1780bfa184a46d80cd588cd4a34086fbff92e16a1ac`.

Stage the archive at `/Users/qianqi/work/hepta-runtime-d2-c1-sealed-payloads-02.tar.gz` and the importer at `/Users/qianqi/work/hepta-runtime-d2-c1-importer-02.py`. Both remain outside the strict private staging inventory. Create exactly the five owned 0700 staging directories listed in operator-plan.json. They must contain no payload or extra file initially; no upload lock needs an exception.

## Original commands

```text
/usr/bin/python3 -B /Users/qianqi/work/hepta-runtime-d2-c1-importer-02.py
/usr/bin/python3 -B /Users/qianqi/work/hepta-runtime-d2-c1-sealed-staging-02/install_campaign.py --sealed-dir /Users/qianqi/work/hepta-runtime-d2-c1-sealed-staging-02 --target mac --manifest-sha256 a3009f021e4287d45d60099e613e4812ba04f17094b9a500ebe0c590cc7aaebe
```

The original installer reads and checks all 21 runtime payloads and installs only the two Mac programs into the new launchers02 directory. The 19 Linux copies remain staging inputs for its whole-package validation. Do not precreate the new runtime destination or holder output.

The later holder command and formal-lock order are recorded in operator-plan.json. All actual importer, Mac installer, holder, and measurement fields remain null: transport preparation is not execution evidence.

## Exact derivation and limits

The importer is derived from reviewed original `8bf6bd5154826e6da2f4558587f1886a0624468b` using the ten unique replacements recorded in source-edit-ledger.json. Only the 02 names, actual 23-member identity map, archive identity, and two frozen total literals change. The eight other functions are byte-identical; parse_archive and main differ only in the frozen payload total. Full source forward and inverse replacement, Python AST parsing without import, and the actual member-map comparison passed.

The archive uses standard USTAR metadata (regular files, mode0600, uid/gid0, mtime0) and deterministic gzip stored DEFLATE blocks. The reused JavaScript builder verified gzip roundtrip, headers, every exact member body and padding. Its 737280-byte uncompressed tar and 737358-byte gzip satisfy the unchanged limits: archive1MiB, file1MiB, total2MiB, uncompressed tar2MiB+65536. This deliberately requires no filesystem extraction or package execution. The independent source reviewer did not repeat the author's binary-tar check.

Every raw payload is linked by Git identity in transport-manifest.json. The original attempt01 is preserved; no private profile, SSH config, known_hosts, or credential body is included. The source package binds the independently retained D1 private seed through its original path and verified identity, rather than publishing its contents.

All work for this transport was local metadata construction or immutable Git object creation. No host, target importer, runtime installer, parser, auditor, controller, benchmark, or compiler was invoked.

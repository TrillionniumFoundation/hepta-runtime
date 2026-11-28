# Public serial transport: source revision 2

This thin package installs a serial transport update over the exact, immutable public80 package at `bcfe93e2d5dc22dd6a07e3889385a2ade38eb936`. It builds a public81 graph with the same nine tools. The added HIA owner is the retained current SDK shutdown owner in slot 53. Slots 47–52 remain reserved for Batch; slot 54 is reserved for a later fixed get_info integration and is not present in this graph.

The native boundary counts the complete incoming line, including LF, against the current SDK default of 16 MiB. It discards an over-limit line through its newline and resumes at the following line. EOF discards an unterminated trailing message. A complete line loses its terminal CR, then one leading UTF-8 BOM, before entering the existing frontend. These framing changes do not impose a result-output limit.

The serial completion path executes the actual shared shutdown owner for events 1, 2, 4, and 5, validates each complete response, closes the writer descriptor, and then tears down the existing owners. Pending sends and handler children are zero because this graph finishes each synchronous publication before reading the next request. This is not an asynchronous task, future, cancellation, or timeout scheduler.

## Exact sources and independent observations

`INPUTS.json` fixes the compiler, original application, public80 package, retained SDK package, and expected installed source binding. The source checker reads every thin-package file. The installer reads every original public80 source file and creates a fresh output tree; it does not change the input package.

The cache seed Rust entry is also an unchanged source input: `reference/cache-seed/src/main.rs` is the exact 164-byte blob `a2463498c5f622a7706b78098670c66704e27542` from the immutable public80 package. Its original text is preserved, and the complete origin is recorded in `reference/SOURCES.json`. It is only a dependency-fetch seed and is never built or executed.

The original Rust observer is preserved byte for byte from the previously qualified G3 source at `b4054165e9b7be63e9309c8223d04131ec4fe31e`. The recipe selects only its ordinary `async` and `codec-eof` observations. It does not select its service-handler shutdown or receive-cancellation modes. The fresh builder uses Rust 1.95.0, derives an offline fixture lock from the exact target lock, and verifies every retained registry archive and source file.

The finite corpus contains 24 ordinary ping streams. It covers LF, CRLF, whitespace, BOM, Unicode IDs, multiple complete messages, valid EOF tails, and the exact line-length boundary using valid JSON followed by JSON whitespace. Each actual public process has a 60-second limit. The Rust observer has the same external per-process limit and retains its original internal transport deadline.

Four additional Rust observations use `JsonRpcMessageCodec::decode_eof`. Those observations demonstrate that the codec accepts a valid final message without LF and has a different default length policy. They are recorded separately and are not used as the expected behavior of the public AsyncRw-style transport.

## Preserved public regression

The nine-tool qualifier retains its complete workflow and case AST. Only its graph admission assertions change from 80 to 81 images and require the shutdown owner. `PUBLIC_CASE_AST.json` records this identity. The actual four-process domain has 90 responses, 30 retained full filesystem snapshot matches, 12 TextEditor effects, and eight same-session View cache checks. These comparisons preserve the existing eight-route prefix and the ordinary ninth route; they do not compare all current original tool handlers.

The readonly public reader adjusts only the graph count, pack count, build directory, and explicit slot/framing assertions. It checks compiled source, compiler receipts, every image, actual pack bytes, complete process streams, and file snapshots. The combined CI reader adds the exact Rust transport observations and a mutation/child-execution audit, with bytes and metadata snapshots before and after its read.

## Fresh CI recipe

Install the external workflow copy from `ci/workflow.public-transport.yml`. The job retains the 15-minute qualification gate. Its first step writes runtime paths through `GITHUB_ENV`; job-level environment values do not use the runner context. The workflow checks out the immutable public80 and SDK source packages and the pinned Hepta compiler.

Run:

```sh
python3 -I -B <source>/drivers/run_ci.py \
  --source <source> --base-source <public80-package> \
  --sdk-source <retained-sdk-package> --hepta <hepta-checkout> \
  --rust-bin <rust-1.95-bin> --output <fresh-output>
```

The recipe installs the source delta, freshly compiles the retained 62-image baseline and all 81 candidate members, captures the 24 native streams, builds and runs the current Rust observer for all 28 cases, runs the preserved public90 domain, and invokes the independent reader. Its wrapper adds no outer subprocess timeout that could leave an inner process group alive; the original inner deadlines and the workflow's overall job limit remain in force.

The artifact retains the complete thin source, the actual immutable base input, installed graph, HIA build receipts and images, fixture source and lock, checked registry archives, actual Rust executable, all ordinary input bytes, stdout/stderr, and file snapshots. Only the rebuildable Rust target directory is excluded. Every archive member is reread and hashed before upload.

After extracting the artifact, read it without running either implementation:

```sh
python3 -I -B <artifact>/recipe-source/drivers/verify_complete.py \
  --source <artifact>/recipe-source --run <artifact>/run \
  --module-map <artifact>/module-map.json --require-recipe-pass
```

## Development status and boundaries

`DEVELOPMENT.json` distinguishes actual local development from the pending fresh CI qualification. The recovered v1 graph passed four smoke processes and captured 24 framing cases. Two BOM cases exposed the old parser's ordinary compatibility difference. Its source and observations remain unchanged.

Revision 2 passed a new native build, all 24 framing captures, the preserved public90 qualification, and the full native readonly reader. That development build strictly reused 79 known images and compiled two images; it is not a fresh 81-image CI result. Current original Rust comparison remains pending at this source freeze.

An initial revision-2 installation copied the immutable input's read-only file modes and correctly failed on the first edit. The failed copy is retained. The installer now copies bytes into fresh writable output files without changing input modes or bytes.

This package leaves full SDK qualification, all 136 routes, general response ownership, current connection identity, public get_info integration, asynchronous task/future behavior, cancellation timing, production activation, and removal of the old path false. Historical wide-input evidence remains attached to its historical unbounded transport profile. No old expected output is rewritten to represent the new input frame limit.

# Current public83 qualification and default entry

This runner consumes the unchanged 249-file source checkpoint at
`3aada51f16d4604b6d7daa7d79a6b680ef067012`. It installs the actual default
`scripts/hia_native_runtime_mcp_build.py` command and updates only that file's
entry in the source-binding manifest. All HIA, assembly, cases, and individual
readers remain exact checkpoint bytes. The resulting executable is built with
83 fresh member compiles; no prebuilt member is accepted by this CI recipe.

## Commands

The eventual main-tree user build and launch use the same command exercised by
this recipe:

```sh
python3 -I -B scripts/hia_native_runtime_mcp_build.py \
  --hepta /path/to/pinned/Hepta --bootstrap /path/to/verified/bootstrap \
  --output /new/build-directory
/new/build-directory/build/public-connection/runtime-mcp.elf
```

The bootstrap option is required for local development; its exact B3 identity
is checked. CI obtains bootstrap from this invocation's fresh retained62 build.
The builder remains an offline build tool, and the emitted ELF owns stdio and
filesystem operations. The private observation action is not public dispatch.

```sh
python3 -I -B run_ci.py --source /path/to/public_connection_ci --check-only
python3 -I -B run_ci.py --source /path/to/public_connection_ci \
  --sdk-source /path/to/immutable/sdk_target_ci --hepta /path/to/pinned/Hepta \
  --rust-bin /path/to/rust-1.95.0/bin --get-info-reference /path/to/qualified/profile.stdout \
  --output /new/qualification
python3 -I -B verify_complete.py --source /path/to/public_connection_ci \
  --run /new/qualification --require-fresh --require-recipe-pass
```

Full execution is restricted to CI. The job remains 15 minutes. Existing
60-second native/original process limits and 180-second Rust-build step limits
are unchanged. The outer recipe adds no timeout that could leave inner
processes in a different session alive.

## Exact domains

The recipe rebuilds the retained62 comparison graph and current83 graph, then
freshly builds both references against current target `d3d75c30719db966b004756f610007a7c723729e`,
rmcp 3.9.0 and Rust 1.95.0. It retains every ordinary input and complete output:

- 54 actual SDK handshake sessions and all 324 full native/original responses,
  including nine integral-float initialize IDs and all 54 modern-metadata ping
  method-not-found responses. Original peer/context observations are retained.
- 24 actual serial transport cases, plus four separate codec-only original
  observations. The 16 MiB input framing limit includes newline; result-output
  size remains a separate boundary.
- Four ordinary public processes and 90 responses, with full filesystem
  snapshots, 12 TextEditor effects and eight same-session View cache checks.

The independently qualified catalog profile is verifier input only. Its entire
ZIP, selected stdout and selection receipt are retained. No expected wire is
read by any HIA owner or author.

The combined reader rejects writes, metadata changes, subprocesses, ctypes and
mmap after initialization. It checks files and directories before/after, and
executes no native or Rust code. The archive includes empty process working
directories, exact original source, compiler/bootstrap/member artifacts, input
bytes, stdout/stderr, failures and portable module-path mappings. Only the two
explicit Rust build-cache directories are excluded.

## Scope and historical evidence

The current default entry advertises nine implemented routes; TextEditor calls
the actual Local four-command graph. Batch slots 47–52 and context offsets
416/424 remain reserved. Shutdown is slot 53, current fixed get_info is 54,
and actual G2 connection is 55. Protocol metadata and peer capabilities do not
grant caller authentication or owner authority. Existing configuration,
execution, fence, Session, Text caller and cache owners remain their owners.

The historical 58-image builder and its broad original fixtures require their
own pinned test source root. Their successes, including wider historical
inputs, do not qualify current83. This package changes the default entry; the
main installation's separate historical caller patch must be applied before
running the old registry on a checkout containing the new graph.

All full SDK, full 136-route, asynchronous/task/future/cancellation,
production-activation and old-stack-removal claims remain false. Other
non-CallTool methods still pass through the historical protocol after actual
G2 admission. G2 op2 EOF is not connected to the public shutdown owner.

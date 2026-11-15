# Original local-file regex search

This harness compiles unchanged original search, view caller, request-context,
I/O, line identifier and result-gate bodies pinned by source_manifest.json.
The generator supplies independent regex inputs and actual filesystem changes.
It has no expected search results, native parser, or native matching fallback.

One separately counted whole-file call primes the actual session cache. All
other cases pass nonblank content with regex=true. The harness does not execute
the original MCP router, remote paths, directory search or alternative paths.
The literal oracle and its evidence remain unchanged in their own namespace.

run.py creates a fresh target, performs a locked build and retains complete
input, stdout, stderr and process receipts with a strict 180-second deadline.

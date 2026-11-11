# Exact source admission for the native-helper MCP qualification

This companion starts from Runtime
`9a43021137b72316f5345ce660c7f3d00ea93c02` (PR #118) and pins Hepta
`7c20b6cfc792f0147b5418968f94734b8890fcca` (PR #891).

## Defects and resulting behavior

The previous joint entry point checked a cold report's successful status,
budget, nested hash and B3 location without binding its source/profile to the
selected Hepta checkout. Git status alone could also miss assumed-unchanged
source, and `python -B` could still load ignored timestamp-valid bytecode.
An external regular `tools` package could override the selected namespace.

The updated entry point binds the cold and nested reports, support contract,
all declared source bytes, exact Git blobs, actual B3 and both generation
chains before importing the builder. It additionally requires `-I -B`, uses a
new private empty bytecode prefix, rejects preloaded repository modules and
source/package/cache/extension shadows, and fixes the Hepta tools namespace.
The actual client source is also part of the Git-byte inventory. Importable
source is checked again around MCP calls, restart and final reporting.

The Runtime tools directory remains independently inventoried. It is not an
alternative owner for the Hepta tools namespace. The real worker's existing
command, permission and resource contracts are unchanged.

## Retained development evidence

The archive and every member have exact SHA-256/lengths in
`development-manifest.json`. It retains the original exact-Git-client bypass
reproductions, the Python cache and namespace controls, final positive and
negative tests, and the independent review. Read these as data; the archive
contains deliberately adversarial import fixtures for isolated tests.

The final 20-test suite passed without failures, errors or skips. Root and
independent reviews reran overlapping controls; these counts must not be
summed into a unique-test total. The current Hepta source import positive
control binds 904 Python source files, imports the actual builder and worker,
rejects invalid cold input and leaves its private cache empty.

These are source/admission/Python import tests. They do not count as a new
MCP, SSH or native-worker qualification. The changed GitHub workflow retains
this source-control stage separately, runs the existing original cold and
language gates, then executes the real disposable MCP/SSH/native lifecycle
against the exact new source pair. No timeout or proof-domain limit is raised.

## Scope

The selected native identity helper, hosted worker JSON/journal policy and
finite scripted lifecycle keep their existing scope. Production activation,
a completely native worker, unfamiliar-agent learning, performance gains and
arbitrary concurrent privileged source writers are not qualified here.

The earlier report's client digest was independently checked against original
Git blob `4c9c00992757c72b580cd9d964385fe6c5abdceb`. Its 39,042 bytes have
SHA-256 `df14dae2a1b14b52783770e9808c5ce4f2254f10d877411db5a672b56a6d70c8`.
An intermediate text fetch appended one LF. That discrepancy was diagnosed
and does not establish drift in the historical executed client.

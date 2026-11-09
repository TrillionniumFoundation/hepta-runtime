# Saved web observations and JavaScript package declarations

These native Rust routes inspect files already present in an admitted controller
workspace. They do not start a browser, evaluate JavaScript, run a package
manager, fetch a URL, or submit recorded requests to a server. They reuse the
existing descriptor-confined reader and runtime policy; no second daemon,
process supervisor or recovery ledger is introduced.

## HAR capture inspection

`rea_inspect_web_capture` reads a saved HAR 1.2 JSON file. It validates selected
container/request/response declarations, refuses duplicate JSON members, and
returns a paginated inventory with original entry indices, methods, URLs,
recorded status, MIME type, header counts and body-presence facts.

Request and response header values, cookies and body text are not included in
ordinary summaries. Complete request and response identities include those
captured fields; they are hashes of parsed JSON with sorted object keys and
preserved array order, not HTTP wire-byte identities. The source identity is a
SHA-256 of the complete saved file. A continuation requires that source digest.
Exact method, URL and status filters intersect; page offsets count matching
entries and entry indices continue to address the original capture.

The implementation supports at most 8 MiB of input, 10,000 entries, 256 rows per
page and 1 MiB of encoded output. Independent parser work has no runtime count
ceiling; see [concurrent execution](../CONCURRENCY_POLICY.md). An already-running
blocking parse retains its captured input until completion even if its caller
cancels. Resource excess,
malformed selected fields and changed source identity are errors, not empty
successful inventories. This bounded in-process parser is for saved owned
artifacts; it is not an independently sandboxed browser or hostile-file service.

## Comparison

`rea_compare_web_captures` requires both source paths and their complete hashes.
It pairs the first occurrence of an identical complete recorded request with
the first such occurrence in the other capture, then the second with the
second, and so on. Repeated requests are never collapsed into one endpoint.
A changed cookie, header, query, request body or other request declaration makes
a different request identity. The result records added/removed requests and
changed complete response JSON, with provenance back to both source indices.

The comparison is deliberately literal. It does not assert that different
headers represent the same authenticated context, that a response difference
is a server regression, or that temporal pairing proves causal equivalence.
Timing outside the response JSON is not part of this comparison. Results are
ordered by request digest and occurrence, then paginated.

## Offline recorded-response delivery

`rea_replay_web_entry` accepts a pinned capture and an original entry index.
Its replay scope is exactly the selected saved response. It returns the
recorded response metadata and up to 65,536 bytes of its saved content.text
representation, encoded as hex with an exact byte cursor and representation
SHA-256. UTF-8 ranges can split a character because the response contains bytes,
not a potentially corrupted string.

A HAR base64 representation remains base64 text. No base64 decoding, content
decompression, JavaScript evaluation, network access or state-transition
inference occurs. A missing body is unknown and differs from a present empty
string. An invalid body range is refused. Response metadata may contain
sensitive captured headers and is returned only for the explicitly selected
record. This operation is not a general API simulator, an RL environment or a
complete browser-session replay.

The saved source itself is the durable artifact. Reading it after a controller
restart requires the same complete digest and no retained in-memory session.
These routes do not claim to preserve a source that has been deleted or changed.

## JavaScript/Electron package declarations

`rea_inspect_javascript_package` reads one package.json object, bounded to
2 MiB. Collections are `summary`, `entries`, `dependencies` and `scripts`.
Rows preserve JSON-pointer source locations; continuations bind the complete
source SHA-256. At most 10,000 rows per collection, 256 rows per page and 1 MiB
per encoded result are admitted.

The tool reports literal main/module/types/typings/bin/browser/exports/imports
declarations; dependency groups and their literal specifications; and, only
when selected, script names and command strings. An Electron dependency and a
main declaration are observations. They do not prove that Electron is installed,
that an entry file exists, or that a particular preload, renderer or IPC graph
is used. Script strings never execute and referenced paths are never followed.

Export/import leaves preserve JSON pointers and array indices. JSON object
condition order is not retained or evaluated, so the output is an inventory,
not Node package resolution. Empty exports are explicitly distinguished from
an absent exports declaration. The implementation does not claim JavaScript
AST analysis, source-map decoding, ASAR extraction or complete npm validation.

Reference documentation: [npm package.json](https://docs.npmjs.com/cli/v11/configuring-npm/package-json/)
and [Electron application entry declarations](https://www.electronjs.org/docs/latest/tutorial/tutorial-first-app).

## Qualification

Authored offline fixtures exercise duplicate keys, malformed fields, resource
bounds, exact source identities, repeated-request occurrences, missing/empty/
encoded bodies, UTF-8 byte ranges, sensitive-summary omission, package
declaration provenance, literal scripts, filesystem confinement and symlinks.
The external stdio test covers the shipped MCP tool discovery and dispatch,
source-bound replay after a controller restart, comparison and package
inspection with no remote execution host permitted.

Run only with the shared build coordination of this checkout:

```sh
cargo test --locked --all-features --lib rea_web
cargo test --locked --all-features --lib rea_javascript
cargo test --locked --all-features --test rea_web_external
```

Test definitions are not execution receipts. Record the actual exit status and
output before claiming qualification. No full upstream REA behavior parity,
live-browser qualification or production service adoption is implied.

## Native-owned local capture producer

The optional [local browser capture adapter](LOCAL_BROWSER_CAPTURE.md) produces saved HAR from SHA-bound local resources through the existing native job owner and the shared private Chromium lifecycle. Its generated page makes fixed local fetches; supplied JavaScript and HTML remain response data. A live qualification receipt is required before claiming that producer qualified. These saved-file inspection and replay tools keep the contract above, including zero network replay and no browser-state restoration.

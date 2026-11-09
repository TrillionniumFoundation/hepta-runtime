# HeptaRuntime → Kaggle batch adapter

This adapter submits a private Python script or notebook through **official Kaggle SDK request types and the official Kaggle RPC endpoint**. It supports authenticated account and quota discovery, a durable submission ledger, fixed-version status/log reads, verified artifact retrieval, observation-only recovery, and cancellation when the provider has supplied a proven session ID.

The implementation is usable from a CLI or as one JSON tool call per subprocess. It is a transport adapter for HeptaRuntime, not a claim that a particular Hepta tool registry has already been configured. Live acceptance must be established by deployment receipts; unit tests are fault-injection tests, not cloud execution evidence. Interactive Jupyter execution is a separate adapter.

## Read-only submission readiness (0.1.7)

`readiness [--request-id TASK]` verifies authentication and enumerates the full
authenticated owner's notebook profile using the same validator as `submit`.
It does not create a request directory, reserve a notebook, allocate compute,
or send a cloud mutation. The optional request ID is correlation only. A
successful observation means these two prerequisites passed at the observed
time; quota, allocation, and final submission are separate checks. `submit`
always repeats the full preflight against its actual persisted notebook ref.

The JSON result uses schema `hepta-kaggle-readiness-v1`. `ready: false` returns
exit code 4 with a structured `error`. A missing or foreign notebook ref stays
`NOTEBOOK_LIST_SCOPE`; a `[Private Notebook]` placeholder is never silently
removed. Diagnostics include the page/item position, a response hash, and
whether the observed item was redacted, without printing the notebook list.

This release preserves the complete ownership guard. Incomplete or redacted
provider listings remain blocked even when authentication and quota checks pass.
The readiness tests do not establish live allocation or execution success.

## Installation and account

Use the deployment's isolated environment. The reviewed SDK contract is `kagglesdk==0.1.38`; the reviewed official client is `kaggle==2.2.5`. `requirements.in` pins the direct dependencies. Keep the actual environment freeze with the deployment receipt; this repository does not invent a transitive lockfile.

```sh
python3 -m venv ~/.local/share/hepta-kaggle/venv
~/.local/share/hepta-kaggle/venv/bin/python -m pip install -r requirements.in
~/.local/share/hepta-kaggle/venv/bin/kaggle auth login
~/.local/share/hepta-kaggle/venv/bin/python verify_contract.py
~/.local/share/hepta-kaggle/venv/bin/python hepta_kaggle.py capabilities --live
~/.local/share/hepta-kaggle/venv/bin/python hepta_kaggle.py account
~/.local/share/hepta-kaggle/venv/bin/python hepta_kaggle.py quota
~/.local/share/hepta-kaggle/venv/bin/python hepta_kaggle.py notebooks --page-size 20
```

The adapter reuses the official host-local OAuth credential file `~/.kaggle/credentials.json`, refreshing five minutes before expiry. Files must be owned by the current user and mode `0600`. An alternative credential file is configured with the global `--credentials-file` option; tool arguments never contain credential values. Browser cookies are not read. A logged-in browser alone does not create API authorization; finish official OAuth first.

Version 0.1.4 adds the optional global `--expected-username` account guard. Configure it on the trusted host, for example `python hepta_kaggle.py --expected-username example-owner account` or add it before `call` in the Hepta command. The constructor also accepts `KaggleTransport(expected_username="example-owner")`. OAuth/API-token introspection must match the expected account before any business RPC is sent. Cached identities are checked too; a different legacy configured username is rejected before its authentication quota probe. The argument is deliberately unavailable inside chat tool arguments. Omitting it preserves compatibility. Local-only `inspect` checks the recorded account against this guard without fetching credentials or making a network request.

Official API tokens and legacy `kaggle.json` credentials are also supported. OAuth/API-token account identity is verified by `IntrospectToken`. Legacy credentials are deliberately labelled as an authenticated quota request under a configured username; this weaker identity mechanism is not described as token introspection. Quota output preserves the provider's complete raw used/reserved/total/minimum/refresh fields. It does not assume that `total - used` is available capacity.

### Permission and write-effect boundaries

Different RPCs require their official account and resource permissions. A 403
response for a nonexistent reference is not proof of absence. A dispatched
write that receives an HTTP error may have partial remote effects; preserve
its original identity and reconcile it instead of resubmitting. Permission
changes belong to the explicit official OAuth flow. The adapter never adds
scopes or retries a rejected cloud write automatically.

Version 0.1.3 introduced failed-RPC diagnostics without exposing upstream messages; 0.1.4 preserves them. The transport reads at most 64 KiB from an HTTP error and returns only a bounded numeric `api_error_code`, a recognized RPC `api_error_status`, and an exact permission name from one of two strict message forms. `Required permission 'X' was not satisfied` produces `required_permission`; `Permission 'X' was denied` produces `denied_permission`. `rpc_action` identifies the local operation. The error body, headers, URLs, tokens and all other fields remain excluded. HTTP status codes are not changed, and 0.1.4 separately treats the remote effects of a dispatched failed write as unknown.

## One private, bounded task

```sh
python hepta_kaggle.py submit --request-id cpu-proof-001 --source cpu_smoke.py --timeout 120
python hepta_kaggle.py status --request-id cpu-proof-001
python hepta_kaggle.py wait --request-id cpu-proof-001 --wait-seconds 30
python hepta_kaggle.py logs --request-id cpu-proof-001 --limit 16384
python hepta_kaggle.py artifacts --request-id cpu-proof-001 --manifest-name artifact-manifest.json
python hepta_kaggle.py resume --request-id cpu-proof-001
```

Submission always sets private visibility. Internet is disabled unless `--internet` is supplied. CPU is the default. `--accelerator` accepts an actual Kaggle machine-shape identifier; the server decides eligibility and availability. The adapter does not substitute a different accelerator or interpret a request flag as proof that a device was assigned. A workload must inspect its actual device, complete a bounded operation on it, and record its results to pass an accelerator acceptance test.

Python scripts and `.ipynb` notebooks are supported. A source file is limited to 2 MiB. Notebook code-cell outputs are cleared and cell source lists are normalized before hashing/submission. Dataset, notebook, model and competition inputs can be repeated with `--dataset-source`, `--kernel-source`, `--model-source`, `--competition-source`. The remote runtime limit is 1–43,200 seconds; use short limits for integration checks.

### Identity and retry behavior

`request_id` is a caller-supplied stable identifier. The ledger binds it to the SHA-256 of normalized source, input references, visibility, accelerator, internet and runtime settings. A second submit using the same identifier returns the existing record without another cloud submission. Changed code/settings under the same identifier fail with `IDEMPOTENCY_CONFLICT`.

Before a new submission, version 0.1.2 generates and durably records a random request nonce and uses a 96-bit suffix in the notebook slug. It enumerates the authenticated account's complete `ListKernels(PROFILE)` listing, explicitly selecting `language=all`, `kernel_type=all`, `output_type=all` with pages of 100. Every page must succeed and confirm owned references. A matching target reference, repeated page token/reference, malformed page, or failure to reach the final page within the bounded scan rejects the request before `SaveKernel`. Failed preflight requests remain rejected and are never replayed under the same request ID.

The new reference is deliberately not probed with `GetKernel`: live Kaggle behavior can return permission-denied for a nonexistent notebook, so 403 is not evidence of absence. Reading an already submitted notebook still requires the applicable `kernels.get` and `users.get` authorization. The full owner listing plus random persisted suffix reduces accidental collisions, but the reviewed API does not provide an atomic conditional-create operation. Another actor can theoretically create the same reference between enumeration and submission; no global uniqueness guarantee is claimed.

The adapter persists intent before the only `SaveKernel` attempt. A lost acknowledgement, interrupt or ambiguous response leaves `UNKNOWN`. Such a request is never automatically submitted again. `resume` restores an unbound original version only from a durable, create-only `SaveKernel` response receipt containing the exact reference, notebook ID and version. It then verifies source/private visibility and observes that precise `v<N>` version. If the acknowledgement was never durably recorded, a same-source notebook—even its first visible version—is only a candidate and the request stays `UNKNOWN`. A later same-source version is never adopted as the original execution. A 404 during recovery leaves the request unknown; absence in one observation is not permission to replay. There is no provider-side idempotency key in the reviewed API, so these safeguards are described as local duplicate prevention, not global exactly-once execution.

Version 0.1.5 accepts the two observed `SaveKernel.ref` representations only when they exactly identify the intended notebook: `owner/slug` and `/code/owner/slug`. It does not accept a full URL, query, fragment, encoded path, extra path segment, alternate owner or any other normalization. The original raw ACK stays immutable. Both new submissions and durable-ACK recovery use this same strict check. This permits recovery of a successfully acknowledged execution such as CPU08 without a new `SaveKernel` call. The ACK's original version is pinned even if the current latest version has identical code.

Starting with 0.1.4, **every HTTP error from a dispatched mutating RPC, including 4xx, has `remote_effect_unknown: true`**. `SaveKernel` failures after dispatch leave the ledger `UNKNOWN`; a 403 describes an HTTP authorization rejection, not a guaranteed transaction rollback. The same conservative rule applies to a provider error response that lacks a reliable successful notebook identity. No write is replayed automatically.

The independent `remote_submission_state` field distinguishes `NOT_SENT` (local preflight failed before submission dispatch), `MAY_HAVE_BEEN_SENT` (persisted before the attempt; remote effect is unconfirmed), and `ACKNOWLEDGED` (the intended reference, numeric notebook ID and exact version were returned reliably). It deliberately does not claim that bytes reached the server merely because dispatch began. Historical 0.1.0–0.1.3 post-dispatch `REJECTED` records, including integration attempts 03–06 where applicable, cannot establish that no draft/object/version was created. Their stored evidence is retained, but public receipts add `effective_submission_state: UNKNOWN`, a historical explanation, and a corrected effect-uncertainty indicator. A historical preflight rejection with no submission-dispatch event remains `NOT_SENT`. None of these interpretations permits a duplicate submission.

Each request has its own nonblocking cross-process lock. State JSON is replaced atomically with fsync. Event receipts are create-only and survive an interruption between event publication and ledger update. The default state directory is `~/.local/state/hepta-kaggle`; keep it durable. Changing or deleting the ledger removes local duplicate prevention. Do not manually delete an unknown request to retry it.

Notebook reference, notebook ID, notebook version and Kaggle session ID are distinct. Every status, output and log call uses the recorded `v<N>` label. The adapter never substitutes the current latest version. Ledger entries are also bound to the verified account and the original numeric notebook ID. Status, logs and artifact acceptance verify that ID through the pinned source endpoint, rejecting a deleted-and-recreated notebook even if its reference and source are identical.

### Logs and artifact proofs

`logs` uses the official fixed-version output endpoint. It preserves raw log snapshots in the private ledger and returns bounded redacted text. Its cursor is `generation:byte_offset`; if the remote log is replaced rather than appended, old cursors fail with `LOG_REPLACED`. This is snapshot polling, not a claim of live streaming.

`artifacts` requires an already completed execution, verifies source identity/private visibility, paginates both the provider size and URL lists using the same exact version, and requires identical file names. It downloads anonymously through validated HTTPS storage hosts, never forwarding API credentials to signed links or redirects. Traversal, absolute paths, duplicate names, partial downloads and output-budget excesses are rejected. Downloaded files are independently rehashed, then atomically published with a durable receipt containing each file's byte count and SHA-256. A crash after folder publication can recover from that receipt without downloading or executing again.

For end-to-end content verification, have the workload write a manifest with this exact shape:

```json
{
  "schema": "hepta-artifact-manifest-v1",
  "request_id": "cpu-proof-001",
  "files": [
    {"path": "result.json", "bytes": 123, "sha256": "the-actual-64-digit-sha256"}
  ]
}
```

The manifest must enumerate **every downloaded output except the manifest itself**. The request ID must match. Invoke `artifacts --manifest-name artifact-manifest.json` to require this check. Subsequent retrieval rehashes existing local files; changed bytes fail. The reserved local receipt name `.hepta-download-receipt.json` cannot be an output file.

Version 0.1.6 downloads the required manifest first and verifies an explicit HTTP `Content-Length` against its actual bytes, retaining its local SHA-256. It validates the manifest schema, request ID, complete fixed-version file-name coverage, integer byte counts and SHA-256 values before downloading payloads. Each payload must then match both the manifest's byte count/SHA-256 and its own HTTP `Content-Length`. Missing HTTP lengths, truncated data, incomplete coverage or any payload hash/size mismatch fail before publication. The total actual/manifest byte budget remains enforced. The manifest itself cannot self-authenticate its own hash; its receipt records HTTP size and local hash, while the fixed-version provider response and verified source establish the execution binding.

Live CPU08 returned provider `ListKernelFiles.size` values 920/887 for manifest/result files whose HTTP and actual sizes were 213/197. The execution-generated manifest declared 197 payload bytes and its SHA-256 matched the downloaded result. The reviewed official SDK and [official MCP response schema](https://www.kaggle.com/docs/mcp) only document `size` as an integer/int64; they do not explain this discrepancy or specify an alternate encrypted/wrapped size conversion. The adapter therefore does not invent a correction formula or claim those provider sizes matched.

In manifest mode, every file receipt preserves `provider_list_size`, `provider_size_matches`, `http_content_length`, `http_content_length_verified`, actual `bytes` and `sha256`. A mismatch produces an explicit `PROVIDER_SIZE_CONFLICT` warning and `provider_sizes_all_match: false`, while acceptance rests on the verified execution manifest and HTTP bytes. Without `--manifest-name`, provider size is still mandatory and any mismatch fails. Reusing a conflicted download also requires explicitly selecting the manifest. Old receipts lacking HTTP-length evidence cannot silently upgrade to the new manifest-and-HTTP proof policy.

Default total artifact budget is 1 GiB; `--max-bytes` may set 1 byte–64 GiB. Individual RPC bodies are bounded to 16 MiB. The adapter does not extract untrusted archives. Signed query strings and known credentials are redacted from tool results and ledger events. Version 0.1.5 additionally treats the entire path of Kaggleusercontent and Google Storage URLs as a credential-bearing capability: actual Kaggle output URLs can contain a five-part JWE in the path with no query string. Public logs, receipts and future event files retain only the storage hostname and a redaction marker. Internal downloads still use the original URL in memory. Raw diagnostic outputs containing signed URLs must not be included in a delivery bundle.

### Cancellation

```sh
python hepta_kaggle.py cancel --request-id cpu-proof-001 --wait-seconds 30
```

The reviewed `SaveKernel` schema returns a notebook ID/version but does **not document a session ID**. The adapter only binds an explicit `kernelSessionId`/`kernel_session_id` or `kernelSession.id` from the raw, identity-associated official response. If no such field is returned, cancellation fails safely with `SESSION_IDENTITY_UNPROVEN`. It never uses notebook version as a session ID, and it does not infer that a local process interrupt stopped cloud compute.

When an ID is proven, cancellation intent is persisted, the official cancellation method is sent once, and the same version is observed. `remote_stop_confirmed` is true only after `CANCEL_ACKNOWLEDGED`. An accepted cancel RPC or `CANCEL_REQUESTED` state remains pending. Repeating an uncertain/acknowledged cancellation observes rather than replaying the write. A task that had already completed is reported complete, not incorrectly called canceled. Independently establish the real provider session mapping and remote terminal transition to pass cloud cancellation acceptance.

## Hepta tool integration

`adapter_manifest.json` describes 12 `kaggle_*` tools and their JSON schemas. Configure Hepta to invoke the following trusted-host command for each tool call, writing the request JSON to stdin:

```sh
/home/operator/.local/share/hepta-kaggle/venv/bin/python /absolute/release/hepta_kaggle.py --state-dir /home/operator/.local/state/hepta-kaggle call
```

Input:

```json
{"tool":"kaggle_status","arguments":{"request_id":"cpu-proof-001"}}
```

Output is one JSON object on stdout:

```json
{"ok":true,"result":{"request_id":"cpu-proof-001","remote_state":"COMPLETE"}}
```

The example result is abbreviated, not a real receipt. `ok` means the operation returned a structured result; acceptance also depends on result fields and process exit status. Exit 0 means the operation's completion criteria were met, 1 means an adapter/protocol error, 3 means an authorization error, 4 means a submission/compute/cancellation acceptance condition remains unsatisfied, and 130 means local observation was interrupted. `cancel` uses exit 4 until the cloud cancellation terminal state is observed. `capabilities --live` includes authorization errors in its capability result instead of failing discovery.

Credential and state locations are host configuration, not tool arguments. `submit.source` must be a source file already prepared on that host. The bridge must preserve the caller's request ID and the durable state directory. A registered tool is not live-verified solely because the manifest exists; each `cloud_verified` field initially remains false. Record real calls through the deployed Hepta execution path to establish integration evidence.

## Verification and maintenance

```sh
python -m unittest discover -s tests -v
python verify_contract.py
```

Fault tests cover lost submission acknowledgement, exact-version recovery, source/account mismatch, cross-process locking, uncertain cancellation, refusal to guess session IDs, path traversal, credential-bearing redirects, partial files, SHA mismatch, publish-before-ledger crashes, log replacement and typed tool-call boundaries. `verify_contract.py` additionally checks serialization against the installed official SDK without making a network request or reading credentials. A clean contract check and unit tests are prerequisites for real cloud tests, not replacements for them.

The transport protocol exposed to `KaggleAdapter` is `account() -> dict`, `call(action, values, mutation=False) -> dict` and `download(url, path, expected_size, max_bytes, require_content_length=False) -> {bytes,sha256,http_content_length,http_content_length_verified}`. Tests inject a fake implementation to create failures at the effect/acknowledgement boundary. Production uses the official SDK classes to serialize requests and a bounded standard-library HTTP transport. Authenticated RPC redirects are refused; mutating calls are single-attempt. Request-specific filesystem reads/writes remain private to the current OS account.

Official source reviewed:

- [SDK generated kernels service, pinned snapshot](https://github.com/Kaggle/kaggle-sdk-python/blob/46efde203816039e34205bb6cd62ad57d946c25a/kagglesdk/kernels/services/kernels_api_service.py)
- [SDK request/response types, same snapshot](https://github.com/Kaggle/kaggle-sdk-python/blob/46efde203816039e34205bb6cd62ad57d946c25a/kagglesdk/kernels/types/kernels_api_service.py)
- [Official Kaggle CLI](https://github.com/Kaggle/kaggle-cli)
- [Official Kaggle MCP endpoint](https://www.kaggle.com/mcp)

The adapter does not rely on notebook editor internals, cookie extraction, an undocumented cancellation route, or a fabricated session/version equivalence. Source-review downloads are development intermediates and are excluded from the release bundle.

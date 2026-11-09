# Hepta Compute Router 0.1.0

Runs on a configured Linux compute worker. The controller calls the installed
`hepta-compute` executable through HeptaRuntime. Credentials remain with the
existing private account launchers on that worker.

## CLI

```text
hepta-compute evaluate [--provider {kaggle,colab}] [--account ALIAS]
                      [--accelerator {T4,cpu}] [--timeout SECONDS] [--json]
hepta-compute plan --request-id ID --source /absolute/task.py
                  [--provider {kaggle,colab}] [--account ALIAS]
                  [--accelerator {T4,cpu}] [--timeout SECONDS]
                  [--artifact relative-name ...] [--json]
hepta-compute execute --request-id ID
hepta-compute inspect --request-id ID
hepta-compute collect --request-id ID [--max-bytes BYTES]
```

All output is JSON. Global `--state-dir ABS` precedes the command; default
`~/.local/state/hepta-compute`. Reconnect to the same controller state.
Timeout defaults to 120 seconds, range 1–43,200. Collection defaults to 64 MiB,
maximum 1 GiB. Source must be an absolute Python file.

Provider constraints are checked before allocation. The current Colab profile
allows at most 600 seconds, 262,144 UTF-8 source bytes, and 32 artifacts;
`stdout` and `stderr` are reserved names. Artifact paths must be relative, at
most 512 UTF-8 bytes, with no NUL, empty segment, or traversal component.

## Guarantees and boundaries

- Six configured provider/account pairs are evaluated concurrently; each account
  is serialized across processes. Colab requires eligibility, provisioning and
  profile readiness. Kaggle requires quota and complete notebook ownership.
- Supported choices are T4 and CPU, standard Colab shape. Kaggle T4 maps to
  NvidiaTeslaT4. Existing Colab runtimes require explicit binding and are not
  automatically adopted. Ready permits an attempt, not guaranteed hardware.
- Stable preference: Kaggle then Colab; configured default account first,
  then other aliases lexically. Explicit filters
  narrow candidates. Quotas are never aggregated and a request never rotates.
- Plan freezes source SHA-256, parameters, account and authenticated identity
  hash. Before new effects the identity is checked again. Plans contain no tokens
  or account email. Atomic reservations prevent simultaneous duplicate claims.
- Only unexecuted plans expire after 15 minutes. Started/unknown/uncollected
  effects retain their reservations. Changed intent under one ID is rejected.
- Execution claims the reservation transactionally as PREPARING before any
  authentication network call. An expired or terminal plan cannot be revived.
  After a crash with no effect started, the same request can inspect PREPARING
  and resume under its original binding. Pre-effect auth failure records its
  cause and restores the original plan lease without renewing it.
- Kaggle is private with internet disabled. Colab's adapter has no network-disable
  switch; receipts record provider_default rather than promising isolation.
- Durable intent precedes mutation. Known finished stages may advance to an
  unstarted next stage, but uncertain effects are never replayed. Inspect uses
  original IDs. A local process timeout is not cloud completion.
- Unknown Kaggle submissions use the adapter's read-only `resume` with the
  original request ID. Durable SaveKernel responses can restore the exact
  original execution; missing evidence remains unknown. Submission is not replayed.
- Official Colab HTTP 412 with owned_runtime=false is a definite rejection;
  refusal_http_status/refusal_source are retained. Old unknowns stay unknown.
- Collection checks terminal identity, all log pages, UTF-8 bytes, artifact
  manifests, lengths and hashes. It retains evidence before releasing only the
  task-owned Colab runtime. Unknown release is reconciled under the original key.
  Retained evidence is rechecked locally if the released runtime is unreachable.
- Task files use `outputs/artifacts`, logs use `outputs/logs`, and the controller
  receipt is `outputs/router-receipt.json`; task names cannot overwrite evidence.
- If computation stopped but output retrieval or integrity checks fail, retain
  the runtime and reservation so the original request can retry collection.
  No command silently discards potentially unique results.
- A failed allocation workflow with no run intent can close an owned runtime
  only after the original ledger proves it was never dispatched. Original-key
  lookup checks the complete task intent and runner/profile identity. Queued
  jobs require an observed local-only cancellation; unknown cancellation is
  not replayed. Unknown cleanup only reconciles the original allocation key.
  CLEANED_NOT_EXECUTED reports compute_succeeded=false and contains no fabricated
  task artifacts. Missing ledgers or any run intent block this cleanup path.
- COLLECTED is a lifecycle state, not GPU proof. Outcome separately reports
  provider state, compute_succeeded, requested accelerator and the need for
  actual task-specific CUDA/device/computation evidence.

Requires Kaggle batch 0.1.7 readiness and Colab v4 readiness/provision-key support,
including `run inspect-key --key KEY` and `manage close-unstarted --key KEY`.
Colab v4 initializes the fixed jobs ledger before the first kernel mutation or
profile publication. A missing ledger on an already bound profile remains a
blocker and is never recreated as empty evidence.
Run `python3 -m unittest -v test_hepta_compute.py`. These local regression tests
do not submit cloud work. Live readiness and GPU acceptance remain separate.

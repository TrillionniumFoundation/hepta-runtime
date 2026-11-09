# Hepta cloud compute adapters

This directory contains compute router 0.1.1, the Colab scoped-profile adapter
v5, and Kaggle batch adapter 0.1.8 as a standalone Python toolchain.
A HeptaRuntime controller invokes the installed entry points on a configured
Linux worker. Provider credentials remain in the worker's existing private
account stores.

| Component | Directory | Main responsibility |
| --- | --- | --- |
| Router 0.1.1 | `router` | Durable request binding, resource ownership, collection and cleanup |
| Colab scoped profiles v5 | `colab` | Account-scoped runtime jobs and immutable runner compatibility |
| Kaggle batch 0.1.8 | `kaggle` | Exact notebook-version jobs and bounded artifact retrieval |

These suites test state, concurrency, identity, recovery and artifact integrity
with local fixtures. They submit no cloud workloads. Readiness, actual GPU
computation, output retrieval and runtime release require separate live evidence.
In particular, Kaggle's opaque notebook ownership responses remain blocked in
this release; quota or a passing unit suite does not override that guard.

## Run the offline suites

Use Python 3.12 or newer on Linux. The following tests need only the standard
library; the official provider SDKs are loaded lazily by live operations.

```sh
cd tools/cloud-compute/router
python3 -B -m unittest -v test_hepta_compute.py
cd ../colab
python3 -B -m unittest discover -s . -p 'test_*.py' -v
cd ../kaggle
python3 -B -m unittest discover -s tests -v
```

The separate Cloud Compute Offline Tests workflow runs these exact three suites
without provider credentials. The repository's existing Rust checks retain
their own scope and results.

## Install on a worker

Keep the source and executable launchers in private, versioned release
directories. Review the component READMEs and install each provider's pinned
dependencies in its own virtual environment before configuring real accounts.
The Colab SDK is pinned to an official source commit; Kaggle direct dependencies
are pinned in `kaggle/requirements.in`. This source publication does not modify
an existing installation, credential store or job ledger.

The router expects `~/.local/bin/hepta-colab-account` and
`~/.local/bin/hepta-kaggle-account`. Use fixed absolute release paths and the
provider's virtual-environment interpreter in installed launchers; keep each
`account_launcher.py` with its corresponding component modules. The Kaggle
launcher expects its batch source at
`~/.local/share/hepta-kaggle/releases/batch-0.1.8`.
Its session and interactive modes refer to separately installed adapters and
are outside this batch-only source publication.

For Colab upgrades, retain the complete old release and use the release
dispatcher described in the Colab README. The original job ledger binds each
job to its runner SHA-256. A new runner belongs in a new release; replacing the
old file in place would invalidate existing queued jobs and original-key
recovery. The dispatcher selects an explicitly trusted release from that
immutable hash and starts its original account launcher in a fresh process.
It rejects unknown runner identities instead of rewriting the job's intent.

The router's `hepta-compute` entry point runs its colocated `hepta_compute.py`.
Install the pair together in a versioned release and expose a launcher from
`~/.local/bin`. A controller should pass the installed absolute executable path,
an argv array and a stable Hepta operation key.

Each provider reads `~/.config/hepta-PROVIDER/accounts.json`. The router reads
the same account map and its optional `default_account` value. A minimal shape
is shown below; `account-a` is a fictional alias, and all paths and identity
values must be replaced by the operator's private verified configuration.
No tokens belong in this file or in task source.

```json
{
  "default_account": "account-a",
  "accounts": {
    "account-a": {
      "provider_specific_fields": "See the table below"
    }
  }
}
```

| Provider | Required per-account fields |
| --- | --- |
| Colab | `email`, `keyring_service`, `state_dir`, `profile`; `chrome_profile` for explicit browser authorization; optional `quota_project` |
| Kaggle batch | `username`, `credentials_file`, `batch_state_dir` |

State and credential directories must be owned by the worker's current user
and private. Existing sessions and requests retain their original provider,
account, state directory, profile, runtime, kernel and version. A new checkout
or new default account must never redirect an old request.

## Routing and recovery

Start with `hepta-compute evaluate`, then create a bounded plan using a stable
`--request-id`, absolute Python source, device requirement, timeout and declared
artifacts. The supported device choices are `T4` and `cpu`. The plan binds a
single provider/account and actual authenticated identity hash before effects.
Default priority is Kaggle, then Colab; within each provider, the configured
default precedes the remaining aliases in lexical order.

Use `execute`, `inspect` and `collect` with the original request ID. An uncertain
submission or release retains its reservation and identity. It is reconciled,
not replayed or moved to another account. Account quotas are not combined.
Resources reported as eligible are not guaranteed allocations.

Collection verifies the provider's terminal identity, log bytes and artifact
manifests, retains results, then releases only a runtime owned by that task.
`COLLECTED` describes lifecycle completion; the separate outcome reports
whether computation succeeded. GPU success requires task-specific device and
arithmetic evidence. A never-dispatched allocation may instead finish as
`CLEANED_NOT_EXECUTED`, which reports no computation success.

## Review fixes and compatibility

Router 0.1.1 checks task ownership before binding a newly returned or recovered
Colab allocation. If a runtime appears after planning and the provider returns
it as externally owned, the router does not execute work on it or release it.
It releases only its local reservation when the original allocation receipt
proves there were no allocation, binding or dispatch attempts. Ambiguous
ownership or prior effects keep the original reservation for reconciliation.

Kaggle 0.1.8 applies the caller's current artifact byte budget to retained
results as well as fresh downloads. It checks recorded totals before hashing
and bounds reads of files that grow during verification.

Colab v5 checks final stdout and stderr sizes after the process group stops,
including programs that exit before the polling loop observes their output.
Existing jobs retain their original runner and release; new jobs use the
updated runner. The compatibility dispatcher preserves the original account,
profile and job validation performed by the selected release.

## Publication provenance

`SOURCE-MANIFEST.json` records the accepted baseline, initial public source and
current public-source hashes. The original baseline versions were router
0.1.0, Colab scoped profiles v4 and Kaggle batch 0.1.7. The initial publication
made these portability and privacy changes to executable code:

- Derive launcher configuration roots from the current home directory and the
  Linux keyring session path from the current UID.
- Accept aliases from the existing private account map instead of a fixed
  deployment-specific list; identity override guards remain intact.
- Use configured default and lexical account order, removing a personal alias
  preference from the router.
- Resolve the portable router entry point relative to its colocated source.

Tests use fictional aliases. Documentation uses example identities and paths;
the Colab dependency snapshot uses the official pinned Git URL instead of a
machine-local SDK checkout. Obsolete deployment manifests, live account
observations, task logs, runtime profiles and credentials are excluded.
The current source additionally includes the explicit review fixes and runner
compatibility described above. The manifest distinguishes those changes from
the initial packaging and identifies newly added tests and dispatcher files.
It does not imply that passing offline tests establishes live provider access
or accelerator availability.

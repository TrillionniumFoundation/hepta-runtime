# Hepta cloud compute adapters

This directory publishes the accepted compute router 0.1.0, Colab scoped-profile
adapter v4, and Kaggle batch adapter 0.1.7 as a standalone Python toolchain.
A HeptaRuntime controller invokes the installed entry points on a configured
Linux worker. Provider credentials remain in the worker's existing private
account stores.

| Component | Directory | Offline regression suite |
| --- | --- | --- |
| Router 0.1.0 | `router` | 40 tests |
| Colab scoped profiles v4 | `colab` | 31 tests |
| Kaggle batch 0.1.7 | `kaggle` | 72 tests |

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
python3 -B -m unittest -v test_scoped_profiles.py test_cleanup_unstarted.py test_bind_ledger.py
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
`~/.local/bin/hepta-kaggle-account`. Each should launch its corresponding
`account_launcher.py` with that provider's virtual-environment interpreter.
Use a fixed absolute release path in the installed launcher; keep the actual
Python file in the same directory as the other component modules. The Kaggle
launcher expects its batch source at
`~/.local/share/hepta-kaggle/releases/batch-0.1.7`.
Its session and interactive modes refer to separately installed adapters and
are outside this batch-only source publication.

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

## Publication provenance

`SOURCE-MANIFEST.json` records each included file's accepted-release hash and
its public-source hash. Public packaging makes only these portability/privacy
changes to executable code:

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
The provider state machines, unknown-effect handling, ownership checks,
artifact verification and cleanup proofs remain the accepted release logic.

This publication contains only the three accepted component versions above.

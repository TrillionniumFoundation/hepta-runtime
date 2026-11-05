# X230 R20–R21 evidence and rejected candidate

R21 passed its fresh eight-stage qualification and the six-host correctness,
capacity, cancellation and recovery checks. It failed the unchanged native
performance screen: C1 throughput −12.2922%, C1 p95 +37.1637%, and C8 p95
+18.2526%. The source candidate is **not adopted**. The repository keeps the
accepted R19 compiled source from `acdd07363cbff335e50c2944e02143d44ab03d6b`.

The [Chinese report](../../../../docs/X230_OPTIMIZATION_20261105_R21.md)
explains component measurements, controls, all native pair directions, lifecycle
costs, resource scope and the rejection. [evidence-identities.json](evidence-identities.json)
binds selected repository paths to complete byte counts, SHA256 and Git blob
identities. [publication-selector.json](publication-selector.json) closes the
selected files and the separate local review inventory.

## Source identities

| Role | `jobs.rs` SHA256 | Status |
|---|---|---|
| R19 accepted source | `c9080de8aa9a35f7495aa2822a1495d297903900ae0f0de26d7b0c86d043d3c9` | Preserved |
| R20 STATUS-only intermediate | `2f751c09a9a29bebb0cda0a9bd2bb522d145ee8183740ed1442d77666ee44aa7` | Qualified; no formal six-host campaign run |
| R21 STATUS + CANCEL candidate | `1f1f086e3bc0fc62184ed51949964e1f82e337b87d330225097ae38722e4ac8c` | Qualified; rejected by native performance gate |

The [production diff](production.diff) is the **unadopted** 7-insertion,
2-deletion candidate. It is retained for review, not applied to `src` by this
publication. The [component chain](component-chain-01.json) preserves the two
actual source steps; STATUS was tested against the R20 intermediate and must
not be relabelled as a direct test of final R21 source.

The [qualified candidate source proof](reviews/qualified-source-binding-01.json)
binds 219 compilation inputs and the candidate `src` tree
`5f814d4faa80b87cfb3a34ca38275664444c0883`. The source retained in the repository
has the different accepted R19 tree `3aa8c9aadbf42b6a0ebdac3954bd1e64b4055e20`.
Qualification does not itself imply adoption.

## Original evidence packages

All paths in this table are relative to this directory. Original archives are
preserved without expanding thousands of members into Git.

| Archive | Payload / total members | Scope |
|---|---:|---|
| [R20 qualification](../r20/evidence/qualification-01.tar.gz) | 3,362 / 3,363 | Intermediate fresh build and complete raw tests |
| [STATUS cold processes](../r20/evidence/coldprocess-01.tar.gz) | 840 / 840 | Fresh-helper semantics, controls and ABBA |
| [CANCEL processes](../r20/evidence/cancelprocess-01.tar.gz) | 1,922 / 1,923 | Helpers, 66 owned targets and all raw outcomes |
| [4 KiB hash buffer](../r20/evidence/request-hash-4096-01.tar.gz) | 332 / 333 | Rejected component and complete raw results |
| [64 B hash buffer](../r20/evidence/request-hash-64-01.tar.gz) | 332 / 333 | Rejected follow-up and complete raw results |
| [R21 qualification](evidence/qualification-01.tar.gz) | 3,364 / 3,365 | Final candidate, eight stages, raw tests and source bindings |
| [R21 six-host campaign](evidence/campaign-01.tar.gz) | 5,379 / 5,380 | All four raw trees, transport, phases, original audits and pinned inputs |
| [Mac holder](evidence/holder-01.tar.gz) | 28 / 29 | Actual holder/bootstrap, original logs, receipts and cleanup observations |
| [Local reviews](evidence/local-review-01.tar.gz) | Exact embedded inventory | Development failures, transport receipts, offline reviews and orchestration |

The STATUS package has **no embedded manifest**. Its original
[external manifest](../r20/evidence/coldprocess-01.manifest.json) is mandatory.
Every other raw package carries its original embedded manifest. ELF bodies,
compiler objects, private keys and SSH agent sockets are not packaged. The
eight qualification and nine campaign ELF omissions carry complete remote
file SHA256 witnesses and accepted path/size bindings. They are not described
as locally rehashed ELF bodies.

## Reproduce the six-host analysis offline

The frozen [replay tool](evidence-tools/replay_campaign_01.py) first validates the
entire archive and every member, then invokes seven original analysis entries:
native, boundary, four lifecycle recovery audits, and the lifecycle summarizer.
It does not run a workload, compiler, runtime or SSH command. Use fresh output
directories; originals and failed attempts are never overwritten.

From this directory:

```sh
python3 -B evidence-tools/replay_campaign_01.py \
  --archive evidence/campaign-01.tar.gz \
  --expected-archive-sha256 f899f7a4140154db2bf74641c9e64d768852b9b072ca67c5a8d3ab50648c1b26 \
  --expected-manifest-sha256 3317d1cc0fbe9c264dc7969e58061dfc8dc635569e3ecafe3754b538a52ba8fd \
  --expected-campaign-report-sha256 d4f7fbe92f16aaa6a16c9ed4dc11d522dcb7ebadc29234db7c6096b63819bb4c \
  --expected-candidate-sha256 7709579269d5c7ec1eba8512dd7cc028ecc602c08156f8172a15203080e39878 \
  --extract-root /tmp/hepta-r21-evidence-extract \
  --output-root /tmp/hepta-r21-evidence-replay
```

The [replay result](reviews/offline-campaign-replay-01.json) and
[final orchestration](reviews/orchestration-final-01.json) keep correctness,
raw consistency, performance screening and adoption as separate fields. A
successful evidence replay must preserve `native_regression_screen_passed=false`.

## Qualification and other review tools

[audit_r21_qualification_export_01.py](audit-tools/audit_r21_qualification_export_01.py)
validates and restores the exact qualification package. The narrow
[raw test adapter](audit-tools/replay_r21_qualification_raw_01.py) calls the
unchanged original audit function, with only two exact text-path mappings and
five accepted remote ELF digest witnesses. It rereads raw gzip streams and
compares deterministic audit fields; it does not rerun tests or claim local ELF
byte validation. The frozen
[source binder](audit-tools/bind_qualified_source_r21_01.py) separately checks
the seven 219-input maps, three 281-file snapshots, actual release identities,
and the two component source steps against the published R19 proof.

Exact original invocations, all stdout/stderr, tool sources and failed local
attempts are retained in the local review package. Source and archive paths in
historical receipts refer to their original machines; repository paths in the
identity catalog are the portable entry points. The package member mappings
preserve those original-path associations.

The [campaign capture description](evidence-tools/README.md) and
[Mac capture description](mac-evidence-tools/README.md) describe precise capture
boundaries and failure behavior. The Mac exporter never reads the X230 report;
the final orchestration binds the actual X230 report and the Mac terminal
footer across the two independent packages.

## Interpretation and stopping point

STATUS and CANCEL component CPU improvements are retained as measured local
results, together with their unchanged READ controls and mock limitations.
They did not establish acceptable end-to-end performance for the composite
candidate. Both hash-buffer variants also failed their original small-request
gate. No performance samples were removed, no gate was loosened, and no formal
campaign was rerun to obtain a different result.

This is a finite measured stopping point under the existing integrity,
persistence and admission contracts. It is not a proof of global optimality,
maximum cluster throughput, 32 successful simultaneous admissions, or reduced
steady-state RSS. The current publication changes evidence and documentation
only, and does not deploy a production controller.

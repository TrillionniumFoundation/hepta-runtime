# Current100k USD regression adapter

The `current100k_value` provider uses the existing resident weight worker and
job owner. It supports the separate 768-to-1 monetary value head over the frozen
Laya encoder. The existing `laya` provider is a different seven-option/action
classification graph; its logits, Brier evaluator and scorer adapters are not
substitutes for this regression task.

## Model identity and loading

The `model` object requires:

| Field | Binding |
| --- | --- |
| `source_dir`, `source_tree_sha256` | Existing admitted `learn`/source directory containing `laya_cell.model` and its Python tree identity |
| `base_dir`, `base_manifest_sha256` | Existing local Laya base and exact `base-manifest.json` |
| `head_path`, `head_sha256` | Complete separate `value-head.safetensors` bytes |
| `expected_base_id` (optional) | Base identity returned by the existing verified loader |
| `allowed_patch_targets` (optional) | Explicit parameter names; defaults to `value.weight` and `value.bias` |
| `task_contract_sha256` (optional) | Exact digest of the adapter's reported task contract |

Source/root access follows the existing worker policy. The pinned loader runs
`load_verified_laya(..., enforce_gpu=False)` against already installed files;
this adapter downloads or installs nothing. The head is bounded to 128 KiB and
decoded from the same bytes whose complete SHA-256 was checked. Only finite FP32
`value.weight` of shape `[1,768]` and `value.bias` of shape `[1]` are accepted.
The model identity binds the source, loader, base, head and task contract. The
backend identity separately records CPU, PyTorch, worker package and thread settings.
The session publishes its live provider only after identity checks and the
immutable admission receipt succeed. A failed admission closes the loaded graph
and cannot subsequently be used for probes or patches.

Encoder parameters are inspectable. Editing them requires explicit existing
names in `allowed_patch_targets`; an empty list permits no parameter edits.
The source checkpoint and active trading model are never overwritten. This
research provider does not impose the production head's joint-norm eligibility
rule; the candidate/evaluation contract must state which limits it compares.

## Frozen input-only rows

`probe.inputs` accepts exactly `{"rows":[...]}` or
`{"rows_artifact_id":"RETURNED_ARTIFACT_ID"}`. The latter must refer to a
retained JSON array with the same row schema. Each row contains:

```json
{
  "row_id": "original-row-id",
  "input_id": "original-input-id",
  "request_id": "original-request-id",
  "action": "BUY",
  "input_started_at_ms": 1793700000000,
  "feature_text": "ORIGINAL PROMPT\nFinancial value context: EUR.USD; requested reference notional budget=100000 USD; selected action=BUY; behavior model=ORIGINAL_MODEL. Predict eventual roundtrip net USD after reported execution commissions.",
  "feature_text_sha256": "EXACT_SHA256_OF_UTF8_FEATURE_TEXT"
}
```

Optional `source_request_sha256` and `source_record_sha256` retain additional
original bindings. Labels, rewards, commissions, raw outcome records and unknown
fields are rejected. A label-bearing dataset must be projected into input-only
rows before admission. A call contains 1–64 rows; duplicate row IDs and duplicate
request/action pairs are refused. Metadata records ordered row digests, all
provided identities, token counts, the exact encoded tensor hashes and the
aggregate ordered model-input identity. Hashes establish identity, not that a
caller obtained authentic records or never previously viewed outcomes.

The text/action suffix is checked against the USD100k template. The earlier
fixed-quantity 25,000 EUR task cannot be relabeled as this task. The exported
`feature_text(request, action)` helper constructs this exact template; source
request verification stays with HeptaTrader's existing owner.

## Exact computation and output meaning

Each row is tokenized **separately** with `padding=True`, `truncation=False`,
`return_tensors='pt'`. Inputs longer than 2,048 tokens fail. `input_ids`,
`attention_mask` and optional `token_type_ids` are retained in the input identity.
The encoder runs on one row at a time. Its attention-mask-weighted mean is
converted to FP32 and L2-normalized with PyTorch's epsilon `1e-12`. The actual
`nn.Linear` head runs on the concatenation of these rows, as in the production
forward path, preserving registered hooks and temporary parameter edits. Results
preserve input order:

| Tensor | Shape | Meaning |
| --- | --- | --- |
| `features` | `[rows,768]` | Masked-mean, L2-normalized FP32 encoder features |
| `value_scaled` | `[rows]` | Raw linear value in USD/100 units |
| `value_usd` | `[rows]` | `100 * value_scaled`, without clipping |

The separate prospective collector owns its frozen ±15 USD output bound. This
adapter does not silently apply it, generate class probabilities, apply softmax,
claim a forward-window prediction, or write into an existing frozen experiment.
New CPU observations cannot replace earlier GPU or frozen-cache observations
without an explicit, independently verified backend/input comparison.

## Resident feature reuse

The provider keeps at most 128 normalized FP32 vectors (393,216 payload bytes)
in a session-local LRU. Keys bind the pinned encoder/base/source, worker backend,
task contract and exact encoded token tensors. Head-only patches reuse these
features. Captures, interventions and encoder-parameter patches always bypass
the cache, and their temporary features never enter the unedited cache. Closing
the session releases it. A restart creates a new cache; retained artifacts do
not imply a live encoder state has been restored.

`probe.bypass_feature_cache=true` forces an actual encoder recomputation even
for the unedited parent. It neither reads nor replaces cached vectors and reports
`feature_cache_bypass_reason='explicit_recomputation'`. Use this for final
restoration checks so cached outputs cannot substitute for a new encoder forward.

`computation` in each probe receipt distinguishes `logical_forward_examples`
from `encoder_forward_examples`, cache hits, misses, bypassed examples and the
bypass reason. The ordinary forward budget counts every logical row even when
its features are reused. `feature_cache_retained_entries/bytes` report the
bounded payload retained after that probe; they are not total process RSS.
The explicit `task_kind='regression'` also makes the session reject an attempted
`softmax_output` before model work or forward-budget consumption.

## Verification scope

`tests/test_current100k_provider.py` uses actual CPU PyTorch embedding/linear
modules and safetensors. It checks serial execution, padding-aware pooling,
normalization, USD scaling, immutable row/tensor identities, retained inputs,
temporary head edits/restoration, input-label refusal, maximum context, malformed
attention masks, wrong head hashes/shapes/dtypes and default edit scope.

`experiments/weight/qualify_current100k.py` fixes its numerical tolerances before
opening the disposable session. After closing it, one final integrity audit
rehashes the complete Python source tree, the base manifest, every file and size
bound by that manifest, and the original config, inputs, reference and head.
`source_tree_unchanged`, `base_files_unchanged` and `source_files_unchanged` must
all hold for `PASS_ENGINEERING_PARITY`. The cost is reported separately as
`timings.source_integrity`; no file-tree audit is added to individual forwards or
cache lookups. An in-memory numerical pass cannot hide a later source-file change.

These deterministic fixtures establish the adapter contract. They do not prove
parity with an installed tokenizer/full Laya checkpoint, GPU bitwise equality,
future forecast improvement or financial return. Owned-host verification should
compare exact production token tensors and the frozen head output on the same
input rows before starting a new experiment. Existing registered windows remain
under their original evaluator, dates, model IDs and numerical output rules.

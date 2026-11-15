"""Pinned, tokenizer-only regression against the actual Laya production encoder.

This command loads the local tokenizer, never model weights or outcome files. It
is separate from portable unit discovery because it requires an owned Laya install.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from weight_runtime.artifacts import file_sha256
from weight_runtime.errors import digest, loads, need
from weight_runtime.providers import make_laya_encoder, source_tree_identity


def reference_batch(common, dataset, tokenizer, state, order, parallel):
    result = common.build_sequence(tokenizer, state, dataset.question(300), max_len=1024, head_max_len=256,
                                   option_order=order, return_stats=True, return_truncation_stats=True,
                                   return_layout=parallel)
    ids, markers, stats, truncation = result[:4]
    need(len(markers) == 7 and stats["options_distinct"] == 7 and not truncation["truncated"],
         "INVALID_INPUT", "Reference input is truncated or has missing options")
    item = {"ids": ids, "markers": markers, "qtype": 0}
    if parallel:
        item["layout"] = result[4]
    batch = common.collate_items([[item]], tokenizer.pad_token_id)
    keys = ["input_ids", "attention_mask", "marker_pos", "marker_mask", "qtype"]
    if parallel:
        keys += ["position_ids", "option_ids"]
    return {key: batch[key] for key in keys}


def batch_id(batch):
    return digest({key: value.tolist() for key, value in batch.items()})


def run(args):
    os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", USE_TF="0", TOKENIZERS_PARALLELISM="false")
    source, base, input_path = (Path(p).resolve(strict=True) for p in (args.source_dir, args.base_dir, args.input))
    dataset_path = source / "laya_cell" / "dataset.py"
    need(file_sha256(dataset_path) == args.expected_dataset_sha256, "IDENTITY_MISMATCH", "Pinned dataset code differs")
    need(file_sha256(input_path) == args.expected_input_sha256, "IDENTITY_MISMATCH", "Frozen input differs")
    sys.path.insert(0, str(source))
    import torch
    torch.set_num_threads(2)
    torch.set_num_interop_threads(1)
    torch.set_grad_enabled(False)
    from laya_cell import dataset
    from laya import common
    from transformers import AutoTokenizer
    need(Path(dataset.__file__).resolve() == dataset_path, "IDENTITY_MISMATCH", "Dataset came from another release")
    need(file_sha256(common.__file__) == args.expected_common_sha256, "IDENTITY_MISMATCH", "Pinned Laya common code differs")
    tokenizer = AutoTokenizer.from_pretrained(str(base / "tokenizer"), local_files_only=True,
                                             trust_remote_code=False, use_fast=True)
    state = loads(input_path.read_bytes())["state"]
    need(state.get("horizon_sec") == 300, "INVALID_INPUT", "This provider currently tests the 300-second question")
    ordered = {key: state[key] for key in dataset.CAUSAL_STATE_FIELDS}
    variants = {"retained": state, "causal": ordered,
                "reversed": dict(reversed(list(state.items()))),
                "alphabetical": {key: state[key] for key in sorted(state)}}
    encoder = make_laya_encoder(dataset, common)
    ordinary = dataset.encode_rows(tokenizer, [{"state": state, "question": dataset.question(300)}])
    rows = []
    for parallel in (False, True):
        for order in (list(range(7)), list(reversed(range(7))), list(range(1, 7)) + [0]):
            reference = reference_batch(common, dataset, tokenizer, ordered, order, parallel)
            expected_id = batch_id(reference)
            raw = reference_batch(common, dataset, tokenizer, state, order, parallel)
            checked = {}
            for label, variant in variants.items():
                original = json.dumps(variant, ensure_ascii=False)
                actual, meta = encoder(tokenizer, variant, order, parallel)
                need(set(actual) == set(reference) and all(torch.equal(actual[k], reference[k]) for k in reference),
                     "ENCODING_PARITY", "Provider tensors differ from the pinned reference", variant=label,
                     order=order, parallel=parallel)
                need(json.dumps(variant, ensure_ascii=False) == original, "INPUT_MUTATION", "Encoding changed the frozen state")
                need(meta["state_field_order"] == list(dataset.CAUSAL_STATE_FIELDS), "ENCODING_PARITY", "Field-order receipt differs")
                checked[label] = batch_id(actual)
            default_order = order == list(range(7))
            if default_order:
                need(all(torch.equal(reference[k], ordinary[k]) for k in ordinary),
                     "ENCODING_PARITY", "Default tokens differ from production dataset.encode_rows")
            same_shape = raw["input_ids"].shape == reference["input_ids"].shape
            rows.append({"parallel_layout": parallel, "option_order": order,
                         "model_input_id": expected_id, "variant_model_input_ids": checked,
                         "tokens": reference["input_ids"].shape[-1],
                         "raw_input_id": batch_id(raw),
                         "raw_vs_normalized_different_token_positions": int((raw["input_ids"] != reference["input_ids"]).sum()) if same_shape else None,
                         "encode_rows_default_tensor_parity": True if default_order else None})
    tokenizer_root = base / "tokenizer"
    tokenizer_files = {p.relative_to(tokenizer_root).as_posix(): file_sha256(p)
                       for p in sorted(tokenizer_root.rglob("*")) if p.is_file()}
    return {"schema": "hepta.weight.laya-encoding-parity.v1", "passed": True,
            "checked_at_ms": int(time.time() * 1000), "model_weights_loaded": False, "model_forwards": 0,
            "gpu_initialized": torch.cuda.is_initialized(), "source_dir": str(source),
            "source_tree_sha256": source_tree_identity(source),
            "dataset_sha256": file_sha256(dataset_path), "common_sha256": file_sha256(common.__file__),
            "worker_providers_sha256": file_sha256(Path(__file__).resolve().parents[1] / "weight_runtime" / "providers.py"),
            "regression_script_sha256": file_sha256(__file__),
            "input_path": str(input_path), "input_file_sha256": file_sha256(input_path),
            "tokenizer_files_sha256": digest(tokenizer_files), "tokenizer_files": tokenizer_files,
            "causal_field_order": list(dataset.CAUSAL_STATE_FIELDS), "retained_field_order": list(state),
            "cases": rows, "checked_variant_encodings": len(rows) * len(variants)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", required=True)
    parser.add_argument("--base-dir", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--expected-dataset-sha256", required=True)
    parser.add_argument("--expected-common-sha256", required=True)
    parser.add_argument("--expected-input-sha256", required=True)
    args = parser.parse_args()
    print(json.dumps(run(args), sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()

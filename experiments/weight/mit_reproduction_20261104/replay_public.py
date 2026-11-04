#!/usr/bin/env python3
"""Replay public weight edits, not the unavailable original AI editor or training.

Upstream logs/data/networks: Takehi, Teoh, Zhang and Khattab (2026), CC BY 4.0.
https://github.com/RikiyaT/lm_understand-logs/tree/4d09ba6d6a7e891dd8063974dfe81b3d78e3494f
MinAtar source is separately GPL-3.0 and is not needed by this exact-weight replay.
"""
from __future__ import annotations

import ast
import contextlib
import hashlib
import io
import json
import re
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent
UP = ROOT / "upstream"
OUT = ROOT / "reproduced"
IDENTITY = json.loads((ROOT / "source_identity.json").read_text())
SHAS = {x["path"]: x["sha"] for x in IDENTITY["tree"]}


def blob_sha(b: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(b)).encode() + b"\0" + b).hexdigest()


def checked_read(rel: str) -> bytes:
    b = (UP / rel).read_bytes()
    if blob_sha(b) != SHAS[rel]:
        raise ValueError(f"Upstream source identity mismatch: {rel}")
    return b


def digest(a: np.ndarray) -> str:
    return hashlib.sha256(np.ascontiguousarray(a).tobytes()).hexdigest()


def constant(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        v = constant(node.operand)
        return -v if isinstance(node.op, ast.USub) else v
    if isinstance(node, ast.List):
        return [constant(x) for x in node.elts]
    raise ValueError("Edit contains a nonliteral value")


def index(node):
    if isinstance(node, ast.Tuple):
        return tuple(index(x) for x in node.elts)
    if isinstance(node, ast.Slice):
        values = [None if v is None else constant(v) for v in (node.lower, node.upper, node.step)]
        if not all(v is None or isinstance(v, int) for v in values):
            raise ValueError("Noninteger slice")
        return slice(*values)
    v = constant(node)
    if not isinstance(v, int):
        raise ValueError("Noninteger index")
    return v


def target(node, weights):
    if not isinstance(node, ast.Subscript):
        raise ValueError("Only indexed tensor assignments are supported")
    n = node.value
    if isinstance(n, ast.Name):
        name = n.id
    elif isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name):
        name = f"{n.value.id}.{n.attr}"
    else:
        raise ValueError("Unsupported tensor target")
    if name not in weights:
        raise ValueError(f"Unknown tensor: {name}")
    return weights[name], index(node.slice)


def apply_literal_edits(reply: str, weights: dict) -> int:
    """Parse only literals, tensor indices, and =/+=/-=/*=; no eval or exec."""
    blocks = re.findall(r"```edits\s*\n(.*?)```", reply, re.S)
    if not blocks:
        raise ValueError("No edits block")
    body = ast.parse(blocks[-1]).body
    for s in body:
        if isinstance(s, ast.Assign) and len(s.targets) == 1:
            a, ix = target(s.targets[0], weights)
            a[ix] = constant(s.value)
        elif isinstance(s, ast.AugAssign):
            a, ix = target(s.target, weights)
            value = constant(s.value)
            if isinstance(s.op, ast.Add):
                a[ix] += value
            elif isinstance(s.op, ast.Sub):
                a[ix] -= value
            elif isinstance(s.op, ast.Mult):
                a[ix] *= value
            else:
                raise ValueError("Unsupported assignment operator")
        else:
            raise ValueError("Not a literal tensor edit")
    if not all(np.isfinite(v).all() for v in weights.values()):
        raise ValueError("Nonfinite edited value")
    return len(body)


def replay_breakout():
    reply = checked_read("exp5_write_from_scratch/runs/breakout/reply/answer.md").decode()
    shapes = {"W1": (600, 32), "b1": (32,), "W2": (32, 32), "b2": (32,), "W3": (32, 6), "b3": (6,)}
    weights = {k: np.zeros(s, np.float32) for k, s in shapes.items()}
    count = apply_literal_edits(reply, weights)
    reference = np.load(io.BytesIO(checked_read("exp5_write_from_scratch/networks/breakout/hand.npz")))
    names = {"W1": "actor/dense1/kernel", "b1": "actor/dense1/bias", "W2": "actor/dense2/kernel", "b2": "actor/dense2/bias", "W3": "actor/logits/kernel", "b3": "actor/logits/bias"}
    equality = {k: bool(np.array_equal(v.view(np.uint32), reference[names[k]].view(np.uint32))) for k, v in weights.items()}
    assert all(equality.values()), equality
    np.savez(OUT / "breakout_from_zero.npz", **weights)
    return {"status": "PASS_EXACT_WEIGHT_REPLAY", "statements": count,
            "parameters": sum(v.size for v in weights.values()),
            "nonzero_parameters": sum(int(np.count_nonzero(v)) for v in weights.values()),
            "tensors_bitwise_equal": equality, "training_or_gradient_steps": 0,
            "claim_boundary": "Published numerical construction replayed, not a new independent AI discovery."}


def parse_car_weights(prompt: str):
    header = re.compile(r"^((?:embed|actor\d+|actor_head)\.[Wb]) \(([\d x]+)\), scale ([\deE+.-]+):[^\n]*\n", re.M)
    matches = list(header.finditer(prompt))
    source = np.load(io.BytesIO(checked_read("exp4_fix_car/networks/ppo_final_seed0.npz")))
    out = {}
    for i, m in enumerate(matches):
        name, shape, scale = m.groups()
        shape = tuple(int(s.strip()) for s in shape.split("x"))
        segment = prompt[m.end():matches[i+1].start() if i+1 < len(matches) else len(prompt)].strip()
        if len(shape) == 2:
            rows = segment.splitlines()
            assert len(rows) == shape[0], (name, len(rows), shape)
            integers = []
            for r, line in enumerate(rows):
                prefix, values = line.split(":", 1)
                assert int(prefix) == r
                row = [float(v) for v in values.split()]
                assert len(row) == shape[1]
                integers.extend(row)
        else:
            integers = [float(v) for v in segment.split()]
        # Published rounded actor uses float64. The integer text erases the sign
        # of rounded zeros; recover that sign from the original PPO checkpoint,
        # never from the target edited actor. Verify every rounded numeric value.
        shown = np.asarray(integers, dtype=np.float64).reshape(shape) * float(scale)
        unit, field = name.split(".")
        suffix = "kernel" if field == "W" else "bias"
        if unit == "embed":
            key = "params/Dense_0/" + suffix
        elif unit == "actor_head":
            key = "params/GeneralActorCriticRNN_0/Dense_0/" + suffix
        else:
            key = f"params/GeneralActorCriticRNN_0/DenseAndActivation_{int(unit[5:])}/Dense_0/{suffix}"
        rounded = np.round(source[key].astype(np.float64) / float(scale)) * float(scale)
        assert np.array_equal(shown, rounded), name
        out[name] = rounded
    assert len(out) == 14
    return out


def replay_car():
    prompt = checked_read("exp4_fix_car/runs/oneshot_repair/reply/prompt.txt").decode()
    reply = checked_read("exp4_fix_car/runs/oneshot_repair/reply/answer.md").decode()
    base = parse_car_weights(prompt)
    edited = {k: v.copy() for k, v in base.items()}
    count = apply_literal_edits(reply, edited)
    reference = np.load(io.BytesIO(checked_read("exp4_fix_car/networks/edited_actor.npz")))
    equality = {k: bool(np.array_equal(v.view(np.uint64), reference[k].view(np.uint64))) for k, v in edited.items()}
    assert all(equality.values()), {k: int(np.count_nonzero(edited[k] != reference[k])) for k in edited if not equality[k]}
    changes = {k: int(np.count_nonzero(edited[k] != base[k])) for k in base}
    assert sum(changes.values()) == 6073
    np.savez(OUT / "car_rounded_baseline.npz", **base)
    np.savez(OUT / "car_replayed_edit.npz", **edited)
    patch = {}
    for k in base:
        ix = np.flatnonzero(base[k].ravel().view(np.uint64) != edited[k].ravel().view(np.uint64))
        patch[k + ".indices"] = ix
        patch[k + ".old_bits"] = base[k].ravel().view(np.uint64)[ix]
        patch[k + ".new_bits"] = edited[k].ravel().view(np.uint64)[ix]
    np.savez_compressed(OUT / "car_exact_reversible_patch.npz", **patch)
    restored = {k: v.copy() for k, v in edited.items()}
    for k in restored:
        restored[k].ravel().view(np.uint64)[patch[k + ".indices"]] = patch[k + ".old_bits"]
    assert all(digest(restored[k]) == digest(base[k]) for k in base)
    return {"status": "PASS_EXACT_WEIGHT_REPLAY_AND_ROLLBACK", "statements": count,
            "parameters": sum(v.size for v in base.values()), "changed_parameters": sum(changes.values()),
            "bitwise_changed_parameters_including_signed_zero": sum(len(patch[k + ".indices"]) for k in base),
            "changes_per_tensor": changes, "tensors_bitwise_equal": equality, "rollback_bitwise_equal": True,
            "baseline_tensor_sha256": {k: digest(v) for k, v in base.items()},
            "edited_tensor_sha256": {k: digest(v) for k, v in edited.items()},
            "training_or_gradient_steps": 0,
            "claim_boundary": "Exact 6073-parameter edit and inverse patch replayed. Kinetix 1024-episode success is upstream evidence, not locally rerun."}


def replay_go():
    row = json.loads(checked_read("exp6_go_from_scratch/runs/budget_0/tool_calls.jsonl"))
    code = row["code"]
    # This exact, pinned 336-line NumPy construction was manually inspected.
    # It computes constants/weights only and writes through the bounded save below.
    tensors = {}
    def save(name, array):
        if not re.fullmatch(r"(?:L[1-6]|out)\.[Wb]", name):
            raise ValueError("Unexpected tensor name")
        tensors[name] = array.copy()
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        exec(compile(code, "upstream/exp6_budget0_pinned.py", "exec"), {"save": save})
    output_dir = OUT / "go_budget0"
    output_dir.mkdir(exist_ok=True)
    checks = {}
    for name, array in tensors.items():
        p = output_dir / (name + ".npy")
        np.save(p, array)
        b = p.read_bytes()
        expected = SHAS["exp6_go_from_scratch/networks/budget_0/" + p.name]
        checks[name] = {"sha256": hashlib.sha256(b).hexdigest(), "git_blob_sha": blob_sha(b), "expected_git_blob_sha": expected, "exact": blob_sha(b) == expected}
    assert all(x["exact"] for x in checks.values()), checks
    return {"status": "PASS_EXACT_CONSTRUCTION_REPLAY", "parameters": sum(v.size for v in tensors.values()),
            "nonzero_parameters": sum(int(np.count_nonzero(v)) for v in tensors.values()),
            "tensors": checks, "construction_code_lines": len(code.splitlines()),
            "training_or_gradient_steps": 0, "construction_forward_passes": 0,
            "claim_boundary": "All 14 network files reconstructed exactly. No Go match or PPO training was rerun."}


def audit_qwen_diff():
    manifest = json.loads(checked_read("exp8_math/runs/p50c/edit/manifest.json"))
    frozen = json.loads(checked_read("exp8_math/runs/p50c/work_notes/frozen_weights_manifest.json"))
    z = np.load(io.BytesIO(checked_read("exp8_math/runs/p50c/edit/edit.npz")))
    result = []
    for i, t in enumerate(manifest["tensors"]):
        ix, values = z[f"t{i}_idx"], z[f"t{i}_val"]
        cols = np.unique(ix % t["shape"][1])
        layer = str(int(t["name"].split("layers.")[1].split(".")[0]))
        assert len(ix) == t["changed_entries"] and len(np.unique(ix)) == len(ix)
        assert len(cols) == 64 and cols.tolist() == frozen[layer]["selected_neurons"]
        assert np.all(ix >= 0) and np.all(ix < np.prod(t["shape"]))
        # BF16 exponent-all-ones denotes infinity/NaN.
        assert np.all((values & np.uint16(0x7f80)) != np.uint16(0x7f80))
        result.append({"name": t["name"], "changed_entries": len(ix), "changed_columns": len(cols), "base_sha256": t["base_sha256"], "edited_sha256": t["edited_sha256"]})
    return {"status": "PASS_DIFF_STRUCTURE_AUDIT_ONLY", "tensors": result,
            "touched_parameters": 131072, "bf16_changed_parameters": sum(t["changed_entries"] for t in result),
            "claim_boundary": "This function audits diff structure only. Exact base/edited tensor replay is recorded separately in qwen_tensor_replay_results.json; no MATH-500 inference is claimed."}


def main():
    OUT.mkdir(exist_ok=True)
    start = time.perf_counter()
    result = {"source_repository": IDENTITY["repository"], "source_commit": IDENTITY["commit"],
              "numpy_version": np.__version__, "wall_start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "breakout": replay_breakout(), "car": replay_car(), "go": replay_go(), "qwen_diff": audit_qwen_diff()}
    result["wall_seconds"] = time.perf_counter() - start
    (OUT / "exact_replay_results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

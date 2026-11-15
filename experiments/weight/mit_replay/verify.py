"""Verify the pinned MIT sparse patch against real BF16 checkpoint bytes.

No model is instantiated. The source checkpoint is only opened read-only, and
the reconstructed arrays stay in memory until an inference adapter uses them.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct

import numpy as np

try:
    from .acquire import digest
    from .reference import BASE_REVISION, EXPECTED_TENSORS, SOURCE_COMMIT
except ImportError:
    from acquire import digest
    from reference import BASE_REVISION, EXPECTED_TENSORS, SOURCE_COMMIT


def raw_sha256(array):
    return hashlib.sha256(np.ascontiguousarray(array, dtype="<u2").tobytes()).hexdigest()


def read_bf16_tensor(path, name):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("checkpoint symlink refused")
    with path.open("rb") as stream:
        prefix = stream.read(8)
        if len(prefix) != 8:
            raise ValueError("truncated safetensors header")
        length = struct.unpack("<Q", prefix)[0]
        if length > 16 << 20:
            raise ValueError("oversized safetensors header")
        header = json.loads(stream.read(length))
        info = header[name]
        if info["dtype"] != "BF16":
            raise ValueError("the published reference requires BF16 checkpoint tensors")
        start, end = info["data_offsets"]
        count = int(np.prod(info["shape"]))
        if start < 0 or end - start != 2 * count or 8 + length + end > path.stat().st_size:
            raise ValueError("invalid tensor offsets or shape")
        stream.seek(8 + length + start)
        data = stream.read(end - start)
    if len(data) != 2 * count:
        raise ValueError("truncated tensor data")
    return np.frombuffer(data, dtype="<u2").copy().reshape(info["shape"])


def rebuild_sparse(base, indices, values, expected):
    if base.dtype != np.dtype("uint16") or list(base.shape) != expected["shape"]:
        raise ValueError("unexpected source dtype or shape")
    if raw_sha256(base) != expected["base_sha256"]:
        raise ValueError("source tensor hash mismatch")
    if indices.ndim != 1 or indices.dtype.kind not in "iu" or values.dtype != np.dtype("uint16"):
        raise ValueError("invalid sparse index or BF16 value dtype")
    if values.ndim != 1 or len(indices) != len(values) or len(indices) != expected["changed_entries"]:
        raise ValueError("sparse edit length mismatch")
    if len(indices) and (indices.min() < 0 or indices.max() >= base.size):
        raise ValueError("sparse edit index is outside the tensor")
    if np.unique(indices).size != len(indices):
        raise ValueError("duplicate sparse indices")
    edited = base.copy()
    edited.reshape(-1)[indices] = values
    changed = edited != base
    if int(changed.sum()) != expected["changed_entries"]:
        raise ValueError("declared edit includes unchanged entries")
    if int(changed.any(axis=0).sum()) != expected["changed_columns"]:
        raise ValueError("unexpected edited column count")
    if raw_sha256(edited) != expected["edited_sha256"]:
        raise ValueError("reconstructed tensor hash mismatch")
    # BF16 infinity/NaN exponent patterns are rejected without rounding via float32.
    if np.any((edited & np.uint16(0x7F80)) == np.uint16(0x7F80)):
        raise ValueError("non-finite edited BF16 weight")
    return edited


def verify_reference(root, verify_downloads=True):
    root = Path(root).expanduser().resolve()
    acquisition = json.loads((root / "acquisition.json").read_text())
    if acquisition["base_revision"] != BASE_REVISION or acquisition["source_commit"] != SOURCE_COMMIT:
        raise ValueError("immutable reference identity mismatch")
    if verify_downloads:
        for record in acquisition["files"]:
            path = Path(record["path"])
            if not path.resolve().is_relative_to(root) or path.is_symlink():
                raise ValueError("download receipt escapes the reference root")
            actual = digest(path)
            if actual != record["sha256"] or (record.get("upstream_sha256") and actual != record["upstream_sha256"]):
                raise ValueError(f"downloaded file changed: {path.name}")
    manifest = json.loads((root / "source/manifest.json").read_text())
    if manifest["changed_tensors"] != 2 or manifest["changed_entries_total"] != 130188:
        raise ValueError("unexpected published patch scope")
    names = [t["name"] for t in manifest["tensors"]]
    if len(names) != 2 or set(names) != set(EXPECTED_TENSORS):
        raise ValueError("unexpected or duplicated patch tensor")
    index = root / "base/model.safetensors.index.json"
    weight_map = json.loads(index.read_text())["weight_map"] if index.exists() else {}
    arrays, rows = {}, []
    with np.load(root / "source/edit.npz", allow_pickle=False) as patch:
        if set(patch.files) != {f"t{i}_{suffix}" for i in range(2) for suffix in ("idx", "val")}:
            raise ValueError("unexpected arrays in the sparse edit archive")
        for i, tensor in enumerate(manifest["tensors"]):
            name = tensor["name"]
            expected = EXPECTED_TENSORS[name]
            if tensor["form"] != "sparse" or tensor["dtype"] != "bfloat16":
                raise ValueError("unexpected edit form")
            if any(tensor[key] != value for key, value in expected.items()):
                raise ValueError("published manifest disagrees with the pinned tensor identities")
            shard = weight_map.get(name, "model.safetensors")
            if Path(shard).name != shard:
                raise ValueError("unexpected shard path")
            base = read_bf16_tensor(root / "base" / shard, name)
            edited = rebuild_sparse(base, patch[f"t{i}_idx"], patch[f"t{i}_val"], expected)
            arrays[name] = {"base": base, "edited": edited}
            rows.append({"name": name, **expected, "dtype": "bfloat16", "hashes_verified": True})
    report = {"schema": "hepta.mit_qwen.verification.v1", "base_revision": BASE_REVISION,
              "source_commit": SOURCE_COMMIT, "download_checks": verify_downloads,
              "changed_entries_total": 130188, "changed_tensors": 2, "tensors": rows,
              "source_checkpoint_modified": False}
    return report, arrays


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report, _ = verify_reference(args.root)
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps(report))

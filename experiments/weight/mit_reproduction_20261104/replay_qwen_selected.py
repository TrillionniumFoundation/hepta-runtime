#!/usr/bin/env python3
"""Fetch only the two pinned Qwen tensor ranges and replay MIT's exact edit.

NumPy + Python standard library; never downloads the full model or runs it.
Saved safetensors files contain TWO TENSORS ONLY and are not runnable models.
The source model is Apache-2.0; upstream edit/logs CC BY 4.0.
"""
import hashlib
import io
import json
import struct
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
import numpy as np
from replay_public import ROOT, OUT, checked_read
sys.path.insert(0, str(ROOT / "upstream/exp8_math/code"))
import st_numpy as S
from apply_edit import rebuild

REV = "2fc06364715b967f1860aea9cf38778875588b17"
BASE = f"https://huggingface.co/Qwen/Qwen3.5-0.8B/resolve/{REV}/"


def read_small_json(url):
    with urllib.request.urlopen(url, timeout=15) as r:
        b = r.read(4 * 1024 * 1024 + 1)
    if len(b) > 4 * 1024 * 1024:
        raise ValueError("Unexpected metadata size")
    return json.loads(b)


def read_range(url, start, end):
    request = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end}", "Accept-Encoding": "identity"})
    with urllib.request.urlopen(request, timeout=20) as response:
        cr = response.headers.get("Content-Range", "")
        if response.status != 206 or not cr.startswith(f"bytes {start}-{end}/"):
            raise ValueError(f"Range request not honored: HTTP {response.status}, Content-Range {cr}")
        b = response.read(end - start + 2)
        if len(b) != end - start + 1:
            raise ValueError("Unexpected range response length")
    return b


def main():
    start_time = time.perf_counter()
    OUT.mkdir(exist_ok=True)
    result = {"base_model": "Qwen/Qwen3.5-0.8B", "base_revision": REV,
              "edit_source_commit": "4d09ba6d6a7e891dd8063974dfe81b3d78e3494f", "forward_passes": 0}
    try:
        metadata = read_small_json(f"https://huggingface.co/api/models/Qwen/Qwen3.5-0.8B/revision/{REV}")
        assert metadata["sha"] == REV
        index = read_small_json(BASE + "model.safetensors.index.json")
        man = json.loads(checked_read("exp8_math/runs/p50c/edit/manifest.json"))
        z = np.load(io.BytesIO(checked_read("exp8_math/runs/p50c/edit/edit.npz")))
        files = {index["weight_map"][t["name"]] for t in man["tensors"]}
        assert len(files) == 1
        filename = files.pop()
        result["source_filename"] = filename
        url = BASE + filename + "?download=true"
        head_n = struct.unpack("<Q", read_range(url, 0, 7))[0]
        assert 0 < head_n <= 4 * 1024 * 1024
        header = json.loads(read_range(url, 8, 7 + head_n))
        base, edited, inverse, entries = {}, {}, {}, []
        for i, t in enumerate(man["tensors"]):
            name = t["name"]
            h = header[name]
            assert h["dtype"] == "BF16" and h["shape"] == t["shape"]
            begin, end = h["data_offsets"]
            b = read_range(url, 8 + head_n + begin, 7 + head_n + end)
            assert hashlib.sha256(b).hexdigest() == t["base_sha256"]
            bits = np.frombuffer(b, dtype="<u2").reshape(t["shape"]).copy()
            new = rebuild(bits, t, z, i)
            assert hashlib.sha256(new.tobytes()).hexdigest() == t["edited_sha256"]
            ix = z[f"t{i}_idx"]
            assert int(np.count_nonzero(bits != new)) == t["changed_entries"]
            inverse[f"t{i}_idx"] = ix
            inverse[f"t{i}_old"] = bits.ravel()[ix]
            inverse[f"t{i}_new"] = new.ravel()[ix]
            restored = new.copy().ravel()
            restored[ix] = inverse[f"t{i}_old"]
            assert restored.tobytes() == b
            base[name] = ("BF16", bits)
            edited[name] = ("BF16", new)
            entries.append({"name": name, "base_sha256": t["base_sha256"], "edited_sha256": t["edited_sha256"], "changed_entries": t["changed_entries"], "rollback_exact": True})
        S.save(str(OUT / "qwen_base_two_tensors.safetensors"), base, {"format": "pt", "subset_only": "true"})
        S.save(str(OUT / "qwen_edited_two_tensors.safetensors"), edited, {"format": "pt", "subset_only": "true"})
        np.savez_compressed(OUT / "qwen_two_tensors_reversible_patch.npz", **inverse)
        result.update({"status": "PASS_EXACT_TWO_TENSOR_REPLAY_AND_ROLLBACK", "tensors": entries,
                       "claim_boundary": "Only the two edited model tensors were rebuilt. The rest of the model and behavioral accuracy were not run."})
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError, AssertionError) as e:
        result.update({"status": "BLOCKED_BASE_TENSOR_FETCH_OR_IDENTITY", "error_type": type(e).__name__,
                       "error": str(e).split("?")[0][:250], "claim_boundary": "Diff structure audit only; original tensor bytes unavailable or failed identity checks. No behavioral reproduction claimed."})
    result["wall_seconds"] = time.perf_counter() - start_time
    (OUT / "qwen_tensor_replay_results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()

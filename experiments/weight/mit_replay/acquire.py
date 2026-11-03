"""Acquire the immutable public reference without credentials or model execution."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import time
import urllib.parse
import urllib.request

try:
    from .reference import BASE_REPOSITORY, BASE_REVISION, SOURCE_COMMIT, SOURCE_PREFIX, SOURCE_REPOSITORY
except ImportError:
    from reference import BASE_REPOSITORY, BASE_REVISION, SOURCE_COMMIT, SOURCE_PREFIX, SOURCE_REPOSITORY


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(4 << 20), b""):
            h.update(block)
    return h.hexdigest()


def get_json(url, limit=8 << 20):
    with urllib.request.urlopen(url, timeout=45) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("metadata response exceeds the byte limit")
    return json.loads(data)


def download(url, target, max_bytes, expected_sha256=None):
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    receipt = target.with_name(target.name + ".download.json")
    if target.is_symlink() or receipt.is_symlink():
        raise ValueError("refusing a symlink download destination")
    if target.exists():
        actual = digest(target)
        old = json.loads(receipt.read_text()) if receipt.exists() else {}
        if actual != (expected_sha256 or old.get("sha256")) or old.get("url") != url:
            raise ValueError(f"existing file is not the pinned download: {target}")
        return {**old, "reused": True}
    part = target.with_name(target.name + ".partial")
    if part.exists():
        raise ValueError(f"inspect incomplete prior download before retry: {part}")
    start, size, h = time.monotonic(), 0, hashlib.sha256()
    with urllib.request.urlopen(url, timeout=60) as response, part.open("xb") as stream:
        announced = response.headers.get("Content-Length")
        if announced and int(announced) > max_bytes:
            raise ValueError("download exceeds the declared byte budget")
        for block in iter(lambda: response.read(4 << 20), b""):
            size += len(block)
            if size > max_bytes:
                raise ValueError("download exceeds the byte budget")
            stream.write(block)
            h.update(block)
    actual = h.hexdigest()
    if expected_sha256 and actual != expected_sha256:
        raise ValueError(f"upstream checksum mismatch for {target.name}")
    os.replace(part, target)
    record = {"url": url, "path": str(target), "sha256": actual, "bytes": size,
              "elapsed_seconds": time.monotonic() - start,
              "upstream_sha256": expected_sha256, "reused": False}
    receipt.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"downloaded": target.name, "bytes": size, "sha256": actual}), flush=True)
    return record


def acquire(root):
    root = Path(root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    metadata_url = (f"https://huggingface.co/api/models/{BASE_REPOSITORY}/revision/"
                    f"{BASE_REVISION}?blobs=true")
    metadata = get_json(metadata_url)
    if metadata.get("sha") != BASE_REVISION:
        raise ValueError("model revision mismatch")
    accepted = {"config.json", "generation_config.json", "tokenizer.json", "tokenizer_config.json",
                "vocab.json", "merges.txt", "special_tokens_map.json", "chat_template.jinja",
                "preprocessor_config.json", "processor_config.json", "model.safetensors.index.json"}
    siblings = [item for item in metadata["siblings"]
                if item["rfilename"] in accepted or item["rfilename"].endswith(".safetensors")]
    if not any(item["rfilename"].endswith(".safetensors") for item in siblings):
        raise ValueError("no safetensors checkpoint")
    records = []
    source_files = {
        "manifest.json": f"{SOURCE_PREFIX}/edit/manifest.json",
        "edit.npz": f"{SOURCE_PREFIX}/edit/edit.npz",
        "teacher_forced_request.json": f"{SOURCE_PREFIX}/requests/fwd_24.json.claimed",
        "transfer_probe_bounds.json": f"{SOURCE_PREFIX}/work_notes/transfer_probe_bounds.json",
        "UPSTREAM_LICENSE": "LICENSE",
    }
    for name, path in source_files.items():
        url = f"https://raw.githubusercontent.com/{SOURCE_REPOSITORY}/{SOURCE_COMMIT}/{path}"
        records.append(download(url, root / "source" / name, 16 << 20))
    if sum(int(item.get("size", 0)) for item in siblings) > 6 << 30:
        raise ValueError("checkpoint exceeds the six GiB acquisition budget")
    for item in siblings:
        name = item["rfilename"]
        if Path(name).name != name:
            raise ValueError("unexpected nested model filename")
        lfs = item.get("lfs") or {}
        expected = lfs.get("sha256") or lfs.get("oid")
        if expected and expected.startswith("sha256:"):
            expected = expected.split(":", 1)[1]
        url = (f"https://huggingface.co/{BASE_REPOSITORY}/resolve/{BASE_REVISION}/"
               f"{urllib.parse.quote(name, safe='')}")
        records.append(download(url, root / "base" / name, 6 << 30, expected))
    report = {"schema": "hepta.mit_qwen.acquisition.v1", "base_repository": BASE_REPOSITORY,
              "base_revision": BASE_REVISION, "source_repository": SOURCE_REPOSITORY,
              "source_commit": SOURCE_COMMIT, "files": records,
              "downloaded_bytes": sum(r["bytes"] for r in records if not r["reused"])}
    (root / "acquisition.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    args = parser.parse_args()
    acquire(args.root)

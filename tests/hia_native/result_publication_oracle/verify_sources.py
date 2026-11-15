"""Materialize only the frozen original function needed by this Rust oracle."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tomllib


def checked_original(root: Path, runtime_root: Path):
    manifest = json.loads((root / "source_manifest.json").read_text())
    sources = {}
    for path, pin in manifest["files"].items():
        data = (runtime_root / path).read_bytes()
        if len(data) != pin["bytes"] or hashlib.sha256(data).hexdigest() != pin["sha256"]:
            raise AssertionError(f"frozen original source differs: {path}")
        sources[path] = data
    text = sources["src/mcp/server.rs"].decode("utf-8")
    start = text.index("fn append_hints(")
    end = text.index("\n// ── Tool parameter schemas", start)
    append = text[start:end].encode("utf-8")
    pin = manifest["extractions"]["append_hints"]
    if len(append) != pin["bytes"] or hashlib.sha256(append).hexdigest() != pin["sha256"]:
        raise AssertionError("original append_hints extraction differs")
    return manifest, sources, append


def check_dependency_subset(lock: bytes, original: bytes) -> int:
    packages = tomllib.loads(lock.decode("utf-8"))["package"]
    original_packages = tomllib.loads(original.decode("utf-8"))["package"]
    pins = {(p["name"], p["version"], p.get("source")): p.get("checksum")
            for p in original_packages}
    count = 0
    for package in packages:
        if "source" not in package:
            if package["name"] != "hepta-result-publication-original-oracle":
                raise AssertionError("unexpected unpinned local dependency")
            continue
        key = (package["name"], package["version"], package["source"])
        if key not in pins or pins[key] != package.get("checksum"):
            raise AssertionError(f"dependency differs from original lock: {key}")
        count += 1
    selected = {p["name"]: p["version"] for p in packages}
    if selected.get("rmcp") != "3.4.1" or selected.get("serde_json") != "1.0.151":
        raise AssertionError("original serializer versions differ")
    return count


def materialize(root: Path, runtime_root: Path, crate: Path) -> dict:
    manifest, sources, append = checked_original(root, runtime_root)
    count = check_dependency_subset((root / "Cargo.lock").read_bytes(), sources["Cargo.lock"])
    crate.mkdir(parents=True, exist_ok=False)
    (crate / "src").mkdir()
    (crate / "fixtures").mkdir()
    for name in ("Cargo.toml", "Cargo.lock", "src/main.rs"):
        shutil.copyfile(root / name, crate / name)
    (crate / "fixtures/original_append_hints.rs").write_bytes(append)
    return {"current_frozen_original_files_match": True,
            "source_commit": manifest["commit"], "original_git_history_required": False,
            "original_append_function_unchanged": True,
            "original_dependency_lock_match": True, "registry_dependency_count": count,
            "reference_domain": "append_hints with already-drained list plus locked SDK JSON",
            "protocol_version": manifest["protocol_version"],
            "request_context_dedup_not_reimplemented": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(materialize(Path(__file__).resolve().parent,
                                args.runtime_root.resolve(), args.output.resolve()), sort_keys=True))

"""Materialize exact original owners into a fresh isolated reference crate."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import shutil
import tomllib


def materialize(harness: Path, runtime: Path, crate: Path) -> dict:
    manifest = json.loads((harness / "source_manifest.json").read_bytes())
    sources = {}
    for name, expected in manifest["files"].items():
        raw = (runtime / name).read_bytes()
        if len(raw) != expected["bytes"] or hashlib.sha256(raw).hexdigest() != expected["sha256"]:
            raise ValueError("frozen original differs: " + name)
        sources[name] = raw
    delta = sources["src/mcp/fs/delta.rs"].decode()
    start = delta.index("/// Last full content served per file")
    end = delta.index("/// Line-ending agnostic", start)
    limit = re.search(r"^const MAX_CACHED_BYTES:.*$", delta, re.M)
    if limit is None:
        raise ValueError("original cache limit missing")
    cache = ("use std::collections::HashMap;\nuse std::sync::Mutex;\n" + limit.group(0) + "\n" + delta[start:end]).encode()
    expected = manifest["extractions"]["ViewCache"]
    if len(cache) != expected["bytes"] or hashlib.sha256(cache).hexdigest() != expected["sha256"]:
        raise ValueError("original complete cache struct/impl differs")
    original = tomllib.loads(sources["Cargo.lock"].decode())
    subset = tomllib.loads((harness / "Cargo.lock").read_text())
    pins = {(p["name"], p["version"]): p.get("checksum") for p in original["package"]}
    registry = [p for p in subset["package"] if "source" in p]
    for package in registry:
        if pins.get((package["name"], package["version"])) != package["checksum"]:
            raise ValueError("oracle registry version/checksum differs from original lock")
    crate.mkdir(parents=True, exist_ok=False)
    (crate / "src").mkdir()
    (crate / "fixtures").mkdir()
    for name in ("Cargo.toml", "Cargo.lock", "src/main.rs"):
        shutil.copyfile(harness / name, crate / name)
    (crate / "fixtures/original_request_ctx.rs").write_bytes(sources["src/mcp/request_ctx.rs"])
    (crate / "fixtures/original_view_cache.rs").write_bytes(cache)
    return {"original_function_bodies_unchanged": True, "current_complete_sources_match": True,
            "git_history_required": False, "original_commit": manifest["commit"],
            "registry_dependency_count": len(registry), "original_dependency_lock_match": True}

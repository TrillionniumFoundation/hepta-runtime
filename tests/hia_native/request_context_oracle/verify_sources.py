"""Extract original Rust into an isolated test crate after complete source checks."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import tomllib


def materialize(root: Path, runtime_root: Path, crate: Path) -> dict:
    manifest = json.loads((root / "source_manifest.json").read_text())
    sources = {}
    for path, pin in manifest["files"].items():
        data = (runtime_root / path).read_bytes()
        assert len(data) == pin["bytes"] and hashlib.sha256(data).hexdigest() == pin["sha256"], path
        sources[path] = data
    source = sources["src/mcp/server.rs"].decode()
    start = source.index("fn append_hints(")
    end = source.index("\n// ── Tool parameter schemas", start)
    append = source[start:end].encode()
    source = sources["src/mcp/fs/delta.rs"].decode()
    start = source.index("/// Last full content served per file")
    end = source.index("/// Line-ending agnostic", start)
    cache = ("use std::collections::HashMap;\nuse std::sync::Mutex;\n"
        + re.search(r"^const MAX_CACHED_BYTES:.*$", source, re.M).group(0)
        + "\n" + source[start:end]).encode()
    for data, pin in [(append, manifest["extractions"]["append_hints"]),
        (cache, manifest["extractions"]["ViewCache"])]:
        assert len(data) == pin["bytes"] and hashlib.sha256(data).hexdigest() == pin["sha256"]
    original_lock = tomllib.loads(sources["Cargo.lock"].decode())
    subset = tomllib.loads((root / "Cargo.lock").read_text())
    pins = {(p["name"], p["version"]): p.get("checksum") for p in original_lock["package"]}
    packages = [p for p in subset["package"] if "source" in p]
    for package in packages:
        assert pins[package["name"], package["version"]] == package["checksum"]
    crate.mkdir(parents=True, exist_ok=False)
    (crate / "src").mkdir()
    (crate / "fixtures").mkdir()
    for name in ["Cargo.toml", "Cargo.lock", "src/main.rs"]:
        shutil.copyfile(root / name, crate / name)
    (crate / "fixtures/original_request_ctx.rs").write_bytes(sources["src/mcp/request_ctx.rs"])
    (crate / "fixtures/original_append_hints.rs").write_bytes(append)
    (crate / "fixtures/original_view_cache.rs").write_bytes(cache)
    return {"current_frozen_original_files_match": True, "original_function_bodies_unchanged": True,
        "source_commit": manifest["commit"], "original_git_history_required": False,
        "original_dependency_lock_match": True, "registry_dependency_count": len(packages)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(materialize(Path(__file__).resolve().parent, args.runtime_root, args.output), sort_keys=True))

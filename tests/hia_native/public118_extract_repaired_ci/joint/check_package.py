"""Exact regular-file closure for the explicit 102-owner joint qualification."""
from pathlib import Path
import argparse
import ast
import hashlib
import json
import os
import stat

SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def pin(path):
    path = Path(path)
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    assert path.resolve(strict=True) == path.absolute()
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=SHA(raw),
        git_blob=hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest())


def check(root):
    root = Path(root).resolve(strict=True)
    profile = json.loads((root / "joint-source.json").read_bytes())
    assert profile["schema"] == "hepta.runtime.authority102-joint-source.v1"
    assert profile["graph_binding_sha256"] == "41a42a6247d8b4bf0ccee11e743bad28285273637b9f824fcbf2f0bf9bad0726"
    assert profile["physical_members"] == 102 and profile["shared_main_modified"] is False
    expected = profile["files"]
    seen = set()
    for directory, children, names in os.walk(root, followlinks=False):
        folder = Path(directory)
        assert all(not (folder / name).is_symlink() for name in children)
        for name in names:
            path = folder / name
            relative = path.relative_to(root).as_posix()
            if relative == "joint-source.json":
                continue
            assert relative in expected and relative not in seen, relative
            assert pin(path) == expected[relative], relative
            if relative.endswith(".py"):
                ast.parse(path.read_bytes(), filename=relative)
            seen.add(relative)
    assert seen == set(expected)
    for label in ("authority/source", "batch/native-source", "installed"):
        binding = root / label / "native/runtime_mcp_sources.json"
        assert pin(binding)["sha256"] == profile["graph_binding_sha256"]
    return dict(status="AUTHORITY102_COMPLETE_SOURCE_CLOSURE_PASS", files=len(expected) + 1,
        manifest=pin(root / "joint-source.json"), physical_members=102,
        graph_binding_sha256=profile["graph_binding_sha256"], native_or_rust_executions=0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    assert pin(args.source / "joint-source.json")["sha256"] == args.expected_sha256
    print(json.dumps(check(args.source), sort_keys=True))

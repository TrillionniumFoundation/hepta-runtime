"""Verify exact current original spans and deterministic wrapper composition."""
from pathlib import Path
import hashlib
import importlib.util
import json
import subprocess

ROOT = Path(__file__).resolve().parent
TARGET = "d3d75c30719db966b004756f610007a7c723729e"


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
        "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def check(target_checkout, core_source):
    target_checkout = Path(target_checkout).resolve(strict=True)
    core_source = Path(core_source).resolve(strict=True)
    proof = json.loads((ROOT / "project/SOURCE.json").read_bytes())
    assert proof["target_commit"] == TARGET
    assert subprocess.check_output(["git", "-C", str(target_checkout), "rev-parse", "HEAD"]).decode().strip() == TARGET
    for name, expected in proof["target_files"].items():
        assert pin((target_checkout / name).read_bytes()) == expected, name
    spec = importlib.util.spec_from_file_location("extract_sdk_reference_author", ROOT / "authoring/author_public_reference.py")
    author = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(author)
    files, reproduced = author.compose(ROOT / "baseline", core_source)
    assert reproduced == proof
    for name, expected in files.items():
        assert (ROOT / "project" / name).read_bytes() == expected, name
    assert {p.relative_to(ROOT / "project").as_posix() for p in (ROOT / "project").rglob("*") if p.is_file()} == set(files)
    return proof

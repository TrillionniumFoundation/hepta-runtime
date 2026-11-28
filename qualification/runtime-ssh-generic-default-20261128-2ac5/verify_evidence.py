#!/usr/bin/env python3
"""Verify complete qualification archives; no extraction or product execution."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import tarfile
import time

SHA = lambda b: hashlib.sha256(b).hexdigest()

def verify(root):
    started = time.monotonic()
    index = json.loads((root / "evidence/index.json").read_bytes())
    results = []
    for spec in index["archives"]:
        chunks = []
        for part in spec["parts"]:
            assert re.fullmatch(r"evidence/objects/[0-9a-f]{64}\.part", part["path"])
            p = root / part["path"]
            st = p.lstat()
            assert stat.S_ISREG(st.st_mode) and st.st_nlink == 1
            raw = p.read_bytes()
            assert len(raw) == part["bytes"] and SHA(raw) == part["sha256"]
            chunks.append(raw)
        archive = b"".join(chunks)
        assert len(archive) == spec["bytes"] and SHA(archive) == spec["sha256"]
        manifest_raw = (root / spec["manifest"]).read_bytes()
        assert SHA(manifest_raw) == spec["manifest_sha256"]
        manifest = json.loads(manifest_raw)
        members = manifest["members"]
        assert len(members) == spec["members"]
        assert len(manifest["directories"]) == spec["directories"]
        expected = {"manifest.json": {"bytes": len(manifest_raw),
                                      "sha256": SHA(manifest_raw), "mode": 0o400}}
        if spec["format"] == "complete-cas":
            for row in members.values():
                name = "objects/" + row["sha256"]
                want = {"bytes": row["bytes"], "sha256": row["sha256"], "mode": 0o400}
                assert name not in expected or expected[name] == want
                expected[name] = want
            assert len(expected) - 1 == spec["objects"]
        elif spec["format"] == "complete-files":
            for name, row in members.items():
                expected["files/" + name] = row
        else:
            raise AssertionError("undeclared archive format")
        seen = set()
        read_bytes = 0
        with gzip.GzipFile(fileobj=io.BytesIO(archive), mode="rb") as gz:
            with tarfile.open(fileobj=gz, mode="r|") as tar:
                for member in tar:
                    assert member.isfile() and member.name in expected
                    assert member.name not in seen
                    seen.add(member.name)
                    raw = tar.extractfile(member).read()
                    row = expected[member.name]
                    assert member.mode == row["mode"], member.name
                    assert len(raw) == row["bytes"] and SHA(raw) == row["sha256"], member.name
                    if member.name == "manifest.json":
                        assert raw == manifest_raw
                    read_bytes += len(raw)
            trailing = gz.read()
            assert not trailing.strip(b"\0")
        assert seen == set(expected)
        for name, row in members.items():
            assert isinstance(name, str) and name and ".." not in Path(name).parts
            assert 0 <= row["mode"] <= 0o7777 and row["bytes"] >= 0
        for name, row in manifest["directories"].items():
            assert isinstance(name, str) and ".." not in Path(name).parts
            assert 0 <= row["mode"] <= 0o7777
        results.append({"name": spec["name"], "sha256": spec["sha256"],
                        "members": len(members), "archive_entries": len(seen),
                        "complete_member_bytes": read_bytes, "passed": True})
    return {"passed": True, "archives": results, "seconds": time.monotonic() - started}

if __name__ == "__main__":
    print(json.dumps(verify(Path(__file__).resolve().parent), indent=2, sort_keys=True))

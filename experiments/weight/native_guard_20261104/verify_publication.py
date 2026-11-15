#!/usr/bin/env python3
"""Verify the declared source and public evidence bytes without running a model.

Use the companion Git commit to identify the complete repository. This verifier
checks the explicitly published changed files, not every unchanged base file.
"""

import hashlib
import json
from pathlib import Path


PACKAGE = Path(__file__).resolve().parent
ROOT = PACKAGE.parents[2]
MANIFEST = PACKAGE / "publication_manifest.json"


def main():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("schema") != "hepta.native-wsp-publication.v1":
        raise ValueError("Unknown publication manifest schema")
    records = manifest["files"]
    total_bytes = 0
    for name, expected in records.items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"Invalid relative path: {name}")
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"Missing regular file: {name}")
        data = path.read_bytes()
        if len(data) != expected["bytes"]:
            raise ValueError(f"Size mismatch: {name}")
        if hashlib.sha256(data).hexdigest() != expected["sha256"]:
            raise ValueError(f"SHA-256 mismatch: {name}")
        total_bytes += len(data)

    evidence_prefixes = (
        "experiments/weight/mit_wsp_replay_20261104",
        "experiments/weight/native_guard_20261104",
    )
    actual_evidence = {
        str(path.relative_to(ROOT))
        for prefix in evidence_prefixes
        for path in (ROOT / prefix).rglob("*")
        if path.is_file() and path != MANIFEST
        and "__pycache__" not in path.parts and path.suffix != ".pyc"
        # The controller's atomic writer keeps local coordination files.
        # They are not source or evidence and are never staged for publication.
        and not path.name.startswith(".hepta-lock-")
    }
    declared_evidence = {
        name for name in records
        if any(name.startswith(prefix + "/") for prefix in evidence_prefixes)
    }
    if actual_evidence != declared_evidence:
        raise ValueError({
            "unlisted_evidence": sorted(actual_evidence - declared_evidence),
            "missing_evidence": sorted(declared_evidence - actual_evidence),
        })
    print(json.dumps({
        "verified_files": len(records),
        "verified_bytes": total_bytes,
        "base_commit": manifest["base_commit"],
        "scope": "declared source and evidence integrity",
        "new_inference_or_training": False,
        "efficacy_qualified_by_this_check": False,
    }, indent=2))


if __name__ == "__main__":
    main()

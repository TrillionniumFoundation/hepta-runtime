"""Rebind the fixed nine-owner native packer without changing its adapter."""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

SOURCE = "c8762a6c08a7270e473b6868798de059cbee2443ad47c1cd49962fe5d27b4775"
IMAGE = "795da0a7234853e9e1afbf8f993321a2f12aa86f16c06a6374a1913473693417"
IMAGE_BYTES = 128422
BASE_PACKER = "c54c54f664944b7a243d8e8e3d10e2ba623ab7e8e4f4189962542722617969d0"
BASE_PROFILE = "927cb5e16d8c3fcb9f4d61dc00c4aa48ae09592fec8e28cb2ba3deb4b0950b92"

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()

def author(root, hepta, check=False):
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import _parse_assembly_document, render_assembly
    from hepta.hia_program import verify_program
    baseline = (root / "native/authority_profile.json").read_bytes()
    old = (root / "native/authority_packer.hepta").read_bytes()
    assert sha(baseline) == BASE_PROFILE and sha(old) == BASE_PACKER
    assert sha((root / "native/caller_authority.hepta").read_bytes()) == SOURCE
    profile = json.loads(baseline)
    old_member = copy.deepcopy(profile["members"][0])
    profile["members"][0].update(source_sha256=SOURCE, image_sha256=IMAGE, image_bytes=IMAGE_BYTES)
    profile.update(schema="hepta.runtime.caller-owner-export-profile.v2", new_version=True,
        target_commit="d3d75c30719db966b004756f610007a7c723729e",
        public_route_qualified=False, current_http_startup_qualified=False)
    profile_raw = encoded(profile)
    before = _parse_assembly_document(old)
    after = copy.deepcopy(before)
    changes = [("b0", "v7", old_member["image_bytes"], IMAGE_BYTES)]
    old_words = struct.unpack("<8Q", bytes.fromhex(old_member["source_sha256"] + old_member["image_sha256"]))
    new_words = struct.unpack("<8Q", bytes.fromhex(SOURCE + IMAGE))
    for i, (a, b) in enumerate(zip(old_words, new_words, strict=True)):
        changes.append(("b" + str(16 + 2 * i), "v" + str(110 + 13 * i), a, b))
    # The descriptor pins and the independently calculated SHA digest are both
    # mandatory. Rebinding only descriptor words must continue to be rejected.
    old_digest = struct.unpack(">8I", bytes.fromhex(old_member["image_sha256"]))
    new_digest = struct.unpack(">8I", bytes.fromhex(IMAGE))
    for i, (a, b) in enumerate(zip(old_digest, new_digest, strict=True)):
        changes.append(("b" + str(32 + 2 * i), "v" + str(219 + 11 * i), a, b))
    function = after["functions"][21]
    assert function["name"] == "f21"
    for block_id, value_id, a, b in changes:
        block = next(row for row in function["blocks"] if row["id"] == block_id)
        op = next(row for row in block["ops"] if row["out"] == [{"name": value_id, "type": "u64"}])
        assert op == {"op": "const", "args": [], "out": [{"name": value_id, "type": "u64"}], "attrs": {"value": a}}
        op["attrs"]["value"] = b
    verify_program(after)
    inverse = copy.deepcopy(after)
    for block_id, value_id, a, b in changes:
        block = next(row for row in inverse["functions"][21]["blocks"] if row["id"] == block_id)
        next(row for row in block["ops"] if row["out"] == [{"name": value_id, "type": "u64"}])["attrs"]["value"] = a
    assert inverse == before
    raw = render_assembly(after).encode()
    provenance = json.loads((root / "native/authority_packer_provenance.json").read_bytes())
    provenance.update(profile_sha256=sha(profile_raw), source_sha256=sha(raw))
    provenance["root_image_rebind"] = {"new_version": True, "actual_pack_executed": False,
        "root_source_sha256": SOURCE, "root_image_sha256": IMAGE, "root_image_bytes": IMAGE_BYTES,
        "old_packer_sha256": BASE_PACKER, "old_profile_sha256": BASE_PROFILE,
        "changed_function": "f21", "changed_constant_count": len(changes),
        "inverse_all_function_asts_exact": True, "mechanical_adapter_unchanged": True,
        "author_source_sha256": sha(Path(__file__).read_bytes())}
    provenance_raw = encoded(provenance)
    builder_path = root / "scripts/hia_native_owner_export_build.py"
    builder = builder_path.read_text()
    for name, value in {"PROFILE_SHA": sha(profile_raw), "PACKER_SHA": sha(raw), "PROVENANCE_SHA": sha(provenance_raw)}.items():
        builder, count = re.subn(r'^' + name + r' = "[0-9a-f]{64}"$', name + ' = "' + value + '"', builder, flags=re.M)
        assert count == 1
    outputs = {root / "native/caller_owner_export_profile.json": profile_raw,
        root / "native/caller_owner_export_packer.hepta": raw,
        root / "native/caller_owner_export_packer_provenance.json": provenance_raw,
        builder_path: builder.encode()}
    for path, value in outputs.items():
        if check:
            assert path.read_bytes() == value, str(path)
        else:
            path.write_bytes(value)
    return {str(path.relative_to(root)): {"bytes": len(raw), "sha256": sha(raw)} for path, raw in outputs.items()}

if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--source-root", type=Path, required=True)
    p.add_argument("--hepta", type=Path, required=True)
    p.add_argument("--check", action="store_true")
    a=p.parse_args()
    print(json.dumps(author(a.source_root, a.hepta, a.check), sort_keys=True))

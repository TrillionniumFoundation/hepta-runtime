"""Freshly compile and link the complete private Local four-command HIA graph."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import sys
import time

sys.dont_write_bytecode = True
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--hepta", required=True, type=Path)
parser.add_argument("--source", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
parser.add_argument("--bootstrap", type=Path)
args = parser.parse_args()
source = args.source.resolve(strict=True)
output = args.output.resolve()
output.mkdir(parents=True, exist_ok=False)
build_root = output / "build"
if args.bootstrap is not None:
    bootstrap = args.bootstrap.resolve(strict=True)
    receipt = json.loads((bootstrap / "bootstrap.json").read_bytes())
    expected = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
    assert receipt["generation_sha256"] == expected
    for label in ("B1", "B2", "B3"):
        assert hashlib.sha256((bootstrap / (label + ".image.bin")).read_bytes()).hexdigest() == expected
    build_root.mkdir()
    shutil.copytree(bootstrap, build_root / "bootstrap")
sys.path.insert(0, str(source / "scripts"))
from text_editor_create_private_build import build_runtime_mcp

started = time.monotonic()
manifest = build_runtime_mcp(args.hepta.resolve(strict=True), build_root,
    name="text-editor-complete-private", source_root=source, private_fixture=True)
metadata = json.loads(manifest.read_bytes())
assert metadata["physical_images"] == 75
assert len(metadata["members"]) == 75
assert all(member["fresh_compile"] is True for member in metadata["members"])
elf = manifest.parent / metadata["elf"]
assert hashlib.sha256(elf.read_bytes()).hexdigest() == metadata["elf_sha256"]
typed = next(row for row in metadata["members"] if row["name"] == "wide_value")
typed_members = {"serde_json_span": {
    "manifest": typed["manifest"], "manifest_sha256": typed["manifest_sha256"]}}
(output / "typed-members.json").write_text(json.dumps(typed_members, indent=2, sort_keys=True) + "\n")
summary = dict(status="FRESH_COMPLETE_PRIVATE_GRAPH_BUILD_PASS",
    manifest=str(manifest), manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
    elf=str(elf), elf_bytes=elf.stat().st_size, elf_sha256=metadata["elf_sha256"],
    fresh_native_members=75, source_members=75, fresh_hia_link_pack=True,
    elapsed_seconds=time.monotonic() - started,
    compiler_sha256=metadata["compiler_image_sha256"],
    bootstrap_reused=args.bootstrap is not None, ordinary_parity_qualified=False,
    public_text_editor_route=False, whole_runtime_replaced=False)
(output / "BUILD.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
print(json.dumps(summary, sort_keys=True), flush=True)

"""Build the raw-declaration catalog capability for the current public graph."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import time

POLICY = "tests/hia_native/catalog_policy_ci/source"
PROFILE_SHA256 = "4ac13e456d7e2ed6344a89fef73c19790dcc1c85546e2d5362de165e7d0aa6ed"
FIXED_IMAGE = {"bytes": 2162432, "sha256": "9227b6fc1037aaae89e45380df1c0c12ade05fded83e3fe0736893116aceca81"}
FIXED_SOURCES = (
    "scripts/public_full_catalog_build.py", "scripts/hia_native_full_catalog.py",
    "asm/full_catalog_capability.S", "authoring/full_catalog/ABI.md",
    "authoring/full_catalog/author_pipeline.py", "authoring/full_catalog/pipeline.pseudo",
    "authoring/full_catalog/verification.json", "native/full_catalog_pipeline.hepta",
    "native/full_catalog_pipeline_composition.json", "native/runtime_mcp_catalog_ninth.hepta",
    "native/runtime_mcp_catalog_ninth_composition.json", "tests/hia_native/full_catalog_loader.py",
    "tests/hia_native/test_full_catalog_capability.py", "scripts/hia_native_public_file_info_walk.py",
    "scripts/hia_native_build.py", "scripts/hia_native_loader.py",
)

def pin(path):
    raw = Path(path).read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

def source_paths(root):
    profile = root / POLICY / "source-profile.json"
    if pin(profile)["sha256"] != PROFILE_SHA256:
        raise ValueError("complete original catalog source authority differs")
    document = json.loads(profile.read_bytes())
    paths = set(FIXED_SOURCES)
    paths.add(POLICY + "/source-profile.json")
    for name, expected in document["files"].items():
        rel = Path(name)
        if rel.is_absolute() or ".." in rel.parts or str(rel) != name:
            raise ValueError("catalog source path is not canonical")
        source = root / POLICY / rel
        if pin(source) != expected:
            raise ValueError("whole original catalog input differs: " + name)
        paths.add(POLICY + "/" + name)
    return paths

def build_image(root, build, folder, retained_image):
    before = {path: pin(root/path) for path in sorted(source_paths(root))}
    output = folder / "full-catalog"
    command = [sys.executable, "-I", "-B", str(root/"scripts/hia_native_full_catalog.py"),
               "--source", str(root), "--hepta", str(build.hepta),
               "--bootstrap", str(build.root/"bootstrap"), "--output", str(output)]
    started = time.monotonic()
    with (folder/"full-catalog.stdout").open("xb") as stdout, (folder/"full-catalog.stderr").open("xb") as stderr:
        process = subprocess.run(command, cwd=root, stdin=subprocess.DEVNULL,
                                 stdout=stdout, stderr=stderr, timeout=180, check=False)
    step = {"command": command, "exit_code": process.returncode,
            "elapsed_seconds": time.monotonic()-started, "timeout_seconds": 180}
    (folder/"full-catalog.process.json").write_text(json.dumps(step, sort_keys=True, indent=2)+"\n")
    if process.returncode != 0:
        raise ValueError("complete original catalog capability build failed")
    manifest = output/"BUILD.json"
    record = json.loads(manifest.read_bytes())
    if (record["status"] != "PASS" or record["runtime_hia_images"] != 5
            or record["runtime_images"] != ["owner", "policy", "value", "sdk", "retained"]
            or record["declaration"]["tools"] != 136 or record["precomputed_result_wire_used"] is not False):
        raise ValueError("full catalog runtime composition differs")
    image = output/record["flat_image"]["path"]
    if (pin(image) != FIXED_IMAGE or record["flat_image"]["entry_offset"] != 0
            or record["flat_image"]["container_offset"] != 256):
        raise ValueError("qualified full catalog flat image differs")
    if record["members"]["retained"]["image_pin"] != pin(retained_image):
        raise ValueError("complete original public catalog image was not retained")
    if before != {path: pin(root/path) for path in sorted(source_paths(root))}:
        raise ValueError("catalog source closure changed during integration")
    return image, {
        "build_manifest": str(manifest), "build_manifest_pin": pin(manifest),
        "flat_image": str(image), "flat_image_pin": pin(image), "source_files": before,
        "runtime_hia_images": 5, "additional_runtime_hia_images": 4,
        "original_public_catalog_retained_image": pin(retained_image),
        "complete_declaration_input_count": 136, "profile": 11,
        "configured_presence_flags": [0, 1], "public_dispatch_qualified": False,
        "build": record, "process": step,
    }

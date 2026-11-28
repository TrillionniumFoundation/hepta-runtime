"""Independent full artifact custody and read-only admission; no native or Rust execution."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tarfile
import time
import zipfile

sys.dont_write_bytecode = True
CASES = {
    "public80": {
        "artifact": 14196246901, "run": 43799308240,
        "head": "bcfe93e2d5dc22dd6a07e3889385a2ade38eb936",
        "bytes": 82149250,
        "sha256": "cc4116f4009b86d9eba915f8bb15c3e53df9b1ea7106cab407f7ee42e30b98a8",
    },
    "annotation": {
        "artifact": 14196351716, "run": 43799976079,
        "head": "80d4a3761a7827e16334972003cc6ac006719afc",
        "bytes": 20235405,
        "sha256": "e0be870d987ccc77cb33a99833d1b4b63bd30cc37ffa330ca850d508aeb51f75",
    },
}

def pin(path):
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return dict(bytes=path.stat().st_size, sha256=digest)

def safe(name):
    relative = Path(name)
    assert not relative.is_absolute() and ".." not in relative.parts
    return relative

def snapshot(root):
    result = {}
    for path in sorted(root.rglob("*")):
        row = path.lstat()
        assert stat.S_ISREG(row.st_mode) or stat.S_ISDIR(row.st_mode)
        if path.is_file():
            result[str(path.relative_to(root))] = dict(
                **pin(path), mode=row.st_mode, inode=row.st_ino,
                mtime_ns=row.st_mtime_ns, ctime_ns=row.st_ctime_ns)
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", choices=tuple(CASES), required=True)
    parser.add_argument("--zip", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    expected = CASES[args.kind]
    assert pin(args.zip) == {key: expected[key] for key in ("bytes", "sha256")}
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    outer = output / "outer"
    outer.mkdir()
    with zipfile.ZipFile(args.zip) as archive:
        for member in archive.infolist():
            relative = safe(member.filename)
            assert not member.is_dir()
            target = outer / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, target.open("xb") as sink:
                while block := source.read(1 << 20):
                    sink.write(block)
    archive = next(outer.glob("*.tar.gz"))
    if args.kind == "public80":
        receipt = json.loads((outer / "public-constructor-evidence.archive.json").read_bytes())
        assert pin(archive) == dict(bytes=receipt["archive_bytes"], sha256=receipt["archive_sha256"])
    else:
        receipt = json.loads((outer / "manifest.json").read_bytes())
        assert pin(archive) == {key: receipt["archive"][key] for key in ("bytes", "sha256")}
    evidence = output / "evidence"
    evidence.mkdir()
    with tarfile.open(archive, "r:gz") as stream:
        members = stream.getmembers()
        assert len({member.name for member in members}) == len(members)
        for member in members:
            safe(member.name)
            assert member.isfile() or member.isdir()
        stream.extractall(evidence, filter="data")
    if args.kind == "public80":
        manifest_path = evidence / "artifact-manifest.json"
        assert pin(manifest_path)["sha256"] == receipt["artifact_manifest_sha256"]
        manifest = json.loads(manifest_path.read_bytes())
        inventory = manifest["files"]
        allowed_extra = {"artifact-manifest.json"}
        command = [sys.executable, "-I", "-B",
            str(evidence / "recipe-source/drivers/verify_complete.py"),
            "--source", str(evidence / "recipe-source"),
            "--run", str(evidence / "run"),
            "--module-map", str(evidence / "module-map.json"),
            "--require-recipe-pass"]
    else:
        inventory = receipt["members"]
        allowed_extra = set()
        command = [sys.executable, "-I", "-B",
            str(evidence / "recipe-source/tests/hia_native/scope_annotation/verify_readonly.py"),
            "--source-root", str(evidence / "recipe-source"),
            "--output", str(evidence / "capture"), "--phase", "verify"]
    actual = {str(path.relative_to(evidence)) for path in evidence.rglob("*") if path.is_file()}
    assert actual == set(inventory) | allowed_extra
    complete_bytes = 0
    for name, expected_pin in inventory.items():
        path = evidence / safe(name)
        assert pin(path) == expected_pin, name
        complete_bytes += expected_pin["bytes"]
    before = snapshot(evidence)
    started = time.monotonic()
    process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180,
        env={"PATH": os.environ["PATH"], "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
             "PYTHONDONTWRITEBYTECODE": "1"})
    review = output / "review"
    review.mkdir()
    (review / "reader.stdout").write_bytes(process.stdout)
    (review / "reader.stderr").write_bytes(process.stderr)
    assert process.returncode == 0 and not process.stderr
    verified = json.loads(process.stdout)
    assert before == snapshot(evidence), "reader mutated retained bytes or metadata"
    if args.kind == "public80":
        assert verified["status"] == "READONLY_FRESH80_CONSTRUCTOR_PUBLIC90_PASS"
        assert verified["fresh_public_members"] == 80 and verified["actual_target_rust_cases"] == 65
        assert verified["public_counts"]["response_lines"] == 90
        assert verified["native_or_original_code_launched"] is False
    else:
        assert verified["status"] == "READONLY_PASS" and verified["phase"] == "verify"
        assert verified["verification"]["status"] == "QUALIFIED_BOUNDED_FUNCTION"
        assert verified["verification"]["original_pending"] is False
        assert verified["native_processes_executed"] == verified["original_processes_executed"] == 0
    result = dict(schema="hepta.complete-artifact-readback.v1", status="PASS",
        kind=args.kind, input=expected, archive=pin(archive),
        complete_files=len(inventory), complete_file_bytes=complete_bytes,
        complete_tree_bytes_and_metadata_unchanged=True,
        reader=dict(command=command, exit_code=process.returncode,
            timeout_seconds=180, elapsed_seconds=time.monotonic()-started,
            stdout=pin(review/"reader.stdout"), stderr=pin(review/"reader.stderr")),
        verification=verified, new_native_processes=0, new_rust_processes=0,
        whole_runtime_replaced=False, production_activated=False, old_stack_removal_qualified=False)
    (review / "result.json").write_text(json.dumps(result, sort_keys=True, indent=2)+"\n")
    print("HIA_COMPLETE_READBACK "+json.dumps(result, sort_keys=True), flush=True)

if __name__ == "__main__":
    main()

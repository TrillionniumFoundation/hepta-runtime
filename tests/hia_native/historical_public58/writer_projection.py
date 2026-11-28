"""Restore the exact read-only graph before unchanged historical qualifications.

Every current writer input remains at its original path. The independently
owned output receives the complete retained 856-input graph, then the original
162-to-126 and 126-to-58 readers run with their original authorities and limits.
This source operation does not qualify either executable's behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types


PREFIX = Path("tests/hia_native/historical_public58")
PROFILE = PREFIX / "WRITER_PROJECTION.json"
PROFILE_PIN = {'bytes': 12954, 'sha256': '93556d4d582eba8390d74e168e3d9a2455e51d37feb7f60a7c2105745b5e0907', 'git_blob': '2a7e21032fcbc32ff9883b60c6588cc67355dbe9'}
READER = PREFIX / "current_projection.py"
READER_SHA256 = "85d5995c7fefe666a769bb0b2aaeeab63ff7c7752aef4fdac270599083eee2c2"
CURRENT_BINDING_SHA256 = "2e02569c77e019ae707719680e3d17dd05955fa3a2e2e25024bcb26b955a11ae"
READ_BINDING_SHA256 = "4b77517b7c1d6eba96ede8fbfaaed51446ca1908c96ff6c63ce49e328e20c514"
DIRECTORIES = ("native", "asm", "scripts", "src", "tests", ".github", "authoring",
               "vendor", "runtime_support", "qualification")
ROOT_FILES = ("Cargo.toml", "Cargo.lock", "rustfmt.toml", "README.md", "AGENTS.md")
RECEIPT = "WRITER_SOURCE_PROJECTION.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def old_reader(source):
    path = source / READER
    require(path.resolve(strict=True) == path and path.is_file(), "ordinary retained projection reader")
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == READER_SHA256,
            "complete original current projection reader changed")
    result = types.ModuleType("retained_current_projection")
    result.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), result.__dict__)
    return result


def manifest(source):
    reader = old_reader(source)
    raw = reader.read(source, PROFILE)
    require(reader.pin(raw) == PROFILE_PIN, "writer projection authority changed")
    value = json.loads(raw)
    require(value["schema"] == "hepta.historical-public58.writer-source-projection.v1",
            "writer projection authority schema changed")
    require(value["current_binding"]["sha256"] == CURRENT_BINDING_SHA256
            and value["retained_binding"]["sha256"] == READ_BINDING_SHA256
            and value["current_bound_sources"] == 1062 and value["retained_bound_sources"] == 856,
            "complete writer and retained graph extents changed")
    require(len(value["restore"]) == 15 and len(value["exclude_native_sources"]) == 10,
            "writer projection restore or exclusion scope changed")
    require(not set(value["restore"]) & set(value["exclude_native_sources"]),
            "writer projection domains overlap")
    require(all(value[name] is False for name in ("whole_runtime_replaced", "production_activated",
            "old_stack_removal_qualified", "historical_pass_relabelled")), "writer projection scope changed")
    return reader, value


def admit(source):
    reader, value = manifest(source)
    captured = {}

    def capture(name, identity):
        raw = reader.read(source, name)
        actual = reader.pin(raw)
        require(all(actual[key] == expected for key, expected in identity.items()),
                "writer projection preimage changed: " + str(name))
        captured[str(name)] = raw
        return raw

    row = value["current_binding"]
    current = json.loads(capture(row["path"], {k: row[k] for k in ("bytes", "sha256", "git_blob")}))
    require(len(current["sources"]) == 1062, "complete current writer source closure changed")
    for name, identity in current["sources"].items():
        capture(name, identity)
    row = value["retained_binding"]
    retained = json.loads(capture(row["path"], {k: row[k] for k in ("bytes", "sha256", "git_blob")}))
    require(len(retained["sources"]) == 856, "complete retained read source closure changed")
    for name, identity in retained["sources"].items():
        capture(value["restore"].get(name, {}).get("fixture", name), identity)
    old = reader.manifest(source)
    native = {p.relative_to(source).as_posix() for p in (source / "native").rglob("*.hepta")}
    require(native == set(old["current_native_sources"]) | set(value["exclude_native_sources"])
            and len(native) == 261, "complete writer native inventory changed")
    for name, identity in old["current_native_sources"].items():
        capture(name, identity)
    for name, identity in value["exclude_native_sources"].items():
        capture(name, identity)
    for name, row in value["restore"].items():
        capture(name, row["current"])
        capture(row["fixture"], row["retained"])
    for name, identity in value["workflow_inputs"].items():
        capture(name, identity)
    for name, raw in captured.items():
        require(reader.read(source, name) == raw,
                "writer source changed at terminal readback: " + name)
    require({p.relative_to(source).as_posix() for p in (source / "native").rglob("*.hepta")} == native,
            "writer native inventory changed at terminal readback")
    return reader, value


def snapshot(source, reader=None):
    reader = reader or old_reader(source)
    names = set()
    for directory in DIRECTORIES:
        folder = source / directory
        if not folder.exists():
            continue
        require(folder.resolve(strict=True) == folder and folder.is_dir(),
                "ordinary writer projection directory required")
        for path in folder.rglob("*"):
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            require(not path.is_symlink(), "writer projection refuses symbolic links")
            if not path.is_dir():
                names.add(path.relative_to(source).as_posix())
    for name in ROOT_FILES:
        if (source / name).exists():
            names.add(name)
    result = {}
    for name in sorted(names):
        raw, mode = reader.regular(source, name)
        result[name] = {**reader.pin(raw), "mode": mode}
    return result


def project(source, output):
    require(sys.flags.optimize == 0, "writer projection requires assertions enabled")
    source = source.resolve(strict=True)
    reader, value = admit(source)
    output = output.absolute()
    require(output.parent.resolve(strict=True) == output.parent and not output.exists()
            and not output.is_relative_to(source), "writer projection requires a fresh independent output")
    original = snapshot(source, reader)
    expected = dict(original)
    output.mkdir(mode=0o700)
    for name, identity in original.items():
        raw, mode = reader.regular(source, name)
        require({**reader.pin(raw), "mode": mode} == identity, "writer source changed before copy: " + name)
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(raw)
        target.chmod(mode)
    for name, row in value["restore"].items():
        require(reader.pin(reader.read(output, name)) == row["current"], "writer restore preimage changed")
        raw = reader.read(source, row["fixture"])
        require(reader.pin(raw) == row["retained"], "writer retained source changed")
        (output / name).write_bytes(raw)
        expected[name] = {**row["retained"], "mode": original[name]["mode"]}
    for name, identity in value["exclude_native_sources"].items():
        require(reader.pin(reader.read(output, name)) == identity, "writer exclusion preimage changed")
        (output / name).unlink()
        del expected[name]
    require(snapshot(output, reader) == expected, "complete writer projection output changed")
    require(snapshot(source, reader) == original, "writer source changed during projection")
    reader.admit_current(output)
    admit(source)
    receipt = {"schema": "hepta.historical-public58.writer-source-projection-receipt.v1",
        "status": "WRITER_SOURCE_PROJECTED", "authority": PROFILE_PIN,
        "input_source": str(source), "output_source": str(output), "input_files": original,
        "projected_files": expected, "restored_paths": sorted(value["restore"]),
        "excluded_native_paths": sorted(value["exclude_native_sources"]),
        "current_runtime_hia_images": 175, "retained_runtime_hia_images": 162,
        "current_bound_sources": 1062, "retained_bound_sources": 856,
        "native_or_rust_executed": False, "historical_pass_relabelled": False,
        "current_production_sources_unchanged": True}
    (output / RECEIPT).write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    verify(source, output)
    return receipt


def verify(source, output):
    source, output = source.resolve(strict=True), output.resolve(strict=True)
    reader, value = admit(source)
    receipt = json.loads(reader.read(output, RECEIPT))
    require(receipt["schema"] == "hepta.historical-public58.writer-source-projection-receipt.v1"
            and receipt["status"] == "WRITER_SOURCE_PROJECTED" and receipt["authority"] == PROFILE_PIN,
            "writer projection receipt authority changed")
    require(receipt["input_source"] == str(source) and receipt["output_source"] == str(output),
            "writer projection receipt belongs to another root")
    require(receipt["restored_paths"] == sorted(value["restore"])
            and receipt["excluded_native_paths"] == sorted(value["exclude_native_sources"]),
            "writer projection receipt scope changed")
    original = snapshot(source, reader)
    require(receipt["input_files"] == original, "writer projection source drifted")
    expected = dict(original)
    for name, row in value["restore"].items():
        expected[name] = {**row["retained"], "mode": original[name]["mode"]}
    for name in value["exclude_native_sources"]:
        del expected[name]
    require(receipt["projected_files"] == expected and snapshot(output, reader) == expected,
            "complete writer projected source receipt or files changed")
    reader.admit_current(output)
    return {"status": "WRITER_SOURCE_PROJECTION_VERIFIED", "restored_paths": len(value["restore"]),
        "excluded_native_paths": 10, "current_runtime_hia_images": 175,
        "retained_runtime_hia_images": 162, "native_or_rust_executed": False,
        "historical_pass_relabelled": False}


def matches(source):
    return (source / PROFILE).is_file() and hashlib.sha256(
        (source / "native/runtime_mcp_sources.json").read_bytes()).hexdigest() == CURRENT_BINDING_SHA256


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check-only", action="store_true")
    modes.add_argument("--project-read", action="store_true")
    modes.add_argument("--project-profile", action="store_true")
    args = parser.parse_args(argv)
    require(sys.flags.isolated == 1 and sys.flags.optimize == 0 and sys.dont_write_bytecode,
            "writer projection must run with -I -B and assertions enabled")
    source = args.source.resolve(strict=True)

    def compose(output, check=False):
        current = output if args.project_read else output.with_name(output.name + ".writer-read")
        project(source, current)
        if args.project_read:
            result = verify(source, current)
            result["source_root"] = str(current)
            return result
        command = [sys.executable, "-I", "-B", str(current / READER), "--source", str(current)]
        command += ["--check-only"] if check else ["--output", str(output)]
        if args.project_profile:
            command += ["--project-only"]
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (current / "retained.stdout").write_bytes(completed.stdout)
        (current / "retained.stderr").write_bytes(completed.stderr)
        require(completed.returncode == 0, "unchanged retained projection failed: "
                + completed.stderr.decode(errors="replace"))
        verify(source, current)
        result = json.loads(completed.stdout)
        result["writer_source_projection"] = {"authority": PROFILE_PIN,
            "current_source": str(source), "retained_source": str(current),
            "current_runtime_hia_images": 175, "retained_runtime_hia_images": 162,
            "native_or_rust_executed": False, "historical_pass_relabelled": False}
        return result

    if args.check_only:
        with tempfile.TemporaryDirectory(prefix="hia-writer-profile-") as directory:
            result = compose(Path(directory) / "profile", check=True)
    else:
        require(args.output is not None, "writer projection output is required")
        result = compose(args.output.absolute())
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

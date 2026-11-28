"""Compose the current public read graph with the unchanged historical profile.

The original profile and reference owners consume their exact earlier inputs in
an explicit, separately owned directory. Current native sources remain intact.
This operation qualifies source custody only; no HIA or Rust behavior is inferred.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


PREFIX = Path("tests/hia_native/historical_public58")
PROFILE = PREFIX / "CURRENT_PROJECTION.json"
FIXTURE = PREFIX / "projection_source"
PROFILE_PIN = {'bytes': 72066, 'sha256': '1fc011c2453a78bda610914c69818190f5671124bfc16db0f4c5b5ef387c807f', 'git_blob': '60ea36c82e88130a816bd26c1c279baedf88aad7'}
CURRENT_BINDING_SHA256 = "4b77517b7c1d6eba96ede8fbfaaed51446ca1908c96ff6c63ce49e328e20c514"
DIRECTORIES = ("native", "scripts", "src", "tests", ".github", "authoring", "vendor", "runtime_support")
ROOT_FILES = ("Cargo.toml", "Cargo.lock", "rustfmt.toml", "README.md", "AGENTS.md")
RECEIPT = "CURRENT_SOURCE_PROJECTION.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def regular(root, name):
    relative = Path(name)
    require(not relative.is_absolute() and relative.parts
            and all(part not in ("", ".", "..") for part in relative.parts),
            "invalid source projection path")
    path = root / relative
    require(path.resolve(strict=True) == path, "source projection refuses symbolic links: " + str(name))
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), "source projection requires an ordinary file: " + str(name))
    raw = path.read_bytes()
    after = path.lstat()
    identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size,
                             item.st_mtime_ns, item.st_ctime_ns)
    require(identity(before) == identity(after) and len(raw) == after.st_size,
            "source projection input changed during read: " + str(name))
    return raw, after.st_mode & 0o777


def read(root, name):
    return regular(root, name)[0]


def selected(root):
    names = set()
    for directory in DIRECTORIES:
        folder = root / directory
        if not folder.exists():
            continue
        require(folder.resolve(strict=True) == folder and folder.is_dir(),
                "source projection directory is not a real directory: " + directory)
        for path in folder.rglob("*"):
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            require(not path.is_symlink(), "source projection refuses symbolic links: " + str(path))
            if path.is_dir():
                continue
            require(stat.S_ISREG(path.lstat().st_mode), "nonregular source projection input")
            names.add(path.relative_to(root).as_posix())
    for name in ROOT_FILES:
        path = root / name
        if path.exists():
            names.add(name)
    return names


def snapshot(root):
    result = {}
    for name in sorted(selected(root)):
        raw, mode = regular(root, name)
        result[name] = {**pin(raw), "mode": mode}
    return result


def manifest(source):
    raw = read(source, PROFILE)
    require(pin(raw) == PROFILE_PIN, "current-to-historical source authority changed")
    value = json.loads(raw)
    require(value["schema"] == "hepta.historical-public58.current-source-projection.v1",
            "current-to-historical source schema differs")
    require(len(value["restore"]) == 21 and len(value["exclude_new_native_sources"]) == 21,
            "current-to-historical projection domain changed")
    require(not set(value["restore"]) & set(value["exclude_new_native_sources"]),
            "projection restore and exclusion domains overlap")
    require(value["current_native_source_count"] == 251
            and value["projected_native_source_count"] == 230
            and value["current_registered_components"] == 196
            and value["historical_registered_components"] == 195,
            "current and historical native inventory relationship changed")
    for key in ("whole_runtime_replaced", "production_activated", "old_stack_removal_qualified"):
        require(value[key] is False, "source projection cannot qualify runtime replacement")
    return value


def admit_current(source):
    value = manifest(source)
    captured = {}

    def capture(name, expected):
        raw = read(source, name)
        actual = pin(raw)
        require(all(actual[key] == digest for key, digest in expected.items()),
                "current projection preimage changed: " + str(name))
        captured[str(name)] = raw
        return raw

    for field in ("profile", "reference_profile", "current_binding"):
        row = value[field]
        capture(row["path"], {key: row[key] for key in ("bytes", "sha256", "git_blob")})
    binding = json.loads(captured[value["current_binding"]["path"]])
    require(value["current_binding"]["sha256"] == CURRENT_BINDING_SHA256
            and len(binding["sources"]) == value["current_bound_source_count"] == 856,
            "complete current public source binding changed")
    for name, expected in binding["sources"].items():
        capture(name, expected)
    native = {path.relative_to(source).as_posix()
              for path in (source / "native").rglob("*.hepta")}
    require(native == set(value["current_native_sources"]),
            "complete current native source inventory changed")
    for name, expected in value["current_native_sources"].items():
        capture(name, expected)
    for name, row in value["restore"].items():
        capture(name, row["current"])
        capture(FIXTURE / name, row["profile"])
    for name, expected in value["exclude_new_native_sources"].items():
        require(name in native and value["current_native_sources"][name] == expected,
                "current-only native exclusion is not an exact current source")
        capture(name, expected)
    original = value["original_reader"]
    capture(FIXTURE / original["path"],
            {key: original[key] for key in ("bytes", "sha256", "git_blob")})
    fixture = source / FIXTURE
    fixture_names = {path.relative_to(fixture).as_posix()
                     for path in fixture.rglob("*") if path.is_file()}
    require(fixture_names == set(value["restore"]) | {original["path"]},
            "profile projection fixture inventory changed")
    for name, raw in captured.items():
        require(read(source, name) == raw, "projection source changed at terminal readback: " + name)
    require({path.relative_to(source).as_posix()
             for path in (source / "native").rglob("*.hepta")} == native,
            "current native inventory changed at terminal readback")
    return value


def project(source, output):
    require(sys.flags.optimize == 0, "source projection requires assertions enabled")
    source = source.resolve(strict=True)
    value = admit_current(source)
    output = output.absolute()
    require(output.parent.resolve(strict=True) == output.parent and not output.exists()
            and not output.is_relative_to(source), "source projection requires a fresh independent output")
    original = snapshot(source)
    expected = dict(original)
    output.mkdir(mode=0o700)
    for name, identity in original.items():
        raw, mode = regular(source, name)
        require({**pin(raw), "mode": mode} == identity,
                "source changed between admission and projection: " + name)
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(raw)
        destination.chmod(mode)
    for name, row in value["restore"].items():
        require(pin(read(output, name)) == row["current"], "projection restore preimage differs")
        raw = read(source, FIXTURE / name)
        require(pin(raw) == row["profile"], "projection restore fixture changed")
        (output / name).write_bytes(raw)
        expected[name] = {**row["profile"], "mode": original[name]["mode"]}
    for name, identity in value["exclude_new_native_sources"].items():
        require(pin(read(output, name)) == identity, "projection exclusion preimage differs")
        (output / name).unlink()
        del expected[name]
    require(snapshot(output) == expected, "projected source differs from its complete input relation")
    require(snapshot(source) == original, "current sources changed during projection")
    admit_current(source)
    receipt = {
        "schema": "hepta.historical-public58.current-source-projection-receipt.v1",
        "status": "CURRENT_SOURCE_PROJECTED",
        "authority": PROFILE_PIN,
        "input_source": str(source),
        "output_source": str(output),
        "input_files": original,
        "projected_files": expected,
        "restored_paths": sorted(value["restore"]),
        "excluded_current_native_paths": sorted(value["exclude_new_native_sources"]),
        "current_native_sources": 251,
        "projected_native_sources": 230,
        "current_runtime_hia_images": 162,
        "profile_runtime_hia_images": 126,
        "native_or_rust_executed": False,
        "historical_pass_relabelled": False,
        "current_production_sources_unchanged": True,
    }
    (output / RECEIPT).write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    verify(source, output)
    return receipt


def verify(source, output):
    source, output = source.resolve(strict=True), output.resolve(strict=True)
    value = admit_current(source)
    receipt = json.loads(read(output, RECEIPT))
    require(receipt["schema"] == "hepta.historical-public58.current-source-projection-receipt.v1"
            and receipt["status"] == "CURRENT_SOURCE_PROJECTED" and receipt["authority"] == PROFILE_PIN,
            "current source projection receipt identity changed")
    require(receipt["input_source"] == str(source) and receipt["output_source"] == str(output),
            "source projection receipt belongs to another root")
    require(receipt["restored_paths"] == sorted(value["restore"])
            and receipt["excluded_current_native_paths"] == sorted(value["exclude_new_native_sources"]),
            "source projection receipt changed its scope")
    original = snapshot(source)
    require(receipt["input_files"] == original, "source projection current input drifted")
    expected = dict(original)
    for name, row in value["restore"].items():
        expected[name] = {**row["profile"], "mode": original[name]["mode"]}
    for name in value["exclude_new_native_sources"]:
        del expected[name]
    require(receipt["projected_files"] == expected and snapshot(output) == expected,
            "complete projected source receipt or files changed")
    require(len({p.relative_to(output).as_posix()
                 for p in (output / "native").rglob("*.hepta")}) == 230,
            "projected native inventory changed")
    return {"status": "CURRENT_SOURCE_PROJECTION_VERIFIED", "restored_paths": 21,
            "excluded_current_native_paths": 21, "current_native_sources": 251,
            "projected_native_sources": 230, "native_or_rust_executed": False,
            "historical_pass_relabelled": False}


def matches(source):
    return (source / PROFILE).is_file() and hashlib.sha256(
        read(source, "native/runtime_mcp_sources.json")).hexdigest() == CURRENT_BINDING_SHA256


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--project-only", action="store_true")
    args = parser.parse_args(argv)
    require(sys.flags.isolated == 1 and sys.flags.optimize == 0 and sys.dont_write_bytecode,
            "source projection must run with -I -B and assertions enabled")
    source = args.source.resolve(strict=True)
    if args.check_only:
        with tempfile.TemporaryDirectory(prefix="hia-current-profile-") as directory:
            projection = Path(directory) / "source"
            project(source, projection)
            command = [sys.executable, "-I", "-B", str(projection / PREFIX / "materialize.py"),
                       "--source", str(projection), "--check-only"]
            completed = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            verify(source, projection)
            result = json.loads(completed.stdout)
            result["current_source_projection"] = {"authority": PROFILE_PIN, "current_runtime_hia_images": 162,
                "current_native_sources": 251, "projected_native_sources": 230,
                "current_registered_components": 196, "historical_registered_components": 195}
    else:
        require(args.output is not None, "source projection output is required")
        output = args.output.absolute()
        projection = output if args.project_only else output.with_name(output.name + ".current-profile")
        receipt = project(source, projection)
        if args.project_only:
            result = verify(source, projection)
            result["source_root"] = str(projection)
        else:
            command = [sys.executable, "-I", "-B", str(projection / PREFIX / "materialize.py"),
                       "--source", str(projection), "--output", str(output)]
            completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (projection / "historical.stdout").write_bytes(completed.stdout)
            (projection / "historical.stderr").write_bytes(completed.stderr)
            require(completed.returncode == 0, "unchanged historical materialization failed: "
                    + completed.stderr.decode(errors="replace"))
            verify(source, projection)
            result = json.loads(completed.stdout)
            result["current_source_projection"] = {"authority": PROFILE_PIN,
                "current_source": str(source), "profile_source": str(projection),
                "receipt": pin(read(projection, RECEIPT)), "current_runtime_hia_images": 162,
                "current_native_sources": 251, "projected_native_sources": 230,
                "current_registered_components": 196, "historical_registered_components": 195}
            (output / "CURRENT_PROJECTION_RESULT.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

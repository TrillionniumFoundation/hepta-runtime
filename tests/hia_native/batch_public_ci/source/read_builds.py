"""Strict build custody: actual compiler streams, images, pack buffers and Rust."""
from pathlib import Path
import io
import json
import struct
import tarfile
import tomllib

from receipt_support import ROOT, PIN, SHA, require, regular, read_json, check_process

GENERATION = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
COMMIT = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
TREE = "8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49"
PROFILES = {"history.v1": (128 << 20, 128 << 20, 256 << 20),
            "batch-plan.v1": (512 << 20, 1024 << 20, 1152 << 20),
            "batch-write.v1": (512 << 20, 2048 << 20, 3072 << 20)}


def sources(report):
    files = report["source_inputs"]["files"]
    for name, expected in files.items():
        p = Path(name)
        require(not p.is_absolute() and ".." not in p.parts, "source pin path")
        require(PIN(regular(ROOT / name)) == expected, "executed build source changed: " + name)
    return files


def compiler(folder, source, expected=None):
    folder = Path(folder)
    manifest_raw = regular(folder / "manifest.json")
    manifest = read_json(folder / "manifest.json")
    require(manifest["schema"] == "hepta.runtime.native-module.v1" and manifest["standalone"] is None
        and manifest["abi"] == "hepta.runtime.borrowed-bytes.linux-x86_64.v1"
        and manifest["target"] == "linux-x86_64" and manifest["compiler_commit"] == COMMIT
        and manifest["compiler_sha256"] == GENERATION and manifest["qualification"] == "development_fixed_point",
        "actual HIA module admission")
    require(manifest["buffer_profile"] in PROFILES and tuple(manifest[k] for k in
        ("input_capacity", "output_capacity", "workspace_capacity")) == PROFILES[manifest["buffer_profile"]],
        "HIA borrowed-buffer profile")
    for key in ("image", "source"):
        require(Path(manifest[key]).name == manifest[key], "module member escaped build folder")
    require(regular(folder / manifest["source"]) == regular(folder / "module.input.bin") == source
            and SHA(source) == manifest["source_sha256"], "actual compiled HIA source")
    image = regular(folder / manifest["image"])
    require(SHA(image) == manifest["image_sha256"], "actual compiled image hash")
    build = read_json(folder / "build.json")
    receipt = read_json(folder / "module.receipt.json")
    stdout = read_json(folder / "module.stdout.log")
    require(len(stdout) == 15 and all(receipt.get(k) == v for k, v in stdout.items())
            and receipt == build["compile_receipt"] and regular(folder / "module.stderr.log") == b"",
            "actual HIA stdout/receipt/build custody")
    require(receipt["status"] == "returned" and receipt["abi_status"] == 0
            and receipt["source_unchanged"] is True and receipt["forbidden_compiler_modules_loaded"] == []
            and receipt["return_encoding"] == "zero-extended-u32" and receipt["format"] == "flat-x86-64"
            and receipt["artifact_sha256"] == receipt["image_sha256"] == GENERATION
            and receipt["input_sha256"] == receipt["source_sha256"] == SHA(source)
            and receipt["input_bytes"] == len(source) and receipt["produced_sha256"] == SHA(image)
            and receipt["produced_bytes"] == receipt["core_u32"] == receipt["result_u64"] == len(image),
            "native compiler successful result identity")
    output = regular(folder / "module.output.bin")
    require(SHA(output) == receipt["output_sha256"] and output == image + b"\xa5" * (len(output) - len(image)),
            "complete compiler output and tail")
    request = read_json(folder / "module.request.json")
    require(request["capacity"] == len(output) == receipt["limits"]["output_capacity"]
            and request["workspace_size"] == receipt["limits"]["workspace_bytes"]
            and request["source_sha256"] == SHA(source) and request["image_sha256"] == GENERATION
            and request["format"] == "flat-x86-64" and request["workspace_fill"] == 0,
            "actual compiler request limits")
    dependency = build["compiler_dependency"]
    require(dependency["commit"] == COMMIT and dependency["tree"] == TREE
            and build["whole_runtime_replaced"] is False, "pinned compiler dependency")
    if expected is not None:
        require(PIN(manifest_raw) == expected["manifest_pin"] and PIN(image) == expected["image_pin"]
                and PIN(source) == expected["source_pin"], "registered compiled member bytes")
    return image, manifest


def bootstrap(root):
    root = Path(root)
    report = read_json(root / "bootstrap/bootstrap.json")
    require(report["generation_sha256"] == GENERATION, "B3 fixed-point identity")
    for name in ("B1.image.bin", "B2.image.bin", "B3.image.bin"):
        require(PIN(regular(root / "bootstrap" / name)) == {"bytes": 673413, "sha256": GENERATION},
                "complete bootstrap generations differ")


def native(adapters, body, fixture):
    adapters, body, fixture = map(Path, (adapters, body, fixture))
    a, b, f = (read_json(p / "BUILD.json") for p in (adapters, body, fixture))
    require(a["status"] == b["status"] == f["status"] == "PASS"
        and a["fresh_native_compilations"] == 5 and b["fresh_native_compilations"] == 16
        and f["fresh_packer_compilations"] == 1 and f["reused_reverified_member_compilations"] == 14,
        "complete actual HIA build set")
    # The frozen adapter builder binds each exact member in modules; the body
    # and pack builders additionally retain a source_inputs files map.
    for report in (b, f):
        sources(report)
    for root in (adapters, body, fixture):
        bootstrap(root)
    require(set(a["modules"]) == {"value", "batch_params_original", "batch_params", "batch_gateway", "batch_call"},
            "adapter module set changed")
    body_inputs = read_json(ROOT / "body-inputs.json")
    require(b["order"] == body_inputs["order"] and set(b["modules"]) == set(b["order"]) | {"batch_plan_input", "batch_body_adapter"},
            "body module composition changed")
    images = {}
    for root, report in ((adapters, a), (body, b)):
        for name, item in report["modules"].items():
            require(item["manifest"] == "modules/" + name + "/manifest.json", "module build path")
            image, _ = compiler(root / "modules" / name, regular(ROOT / item["source"]), item)
            images[name] = image
    boundary = b["boundary"]
    require(boundary["external_relocations"] == 0 and boundary["shared_object"] == "boundary/callable.so"
            and boundary["image"] == "boundary/callable.image.bin", "callable boundary layout")
    require(PIN(regular(body / boundary["shared_object"])) == boundary["shared_object_pin"]
            and PIN(regular(body / boundary["image"])) == boundary["image_pin"], "actual callable code bytes")
    require([row["name"] for row in boundary["processes"]] == ["assemble", "link", "relocations", "symbols", "image"],
            "actual callable build commands")
    for row in boundary["processes"]:
        require(row["returncode"] == 0 and row["timeout_seconds"] == 60 and 0 <= row["elapsed_seconds"] < 60,
                "actual callable build completion")
        for kind in ("stdout", "stderr"):
            require(PIN(regular(body / "boundary" / (row["name"] + "." + kind))) == row[kind], "complete assembler stream")
        require(regular(body / "boundary" / (row["name"] + ".stderr")) == b"", "assembler diagnostics")
    require(regular(body / "boundary/relocations.stdout") == b"\nThere are no relocations in this file.\n", "unexpected callable relocation")
    symbols = {parts[2]: int(parts[0], 16) for line in regular(body / "boundary/symbols.stdout").decode().splitlines()
               if len(parts := line.split()) == 3 and parts[1] == "T"}
    require(symbols == boundary["symbols"] and set(symbols) == {"local_batch_body_run", "local_batch_body_resume",
        "local_batch_body_cancel_wait", "local_batch_body_release"}, "exported callable symbols")
    component = read_json(ROOT / "fixture-component.json")
    require([row["name"] for row in component["members"]] == b["order"]
            and f["body_build_pin"] == PIN(regular(body / "BUILD.json")), "fixture compiled body identity")
    prefix = regular(ROOT / "native_boundary/batch_fixture_prefix.bin")
    expected = bytearray(prefix)
    children = [images[name] for name in b["order"]]
    total = len(prefix) + sum(map(len, children))
    struct.pack_into("<QQ", expected, 96, total, total)
    struct.pack_into("<14Q", expected, component["table_offset"], *map(len, children))
    expected = bytes(expected) + b"".join(children)
    require(PIN(expected) == component["expected_elf"], "fixed final ELF bytes")
    compiler(fixture / "modules/batch-fixture-packer", regular(ROOT / "native/batch_fixture_packer.hepta"))
    require(PIN(regular(fixture / f["packer_manifest"])) == f["packer_manifest_pin"], "actual packer manifest")
    for name, expected_pin in f["artifacts"].items():
        require(PIN(regular(fixture / name)) == expected_pin, "actual packer artifact changed")
    require(regular(fixture / "pack.input.bin") == b"HLBBPX01" + struct.pack("<14Q", *map(len, children)) + b"".join(children)
        and regular(fixture / "pack.output.bin") == expected + b"\xb3" * 4096
        and regular(fixture / "pack.workspace.bin") == b"\xc7" * 4096
        and regular(fixture / "local-batch-body.elf") == expected and f["actual_packer_return"] == len(expected),
        "complete native pack request/output/workspace and ELF")
    require(regular(fixture / "reproduced/batch_fixture_prefix.bin") == prefix
        and regular(fixture / "reproduced/batch_fixture_packer.hepta") == regular(ROOT / "native/batch_fixture_packer.hepta"),
        "source-author reproduction differs")
    author = read_json(fixture / "author-process.json")
    require(author == f["author_process"] and author["returncode"] == 0 and author["timeout_seconds"] == 60
        and 0 <= author["elapsed_seconds"] < 60 and author["stdout"] == PIN(regular(fixture / "author.stdout"))
        and author["stderr"] == PIN(regular(fixture / "author.stderr")) and regular(fixture / "author.stderr") == b"",
        "actual source reproduction process")
    return {"status": "PASS", "fresh_hia_compilations": 22, "fixed_elf": PIN(expected),
        "callable_source": PIN(regular(ROOT / "native_boundary/local_batch_body_callable.S")),
        "process_launches": 0, "public_batch_qualified": False}


def original(folder):
    folder = Path(folder)
    report = read_json(folder / "BUILD.json")
    require(report["schema"] == "hepta.runtime.rebuilt-batch-current-original-build.v1" and report["status"] == "PASS"
        and report["fresh_original_build"] is True and report["fresh_target_directory"] is True
        and report["all_retained_exactly_match_target"] is True and report["actual_reference_executions"] == 0,
        "fresh current original build gate")
    require(report["target_commit"] == "d3d75c30719db966b004756f610007a7c723729e"
        and report["actual_target_sdk"] == "3.9.0" and report["actual_target_tokio"] == "1.53.3"
        and report["original_body_fragments"] == 15 and report["original_parameter_fragments"] == 2,
        "current original target/owner scope")
    sources(report)
    project = folder / "project"
    seed = regular(ROOT / "reference/target/Cargo.lock")
    require(regular(folder / "lock-before-metadata.toml") == seed and PIN(seed) == report["target_lock"], "actual lock seed")
    lock = regular(project / "Cargo.lock")
    require(PIN(lock) == report["fixture_lock"], "resolved fixture lock")
    target = {(p["name"], p["version"], p.get("source")): p.get("checksum")
        for p in tomllib.loads(seed.decode())["package"] if p.get("source")}
    packages = []
    for p in tomllib.loads(lock.decode())["package"]:
        if p.get("source"):
            require(target.get((p["name"], p["version"], p["source"])) == p["checksum"], "resolved crate escaped target")
            packages.append({k: p[k] for k in ("name", "version", "source", "checksum")})
        else:
            require(p["name"] == "hepta-batch-public-original-oracle" and p["version"] == "0.1.0", "fixture package")
    require(packages == report["retained_packages"], "complete target registry subset")
    names = ["rustc-version", "cargo-version", "metadata-offline", "cargo-build-locked-offline"]
    require(report["process_names"] == names, "fresh original process set/order")
    env = report["controlled_env"]
    rustc = Path(env["RUSTC"])
    original_target = Path(env["CARGO_TARGET_DIR"])
    require(rustc.is_absolute() and original_target.is_absolute()
        and env == {"PATH": str(rustc.parent) + ":/usr/bin:/bin", "RUSTC": str(rustc),
            "CARGO_TARGET_DIR": str(original_target), "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
            "RUSTFLAGS": "", "CARGO_ENCODED_RUSTFLAGS": "", "RUSTC_WRAPPER": "", "RUSTC_WORKSPACE_WRAPPER": ""}
        and report["fresh_rust_targets"] == [str(original_target)], "exact isolated original build environment")
    commands = {
        "rustc-version": [str(rustc), "--version", "--verbose"],
        "cargo-version": [str(rustc.with_name("cargo")), "--version", "--verbose"],
        "metadata-offline": [str(rustc.with_name("cargo")), "metadata", "--offline", "--format-version", "1"],
        "cargo-build-locked-offline": [str(rustc.with_name("cargo")), "build", "--locked", "--offline", "--release", "--bins"],
    }
    records = {}
    for name in names:
        row, streams = check_process(folder / "processes", name)
        require(row["controlled_env"] == dict(PYTHONDONTWRITEBYTECODE="1", LC_ALL="C", **report["controlled_env"])
                and row["stdin"]["bytes"] == 0 and row["argv"] == commands[name]
                and row["cwd"] == str(original_target.parent / "project"), "actual original build environment/input")
        records[name] = (row, streams)
    require(records["rustc-version"][1]["stdout"].decode() == report["rustc_version"]
        and report["rustc_version"].splitlines()[0] == "rustc 1.95.0 (59807616e 2026-04-14)", "actual Rust version stream")
    require(records["cargo-build-locked-offline"][0]["argv"][1:] == ["build", "--locked", "--offline", "--release", "--bins"]
        and records["metadata-offline"][0]["argv"][1:] == ["metadata", "--offline", "--format-version", "1"], "exact cargo commands")
    metadata = json.loads(records["metadata-offline"][1]["stdout"])
    registry = {(p["name"], p["version"], p["source"]): p for p in metadata["packages"] if p.get("source")}
    require(len(registry) == len(report["registry_sources"]) == len(packages), "complete actual registry build closure")
    source_count = 0
    for item in report["registry_sources"]:
        key = item["name"], item["version"], item["source"]
        require(key in registry and str(Path(registry[key]["manifest_path"]).parent) == item["source_directory"],
                "actual metadata source path")
        archive = regular(folder / item["archive"])
        require(PIN(archive) == item["archive_pin"] and SHA(archive) == item["checksum"] == target[key], "complete registry archive")
        files = {}
        crate_name = item["name"] + "-" + item["version"]
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            for member in tar.getmembers():
                parts = Path(member.name).parts
                require(parts and parts[0] == crate_name and ".." not in parts, "registry archived path")
                if member.isdir():
                    continue
                require(member.isfile() and len(parts) > 1, "registry archived node kind")
                name = str(Path(*parts[1:]))
                require(name not in files, "registry duplicate file")
                files[name] = PIN(tar.extractfile(member).read())
        require(files == item["files"], "complete registry source archive/member map")
        source_count += len(files)
    for name, item in report["binaries"].items():
        require(item == dict(path="bin/" + name, **PIN(regular(folder / "bin" / name)))
            and regular(folder / "bin" / name) == regular(folder / "target/release" / name), "fresh actual binary bytes")
        copy = report["compiler_binary_copies"][name]
        require(copy["compiler_path"] == str(original_target / "release" / name)
            and type(copy["compiler_links"]) is int and copy["compiler_links"] >= 1
            and copy["compiler_bytes"] == {key: item[key] for key in ("bytes", "sha256")}
            and copy["independent_evidence_copy"] is True, "complete independent compiler executable copy")
    require(set(report["binaries"]) == {"hepta-batch-body-original-oracle", "hepta-batch-params-original-oracle"}, "fresh binary set")
    require(set(report["compiler_binary_copies"]) == set(report["binaries"]), "complete compiler copy provenance")
    for name, expected in read_json(ROOT / "reference/project/source-extraction.json")["generated_files"].items():
        require(PIN(regular(project / name)) == expected, "compiled original fixture source")
    return {"status": "PASS", "fresh_original_build": True, "actual_build_processes": 4,
        "registry_packages": len(registry), "complete_registry_source_files": source_count,
        "binaries": report["binaries"], "reader_process_launches": 0, "public_batch_qualified": False}

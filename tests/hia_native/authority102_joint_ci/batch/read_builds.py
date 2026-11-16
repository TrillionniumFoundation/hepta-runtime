"""Read-only complete HIA compiler and current Rust build custody."""
from pathlib import Path
import ast
import importlib.util
import io
import json
import math
import struct
import sys
import tarfile
import tomllib
from receipt_support import ROOT, PIN, SHA, require, regular, read_json, check_process

GENERATION = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
COMMIT = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
TREE = "8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49"
COMPILER_STDOUT_FIELDS = {"abi_status", "core_u32", "forbidden_compiler_modules_loaded", "image_sha256",
    "limits", "loader_operations", "native_elapsed_ns", "output_sha256", "output_unchanged", "result_u64",
    "return_encoding", "source_sha256", "source_unchanged", "status", "workspace_header"}
PROFILES = {"standard": (8 << 20, 8 << 20, 32 << 20),
    "view-render.v1": (16 << 20, 16 << 20, 256 << 20),
    "serde-json.v1": (16 << 20, 64 << 20, 256 << 20),
    "sdk-message-target.v1": (32 << 20, 64 << 20, 256 << 20),
    "history.v1": (128 << 20, 128 << 20, 256 << 20),
    "batch-plan.v1": (512 << 20, 1024 << 20, 1152 << 20),
    "batch-write.v1": (512 << 20, 2048 << 20, 3072 << 20)}

def sources(report, source):
    files = report["source_inputs"]["files"]
    for name, expected in files.items():
        p = Path(name)
        require(not p.is_absolute() and ".." not in p.parts, "source pin path")
        require(PIN(regular(source / name)) == expected, "executed build source changed: " + name)
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
    profile = manifest.get("buffer_profile", "standard")
    require(type(profile) is str and profile in PROFILES
        and ("buffer_profile" in manifest) is (profile != "standard")
        and tuple(manifest[k] for k in
        ("input_capacity", "output_capacity", "workspace_capacity")) == PROFILES[profile],
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
    require(set(stdout) == COMPILER_STDOUT_FIELDS and COMPILER_STDOUT_FIELDS <= set(receipt)
            and json.dumps(stdout, sort_keys=True, separators=(",", ":")) == json.dumps(
                {key: receipt[key] for key in COMPILER_STDOUT_FIELDS}, sort_keys=True, separators=(",", ":"))
            and json.dumps(receipt, sort_keys=True, separators=(",", ":")) == json.dumps(
                build["compile_receipt"], sort_keys=True, separators=(",", ":"))
            and regular(folder / "module.stderr.log") == b"",
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


def source_module(name, path):
    """Load only the admitted source bytes, without an implicit pyc file probe."""
    path = Path(path)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(regular(path), str(path), "exec", dont_inherit=True), module.__dict__)
    return module

def load_builder(source):
    """Import only the admitted build definitions; no build method is called."""
    source = Path(source).resolve(strict=True)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(source / "scripts"))
    return source_module("batch_public_admitted_builder", source / "scripts/public_nine_build.py")


def object_layout(raw):
    require(raw[:16] == b"\x7fELF\x02\x01\x01" + bytes(9), "assembler object format")
    require(struct.unpack_from("<HHI", raw, 16) == (1, 62, 1), "assembler target")
    offset = struct.unpack_from("<Q", raw, 40)[0]
    count, names_index = struct.unpack_from("<HH", raw, 60)
    require(offset <= len(raw) and count <= (len(raw) - offset) // 64 and names_index < count,
        "assembler section table")
    sections = [struct.unpack_from("<IIQQQQIIQQ", raw, offset + n * 64) for n in range(count)]
    def span(section):
        at, size = section[4:6]
        require(at <= len(raw) and size <= len(raw) - at, "assembler section extent")
        return raw[at:at + size]
    names = span(sections[names_index])
    def string(table, at):
        require(at < len(table), "assembler string offset")
        end = table.find(b"\0", at)
        require(end >= at, "assembler string terminator")
        return table[at:end].decode()
    section_names = [string(names, section[0]) for section in sections]
    require(section_names.count(".text") == 1, "one complete assembler text section")
    text_index = section_names.index(".text")
    text = span(sections[text_index])
    require(all(s[5] == 0 for s in sections if s[1] in (4, 9)), "unexpected relocations")
    symbols = {}
    for section in sections:
        if section[1] != 2:
            continue
        require(section[6] < count and section[9] == 24 and section[5] % 24 == 0, "assembler symbol table")
        strings = span(sections[section[6]])
        entries = span(section)
        for at in range(0, len(entries), 24):
            name, _, _, index, value, _ = struct.unpack_from("<IBBHQQ", entries, at)
            if index == text_index:
                key = string(strings, name)
                require(key not in symbols, "duplicate assembler symbol")
                symbols[key] = value
    require("_start" in symbols and symbols["_start"] < len(text), "actual assembler entry")
    return text, symbols


def linked_prefix(text, entry):
    end = 256 + len(text)
    aligned = (end + 4095) & ~4095
    raw = bytearray(b"\x7fELF\x02\x01\x01" + bytes(9))
    raw += struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 4194304 + 232, 64, 0, 0, 64, 56, 3, 0, 0, 0)
    raw += struct.pack("<II6Q", 1, 5, 0, 4194304, 4194304, end, end, 4096)
    raw += struct.pack("<II6Q", 1, 6, aligned, 4194304 + aligned, 4194304 + aligned, 0, 0, 4096)
    raw += struct.pack("<II6Q", 0x6474E551, 6, 0, 0, 0, 0, 0, 16)
    raw += bytes.fromhex("31ed4883e4f0e8") + struct.pack("<i", 256 + entry - 243)
    raw += bytes.fromhex("4889c7b83c0000000f050f0b00")
    require(len(raw) == 256, "complete ELF prefix header")
    return bytes(raw) + text + bytes(aligned - end)


def native(folder, source):
    folder, source = Path(folder), Path(source)
    report = read_json(folder / "BUILD.json")
    require(report["schema"] == "hepta.runtime.batch-authority102-complete-build.v1" and report["status"] == "PASS"
        and report["fresh_member_compiles"] == report["reverified_private_members"] == 102
        and report["actual_linker_compiles"] == report["actual_packer_compiles"] == 2
        and report["actual_hia_compiles"] == 106 and set(report["graphs"]) == {"public", "private"},
        "complete fresh public build set")
    builder = load_builder(source / "native-source")
    binding = builder.source_check(source / "native-source")
    require(report["source_binding"] == binding and len(builder.MEMBERS) == 102, "actual public source closure")
    producer = Path(report["build_root"])
    require(producer.is_absolute(), "build producer root")
    def admitted_path(path):
        path = Path(path)
        require(path.is_absolute() and path.is_relative_to(producer), "compiled artifact escaped producer")
        return folder / path.relative_to(producer)
    seen_modules, member_sets, graph_results = {}, {}, {}
    for label in ("public", "private"):
        graph = report["graphs"][label]
        relative = Path(graph["manifest"])
        require(relative.as_posix() == ("public-build/public102/manifest.json" if label == "public"
            else "private-build/private102/manifest.json"), "fixed graph manifest path")
        path = folder / relative
        raw = regular(path)
        require(PIN(raw) == graph["manifest_pin"], "complete graph manifest")
        m = json.loads(raw)
        out = path.parent
        require(m["schema"] == "hepta.runtime.authority-batch-union-build.v1" and m["status"] == "PASS"
            and m["physical_images"] == 102 and m["source_binding"] == binding
            and m["compiler_commit"] == COMMIT and m["compiler_image_sha256"] == GENERATION
            and m["private_instance_fixture"] is (label == "private")
            and m["private_descriptor_base"] == 8192 and m["private_engine_bytes"] == 16384,
            "actual composed public graph identity")
        for name in ("batch_public_route_qualified", "full_sdk_qualified", "full_136_route_qualified",
                "whole_runtime_replaced", "old_path_removed", "production_activated"):
            require(m[name] is False, "build cannot assert semantic qualification: " + name)
        bootstrap(out.parent)
        by_name, images = {}, {}
        require(len(m["members"]) == 102, "exact member count")
        for row, (name, stem, profile) in zip(m["members"], builder.MEMBERS, strict=True):
            require(row["name"] == name and row["source"] == "native/" + stem + ".hepta"
                and row["buffer_profile"] == profile and row["fresh_compile"] is (label == "public"),
                "member source/profile/freshness order")
            module_path = admitted_path(row["manifest"])
            require(SHA(regular(module_path)) == row["manifest_sha256"], "compiled member manifest")
            compiled_source = regular(source / "native-source" / row["source"])
            key = module_path.relative_to(folder).as_posix()
            if key not in seen_modules:
                image, manifest = compiler(module_path.parent, compiled_source)
                seen_modules[key] = (image, manifest)
            image, manifest = seen_modules[key]
            require(manifest["source_sha256"] == row["source_sha256"] == SHA(compiled_source)
                and manifest.get("buffer_profile", "standard") == profile and PIN(image) == {
                    "bytes": row["image_bytes"], "sha256": row["image_sha256"]}, "complete member identity")
            by_name[name], images[name] = row, image
        member_sets[label] = {name: row["manifest_sha256"] for name, row in by_name.items()}
        order = []
        for name in [name for name in builder.EXTRA if name is not None] + [x[0] for x in builder.MEMBERS]:
            if name not in order:
                order.append(name)
        require(order == m["physical_image_members"] and len(order) == 102, "actual physical table order")
        require(regular(out / "combined.S") == builder.adapter_source(source / "native-source",
            private_fixture=label == "private").encode(), "complete regenerated mechanical boundary")
        require(SHA(regular(out / "combined.S")) == m["assembled_source_sha256"], "assembled input hash")
        obj = regular(out / "bridge.o")
        require(SHA(obj) == m["object_sha256"], "complete assembler object")
        text, symbols = object_layout(obj)
        prefix = linked_prefix(text, symbols["_start"])
        require(regular(out / "linked-prefix.elf") == prefix, "complete actual HIA ELF-linker output")
        require(regular(out / "link.input.bin") == b"HIALNK01" + struct.pack("<3Q", 1, 6, 0)
            + b"_start" + struct.pack("<Q", len(obj)) + obj, "complete actual HIA linker request")
        for stage, expected_source in (("link", regular(source / "compiler-inputs/elf_static_linker.hepta")),
                ("pack", regular(source / "native-source/native/runtime_mcp_image_packer.hepta"))):
            row = m[stage]
            require(read_json(out / (stage + ".receipt.json")) == row and row["fresh_compile"] is True
                and type(row["elapsed_seconds"]) in (int, float) and math.isfinite(row["elapsed_seconds"])
                and 0 <= row["elapsed_seconds"] < 180, "actual HIA linker/packer completion")
            module_path = admitted_path(row["manifest"])
            require(SHA(regular(module_path)) == row["manifest_sha256"], "linker/packer compiled manifest")
            compiler(module_path.parent, expected_source)
            for stream in ("input", "output"):
                raw = regular(out / ("linked-prefix.elf" if stage == "link" and stream == "output"
                    else stage + "." + stream + ".bin"))
                require(PIN(raw) == {"bytes": row[stream + "_bytes"], "sha256": row[stream + "_sha256"]},
                    "complete HIA stage stream")
        require(m["link"]["actual_return"] == len(prefix) and m["link"]["output_capacity"] == 8 << 20
            and m["link"]["workspace_capacity"] == 32 << 20, "linker fixed capacities")
        indices = {name: n for n, name in enumerate(order)}
        patches = []
        for symbol, name in [*zip(builder.CONFIG_SYMBOLS, builder.CONFIG), *((name, name) for name in builder.FENCE)]:
            patches.append([2, 256 + symbols[symbol + "_call_displacement"], indices[name]])
        for slot, name in enumerate(builder.EXTRA):
            if name is not None:
                patches.append([1, 256 + symbols["grow_fixture_images"] + slot * 8, indices[name]])
        tables = (("runtime_grow_view_images", builder.VIEW),
            ("runtime_text_create_images", ["lc_spec", "lc_read", "lc_path", "lc_mkdir", "lc_write", "key", "cache"]),
            ("runtime_text_body_images", ["tb_body", "lc_read", "key", "tb_lock", "tb_edit", "tb_match", "tb_history", "tb_atomic", "cache", "tb_render", "tb_unlink", "view_error"]),
            ("runtime_authority_images", ["authority", "authority_record", "authority_kdf", "rf_sha", "authority_aead", "authority_nonce", "authority_scope", "authority_entropy", "authority_loader"]),
            ("runtime_batch_body_images", ["batch_body", "batch_lock", "key", "tb_history", "tb_atomic", "cache", "lc_read", "tb_lock", "tb_edit", "batch_plan", "endpoint", "batch_verify", "batch_apply", "batch_render"]))
        for symbol, names in tables:
            for slot, name in enumerate(names):
                patches.append([1, 256 + symbols[symbol] + slot * 8, indices[name]])
        require(patches == m["pack"]["fixed_patches"], "complete fixed image bindings")
        packed_input = b"HIAIMG02" + struct.pack("<4Q", len(prefix), 102, len(patches), 0) + prefix
        packed_input += b"".join(struct.pack("<Q", len(images[name])) for name in order)
        packed_input += b"".join(struct.pack("<3Q", *row) for row in patches)
        packed_input += b"".join(images[name] for name in order)
        require(regular(out / "pack.input.bin") == packed_input, "complete pack request and every member image")
        expected, positions = bytearray(prefix), []
        for name in order:
            expected += bytes((-len(expected)) % 16)
            positions.append(len(expected))
            expected += images[name]
        text_end = len(expected)
        expected += bytes((-len(expected)) % 4096)
        for kind, at, index in patches:
            struct.pack_into("<Q" if kind == 1 else "<I", expected, at,
                4194304 + positions[index] if kind == 1 else positions[index] - at - 4)
        struct.pack_into("<QQ", expected, 96, text_end, text_end)
        struct.pack_into("<QQQ", expected, 128, len(expected), 4194304 + len(expected), 4194304 + len(expected))
        require(positions == m["pack"]["image_offsets"] and m["pack"]["actual_return"] == 32
            and m["pack"]["output_capacity"] == len(expected) + 32, "complete pack offsets/result")
        require(regular(out / "pack.output.bin") == b"HIAIMR02" + struct.pack("<3Q", 0, len(expected), 0) + expected,
            "complete native pack result")
        work = bytearray((64 + 102 * 8 + 4095) & ~4095)
        struct.pack_into("<QQ", work, 8, text_end, len(expected))
        struct.pack_into("<102Q", work, 64, *positions)
        require(regular(out / "pack.workspace.bin") == work and m["pack"]["workspace_capacity"] == len(work),
            "complete native pack workspace")
        require(graph["elf"] == (relative.parent / m["elf"]).as_posix()
            and regular(folder / graph["elf"]) == expected and graph["elf_pin"] == PIN(expected)
            and PIN(expected) == {"bytes": m["elf_bytes"], "sha256": m["elf_sha256"]}, "complete composed executable")
        require([row["name"] for row in m["boundary_processes"]] == ["assemble", "relocations", "readelf"],
            "exact assembler/inspection process set")
        producer_out = producer / relative.parent
        commands = {"assemble": ["as", "--64", "-o", str(producer_out / "bridge.o"), str(producer_out / "combined.S")],
            "relocations": ["readelf", "-r", str(producer_out / "bridge.o")],
            "readelf": ["readelf", "-lW", str(producer_out / m["elf"])]}
        for row in m["boundary_processes"]:
            name = row["name"]
            require(row == read_json(out / (name + ".process.json")) and row["command"] == commands[name]
                and row["cwd"] == m["source_root"] and row["exit_code"] == 0 and row["timed_out"] is False
                and row["timeout_seconds"] == (60 if name == "assemble" else 30)
                and 0 <= row["elapsed_seconds"] < row["timeout_seconds"], "actual boundary process custody")
            for kind in ("stdout", "stderr"):
                require(PIN(regular(out / (name + "." + kind))) == row[kind], "complete boundary stream")
            require(regular(out / (name + ".stderr")) == b"", "boundary diagnostics")
        require(regular(out / "relocations.stdout") == b"\nThere are no relocations in this file.\n", "boundary relocations")
        headers = regular(out / "readelf.stdout")
        require(b"INTERP" not in headers and b"RWE" not in headers and b"GNU_STACK" in headers, "executable segment permissions")
        graph_results[label] = {"manifest": graph["manifest_pin"], "elf": PIN(expected), "physical_images": 102}
    require(member_sets["public"] == member_sets["private"] and len(seen_modules) == 102,
        "both carriers must use the same complete 102 compiled members")
    return {"status": "PASS", "fresh_hia_compilations": 106, "graphs": graph_results,
        "reader_process_launches": 0, "public_batch_qualified": False}

def original(folder, source):
    folder, source = Path(folder), Path(source)
    report = read_json(folder / "BUILD.json")
    require(report["schema"] == "hepta.runtime.batch-sdk-current-original-build.v1" and report["status"] == "PASS"
        and report["fresh_original_build"] is True and report["fresh_target_directory"] is True
        and report["all_retained_exactly_match_target"] is True and report["actual_reference_executions"] == 0,
        "fresh current original build gate")
    require(report["target_commit"] == "d3d75c30719db966b004756f610007a7c723729e"
        and report["actual_target_sdk"] == "3.9.0" and report["actual_target_tokio"] == "1.53.3"
        and report["original_body_fragments"] == 15 and report["original_parameter_fragments"] == 2,
        "current original target/owner scope")
    sources(report, source)
    project = folder / "project"
    author = source_module("batch_public_original_author", source / "authoring/author_public_reference.py")
    generated, proof = author.compose(source / "baseline", source / "core")
    require(proof == read_json(source / "project/SOURCE.json")
        and report["target_files"] == proof["target_files"]
        and len(proof["preserved_original_items"]) == 106
        and len(proof["preserved_body_fragments"]) == 15
        and len(proof["preserved_parameter_fragments"]) == 2,
        "exact current original source extraction")
    for name, raw in generated.items():
        require(regular(source / "project" / name) == regular(project / name) == raw,
            "complete reproduced original compiler input: " + name)
    seed = regular(source / "core/reference/target/Cargo.lock")
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
            require(p["name"] == "hepta-batch-sdk-current-original-oracle" and p["version"] == "0.1.0", "fixture package")
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
    require(set(report["binaries"]) == {"hepta-batch-sdk-current-original-oracle"}, "fresh binary set")
    require(set(report["compiler_binary_copies"]) == set(report["binaries"]), "complete compiler copy provenance")
    for name, expected in read_json(source / "project/SOURCE.json")["files"].items():
        require(PIN(regular(project / name)) == {key: expected[key] for key in ("bytes", "sha256")}, "compiled original fixture source")
    return {"status": "PASS", "fresh_original_build": True, "actual_build_processes": 4,
        "preserved_original_items": 106, "preserved_body_fragments": 15, "preserved_parameter_fragments": 2,
        "registry_packages": len(registry), "complete_registry_source_files": source_count,
        "binaries": report["binaries"], "reader_process_launches": 0, "public_batch_qualified": False}

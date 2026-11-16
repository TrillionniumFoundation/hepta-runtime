"""Exact retained compiler/ELF reader functions; no execution is performed."""
from pathlib import Path
import json, struct
from common import regular, read_json, need as require, pin as PIN, sha as SHA

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

"""The qualified full compiler reader with explicit unchanged history.v1 caps.

Only the source inventory and the existing history.v1 maxima are specialized.
All full compiler streams, source input, output tail and stdout custody checks
are preserved from the qualified catalog-policy reader.
"""
from pathlib import Path
import json
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import static_common as c
Reader,parse,need,sha=c.BASE.Reader,c.BASE.parse,c.BASE.need,c.BASE.sha
COMPILER,COMPILER_TREE,GENERATION=c.BASE.COMPILER,c.BASE.COMPILER_TREE,c.BASE.GENERATION
SOURCE_PINS=c.source_pins()

def build_check(build, source):
    reader = Reader(build)
    boot = reader.document("bootstrap/bootstrap.json")
    dependency = boot["dependency"]
    need(dependency["commit"] == COMPILER and dependency["tree"] == COMPILER_TREE and dependency["files"], "pinned compiler dependency")
    need(boot["qualification"] == "development_fixed_point" and boot["generation_sha256"] == GENERATION, "bootstrap scope")
    for name in ("B1", "B2", "B3"):
        need(sha(reader.raw("bootstrap/" + name + ".image.bin")) == GENERATION, "complete native compiler generation")
    modules = {}
    for name, (source_name, expected_source, profile) in SOURCE_PINS.items():
        prefix = "modules/" + name + "/"
        manifest_raw = reader.raw(prefix + "manifest.json")
        manifest = parse(manifest_raw)
        need(manifest["name"] == name and manifest["source_sha256"] == expected_source and manifest["compiler_commit"] == COMPILER,
            "native module/source identity")
        need(manifest["compiler_sha256"] == GENERATION and manifest.get("buffer_profile", "standard") == profile and manifest["standalone"] is None, "native module capacity/ABI profile")
        caps = (8 << 20, 8 << 20, 32 << 20) if profile == "standard" else ((128 << 20, 128 << 20, 256 << 20) if profile == "history.v1" else (16 << 20, 64 << 20, 256 << 20))
        need(tuple(manifest[name] for name in ("input_capacity", "output_capacity", "workspace_capacity")) == caps,
            "exact declared three-buffer maxima")
        source_raw = reader.raw(prefix + manifest["source"])
        need(source_raw == (Path(source) / source_name).read_bytes() and sha(source_raw) == expected_source, "actual compiler input source")
        need(reader.raw(prefix + "module.input.bin") == source_raw, "complete compile input")
        image = reader.raw(prefix + "module.image.bin")
        output = reader.raw(prefix + "module.output.bin")
        receipt = reader.document(prefix + "module.receipt.json")
        request = reader.document(prefix + "module.request.json")
        compiled = reader.document(prefix + "build.json")
        need(compiled["compile_receipt"] == receipt and compiled["compiler_dependency"] == dependency, "actual compilation provenance")
        need(manifest["image_sha256"] == sha(image) == receipt["produced_sha256"], "full native image")
        need(receipt["input_sha256"] == receipt["source_sha256"] == expected_source and receipt["input_bytes"] == len(source_raw), "compile source receipt")
        need(receipt["status"] == "returned" and receipt["source_unchanged"] is True and receipt["abi_status"] == 0,
            "native compiler completed")
        need(receipt["forbidden_compiler_modules_loaded"] == [] and receipt["return_encoding"] == "zero-extended-u32", "native-only compiler child")
        need(receipt["core_u32"] == receipt["result_u64"] == receipt["produced_bytes"] == len(image), "exact compiled image extent")
        need(receipt["artifact_sha256"] == receipt["image_sha256"] == GENERATION and request["image_sha256"] == GENERATION, "actual fixed B3")
        need(receipt["output_sha256"] == sha(output) and len(output) == 1048576 and output[:len(image)] == image and output[len(image):] == bytes((0xA5,)) * (len(output)-len(image)), "complete compiler output and tail")
        need(reader.raw(prefix + "module.stderr.log") == b"", "native compiler stderr")
        stdout = reader.document(prefix + "module.stdout.log")
        stdout_fields = ("abi_status", "core_u32", "forbidden_compiler_modules_loaded", "image_sha256",
            "limits", "loader_operations", "native_elapsed_ns", "output_sha256", "output_unchanged",
            "result_u64", "return_encoding", "source_sha256", "source_unchanged", "status", "workspace_header")
        need(type(stdout) is dict and set(stdout) == set(stdout_fields), "complete native compiler stdout fields")
        expected_stdout = {key: receipt[key] for key in stdout_fields}
        need(json.dumps(stdout, sort_keys=True, separators=(",", ":")) ==
             json.dumps(expected_stdout, sort_keys=True, separators=(",", ":")),
             "native compiler stdout/receipt custody")
        need(request["source_sha256"] == expected_source and request["workspace_fill"] == 0 and request["workspace_size"] == request["capacity"] == 1048576, "native compiler request bounds")
        need(Path(request["source"]).name == "module.input.bin" and Path(request["output"]).name == "module.output.bin" and Path(request["image"]).name == "B3.image.bin", "original compiler path roles")
        header = receipt["workspace_header"]
        need(header["40"] == 0 and header["48"] == 2 and header["56"] == len(image) and header["0"] == len(source_raw), "native compiler complete phase")
        modules[name] = {"manifest_sha256": sha(manifest_raw), "source_sha256": expected_source,
            "image_sha256": sha(image), "image_bytes": len(image)}
    return reader, modules

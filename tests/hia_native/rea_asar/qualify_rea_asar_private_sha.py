# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compare complete original/candidate private SHA state using actual native images."""
from pathlib import Path
import argparse
import ast
import hashlib
import json
import random
import shutil
import struct
import sys
import time
import traceback

PROBE = """
def probe(i:readbuf,o:mutbuf,w:mutbuf)->u32:
    if length(i) < 1192 or length(o) < 1184 or length(w) < 1184:
        return 4294967295
    operation = read64(i, 0)
    if operation > 3:
        return 4294967295
    copy_range(w, i, 0, 8, 1184)
    if operation == 0:
        sha_init(w)
    else:
        if operation == 1:
            sha_append_input(i, w, 1192, length(i) - 1192)
        else:
            if operation == 2:
                sha_final(w)
            else:
                sha_compress(w)
    copy_range(o, w, 0, 0, 1184)
    return 1184
"""


def main():
    ap = argparse.ArgumentParser()
    for name in ("original", "candidate", "hepta", "bootstrap", "output"):
        ap.add_argument("--" + name, required=True, type=Path)
    args = ap.parse_args()
    out = args.output
    out.mkdir(mode=0o700, exist_ok=False)
    (out / "qualification-source.py").write_bytes(Path(__file__).read_bytes())
    sys.path.insert(0, str(args.hepta))
    sys.path.insert(0, str(args.candidate / "scripts"))
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    from tools.generate_hia_selfhost import Builder, total_scalar_functions
    from hia_native_build import NativeBuild
    from hia_native_loader import NativeModule

    class Bulk(Builder):
        def expr(self, node):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "copy_range":
                values = [self.expr(arg) for arg in node.args]
                source = values[1]
                if source[1] == "mutbuf":
                    source = self.op("borrow.read", [source], "readbuf")
                result = self.op("buffer.copy_range",
                    [values[0], source, *(self.cast(v, "usize") for v in values[2:])])
                if values[1][1] == "mutbuf":
                    self.op("loan.end", [source])
                return result
            return super().expr(node)

    build_root = out / "native-build"
    build_root.mkdir(mode=0o700)
    shutil.copytree(args.bootstrap, build_root / "bootstrap", copy_function=shutil.copy2)
    assert hashlib.sha256((build_root / "bootstrap/B3.image.bin").read_bytes()).hexdigest() == \
        "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
    builder = NativeBuild(args.hepta, build_root)
    modules, pins = {}, {}
    for label, source in (("original", args.original), ("candidate", args.candidate)):
        program_path = source / "native/rea_asar_parser.hepta"
        raw = program_path.read_bytes()
        mapping_path = source / "native/rea_asar_parser_composition.json"
        mapping_raw = mapping_path.read_bytes()
        mapping = json.loads(mapping_raw)
        assert hashlib.sha256(raw).hexdigest() == mapping["source_sha256"]
        document = assemble_program(raw).as_dict()
        functions = {f["name"]: f for f in document["functions"]}
        names = dict(mapping["functions"])
        names["probe"] = "f0"
        signatures = {name: ([p["type"] for p in functions[target]["params"]],
            functions[target]["returns"][0]) for name, target in names.items()}
        signatures["probe"] = (["readbuf", "mutbuf", "mutbuf"], "u32")
        node = ast.parse(PROBE).body[0]
        b = Bulk(node, names, signatures, total_scalar_functions([node]))
        b.statements(node.body)
        entry = {"name": "f0", "params": [b.param(v) for v in b.params],
            "returns": [b.returns], "effects": ["read", "write", "trap"], "entry": "b0", "blocks": b.blocks}
        document["module"] = "rea_asar_private_sha_" + label
        document["functions"] = [entry] + document["functions"][1:]
        probe = render_assembly(document).encode()
        actual = assemble_program(probe).as_dict()
        assert actual["functions"][1:] == document["functions"][1:]
        path = out / (label + "-probe.hepta")
        path.write_bytes(probe)
        manifest = builder.compile("private-sha-" + label, path,
            standalone=None, buffer_profile="history.v1")
        manifest = Path(manifest)
        modules[label] = NativeModule(manifest,
            manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest())
        pins[label] = {"source": str(program_path), "source_bytes": len(raw),
            "source_sha256": hashlib.sha256(raw).hexdigest(), "mapping": str(mapping_path),
            "mapping_sha256": hashlib.sha256(mapping_raw).hexdigest(),
            "probe_sha256": hashlib.sha256(probe).hexdigest(), "manifest": str(manifest),
            "helper_bodies_byte_exact_in_the_probed_program": True}
    (out / "source-pins.json").write_text(json.dumps(pins, sort_keys=True, indent=2) + "\n")
    calls = comparisons = 0
    seconds = {"original": 0.0, "candidate": 0.0}
    started = time.monotonic()
    try:
        with (out / "complete-states.jsonl").open("x") as log:
            def invoke_pair(label, op, states, payload=b""):
                nonlocal calls, comparisons
                result = {}
                for name, module in modules.items():
                    wire = struct.pack("<Q", op) + states[name] + payload
                    begin = time.process_time()
                    output = module.invoke(wire, output_capacity=1184, workspace_capacity=1184)
                    duration = time.process_time() - begin
                    seconds[name] += duration
                    calls += 1
                    assert len(output) == 1184
                    result[name] = output
                    log.write(json.dumps({"case": label, "implementation": name,
                        "operation": op, "input_hex": wire.hex(), "output_hex": output.hex(),
                        "native_cpu_seconds": duration}, sort_keys=True) + "\n")
                comparisons += 1
                assert result["original"] == result["candidate"], ("complete-state", label, op)
                return result

            initial = invoke_pair("initialize", 0, {name: bytes(1184) for name in modules})
            vectors = 0
            for size in (0, 1, 7, 55, 56, 63, 64, 65, 127, 128, 129, 1024, 8193, 1048576):
                data = bytes((i * 73 + i // 17 + 11) % 256 for i in range(size))
                states = dict(initial)
                states = invoke_pair(f"size-{size}/empty-update", 1, states)
                at = 0
                chunks = (1, 7, 55, 64, 65, 4096, 65536)
                j = 0
                while at < size:
                    length = min(chunks[min(j, len(chunks) - 1)], size - at)
                    states = invoke_pair(f"size-{size}/chunk-{j}", 1, states, data[at:at + length])
                    at += length
                    j += 1
                states = invoke_pair(f"size-{size}/final", 2, states)
                words = struct.unpack_from("<8Q", states["candidate"], 1024)
                assert all(word < 1 << 32 for word in words)
                digest = b"".join(word.to_bytes(4, "big") for word in words)
                assert digest == hashlib.sha256(data).digest(), ("independent-digest", size)
                vectors += 1
            random_source = random.Random(0x484941534841)
            for ordinal in range(128):
                state = bytearray(random_source.randbytes(1184))
                state[:512] = initial["original"][:512]
                for j in range(8):
                    struct.pack_into("<Q", state, 1024 + 8 * j, random_source.getrandbits(32))
                invoke_pair(f"canonical-compression-{ordinal}", 3,
                    {name: bytes(state) for name in modules})
            log.flush()
        for row in pins.values():
            assert hashlib.sha256(Path(row["source"]).read_bytes()).hexdigest() == row["source_sha256"]
            assert hashlib.sha256(Path(row["mapping"]).read_bytes()).hexdigest() == row["mapping_sha256"]
        report = {"status": "PASS", "complete_1184_byte_state_comparisons": comparisons,
            "actual_native_calls": calls, "independent_complete_sha256_vectors": vectors,
            "canonical_random_compression_states": 128, "native_cpu_seconds": seconds,
            "seconds": time.monotonic() - started, "all_source_bytes_stable": True,
            "global_sha_abi_changed": False, "compiler_pin_changed": False,
            "scope": "Private canonical nonalias owner domain only; arbitrary noncanonical SHA states are not admitted product inputs."}
        (out / "terminal.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        print(json.dumps(report, sort_keys=True), flush=True)
    except BaseException as error:
        (out / "failure.json").write_text(json.dumps({"error": repr(error),
            "traceback": traceback.format_exc(), "completed_state_comparisons": comparisons,
            "actual_native_calls": calls}, sort_keys=True, indent=2) + "\n")
        raise
    finally:
        for module in modules.values():
            module.close()


if __name__ == "__main__":
    main()

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compare SHA init/update/final/compress through the actual full parser images."""
from pathlib import Path
import argparse
import ctypes
import hashlib
import json
import random
import struct
import sys
import time
import traceback

def main():
    ap = argparse.ArgumentParser()
    for name in ("source", "original-manifest", "candidate-manifest", "layout", "output"):
        ap.add_argument("--" + name, required=True, type=Path)
    args = ap.parse_args()
    out = args.output
    out.mkdir(mode=0o700, exist_ok=False)
    (out / "qualification-source.py").write_bytes(Path(__file__).read_bytes())
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.source / "scripts"))
    from hia_native_loader import NativeModule
    sha = lambda b: hashlib.sha256(b).hexdigest()
    source = args.source / "native/rea_asar_parser.hepta"
    mapping_path = args.source / "native/rea_asar_parser_composition.json"
    mapping = json.loads(mapping_path.read_bytes())
    assert sha(source.read_bytes()) == mapping["source_sha256"] == "70c1de9a0f9511bed5379cb0ac4eb9495f53fb71b2999a6290cc0605c22d0ab6"
    table_raw = args.layout.read_bytes()
    assert sha(table_raw) == "871b14c6503251afa96f88442af58c5587b89b31dd9f14cc5a7fd19c9a310e1e"
    table = {row["function"]: row for row in json.loads(table_raw)}
    names = [mapping["functions"][name] for name in ("sha_init", "sha_append_input", "sha_final", "sha_compress")]
    assert names == ["f73", "f45", "f72", "f65"]
    paths = [source, mapping_path, args.layout, args.original_manifest, args.candidate_manifest]
    expected_images = {"original": "ab3e303b07aaab48a825627a6d743dfe8724eaf9b8d3c157127917c10be2775d",
                       "candidate": "d5b57ebd0fe6956464cc95b5712449d543e3af5850442ae67d57049f5ef6fbd5"}
    modules, functions = {}, {}
    for label, manifest in (("original", args.original_manifest), ("candidate", args.candidate_manifest)):
        metadata = json.loads(manifest.read_bytes())
        assert metadata["image_sha256"] == expected_images[label]
        image = manifest.parent / metadata["image"]
        assert sha(image.read_bytes()) == expected_images[label]
        paths.append(image)
        module = NativeModule(manifest, manifest_sha256=sha(manifest.read_bytes()))
        modules[label] = module
        functions[label] = [ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p)
            (module._address + table[name]["offset"]) for name in names]
    pins = {str(p): {"bytes": p.stat().st_size, "sha256": sha(p.read_bytes())} for p in paths}
    (out / "source-pins.json").write_text(json.dumps(pins, sort_keys=True, indent=2) + "\n")
    calls = comparisons = 0
    seconds = {"original": 0.0, "candidate": 0.0}
    started = time.monotonic()
    try:
        with (out / "complete-states.jsonl").open("x") as log:
            def invoke_pair(label, op, states, payload=b""):
                nonlocal calls, comparisons
                result, returns = {}, {}
                for name in modules:
                    wire = struct.pack("<Q", op) + states[name] + payload
                    wire_buffer = ctypes.create_string_buffer(wire + b"\x6b" * 16, len(wire) + 16)
                    state = ctypes.create_string_buffer(states[name] + b"\x5a" * 16, 1200)
                    cell = ctypes.create_string_buffer(b"\xa5" * 16, 16)
                    if op == 1:
                        arguments = (ctypes.c_uint64 * 8)(ctypes.addressof(wire_buffer), len(wire),
                            ctypes.addressof(state), 1184, 1192, 0x1122334455667788,
                            len(payload), 0x8877665544332211)
                    else:
                        arguments = (ctypes.c_uint64 * 2)(ctypes.addressof(state), 1184)
                    argument_bytes = bytes(arguments)
                    begin = time.process_time()
                    rax = functions[name][op](arguments, cell)
                    duration = time.process_time() - begin
                    seconds[name] += duration
                    calls += 1
                    assert bytes(arguments) == argument_bytes
                    assert wire_buffer.raw == wire + b"\x6b" * 16
                    assert state.raw[1184:] == b"\x5a" * 16
                    assert cell.raw == struct.pack("<Q", rax) + b"\xa5" * 8
                    result[name] = state.raw[:1184]
                    returns[name] = (rax, cell.raw)
                    log.write(json.dumps({"case": label, "implementation": name, "operation": op,
                        "input_hex": wire.hex(), "output_hex": result[name].hex(), "rax": rax,
                        "result_cell_hex": cell.raw.hex(), "native_cpu_seconds": duration}, sort_keys=True) + "\n")
                    log.flush()
                comparisons += 1
                assert result["original"] == result["candidate"], ("complete-state", label, op)
                assert returns["original"] == returns["candidate"], ("return", label, op)
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
            rnd = random.Random(0x484941534841)
            for ordinal in range(128):
                state = bytearray(rnd.randbytes(1184))
                state[:512] = initial["original"][:512]
                for j in range(8):
                    struct.pack_into("<Q", state, 1024 + 8 * j, rnd.getrandbits(32))
                invoke_pair(f"canonical-compression-{ordinal}", 3, {name: bytes(state) for name in modules})
        for p in paths:
            assert p.stat().st_size == pins[str(p)]["bytes"] and sha(p.read_bytes()) == pins[str(p)]["sha256"]
        assert comparisons == 226 and calls == 452 and vectors == 14
        report = {"status": "PASS", "complete_1184_byte_state_comparisons": comparisons,
            "actual_native_calls": calls, "independent_complete_sha256_vectors": vectors,
            "canonical_random_compression_states": 128, "native_cpu_seconds": seconds,
            "seconds": time.monotonic() - started, "all_source_bytes_stable": True,
            "actual_unmodified_parser_images_called": True, "compiler_pin_changed": False,
            "scope": "Final explicit HIA lowering compared with the pinned direct B3 v9 parser; earlier v9 versus original SHA proof is a separately retained predecessor.",
            "public_route_qualified": False}
    except BaseException as error:
        report = {"status": "FAILED", "error": repr(error), "traceback": traceback.format_exc(),
            "completed_state_comparisons": comparisons, "actual_native_calls": calls}
        (out / "terminal.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        raise
    finally:
        for module in modules.values():
            module.close()
    (out / "terminal.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True), flush=True)

if __name__ == "__main__":
    main()

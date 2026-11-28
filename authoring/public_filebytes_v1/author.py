"""Author the configured binary observation gateway; no filesystem or transport policy in Python."""
from __future__ import annotations
import argparse, ast, hashlib, importlib.util, json, stat
from pathlib import Path

SHA = lambda b: hashlib.sha256(b).hexdigest()
ENC = lambda x: (json.dumps(x, sort_keys=True, indent=2) + "\n").encode()
WORD = lambda x: int.from_bytes(x.encode(), "little")
ROOT = Path(__file__).resolve().parents[2]

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hepta", type=Path, required=True)
    p.add_argument("--source", type=Path, default=ROOT)
    a = p.parse_args()
    source = a.source.resolve(strict=True)
    own = "authoring/public_filebytes_v1/"
    names = [own + "author.py", own + "gateway.pseudo",
             "authoring/public_publication_v1/source_support.py",
             "authoring/public_extract/adapter.pseudo",
             "native/binary_call_plan.hepta", "native/binary_call_plan_composition.json",
             "native/file_info_params.hepta", "native/file_info_params_composition.json",
             "native/binary_read_params.hepta", "native/binary_read_params_composition.json"]
    def take(name):
        path = source / name
        if path.resolve(strict=True) != path or not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError("non-physical source: " + name)
        return path.read_bytes()
    initial = {n: take(n) for n in names}
    for stem in ("binary_call_plan", "file_info_params", "binary_read_params"):
        meta = json.loads(initial["native/" + stem + "_composition.json"])
        raw = initial["native/" + stem + ".hepta"]
        if meta["source_sha256"] != SHA(raw) or meta["source_bytes"] != len(raw):
            raise ValueError("original whole source binding differs: " + stem)
    path = source / "authoring/public_publication_v1/source_support.py"
    spec = importlib.util.spec_from_file_location("_filebytes_original_source_support", path)
    support = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(support)
    api = support.tools(a.hepta)
    common = initial["authoring/public_extract/adapter.pseudo"].decode()
    nodes = {n.name: ast.get_source_segment(common, n) for n in ast.parse(common).body}
    retained = ["child", "region", "region_capacity", "reserve", "request_grow",
                "pending_grow", "admit_growth", "delivery_again"]
    pseudo = initial[own + "gateway.pseudo"].decode() + "\n\n" + "\n\n".join(nodes[n] for n in retained) + "\n"
    constants = {
        "STATE_MAGIC": WORD("HFBGWS01"), "REQUEST_MAGIC": WORD("HFBGWQ01"),
        "ACTION_MAGIC": WORD("HFBGWA01"), "TRANSPORT_REQUEST": WORD("HFBTRQ01"),
        "TYPED_REQUEST": WORD("HBPRQ001"), "TYPED_RESULT": WORD("HBPRR001"),
        "PLAN_REQUEST": WORD("HBPLQ001"), "PLAN_RESULT": WORD("HBPLR001"),
        "CONFIG_REQUEST": WORD("HRCFGQ01"), "CONFIG_RESULT": WORD("HRCFGM01"),
        "GROW_MAGIC": WORD("HGRWS002"), "PHASE": 8, "SEQUENCE": 16,
        "INPUT_LENGTH": 24, "OUTPUT_LENGTH": 32, "WORK_LENGTH": 40, "ACTION": 256,
        "INVALID": 0xffffffff, "CAPACITY": 0xfffffffe, "CANCELLED": 0xfffffff7,
        "CALL": 0xfffffff0, "GROW": 0xffffffd0, "DELIVERY": 0xffffffcd,
        "FIRST_ERROR": 0xffff0000, "MAXIMUM": (1 << 64) - 1,
    }
    raw, aliases, proof = support.compile_new(
        api, initial["native/binary_call_plan.hepta"],
        {"load": "f1", "get": "f2", "put": "f3"}, pseudo, constants,
        "runtime_configured_filebytes_gateway")
    if any(take(n) != b for n, b in initial.items()):
        raise ValueError("actual author input changed")
    output = source / "native/filebytes_gateway.hepta"
    metadata = source / "native/filebytes_gateway_composition.json"
    for dest in (output, metadata):
        if dest.exists():
            raise FileExistsError(dest)
    result = {
        "schema": "hepta.runtime.configured-filebytes-gateway.v1",
        **proof, "aliases": aliases, "constants": constants,
        "source_bytes": len(raw), "source_sha256": SHA(raw),
        "input_files": {n: {"bytes": len(b), "sha256": SHA(b)} for n, b in initial.items()},
        "retained_continuation_helpers": {n: SHA(nodes[n].encode()) for n in retained},
        "request_capture": "complete immutable owned bytes; every continuation compares actual input",
        "children": ["file_info_params", "binary_read_params", "binary_call_plan",
                     "actual_installed_configuration", "actual_captured_host_file_transport"],
        "configuration_root_operation": 9, "configuration_lookup_operation": 4,
        "implicit_configured_host_to_local_alias": False,
        "native_compiled": False, "native_executed": False, "public_handler_qualified": False,
        "whole_runtime_qualified": False,
    }
    output.write_bytes(raw)
    metadata.write_bytes(ENC(result))
    if any(take(n) != b for n, b in initial.items()):
        raise ValueError("actual author input changed at publication")
    print(json.dumps({"source": str(output), "bytes": len(raw), "sha256": SHA(raw),
                      "functions": result["functions"], "operations": result["operations"]}))

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Read complete reference observations; never run Rust, HIA, or subprocesses."""
from pathlib import Path
import argparse
import copy
import hashlib
import json
import stat

TARGET = "d3d75c30719db966b004756f610007a7c723729e"
TREE = "612e145513961556ac8844b5cc978f9b5175e4d4"
VERSIONS = [None, "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25",
            "2026-07-27", "2026-07-28", "2026-08-01"]
FROZEN = {"rea_inspect_elf_notes", "rea_get_evidence_bundle", "rea_inspect_apk_signature_evidence",
          "rea_inspect_analysis_view", "rea_export_evidence_bundle", "rea_import_evidence_bundle"}
FALSE_FLAGS = ("whole_runtime_replaced", "production_activated", "old_stack_removal_qualified")


def need(value, label):
    if not value:
        raise ValueError("current catalog reference: " + label)


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


class Reader:
    def __init__(self, root):
        self.root = Path(root).absolute()
        need(self.root.resolve(strict=True) == self.root, "physical evidence root")
        self.files = {}

    def data(self, name, expected=None):
        relative = Path(name)
        need(not relative.is_absolute() and '..' not in relative.parts, "relative evidence path")
        path = self.root / relative
        need(path.resolve(strict=True) == path and stat.S_ISREG(path.lstat().st_mode), "regular evidence file")
        raw = path.read_bytes()
        pin = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        if expected is not None:
            need(pin == expected, "complete file bytes: " + name)
        self.files[name] = pin
        return raw

    def document(self, name):
        return parse(self.data(name))


def strip_null(value):
    if isinstance(value, list):
        for child in value:
            strip_null(child)
    elif isinstance(value, dict):
        for child in list(value.values()):
            strip_null(child)
        if isinstance(value.get("type"), list):
            types = [item for item in value["type"] if item != "null"]
            value["type"] = types[0] if len(types) == 1 else types
        for key in ("anyOf", "oneOf"):
            if isinstance(value.get(key), list):
                variants = [item for item in value[key]
                            if not isinstance(item, dict) or item.get("type") != "null"]
                value[key] = variants
                if len(variants) == 1 and isinstance(variants[0], dict):
                    del value[key]
                    for name, child in variants[0].items():
                        value.setdefault(name, child)


def strip_noise(value):
    value.pop("$schema", None)
    value.pop("format", None)
    if value.get("default", object()) is None:
        value.pop("default")
    for key, child in value.items():
        if key in ("properties", "$defs") and isinstance(child, dict):
            for schema in child.values():
                if isinstance(schema, dict):
                    strip_noise(schema)
        elif isinstance(child, dict):
            strip_noise(child)
        elif isinstance(child, list):
            for schema in child:
                if isinstance(schema, dict):
                    strip_noise(schema)


def verify(root):
    r = Reader(root)
    result = r.document("result.json")
    need(result.get("status") == "REFERENCE_EXECUTION_COMPLETE", "completed original reference")
    need(result.get("target_commit") == TARGET and result.get("target_tree") == TREE, "exact current target")
    need(all(result.get(flag) is False for flag in FALSE_FLAGS), "global qualification remains false")
    need(result.get("public_transport_executed") is False and result.get("tool_body_calls") == 0
         and result.get("worker_readiness_qualified") is False, "actual observation scope")
    source = r.document("source.json")
    need(source["target_commit"] == TARGET and source["target_tree"] == TREE, "source target")
    tree = {}
    for row in r.data("target-tree.bin").split(b"\0"):
        if row:
            descriptor, name = row.split(b"\t", 1)
            mode, kind, sha = descriptor.split()
            tree[name.decode()] = (mode, kind, sha.decode())
    for name, expected in source["originals"].items():
        raw = r.data("original-source/" + name, expected)
        digest = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        need(tree[name][1:] == (b"blob", digest), "original file matches target Git object: " + name)
    original = r.data("original-source/src/mcp/server.rs", source["original_server_prefix"])
    observer = r.data("recipe-source/observer.rs", source["observer"])
    instrumented = r.data("instrumented-server.rs", source["instrumented_server"])
    need(instrumented == original + b"\n" + observer and source["original_functions_unchanged"] is True,
         "byte-exact complete original server prefix")
    r.data("recipe-source/main.rs", source["example"])
    r.data("reference.elf", result["original_binary"])
    registry = r.document("registry.json")
    need(len(registry) == result["registry_packages"] and "rmcp-3.9.0" in registry, "current complete dependency inventory")
    for package, descriptor in registry.items():
        for name, expected in descriptor["files"].items():
            r.data("registry-source/" + package + "/" + name, expected)
    names = ["rustc-version", "cargo-version", "cargo-build", "cargo-metadata",
             "profile-disabled", *("profile-" + str(i) for i in range(8))]
    seen = {p.name[:-len(".process.json")] for p in (r.root / "processes").glob("*.process.json")}
    need(seen == set(names), "complete actual process inventory")
    for name in names:
        process = r.document("processes/" + name + ".process.json")
        need(process["name"] == name and process["exit_code"] == 0 and process["start_error"] is None
             and process["timed_out"] is False, "successful actual process: " + name)
        deadline = 1800 if name == "cargo-build" else 180 if name == "cargo-metadata" else 120 if name.startswith("profile-") else 30
        need(process["timeout_seconds"] == deadline and 0 <= process["elapsed_seconds"] < deadline,
             "original exact process deadline: " + name)
        for field in ("stdout", "stderr"):
            stream = process[field]
            need(stream["path"] == name + "." + field, "full process stream identity")
            raw = r.data("processes/" + stream["path"], {k: stream[k] for k in ("bytes", "sha256")})
            if name.startswith("profile-") and field == "stderr":
                need(not raw, "original metadata process stderr")
    baseline = None
    all_info = None
    total = 0
    profile_counts = {}
    for number in (None, *range(8)):
        name = "profile-disabled" if number is None else "profile-" + str(number)
        observation = r.document("processes/" + name + ".stdout")
        need(observation["schema"] == "hepta.runtime.current-catalog-observation.v1"
             and observation["target_commit"] == TARGET, "actual original observation identity")
        need(all(observation.get(flag) is False for flag in FALSE_FLAGS), "observation global flags")
        flags = (number is not None, bool(number is not None and number & 1),
                 bool(number is not None and number & 2), bool(number is not None and number & 4))
        need(tuple(observation[k] for k in ("runtime_enabled", "hia_enabled", "rea_enabled", "weight_enabled")) == flags,
             "configuration actually reached original global owner")
        if number is not None:
            config = r.document("configuration-inputs/profile-" + str(number) + ".json")
            state = r.document("configuration-state/profile-" + str(number) + "/config.json")
            need(config == state, "unchanged actual configuration input")
        raw = [parse(wire) for wire in observation["raw_tool_wires"]]
        need(len(raw) == 136 and len({item["name"] for item in raw}) == 136, "complete distinct router metadata")
        need([item["name"] for item in raw] == sorted(item["name"] for item in raw), "actual router order")
        identity = {key: observation[key] for key in ("raw_tool_wires", "runtime_tool_names",
                    "hia_tool_names", "weight_tool_names", "hia_catalog_sha256")}
        if baseline is None:
            baseline = identity
            all_info = observation["get_info_wire"]
        need(identity == baseline and observation["get_info_wire"] == all_info, "original immutable router/server metadata")
        hia = set(observation["hia_tool_names"])
        runtime = set(observation["runtime_tool_names"])
        weight = set(observation["weight_tool_names"])
        expected = []
        for original_tool in raw:
            tool = copy.deepcopy(original_tool)
            name0 = tool["name"]
            if name0 in hia and not flags[1] or name0.startswith("rea_static_") and not flags[2] or name0 in weight and not flags[3]:
                continue
            if flags[0] and name0 == "shell" or not flags[0] and name0 in runtime:
                continue
            if name0 not in hia | FROZEN:
                for value in tool["inputSchema"].values():
                    strip_null(value)
                strip_noise(tool["inputSchema"])
            expected.append(tool)
        rows = observation["list_cases"]
        need([(row["protocol_version"], row["cursor_case"]) for row in rows]
             == [(version, cursor) for version in VERSIONS for cursor in range(3)], "complete protocol and cursor matrix")
        for row in rows:
            body = parse(row["result_wire"])
            need(body["tools"] == expected and row["tool_count"] == len(expected), "actual full tool metadata and visibility")
            need(body.get("resultType") == "complete", "typed original result constructor")
            modern = row["protocol_version"] is not None and row["protocol_version"] >= "2026-07-28"
            fields = {"resultType", "tools", "ttlMs", "cacheScope"} if modern else {"resultType", "tools"}
            need(set(body) == fields, "complete typed list result fields")
            if modern:
                need(body["ttlMs"] == 0 and body["cacheScope"] == "public", "current original public cache policy")
            total += 1
        profile_counts[name] = len(expected)
    info = parse(all_info)
    need(info["protocolVersion"] == "2026-07-28" and info["serverInfo"] == {"name": "rmcp", "version": "3.9.0"},
         "actual current SDK get_info identity")
    need(total == result["original_list_handler_calls"] == 216, "all actual handler observations")
    return {"schema": "hepta.runtime.current-catalog-reference-readback.v1", "status": "PASS",
            "target_commit": TARGET, "target_tree": TREE, "raw_tools": 136, "original_list_handler_calls": total,
            "profile_tool_counts": profile_counts, "original_get_info_calls": 9, "actual_processes": len(names),
            "complete_files_read": len(r.files), "complete_bytes_read": sum(p["bytes"] for p in r.files.values()),
            "readonly": True, "new_processes": 0, "public_transport_executed": False, "tool_body_calls": 0,
            "worker_readiness_qualified": False, **{k: False for k in FALSE_FLAGS}}


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--evidence", required=True, type=Path)
    args = p.parse_args()
    print(json.dumps(verify(args.evidence), sort_keys=True, separators=(",", ":")))

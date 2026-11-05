#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Reproduce the frozen REA inventory without claiming behavioral parity.

This development tool reads authenticated historical catalogs, statically reads
the separately pinned source declarations, and inventories actual Rust handlers.
It never runs a target, an analysis engine, npm, or a model. A successful check
establishes an inventory invariant only. --require-parity is a separate gate and
cannot succeed while any operation lacks qualified differential evidence.
"""

from __future__ import annotations

import argparse
import base64
from collections import Counter
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import zipfile


INPUTS_PATH = "docs/rea-native/compatibility/REA_6_8_0_INPUTS.json"
MAP_PATH = "docs/rea-native/compatibility/REA_6_8_0_CAPABILITY_MAP.json"
LEDGER_PATH = "docs/rea-native/compatibility/REA_6_8_0_LEDGER.json"
ENVIRONMENT_PATH = "docs/rea-native/compatibility/REA_6_8_0_ENVIRONMENT.json"
STATES = {"operation_candidate", "partial_operation", "related_facility", "absent"}
MAX_JSON_BYTES = 16 * 1024 * 1024
HELPERS = "official|enhanced|native|artifact|session|functionWorkflow"
SNAPSHOT_FIELDS = ("upstream_tool", "catalog_index", "family", "source_contract_paths",
                   "schema_fingerprints", "upstream_annotations")
SCHEMA_FINGERPRINT_ALGORITHM = "sha256(sorted-key Python JSON, ASCII strings, compact separators); ledger-only"


class LedgerError(ValueError):
    """A rejected input or an invariant that cannot be established."""


def require(condition, message):
    if not condition:
        raise LedgerError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def digest_json(value):
    # A ledger fingerprint, not the REA Evidence RFC 8785 implementation.
    return sha256(json.dumps(value, ensure_ascii=True, allow_nan=False,
                            sort_keys=True, separators=(",", ":")).encode())


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON member: " + key)
        result[key] = value
    return result


def parse_json(data, label="JSON"):
    require(len(data) <= MAX_JSON_BYTES, label + " exceeds the byte allowance")
    try:
        def finite_float(token):
            value = float(token)
            require(math.isfinite(value), "non-finite JSON number: " + token)
            return value
        return json.loads(data, object_pairs_hook=unique_object, parse_float=finite_float,
                          parse_constant=lambda x: (_ for _ in ()).throw(
                              LedgerError("non-finite JSON constant: " + x)))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise LedgerError(label + ": invalid JSON") from error


def read_json(path):
    with Path(path).open("rb") as handle:
        return parse_json(handle.read(MAX_JSON_BYTES + 1), str(path))


def relative_path(root, relative):
    require(isinstance(relative, str) and relative, "empty relative path")
    posix = PurePosixPath(relative)
    require(not posix.is_absolute() and ".." not in posix.parts
            and "\\" not in relative and ":" not in relative,
            "unsafe relative path: " + relative)
    target = Path(root).joinpath(*posix.parts)
    require(target.resolve().is_relative_to(Path(root).resolve()),
            "path escapes the selected root: " + relative)
    return target


def compact_json_bytes(data):
    """Remove only insignificant whitespace from already validated JSON.

    The capture was emitted by JSON.stringify. Keeping its string/number tokens
    unchanged reproduces the original catalog digest without re-serializing
    IEEE-754 numbers in Python, including exponent and negative-zero spelling.
    """
    parse_json(data, "catalog")
    out = bytearray()
    in_string = False
    escaped = False
    for byte in data:
        if in_string:
            out.append(byte)
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                in_string = False
        elif byte == 34:
            in_string = True
            out.append(byte)
        elif byte not in (9, 10, 13, 32):
            out.append(byte)
    return bytes(out)


def published_pin(root, inputs):
    require(inputs.get("schema") == "hepta.rea.compatibility-inputs.v1",
            "unsupported input manifest schema")
    pin = read_json(relative_path(root, inputs["published_pin_path"]))
    require(pin["publishedPackage"] == inputs["published_package"],
            "published package selection drift")
    require(pin["upstreamGitSource"] == inputs["source_commit"],
            "source commit selection drift")
    return pin


def verify_inputs(root, cache, inputs):
    pin = published_pin(root, inputs)
    for item in inputs["reference_files"]:
        p = relative_path(cache, "oracle/" + item["path"])
        require(p.is_file(), "missing reference input: " + str(p))
        data = p.read_bytes()
        require(len(data) == item["bytes"] and sha256(data) == item["sha256"],
                "reference input identity mismatch: " + item["path"])
    catalogs = {}
    for profile in inputs["catalogs"]:
        raw = relative_path(cache, "oracle/" + profile["path"]).read_bytes()
        actual = sha256(compact_json_bytes(raw))
        require(actual == pin[profile["pin_field"]],
                "published catalog semantic digest drift: " + profile["id"])
        tools = parse_json(raw)
        require(isinstance(tools, list), "catalog is not an array")
        require(len(tools) == pin["toolCount"], "published tool count drift")
        names = [item.get("name") for item in tools]
        require(all(isinstance(x, str) and re.fullmatch(r"[a-z][a-z0-9_]*", x)
                    for x in names), "invalid tool name")
        require(len(set(names)) == len(names), "duplicate published tool name")
        names_digest = sha256(json.dumps(names, separators=(",", ":")).encode())
        require(names_digest == pin["toolNamesSha256"],
                "published tool order/name digest drift")
        catalogs[profile["id"]] = tools
    require(set(catalogs) == {"compact_input_full_output", "full_input_off_output"},
            "both independent MCP schema profiles are required")
    require([t["name"] for t in catalogs["compact_input_full_output"]]
            == [t["name"] for t in catalogs["full_input_off_output"]],
            "schema profiles disagree about tool identity/order")
    for item in inputs["source_files"] + inputs.get("additional_source_files", []):
        data = relative_path(cache, "upstream/" + item["path"]).read_bytes()
        git_blob = hashlib.sha1(b"blob " + str(len(data)).encode()
                                + bytes([0]) + data).hexdigest()
        require(len(data) == item["bytes"] and sha256(data) == item["sha256"]
                and git_blob == item["git_blob"],
                "pinned Git source identity mismatch: " + item["path"])
    return pin, catalogs


def source_inventory(cache, inputs):
    """Static declarations only; this is not execution of the Git build.

    Every source byte is pinned before this narrowly scoped extractor runs.
    Factory calls and metadata calls occur in the reviewed declaration owners.
    Cross-file inclusions are explicit and pinned in the input manifest.
    """
    groups = {}
    origins = {}
    sources = {}
    for item in inputs["source_files"]:
        text = relative_path(cache, "upstream/" + item["path"]).read_text()
        sources[item["symbol"]] = text
        names = set(re.findall(r'\btoolContractMetadata\(\s*"([a-z0-9_]+)"', text))
        names.update(re.findall(r'\b(?:' + HELPERS
                                + r')\(\s*"([a-z0-9_]+)"', text))
        if item["symbol"] == "HOPPER_MEMORY_TOOL_DEFINITIONS":
            names.update(re.findall(r'\bname:\s*"([a-z0-9_]+)"', text))
        groups[item["symbol"]] = names
        for name in names:
            origins.setdefault(name, set()).add(item["path"])
    for group, children in inputs["source_group_includes"].items():
        require(group in groups, "unknown source group: " + group)
        for child in children:
            require(child in groups, "unknown included source group: " + child)
            groups[group].update(groups[child])
    raw = sources["TOOL_FAMILY_DEFINITIONS"]
    require("export const TOOL_FAMILY_DEFINITIONS = [" in raw,
            "pinned family declaration missing")
    body = raw.split("export const TOOL_FAMILY_DEFINITIONS = [", 1)[1]
    body = body.split("] as const satisfies", 1)[0]
    families = {}
    for match in re.finditer(r'\{\s*id:\s*"([^"]+)"([\s\S]*?)(?=\n  \},)', body):
        family, declaration = match.groups()
        require(family not in families, "duplicate source family: " + family)
        refs = re.findall(r"TOOL_CONTRACT_GROUPS\.([A-Z0-9_]+)", declaration)
        require(refs and all(x in groups for x in refs), "unresolved family groups")
        families[family] = set().union(*(groups[x] for x in refs))
    require(list(families) == inputs["tool_families"], "tool family selection drift")
    declared_ids = re.findall(r'^  "([a-z-]+)",$', sources["TOOL_FAMILY_IDS"], re.M)
    require(declared_ids == list(families), "source family ID/order drift")
    by_tool = {}
    for family, names in families.items():
        for name in names:
            require(name not in by_tool, "tool has multiple source families: " + name)
            by_tool[name] = {"family": family, "source_contract_paths": sorted(origins[name])}
    return by_tool


def validate_map(mapping, published_names, families):
    require(mapping.get("schema") == "hepta.rea.capability-map.v1",
            "unsupported capability map schema")
    require(set(mapping) == {"schema", "runtime_baseline", "interfaces", "auxiliary_capabilities",
                             "family_defaults", "overrides", "behavior_gates"},
            "unknown capability map fields (qualification cannot be declared here)")
    require(set(mapping["family_defaults"]) == set(families),
            "capability map omits or invents a family")
    require(set(mapping["overrides"]) <= set(published_names),
            "capability override names a tool outside the published package")
    for interface in mapping["interfaces"].values():
        require(set(interface) <= {"source_paths", "tests", "scope"},
                "unknown interface fields (no handwritten PASS)")
    for gate in mapping["behavior_gates"].values():
        require(set(gate) == {"common", "requirement"}
                and isinstance(gate["common"], bool)
                and isinstance(gate["requirement"], str) and gate["requirement"],
                "invalid behavior gate declaration (no handwritten PASS)")
    allowed = {"implementation", "native_routes", "scope", "missing", "dependencies",
               "extra_gates", "source_paths", "tests", "related_runtime_routes",
               "related_auxiliary_capabilities"}
    for scope in list(mapping["family_defaults"].values()) + list(mapping["overrides"].values()):
        require(set(scope) <= allowed, "unknown scope fields (no handwritten PASS)")
        if "implementation" in scope:
            require(scope["implementation"] in STATES, "unsupported implementation state")
        if "native_routes" in scope:
            require(set(scope["native_routes"]) <= set(mapping["interfaces"]),
                    "mapping references an undeclared native interface")
        if "extra_gates" in scope:
            require(set(scope["extra_gates"]) <= set(mapping["behavior_gates"]),
                    "mapping references an unknown behavior gate")
        require(set(scope.get("related_auxiliary_capabilities", []))
                <= set(mapping["auxiliary_capabilities"]), "unknown auxiliary capability")
    for capability in mapping["auxiliary_capabilities"].values():
        require(set(capability) <= {"kind", "variant", "source_paths", "tests", "scope",
                                    "entrypoint", "required", "upstream_tools"},
                "unknown auxiliary fields (no handwritten PASS)")
        require(capability.get("kind") in {"rust_cli", "python_cli"}, "unknown auxiliary kind")
        require(set(capability.get("upstream_tools", [])) <= set(published_names),
                "auxiliary mapping invents an upstream tool")


def runtime_inventory(root, mapping):
    server_path = "src/mcp/server.rs"
    server = relative_path(root, server_path).read_text()
    names = re.findall(r"^\s*(?:pub(?:\([^)]*\))?\s+)?async\s+fn\s+(rea_[a-z0-9_]+)\s*\(", server, re.M)
    require(len(names) == len(set(names)), "duplicate native REA handler")
    require(set(names) == set(mapping["interfaces"]),
            "native handler mapping drift; unmapped="
            + repr(sorted(set(names) - set(mapping["interfaces"])))
            + "; absent=" + repr(sorted(set(mapping["interfaces"]) - set(names))))
    paths = {server_path}
    for name, interface in mapping["interfaces"].items():
        require(interface["source_paths"], "native interface lacks source binding: " + name)
        paths.update(interface["source_paths"])
        paths.update(interface.get("tests", []))
    for scope in list(mapping["family_defaults"].values()) + list(mapping["overrides"].values()):
        paths.update(scope.get("source_paths", []))
        paths.update(scope.get("tests", []))
    auxiliary = []
    cli_path = relative_path(root, "src/cli.rs")
    main_path = relative_path(root, "src/main.rs")
    if mapping["auxiliary_capabilities"] or cli_path.exists() or main_path.exists():
        cli = relative_path(root, "src/cli.rs").read_text()
        main = relative_path(root, "src/main.rs").read_text()
        variants = set(re.findall(r"^\s*(Rea[A-Z][A-Za-z0-9]+)(?:\s*\{|\s*,|\()", cli, re.M))
        mapped_variants = set()
        for name, capability in sorted(mapping["auxiliary_capabilities"].items()):
            if capability["kind"] == "rust_cli":
                variant = capability["variant"]
                require(variant not in mapped_variants, "duplicate auxiliary CLI variant")
                mapped_variants.add(variant)
                present = variant in variants
                if present:
                    require("Commands::" + variant in main, "CLI variant lacks main dispatch")
            else:
                present = all(relative_path(root, p).is_file() for p in capability["source_paths"])
            require(present or not capability.get("required", True), "missing required auxiliary: " + name)
            if present:
                paths.update(capability["source_paths"])
                paths.update(capability.get("tests", []))
            auxiliary.append({"id": name, "kind": capability["kind"],
                              "entrypoint": capability["entrypoint"],
                              "source_presence": "PRESENT" if present else "ABSENT",
                              "scope": capability["scope"],
                              "upstream_tools": capability.get("upstream_tools", []),
                              "upstream_parity": "NOT_ESTABLISHED"})
        require(variants <= mapped_variants, "unmapped REA CLI variants: " + repr(variants - mapped_variants))
        paths.update({"src/cli.rs", "src/main.rs"})
    records = []
    for name in sorted(paths):
        path = relative_path(root, name)
        require(path.is_file(), "missing mapped runtime source/test: " + name)
        data = path.read_bytes()
        records.append({"path": name, "sha256": sha256(data), "bytes": len(data)})
    return {"baseline_commit": mapping["runtime_baseline"],
            "discovery": "Rust source handler discovery, not live MCP tools/list",
            "interface_count": len(names), "interfaces": sorted(names),
            "auxiliary_capabilities": auxiliary,
            "source_files": records, "source_manifest_sha256": digest_json(records)}


def validate_environment(root, environment):
    require(environment.get("schema") == "hepta.rea.compatibility-environment.v1",
            "unsupported environment observation schema")
    probe = environment["probe"]
    require(sha256(relative_path(root, probe["path"]).read_bytes()) == probe["sha256"],
            "dependency probe source changed")
    seen = set()
    for item in environment["observations"]:
        require(item["host"] not in seen, "duplicate configured host observation")
        seen.add(item["host"])
        require(item["exit_code"] == 0 and item["output_complete"] and item["output_durable"],
                "dependency observation is not an authoritative completed job")
        value = item["observation"]
        require(value.get("qualification") == "DISCOVERY_ONLY", "discovery cannot qualify a provider")
        raw = (json.dumps(value, sort_keys=True) + "\n").encode()
        require(sha256(raw) == item["stdout_sha256"], "dependency observation stdout identity mismatch")
    require(seen, "environment observation set is empty")
    for assessment in environment["components"].values():
        require(assessment["qualification"] == "NOT_ESTABLISHED", "dependency cannot declare parity")
        require(set(assessment["observed_hosts"]) <= seen, "unknown observed host in dependency assessment")
    return environment


def remaining_blockers(scope, dependencies, gates):
    result = [{"category": "code_and_contracts", "status": "OPEN",
               "next_step": scope["missing"]},
              {"category": "behavioral_differential", "status": "OPEN",
               "next_step": "Execute the required gates with frozen npm and independent expected facts",
               "required_gates": gates}]
    if dependencies:
        result.append({"category": "provider_or_platform_qualification", "status": "OPEN",
                       "components": [dependency["component"] for dependency in dependencies],
                       "next_step": "Use observed discovery hints to select/pin a profile; absence of a probe match is not a proven missing installation or license"})
    return result


def snapshot_rows(rows):
    return [{key: row[key] for key in SNAPSHOT_FIELDS} for row in rows]


def mapped_fields(name, family, annotations, mapping, environment):
    """One projection for authenticated generation and the offline CI check."""
    scope = dict(mapping["family_defaults"][family])
    scope.update(mapping["overrides"].get(name, {}))
    require(scope["implementation"] in STATES, "missing implementation state")
    common = [key for key, gate in mapping["behavior_gates"].items() if gate["common"]]
    required = list(dict.fromkeys(common + scope.get("extra_gates", [])))
    if annotations.get("readOnlyHint") is False and "effects_and_recovery" not in required:
        required.append("effects_and_recovery")
    require(set(required) <= set(mapping["behavior_gates"]), "unknown required gate")
    historical = []
    if name == "inspect_elf_notes":
        historical.append("Captured npm Evidence for one /usr/bin/true; generic digest replay only")
    if name == "inspect_rust_binary":
        historical.append("Captured npm invalid-relative-path/missing-path rejections; no native operation parity")
    dependencies = []
    for dependency in scope["dependencies"]:
        dependency = dict(dependency)
        if environment is not None:
            component = dependency["component"]
            require(component in environment["components"], "unassessed dependency: " + component)
            dependency["availability"] = environment["components"][component]["status"]
            dependency["observation_ref"] = component
        dependencies.append(dependency)
    return {"native_implementation": scope["implementation"],
            "native_routes": scope["native_routes"],
            "native_scope": scope["scope"], "remaining_behavior": scope["missing"],
            "dependencies": dependencies,
            "related_runtime_routes": scope.get("related_runtime_routes", []),
            "related_auxiliary_capabilities": scope.get("related_auxiliary_capabilities", []),
            "required_behavior_gates": required,
            "remaining_blockers": remaining_blockers(scope, dependencies, required),
            "qualification": {"status": "OPEN", "passed_gates": [],
                              "historical_reference_observations": historical}}


def assemble_ledger(root, pin, inputs, mapping, environment, snapshots):
    """Project already authenticated or repository-pinned immutable snapshots.

    The caller owns the distinction between full raw-input authentication and
    local consistency checking. This function performs no download or execution.
    """
    names = [row["upstream_tool"] for row in snapshots]
    validate_map(mapping, names, inputs["tool_families"])
    runtime = runtime_inventory(root, mapping)
    if environment is not None:
        validate_environment(root, environment)
    rows = [{**snapshot, **mapped_fields(snapshot["upstream_tool"], snapshot["family"],
                                        snapshot["upstream_annotations"], mapping, environment)}
            for snapshot in snapshots]
    # The capability map can declare implementation scope, never PASS. An
    # optional separate index points at exact operation receipts; the consumer
    # replays their complete wire/fixture/schema/source checks read-only.
    qualification_index = relative_path(root, "docs/rea-native/compatibility/REA_6_8_0_QUALIFICATIONS.json")
    assessments = {}
    if qualification_index.exists():
        source = Path(__file__).with_name("rea_operation_evidence.py")
        spec = importlib.util.spec_from_file_location("rea_operation_evidence", source)
        consumer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(consumer)
        assessments = consumer.consume_index(root, snapshots, mapping)
    for row in rows:
        assessment = assessments.get(row["upstream_tool"])
        if assessment is None:
            continue
        required = set(row["required_behavior_gates"])
        passed = set(assessment["passed_gates"])
        require(passed <= set(mapping["behavior_gates"]), "receipt consumer returned an unknown behavior gate")
        qualified = (assessment["status"] == "QUALIFIED"
                     and row["native_implementation"] == "operation_candidate"
                     and required <= passed and not assessment.get("failed_checks")
                     and not assessment.get("unimplemented_required_observations"))
        row["qualification"] = {**row["qualification"],
            "status": "QUALIFIED" if qualified else "OPEN",
            "passed_gates": sorted(passed & required), "operation_evidence": assessment}
        if qualified:
            row["remaining_behavior"] = "None within the recorded frozen operation/profile qualification scope"
            row["remaining_blockers"] = []
        else:
            row["remaining_blockers"].append({"category": "operation_qualification", "status": "OPEN",
                "required_gates": sorted(required - passed),
                "unimplemented_observations": assessment.get("unimplemented_required_observations", [])})
    counts = Counter(row["native_implementation"] for row in rows)
    qualified_count = sum(row["qualification"]["status"] == "QUALIFIED" for row in rows)
    by_family = {family: {"upstream_tools": sum(r["family"] == family for r in rows),
                          "qualified_tools": sum(r["family"] == family and r["qualification"]["status"] == "QUALIFIED" for r in rows)}
                 for family in inputs["tool_families"]}
    return {"schema": "hepta.rea.compatibility-ledger.v1",
            "qualification_scope": ("Verified frozen inventory and source mapping; operation qualifications are limited to their recorded profiles"
                                    if qualified_count else "Verified frozen inventory and source mapping; no operation parity is established"),
            "upstream": {"package": pin["publishedPackage"], "package_sha256": pin["tarballSha256"],
                         "source_commit": inputs["source_commit"], "catalog_sha256": pin["catalogSha256"],
                         "full_input_catalog_sha256": pin["fullInputCatalogSha256"],
                         "tool_names_sha256": pin["toolNamesSha256"],
                         "source_package_equivalence": "NOT_ESTABLISHED",
                         "source_inventory_scope": "Static pinned declarations, not a live Git-built catalog",
                         "source_declared_count": len(rows) + len(inputs["expected_source_only_tools"]),
                         "source_only_tools": inputs["expected_source_only_tools"]},
            "runtime": runtime,
            "environment_observations_sha256": digest_json(environment) if environment is not None else None,
            "dependency_assessments": environment["components"] if environment is not None else {},
            "mapping_sha256": digest_json(mapping), "inputs_sha256": digest_json(inputs),
            "summary": {"published_tools": len(rows), "families": len(by_family),
                        "native_interfaces": runtime["interface_count"],
                        "implementation_counts": dict(sorted(counts.items())),
                        "qualified_tools": qualified_count, "open_tools": len(rows) - qualified_count, "by_family": by_family},
            "behavior_gates": mapping["behavior_gates"], "tools": rows}


def generate(root, cache, inputs, mapping, environment=None):
    pin, catalogs = verify_inputs(root, cache, inputs)
    declarations = source_inventory(cache, inputs)
    full = catalogs["full_input_off_output"]
    compact = catalogs["compact_input_full_output"]
    names = [row["name"] for row in full]
    require(set(names) <= set(declarations), "npm tool missing a source family declaration")
    source_only = sorted(set(declarations) - set(names))
    require(source_only == inputs["expected_source_only_tools"], "Git/npm source-only tool set drift")
    snapshots = []
    for index, (left, right) in enumerate(zip(full, compact, strict=True)):
        name = left["name"]
        snapshots.append({"upstream_tool": name, "catalog_index": index,
                          "family": declarations[name]["family"],
                          "source_contract_paths": declarations[name]["source_contract_paths"],
                          "schema_fingerprints": {
                              "algorithm": SCHEMA_FINGERPRINT_ALGORITHM,
                              "full_input": digest_json(left["inputSchema"]),
                              "compact_input": digest_json(right["inputSchema"]),
                              "full_output": digest_json(right["outputSchema"]) if "outputSchema" in right else None},
                          "upstream_annotations": right.get("annotations", {})})
    require(digest_json(snapshots) == inputs["catalog_snapshot_sha256"],
            "authenticated catalog projection differs from repository snapshot pin")
    return assemble_ledger(root, pin, inputs, mapping, environment, snapshots)


def check_mapping(root, inputs, mapping, environment, stored):
    """Check committed mapping/source consistency without reading raw references.

    The repository snapshot pin was created by authenticated generation. This
    check does not re-authenticate the raw catalog, Git source, npm package or
    behavioral oracle and is intentionally independent of artifact availability.
    """
    pin = published_pin(root, inputs)
    require(stored.get("schema") == "hepta.rea.compatibility-ledger.v1", "unsupported ledger schema")
    rows = stored["tools"]
    require(isinstance(rows, list) and len(rows) == pin["toolCount"], "frozen published tool count drift")
    names = [row["upstream_tool"] for row in rows]
    require(all(isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_]*", name) for name in names),
            "invalid stored upstream tool name")
    require(len(names) == len(set(names)), "duplicate stored upstream tool name")
    require(sha256(json.dumps(names, separators=(",", ":")).encode()) == pin["toolNamesSha256"],
            "frozen published tool order/name digest drift")
    require([row["catalog_index"] for row in rows] == list(range(len(rows))), "stored catalog index drift")
    require(set(row["family"] for row in rows) == set(inputs["tool_families"]), "stored tool family set drift")
    snapshots = snapshot_rows(rows)
    require(digest_json(snapshots) == inputs["catalog_snapshot_sha256"],
            "stored immutable catalog snapshot drift")
    expected = assemble_ledger(root, pin, inputs, mapping, environment, snapshots)
    require(stored == expected, "stored ledger differs from current repository mapping/source projection")
    return expected


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode()
    descriptor, temporary = tempfile.mkstemp(prefix=".rea-ledger-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def restore(cache, inputs, gh):
    """Acquire exact read-only GitHub inputs; no target/provider execution."""
    cache.mkdir(parents=True, exist_ok=True)
    artifact = inputs["artifact"]
    archive = cache / (str(artifact["id"]) + ".zip")
    if not archive.exists():
        request = [gh, "api", "repos/" + artifact["repository"]
                   + "/actions/artifacts/" + str(artifact["id"]) + "/zip"]
        result = subprocess.run(request, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=90, check=False)
        require(result.returncode == 0, "GitHub artifact download failed (no credentials printed)")
        require(sha256(result.stdout) == artifact["sha256"], "downloaded artifact digest mismatch")
        archive.write_bytes(result.stdout)
    require(sha256(archive.read_bytes()) == artifact["sha256"], "cached artifact digest mismatch")
    wanted = {item["path"]: item for item in inputs["reference_files"]}
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        require(len({m.filename for m in members}) == len(members), "duplicate archive member")
        require(sum(m.file_size for m in members) <= 40 * 1024 * 1024, "oversized archive")
        for member in members:
            relative_path(cache, member.filename)
            if member.filename not in wanted:
                continue
            require(member.file_size <= MAX_JSON_BYTES, "oversized reference member")
            raw = bundle.read(member)
            require(sha256(raw) == wanted[member.filename]["sha256"], "reference member digest mismatch")
            target = relative_path(cache, "oracle/" + member.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                require(target.read_bytes() == raw, "existing reference differs")
            else:
                target.write_bytes(raw)
    for item in inputs["source_files"] + inputs.get("additional_source_files", []):
        target = relative_path(cache, "upstream/" + item["path"])
        if target.exists():
            require(sha256(target.read_bytes()) == item["sha256"], "existing upstream source differs")
            continue
        endpoint = "repos/morluto/rea/contents/" + item["path"] + "?ref=" + inputs["source_commit"]
        result = subprocess.run([gh, "api", endpoint], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False, timeout=30)
        require(result.returncode == 0, "GitHub source read failed: " + item["path"])
        response = parse_json(result.stdout, "GitHub source response")
        require(response.get("encoding") == "base64", "unexpected GitHub content encoding")
        raw = base64.b64decode(response["content"].replace("\n", ""), validate=True)
        require(response.get("sha") == item["git_blob"] and sha256(raw) == item["sha256"],
                "downloaded upstream source identity mismatch")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    return {"restored_reference_files": len(wanted), "restored_source_files": len(inputs["source_files"]) + len(inputs.get("additional_source_files", [])),
            "cache_directory": str(cache), "artifact_sha256": artifact["sha256"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("generate", "check", "restore", "check-mapping"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--inputs", default=INPUTS_PATH)
    parser.add_argument("--mapping", default=MAP_PATH)
    parser.add_argument("--ledger", default=LEDGER_PATH)
    parser.add_argument("--environment", default=ENVIRONMENT_PATH)
    parser.add_argument("--require-parity", action="store_true")
    parser.add_argument("--gh", default="gh")
    args = parser.parse_args(argv)
    inputs = read_json(relative_path(args.root, args.inputs))
    if args.command == "check-mapping":
        require(args.cache is None, "check-mapping does not read --cache; use check for full authentication")
        mapping = read_json(relative_path(args.root, args.mapping))
        environment = read_json(relative_path(args.root, args.environment))
        stored = read_json(relative_path(args.root, args.ledger))
        ledger = check_mapping(args.root, inputs, mapping, environment, stored)
        print(json.dumps({"mapping_check": "PASS", "raw_reference_authenticity": "NOT_REVERIFIED",
                          "parity_gate": "OPEN" if ledger["summary"]["open_tools"] else "QUALIFIED", **ledger["summary"]}, sort_keys=True))
        return 3 if args.require_parity and ledger["summary"]["open_tools"] else 0
    require(args.cache is not None, args.command + " requires --cache")
    if args.command == "restore":
        require(not args.require_parity, "restore does not establish parity")
        print(json.dumps(restore(args.cache, inputs, args.gh), sort_keys=True))
        return 0
    mapping = read_json(relative_path(args.root, args.mapping))
    environment = read_json(relative_path(args.root, args.environment))
    ledger = generate(args.root, args.cache, inputs, mapping, environment)
    destination = relative_path(args.root, args.ledger)
    if args.command == "generate":
        write_json(destination, ledger)
    else:
        require(read_json(destination) == ledger, "stored ledger differs from current verified inputs/source mapping")
    print(json.dumps({"inventory_check": "PASS", "raw_reference_authenticity": "VERIFIED_AGAINST_PINS",
                      "parity_gate": "OPEN" if ledger["summary"]["open_tools"] else "QUALIFIED", **ledger["summary"]}, sort_keys=True))
    return 3 if args.require_parity and ledger["summary"]["open_tools"] else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (LedgerError, OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"inventory_check": "FAIL", "error": str(error)}, ensure_ascii=True), file=sys.stderr)
        raise SystemExit(2)

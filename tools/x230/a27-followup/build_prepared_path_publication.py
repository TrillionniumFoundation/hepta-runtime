#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Create one complete public view of the fixed, completed CString experiment.

Read-only local inputs; no compilation, workload, remote call, or raw publication.
The original CompleteSanitizer implementation and its imports remain frozen.
"""
from collections import Counter
import gzip
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "a27-prepared-path-publication-r01"
ACTUAL = "a27-prepared-path-actual-evidence-r02"
RUN_DIR = "a27-prepared-path-probe-run-r02"
BUILD_DIR = "a27-prepared-path-probe-build-r02"
FAILED_DIR = "a27-prepared-path-probe-build-r01"
ARCHIVE = ACTUAL + ".tar.gz"
ARCHIVE_BYTES = 619186
ARCHIVE_SHA = "79b9821128f60cd3958a4cf260d5ce2fda178a211ef9a5263c538dedc280b2c2"
PLAN_SHA = "847067fc03948f0ce05924604132f2e783529d371c75544facdd421dc4bc1485"
PATCH_SHA = "e970ae2897c6122339342f6b3b1cde9d71f35ea97d376be31333f7b64aa5b1bf"
DEPENDENCIES = {
    "build_x230_a26_series_evidence_r02": ("a26-series-tools", "610b7c95dfa46b25e677b29095f0b813c1074aefef4f8a101910b95b2978748f"),
    "build_x230_evidence": ("a25-evidence-tools", "d868f8aab6db0b8d35fd38116241355660758a1e4b336b64cda3f7b945ffa4fb"),
    "build_x230_six_running_evidence": ("a25-evidence-tools", "e079b19be97815bb8c4a41891fa995e40e1e353425b7e909bb814a65a3359c52"),
}
INPUTS = {
    "prepared-path/run-r02": (ACTUAL + "/" + RUN_DIR + "/run.json", 1259476, "63f68e3e349f921c32c77b3c024d5d015f34fe8eb01e58a7acf2a86471bf24f1"),
    "prepared-path/build-r02": (ACTUAL + "/" + BUILD_DIR + "/build.json", 632254, "ed8f5057fe3af03e9f0bb2431996ff6406b55fae284eb15b84dc82415b0e7cba"),
    "prepared-path/environment-r02": (ACTUAL + "/a27-prepared-path-probe-environment-r02.json", 1339, "4f0ebd169f9541f0a5cbc7dbb76427ca335df8776b7bdaf7d57db78180a8914a"),
    "prepared-path/analysis-r02": (ACTUAL + "/" + RUN_DIR + "/analysis.json", 15086, "43996a5d684c76ed6254d8d689fecbf04d45ee077ad474af10b17fc9d045896b"),
    "prepared-path/failed-prepare-r01": (ACTUAL + "/" + FAILED_DIR + "/build.json", 246940, "073d7ffb5d28c319a7f416ff3b9373773d7ec1d0c79750ca3437903d0b9181c4"),
    "provenance/archive-receipt": (ACTUAL + ".receipt.json", 43144, "3b8e8df82e5a9e2f3755614479d213919cf75b26afc308c8b0f903af7f1d7a26"),
    "provenance/transfer-terminal": (ACTUAL + "/TRANSFER_AND_TERMINAL_RECEIPT.json", 6306, "3206abdd1653552fc34cb6f75e0a68b0d7532a5f48d41bed24b73dc37956d065"),
    "prepared-path/root-recomputation": (ACTUAL + "/ROOT_RECOMPUTATION.json", 2858, "ea04828376edd2b5baa8c0feda20f31506ccefa8a686feff505826868d497ccb"),
}
SIDECAR_SOURCE = (ACTUAL + "/recompute_prepared_path_result.py", 8871,
                  "73a3b76c2c3df9d0c6d359e8ea4cf6d9158763a59464006172c31569aff6d31a")
BUILD_LABELS = {"prepared-path/build-r02", "prepared-path/failed-prepare-r01"}
EXTRA_IDENTITY_KEYS = {"device", "inode", "st_dev", "st_ino", "st_uid", "st_gid"}
METRICS = ("process_cpu_ns", "owner_thread_cpu_ns", "wall_ns")
SOURCE_NAMES = {
    "main.rs", "observation/mod.rs", "observation/profile.rs", "observation/validation.rs",
    "observation/path_semantics.rs", "mcp/runtime/config.rs", "mcp/runtime/config_tests.rs",
    "observation/ssh_observation_profile_tests.rs", "observation/ssh_observation_validation_tests.rs",
    "observation/ssh_observation_prepared_path.rs", "observation/ssh_observation_prepared_path_tests.rs",
}


def need(value, message):
    if not value:
        raise ValueError(message)


def receipt(name, raw):
    return {"file": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob_sha1": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def identity_metadata_key(key):
    lower = key.lower()
    return lower == "stamp" or lower.endswith("_stamp") or lower in EXTRA_IDENTITY_KEYS


def special_identity(label, path):
    if label != "provenance/transfer-terminal":
        return False
    return (len(path) == 3 and path[0] == "chunks" and type(path[1]) is int and path[2] == "version"
            or path in (("build_status", "job_id"), ("run_status", "job_id")))


def load_dependencies():
    sys.dont_write_bytecode = True
    sources = {}
    for name, (directory, expected) in DEPENDENCIES.items():
        path = ROOT / directory / (name + ".py")
        need(path == path.resolve(), "indirect sanitizer dependency")
        raw = path.read_bytes()
        need(hashlib.sha256(raw).hexdigest() == expected, "frozen sanitizer changed")
        sources[name] = raw
    sys.path[:0] = [str(ROOT / "a26-series-tools"), str(ROOT / "a25-evidence-tools")]
    module = importlib.import_module("build_x230_a26_series_evidence_r02")
    for name, (directory, _) in DEPENDENCIES.items():
        need(Path(sys.modules[name].__file__).resolve() == ROOT / directory / (name + ".py"),
             "unexpected imported sanitizer")
    return module, sources


def verify_actual(module, values, archive_raw):
    """Bind every archived member, child ledger and source; never execute it."""
    inventory = values["provenance/archive-receipt"]
    need(inventory["archive_sha256"] == ARCHIVE_SHA and inventory["archive_bytes"] == ARCHIVE_BYTES
         and inventory["binary_bodies_included"] is False and inventory["private_fixture_bodies_included"] is False,
         "original archive scope differs")
    expected = inventory["files"]
    need(len(expected) == 237, "fixed original member inventory differs")
    actual_files, local_raw = {}, {}
    with tarfile.open(ROOT / ARCHIVE, "r:gz") as archive:
        members = archive.getmembers()
        need(len(members) == len(expected) and len({m.name for m in members}) == len(members),
             "duplicate or extra archive member")
        for member in members:
            name = PurePosixPath(member.name)
            need(member.isfile() and not name.is_absolute() and str(name) == member.name
                 and all(part not in (".", "..") for part in name.parts) and member.name in expected,
                 "unsafe or unlisted archive member")
            with archive.extractfile(member) as stream:
                body = stream.read()
            pin = {"bytes": len(body), "sha256": module.sha(body)}
            need(pin == expected[member.name] and member.size == len(body), "archive member pin differs")
            local, copied = module.read_file(ROOT / ACTUAL / member.name)
            need(not local["retention_limit_exceeded"] and copied == body, "extracted original differs")
            actual_files[member.name], local_raw[member.name] = pin, body
    extracted = {str(p.relative_to(ROOT / ACTUAL)) for p in (ROOT / ACTUAL).rglob("*") if p.is_file()}
    need(extracted == set(expected) | {"TRANSFER_AND_TERMINAL_RECEIPT.json", "ROOT_RECOMPUTATION.json",
                                      "recompute_prepared_path_result.py"}, "unaccounted extracted file")
    sidecar, _ = module.read_file(ROOT / SIDECAR_SOURCE[0], 0)
    need(sidecar["bytes"] == SIDECAR_SOURCE[1] and sidecar["sha256"] == SIDECAR_SOURCE[2],
         "independent root recomputation source differs")
    transfer = values["provenance/transfer-terminal"]
    need(transfer["archive_sha256"] == ARCHIVE_SHA and transfer["candidate_adopted"] is False,
         "transfer archive or decision differs")
    chunks, previous, versions = transfer["chunks"], 0, set()
    need(len(chunks) == 10, "fixed transfer chunk count differs")
    for index, chunk in enumerate(chunks):
        end = chunk["next_offset"]
        need(type(end) is int and chunk["offset"] == previous < end <= ARCHIVE_BYTES
             and chunk["size"] == ARCHIVE_BYTES and chunk["eof"] is (index == len(chunks) - 1)
             and module.sha(archive_raw[previous:end]) == chunk["chunk_sha256"], "chunk binding differs")
        need(re.fullmatch(r"[0-9]+(?::[0-9]+){4}", chunk["version"]) is not None,
             "transfer version identity schema differs")
        versions.add(chunk["version"])
        previous = end
    need(previous == ARCHIVE_BYTES and len(versions) == 1, "incomplete or mixed-version transfer")
    for stage in ("build_status", "run_status"):
        status = transfer[stage]
        need(status["state"] == "succeeded" and status["exit_code"] == 0 and status["output_complete"] is True
             and status["cancelled"] is False and status["timed_out"] is False, "native terminal status differs")
    run, build = values["prepared-path/run-r02"], values["prepared-path/build-r02"]
    failed, analysis = values["prepared-path/failed-prepare-r01"], values["prepared-path/analysis-r02"]
    need(build["prepared"] is True and build["compiled"] is True and build["probe_executed"] is False
         and "error" not in build and build["inputs_before"] == build["inputs_after"], "successful build differs")
    need(len(build["stages"]) == 5 and all(s["returncode"] == 0 for s in build["stages"]),
         "successful precompile/compile stages differ")
    need(failed["prepared"] is True and failed["compiled"] is False and failed["probe_executed"] is False
         and len(failed["stages"]) == 3 and all(s["returncode"] == 0 for s in failed["stages"])
         and failed["error"] == {"type": "ValueError", "reason": "formatted B profile differs from the frozen prepared-path candidate plus untimed adapter"},
         "first format-check failure differs")
    need("inputs_after" not in failed and "sources_to_publish" not in failed,
         "failed preparation cannot have a successful final input fence")
    need(run["input_receipts_before"] == run["input_receipts_after"] == build["inputs_after"]
         and run["input_fence_errors"] == [] and run["binary_fence_errors"] == []
         and run["binary_receipts"] == build["binaries"]
         and run["binary_receipts_after"] == {v["path"]: v for v in build["binaries"].values()},
         "run input/binary receipt continuity differs")
    need(run["build"]["sha256"] == INPUTS["prepared-path/build-r02"][2]
         and run["build"]["bytes"] == INPUTS["prepared-path/build-r02"][1]
         and analysis["run_sha256"] == INPUTS["prepared-path/run-r02"][2]
         and run["plan_sha256"] == build["plan"]["sha256"] == failed["plan"]["sha256"] == PLAN_SHA,
         "run/build/analysis/plan binding differs")
    need(values["prepared-path/environment-r02"]["build_report_sha256"] == INPUTS["prepared-path/build-r02"][2],
         "environment build binding differs")
    independent = values["prepared-path/root-recomputation"]
    need(independent["raw_run_sha256"] == INPUTS["prepared-path/run-r02"][2]
         and independent["raw_build_sha256"] == INPUTS["prepared-path/build-r02"][2]
         and independent["raw_analysis_sha256"] == INPUTS["prepared-path/analysis-r02"][2]
         and independent["plan_sha256"] == PLAN_SHA and independent["gates"] == analysis["gates"],
         "independent root receipt binding differs")
    plan_raw = local_raw[BUILD_DIR + "/PLAN.json"]
    need(module.sha(plan_raw) == PLAN_SHA and module.decode(plan_raw) == run["plan"]
         and local_raw[FAILED_DIR + "/PLAN.json"] == plan_raw == local_raw[RUN_DIR + "/PLAN.json"],
         "actual frozen plans differ")
    child_files = 0
    for kind, records in (("semantics", run["semantics"]), ("cells", run["cells"])):
        for item in records:
            label = "semantics-" + item["variant"] if kind == "semantics" else f"c{item['sequence']:02d}{item['variant']}"
            prefix = RUN_DIR + "/" + label + "/"
            added = {"variant"} if kind == "semantics" else {"sequence", "block", "position", "variant"}
            need(module.decode(local_raw[prefix + "child.json"]) == {k: v for k, v in item.items() if k not in added},
                 "original child ledger differs from run wrapper")
            for name in ("stdout.json", "stderr.log"):
                body = local_raw[prefix + name]
                need(item[name]["sha256"] == module.sha(body) and item[name]["bytes"] == len(body),
                     "child stdout/stderr binding differs")
                child_files += 1
            need(module.decode(local_raw[prefix + "stdout.json"]) == item["record"], "parsed child stdout differs")
    source_bindings, unchanged_source_pairs = [], 0
    need(set(build["sources_to_publish"]) == {"A", "B"}, "actual source arms differ")
    for variant, sources in build["sources_to_publish"].items():
        need(set(sources) == SOURCE_NAMES, "actual compiled source inventory differs")
        for relative, bound in sorted(sources.items()):
            name = BUILD_DIR + "/" + variant + "/" + relative
            need(build["inputs_after"][bound["path"]] == bound
                 and actual_files[name] == {"bytes": bound["bytes"], "sha256": bound["sha256"]},
                 "actual compiled source binding differs")
            source_bindings.append({"arm": variant, "file": relative, **actual_files[name]})
            for prefix in ("", "generated-inputs/"):
                a = FAILED_DIR + "/" + prefix + variant + "/" + relative
                b = BUILD_DIR + "/" + prefix + variant + "/" + relative
                need(local_raw[a] == local_raw[b], "r02 changed frozen runtime or probe Rust source")
                unchanged_source_pairs += 1
    need(all(module.sha(local_raw[d + "/candidate.patch"]) == PATCH_SHA for d in (FAILED_DIR, BUILD_DIR)),
         "actual runtime candidate patch differs")
    # This repeats the frozen analyzer, not an independent statistical method.
    analyzer_path = ROOT / "a27-prepared-path-probe-r02/summarize_owner_probe.py"
    analyzer_raw = analyzer_path.read_bytes()
    need(module.sha(analyzer_raw) == "bbd4670cfc65faa2397604a245b53cc928359bb10de39be1e40a768496660b93",
         "frozen analyzer changed")
    spec = importlib.util.spec_from_file_location("_a27_prepared_path_frozen_analyzer", analyzer_path)
    analyzer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(analyzer)
    repeated = analyzer.summarize(run)
    repeated["run_sha256"] = INPUTS["prepared-path/run-r02"][2]
    need(repeated == analysis and analysis["valid_complete_experiment"] is True,
         "complete analysis does not match every original row")
    need(analysis["runtime_optimization_adopted"] is False and analysis["eligible_for_runtime_candidate"] is False,
         "fixed rejected experiment decision differs")
    need(analyzer_path.read_bytes() == analyzer_raw, "frozen analyzer changed while checking")
    return {"archive_regular_members": len(actual_files), "all_original_member_bytes_verified": True,
            "all_34_child_ledgers_and_stdout_verified": True, "child_stdout_stderr_files": child_files,
            "actual_formatted_source_tree_files": source_bindings,
            "source_tree_scope": "compiled tree including disabled test files and A's unused comparison module; no runtime unit-test execution claimed",
            "unchanged_r01_r02_Rust_source_pairs": unchanged_source_pairs,
            "remote_binary_and_dependency_bodies_rehashed_locally": False,
            "remote_input_and_binary_receipt_continuity_verified": True,
            "root_recomputation_sidecars_not_members_of_original_archive": True,
            "root_recomputation_source": {"file": Path(SIDECAR_SOURCE[0]).name,
                "bytes": SIDECAR_SOURCE[1], "sha256": SIDECAR_SOURCE[2], "body_published": False},
            "frozen_analyzer_recomputed_exactly": True, "independent_statistical_method_claimed": False,
            "frozen_analyzer_source": receipt(analyzer_path.name, analyzer_raw)}, actual_files


def transform(module, values):
    environment = values["prepared-path/environment-r02"]
    pid_seeds = []
    for key in ("loadavg_before", "loadavg_after"):
        fields = environment[key].split()
        need(len(fields) == 5 and fields[-1].isdigit(), "loadavg schema differs")
        pid_seeds.append({"pid": int(fields[-1])})
    sanitizer = module.CompleteSanitizer({"documents": values, "identity_discovery_seeds": pid_seeds})
    # Refuse schema-key over-redaction rather than silently changing units/errors.
    # Any future exception needs an observed, exact schema context and receipt.
    need(all(sanitizer.string(key) == key for key in ("bytes", "errno", *METRICS)),
         "fixed metric/receipt schema key would be redacted")
    aliases, key_receipts, transformed_inputs = {}, [], dict(values)
    for label in sorted(BUILD_LABELS):
        original = values[label]
        build = dict(original)
        groups = Counter(sanitizer.string(k) for k in original["dependencies"])
        mapping, renamed = {}, {}
        for key, value in original["dependencies"].items():
            if groups[sanitizer.string(key)] > 1:
                bound = sanitizer.opaque_receipt(key)
                public_key = "<opaque-key:" + bound["canonical_value_sha256"] + ">"
                need(sanitizer.string(public_key) == public_key, "opaque dependency key changed")
                mapping[key] = public_key
                key_receipts.append({"document": label, "path": ["dependencies"],
                                     "original_key": bound, "public_key": public_key})
            else:
                public_key = key
            need(public_key not in renamed, "dependency key collision")
            renamed[public_key] = value
        build["dependencies"], aliases[label] = renamed, mapping
        transformed_inputs[label] = build
    public = {label: sanitizer(value) for label, value in transformed_inputs.items()}

    def public_key(label, path, key):
        if label in BUILD_LABELS and path == ("dependencies",) and key in aliases[label]:
            return aliases[label][key]
        return sanitizer.string(key)

    def count_identity(value):
        if isinstance(value, dict):
            return sum(int(identity_metadata_key(k)) + count_identity(v) for k, v in value.items())
        return sum(map(count_identity, value)) if isinstance(value, list) else 0

    explicit, hidden, special = [], [], []
    def mask(original, target, label, path=()):
        if isinstance(original, dict):
            for key, value in original.items():
                pk, lower = public_key(label, path, key), key.lower()
                child_path = path + (pk,)
                if identity_metadata_key(key) or special_identity(label, child_path):
                    bound = sanitizer.opaque_receipt(value)
                    target[pk] = bound
                    (explicit if identity_metadata_key(key) else special).append({
                        "document": label, "path": list(child_path), "original_value_receipt": bound,
                        "policy": "metadata tuple or native handle identity; unchanged opaque_receipt"})
                elif (lower not in sanitizer.private_keys and lower not in sanitizer.opaque_keys
                      and "base64" not in lower and not lower.endswith("_hex")):
                    mask(value, target[pk], label, child_path)
                else:
                    count = count_identity(value)
                    if count:
                        hidden.append({"document": label, "path": list(child_path),
                                       "identity_metadata_fields_inside": count,
                                       "original_parent_receipt": sanitizer.opaque_receipt(value),
                                       "policy": "already hidden by unchanged generic opaque-parent policy"})
        elif isinstance(original, list):
            need(len(original) == len(target), "list length changed during redaction")
            for index, (a, b) in enumerate(zip(original, target)):
                mask(a, b, label, path + (index,))
    for label, value in values.items():
        mask(value, public[label], label)
    total = sum(count_identity(v) for v in values.values())
    hidden_count = sum(row["identity_metadata_fields_inside"] for row in hidden)
    need(total == len(explicit) + hidden_count and len(special) == 12,
         "identity metadata inventory is incomplete")
    for label in BUILD_LABELS:
        commands = values[label]["commands"]
        need(set(commands) == {"A", "B"} and all(isinstance(v, list) and v for v in commands.values()),
             "compiler command inventory differs")
        for arm, command in commands.items():
            public[label]["commands"][arm] = sanitizer.opaque_receipt(command)

    structure, opaque, relative_file_key_adaptations = {}, [], []
    def walk(original, published, label, path, counts):
        if label in BUILD_LABELS and len(path) == 2 and path[0] == "commands":
            need(published == sanitizer.opaque_receipt(original), "compiler argv receipt differs")
            opaque.append({"document": label, "path": list(path), "policy": "plural compiler argv container"})
            counts["opaque_subtrees_replaced"] += 1
        elif isinstance(original, dict):
            need(isinstance(published, dict) and len(original) == len(published)
                 and {public_key(label, path, k) for k in original} == set(published), "dictionary shape changed")
            counts["dictionary_keys_retained"] += len(original)
            for key, value in original.items():
                pk, lower = public_key(label, path, key), key.lower()
                child_path = path + (pk,)
                if pk != key:
                    if label in BUILD_LABELS and path == ("dependencies",) and key in aliases[label]:
                        pass
                    elif module.common.Sanitizer.private_path.search(key) is not None:
                        pass
                    else:
                        need(label == "provenance/archive-receipt" and path == ("files",)
                             and key in values[label]["files"], "fixed schema key changed by generic policy")
                        relative_file_key_adaptations.append({"document": label, "path": list(path),
                            "original_key_receipt": sanitizer.opaque_receipt(key), "public_key": pk,
                            "reason": "long relative source filename matches frozen encoded-token policy"})
                else:
                    counts["unchanged_schema_or_data_key_names"] += 1
                if (identity_metadata_key(key) or special_identity(label, child_path)
                    or lower in sanitizer.private_keys or lower in sanitizer.opaque_keys
                    or "base64" in lower or lower.endswith("_hex")):
                    need(published[pk] == sanitizer.opaque_receipt(value), "opaque receipt differs")
                    if not identity_metadata_key(key) and not special_identity(label, child_path):
                        opaque.append({"document": label, "path": list(child_path), "policy": "unchanged field policy"})
                    counts["opaque_subtrees_replaced"] += 1
                else:
                    walk(value, published[pk], label, child_path, counts)
        elif isinstance(original, list):
            need(isinstance(published, list) and len(original) == len(published), "list rows changed")
            counts["list_rows_retained"] += len(original)
            for index, (a, b) in enumerate(zip(original, published)):
                walk(a, b, label, path + (index,), counts)
        elif isinstance(original, str):
            need(published == sanitizer.string(original), "string changed outside frozen policy")
            counts["strings_verified"] += 1
        else:
            need(type(original) is type(published) and original == published, "metric/flag/null changed")
            counts["numeric_boolean_null_values_unchanged"] += 1
    for label, original in values.items():
        counts = Counter()
        walk(original, public[label], label, (), counts)
        structure[label] = dict(counts)
    run, shown = values["prepared-path/run-r02"], public["prepared-path/run-r02"]
    need(len(run["cells"]) == len(shown["cells"]) == 32 and len(run["semantics"]) == 2,
         "fixed complete experiment shape differs")
    rows = [row for cell in run["cells"] for row in cell["record"]["rows"]]
    need(len(rows) == 2176 and sum(r["phase"] == "measured" for r in rows) == 2048
         and sum(r["phase"] == "warmup" for r in rows) == 128, "complete operation count differs")
    for a, b in zip(run["cells"], shown["cells"]):
        need(a["record"]["rows"] == b["record"]["rows"], "a complete timing/error row changed")
    for a, b in zip(run["semantics"], shown["semantics"]):
        need(a["record"] == b["record"] and len(a["record"]["checks"]) == 17, "semantic record changed")
    need(values["prepared-path/analysis-r02"] == public["prepared-path/analysis-r02"], "analysis changed")
    need(values["prepared-path/root-recomputation"] == public["prepared-path/root-recomputation"],
         "independent root recomputation changed")
    text_public = "\n".join(module.canonical(value).decode() for value in public.values())
    need(module.common.Sanitizer.private_path.search(text_public) is None, "private path remains")
    need(re.search(r"/proc/[0-9]+(?:/|\b)", text_public) is None, "raw proc PID remains")
    def no_raw_metadata(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if identity_metadata_key(key):
                    need(isinstance(item, dict) and item.get("redacted") is True
                         and module.HEX256.fullmatch(item.get("canonical_value_sha256", "")), "raw metadata remains")
                no_raw_metadata(item)
        elif isinstance(value, list):
            for item in value:
                no_raw_metadata(item)
    for value in public.values():
        no_raw_metadata(value)
    loadavg = []
    for key in ("loadavg_before", "loadavg_after"):
        shown_value = public["prepared-path/environment-r02"][key]
        need(environment[key].split()[:4] == shown_value.split()[:4] and shown_value.split()[-1] == "<pid>",
             "loadavg metrics or final PID handling differs")
        loadavg.append({"document": "prepared-path/environment-r02", "path": [key],
                        "original_complete_string": sanitizer.opaque_receipt(environment[key]),
                        "public_value": shown_value, "first_four_fields_preserved": True, "last_PID_replaced": True})
    need(public["prepared-path/environment-r02"]["hostname"] == sanitizer.opaque_receipt(environment["hostname"]),
         "actual hostname remains")
    inventory = {"explicit_adaptations": explicit, "already_inside_opaque_parents": hidden,
                 "transfer_and_native_identity_adaptations": special}
    detail = {"preservation_checks": structure, "dependency_key_collision_receipts": key_receipts,
              "identity_metadata_adaptations": {"count": len(explicit), "already_inside_opaque_parent_count": hidden_count,
                  "complete_original_identity_metadata_field_count": total,
                  "counts_by_document": dict(Counter(row["document"] for row in explicit))},
              "transfer_and_native_identity_count": len(special), "loadavg_identity_adaptations": loadavg,
              "numeric_coverage_counter_exceptions": [], "schema_key_overrides": [],
              "bytes_errno_and_metric_keys_preserved": True, "opaque_context_inventory": opaque,
              "all_fixed_schema_key_names_preserved": True,
              "relative_archive_file_key_adaptations": relative_file_key_adaptations,
              "owner_counts": {"cells": 32, "rows": len(rows), "measured": 2048, "warmup": 128,
                  "row_passed": sum(row.get("passed") is True for row in rows),
                  "row_failed_or_not_passed": sum(row.get("passed") is not True for row in rows),
                  "semantics": 2, "cases_per_semantic_record": 17},
              "known_generic_over_redaction": {"field": "run.plan.owner_runtime",
                  "original": run["plan"]["owner_runtime"], "public": shown["plan"]["owner_runtime"],
                  "scope": "nonmetric descriptor; exact original PLAN separately frozen"}}
    return public, inventory, detail


def main():
    need(len(sys.argv) == 1 and not os.path.lexists(OUT), "fresh fixed publication output required")
    module, dependencies = load_dependencies()
    source = Path(__file__).read_bytes()
    values, input_receipts, raw_inputs = {}, {}, {}
    for label, (relative, size, expected) in INPUTS.items():
        bound, raw = module.read_file(ROOT / relative)
        need(not bound["retention_limit_exceeded"] and bound["bytes"] == size and bound["sha256"] == expected,
             "fixed original input differs: " + label)
        values[label], input_receipts[label], raw_inputs[label] = module.decode(raw), bound, raw
    archive, archive_raw = module.read_file(ROOT / ARCHIVE)
    need(not archive["retention_limit_exceeded"] and archive["bytes"] == ARCHIVE_BYTES
         and archive["sha256"] == ARCHIVE_SHA, "original private archive differs")
    validation, members = verify_actual(module, values, archive_raw)
    public, inventory, detail = transform(module, values)
    outputs, bindings = {}, {}
    for label, value in public.items():
        plain = module.canonical(value)
        name, body = label + ".complete.sanitized.json", plain
        info = {"original": receipt(INPUTS[label][0], raw_inputs[label]),
                "complete_public_content_bytes": len(plain), "complete_public_content_sha256": module.sha(plain)}
        if len(plain) > 65536:
            body, _ = module.compressed(value)
            need(gzip.decompress(body) == plain, "complete gzip roundtrip differs")
            name += ".gz"
            info["gzip_mtime"] = 0
        outputs[name], info["public"] = body, receipt(name, body)
        bindings[label] = info
    inv_body, inv_plain = module.compressed(inventory)
    need(module.decode(gzip.decompress(inv_body)) == inventory, "identity inventory roundtrip differs")
    inv_name = "identity-adaptations.complete.sanitized.json.gz"
    outputs[inv_name] = inv_body
    detail["identity_metadata_adaptations"]["complete_inventory"] = {**receipt(inv_name, inv_body), **inv_plain}
    count = detail["identity_metadata_adaptations"]
    notes = f"""# Prepared CString path experiment: complete public evidence

This package derives public views from the one fixed, completed r02 experiment.
It retains both semantic preflights (17 cases each), all 32 cells and all 2,176
operation rows: 2,048 measured and 128 warmup. Every timing/error row and the
entire analysis remain equal to the original parsed values. No rows, failures,
outcomes or unsuccessful blocks are filtered. All three CPU gates failed; the
candidate was rejected and A26 remains unchanged. This is isolated full owner
verification, including its local synthetic agent, not RPC throughput.

The r01 preparation is preserved separately: formatting completed, then the
strict source checker refused one closure-layout difference. prepared=true,
compiled=false and probe_executed=false are preserved; no successful final
input fence is invented. The r02 checker correction did not change the plan,
candidate, Rust source, workload or statistical gates. Actual formatted source
copies are bound separately from raw generated inputs; no draft is relabeled
as compiled source. All 237 original archive members are byte-verified.

The frozen A26 CompleteSanitizer and both imports are unchanged. Every public
document preserves its full shape except explicitly receipted opaque private
subtrees. The inventory accounts for all {count['complete_original_identity_metadata_field_count']}
metadata fields: {count['count']} explicit tuples/aliases and
{count['already_inside_opaque_parent_count']} already inside opaque parents.
Ten transfer-version identities and two native job handles also use exact
opaque receipts. Loadavg keeps its first four fields and masks the final PID;
each complete original string is bound separately. Private paths and actual
hostname are redacted. All dependency-key collisions in both build reports
receive unique opaque-key hashes; values are neither merged nor removed.
Both build reports' plural compiler commands receive opaque argv receipts.
No numeric identity-counter exception is needed for this experiment.

The generic crate/user heuristic also redacts the word tokio in the descriptive
owner_runtime string. It is a known nonmetric over-redaction; the exact frozen
PLAN is a separate source artifact. bytes, errno and timing keys are explicitly
checked to stay intact. Every metric, flag and nonidentity numeric value is
verified against the original by a complete recursive walk. The same walk
rejects any altered fixed schema key; the only renamed data keys are private
paths, the documented dependency aliases, and long relative archive filenames
which match the original encoded-token rule. Each latter mapping has a key
receipt, while the separately bound original member inventory remains exact.

The private raw archive, executable bodies, rlibs and fixture bodies are not
copied into this package. Original hashes refer to original bytes; derived
public hashes are separate. Frozen source bundles are separate artifacts.
Native statuses, transfer chunk receipts, complete reports and all failures
remain visible within their privacy policy. This operation made no remote
call and ran no compilation, qualification or workload.
"""
    outputs["PUBLICATION_NOTES.md"] = notes.encode()
    outputs[Path(__file__).name] = source
    for label, (relative, _, _) in INPUTS.items():
        bound, raw = module.read_file(ROOT / relative)
        need(bound == input_receipts[label] and raw == raw_inputs[label], "original document changed")
    current_archive, _ = module.read_file(ROOT / ARCHIVE, 0)
    need(current_archive["sha256"] == ARCHIVE_SHA and current_archive["bytes"] == ARCHIVE_BYTES,
         "private archive changed")
    for name, pin in members.items():
        bound, _ = module.read_file(ROOT / ACTUAL / name, 0)
        need(bound["sha256"] == pin["sha256"] and bound["bytes"] == pin["bytes"], "original member changed")
    sidecar, _ = module.read_file(ROOT / SIDECAR_SOURCE[0], 0)
    need(sidecar["bytes"] == SIDECAR_SOURCE[1] and sidecar["sha256"] == SIDECAR_SOURCE[2],
         "independent root source changed")
    for name, (directory, _) in DEPENDENCIES.items():
        need((ROOT / directory / (name + ".py")).read_bytes() == dependencies[name], "sanitizer source changed")
    need(Path(__file__).read_bytes() == source, "publisher changed")
    record = {"schema": "hepta-a27-prepared-path-publication/v1", "publication_integrity_passed": True,
        "new_workload_run": False, "remote_calls": False, "raw_inputs_modified": False,
        "sanitizer_implementation_modified": False, "runtime_optimization_adopted": False,
        "original_archive": {"file": ARCHIVE, "bytes": ARCHIVE_BYTES, "sha256": ARCHIVE_SHA,
                             "published": False, "contents_copied_to_publication": False},
        "sanitizer_dependencies": [receipt(name + ".py", raw) for name, raw in dependencies.items()],
        "transform_source": receipt(Path(__file__).name, source), "document_bindings": bindings,
        "raw_evidence_checks": validation, "first_failed_preparation_retained": True,
        "actual_native_statuses_retained": True, "original_member_hashes": members, **detail,
        "public_artifacts": [receipt(name, body) for name, body in outputs.items()]}
    outputs["publication-receipt.json"] = module.canonical(record)
    outputs["package-manifest.json"] = module.canonical({
        "schema": "hepta-a27-prepared-path-publication-package/v1", "publication_complete": True,
        "complete_document_integrity_rechecked": True, "raw_archive_published": False,
        "original_archive_sha256": ARCHIVE_SHA, "runtime_optimization_adopted": False,
        "owner_counts": detail["owner_counts"], "identity_metadata_adaptations": count["count"],
        "identity_fields_already_inside_opaque_parents": count["already_inside_opaque_parent_count"],
        "transfer_native_identity_adaptations": detail["transfer_and_native_identity_count"],
        "schema_key_overrides": 0, "original_archive_members_verified": len(members),
        "files": [receipt(name, body) for name, body in outputs.items()]})
    OUT.mkdir(mode=0o700)
    directories = (OUT / "prepared-path", OUT / "provenance", OUT)
    for directory in directories[:-1]:
        directory.mkdir(mode=0o700)
    for name, body in outputs.items():
        module.create_only(OUT / name, body)
        need((OUT / name).read_bytes() == body, "public output verification failed")
    for path in (*directories, ROOT):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    print(json.dumps({"publication_integrity_passed": True, "files": [receipt(n, b) for n, b in outputs.items()]},
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

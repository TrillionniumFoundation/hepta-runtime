"""Finish native qualification with original owners and independent Rust references.

The aggregate result can become PASS only after all required recipes match the
retained native corpus. Replaying a corpus does not add new native test cases.
"""
from __future__ import annotations

import argparse
import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from qualify_hia_runtime_native import (MODULES, completed_test_summary, entropy_evidence,
                                       PARALLEL_NATIVE_SUITES,
                                       editable_content_evidence, view_render_evidence, view_cache_evidence,
                                       line_verify_evidence, batch_plan_evidence, batch_apply_evidence, caller_authority_evidence,
                                       history_evidence, json_evidence, request_context_evidence, result_publication_evidence,
                                       request_scope_evidence,
                                       execution_evidence, effect_fence_evidence, config_evidence,
                                       session_evidence,
                                       atomic_write_evidence, atomic_write_completed_process, atomic_write_retained_files,
                                       atomic_write_retire_fixtures,
                                       file_info_evidence, multi_read_controller_evidence, native_composition_evidence,
                                       operation_aead_evidence, operation_kdf_evidence, operation_nonce_evidence,
                                       operation_record_evidence, operation_scope_evidence,
                                       operation_scope_os_evidence,
                                       python_reference_evidence, qualification_env,
                                       record_check, save_report, sha, sources)
from check_hia_native_inventory import RUNTIME_BASE_COMMIT, check_original_sources
from hia_native_build import HEPTA_COMMIT
from hia_native_cold import validate_cold_evidence
from hia_native_entropy_qualification import (FOLDER as ENTROPY_FOLDER, KERNEL_RECEIPT,
                                             ORIGINAL_SOURCE as ENTROPY_ORIGINAL_SOURCE,
                                             normalized_kernel_report, object_at as entropy_object,
                                             oracle_dependencies as entropy_dependencies)
from hia_native_scope_qualification import FOLDER as SCOPE_FOLDER, ORACLE_COUNTS as SCOPE_ORACLE_COUNTS
from hia_native_editable_qualification import FOLDER as EDITABLE_FOLDER, CASES as EDITABLE_CASES
from hia_native_view_qualification import FOLDER as VIEW_FOLDER, CASES as VIEW_CASES, stream_identity as view_stream_identity
from hia_native_view_cache_qualification import compare_original as compare_cache_original
from hia_native_authority_qualification import compare_original as compare_authority_original
from hia_native_history_qualification import compare_original as compare_history_original
from hia_native_json_qualification import (compare_original as compare_json_original,
                                           check_original_receipts as check_json_original_receipts)
from hia_native_request_context_reference import (compare_original as compare_request_original,
                                                  check_original_receipts as check_request_original_receipts)
from hia_native_result_publication_reference import (compare_original as compare_publication_original,
                                                     check_original_receipts as check_publication_original_receipts)
from hia_native_request_scope_reference import (compare_original as compare_request_scope_original,
                                                check_original_receipts as check_request_scope_original_receipts)
from hia_native_batch_plan_qualification import (FOLDER as BATCH_PLAN_FOLDER,
                                                ORIGINALS as BATCH_PLAN_ORIGINALS,
                                                REFERENCE_ROWS as BATCH_PLAN_ROWS)
from hia_native_scope_os_qualification import (FOLDER as SCOPE_OS_FOLDER, PAIRED_RECEIPT as SCOPE_OS_PAIRED_RECEIPT,
                                              exact_profile as scope_os_profile, paired_evidence as scope_os_paired_evidence)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def packet_count(raw: bytes, *, output: bool) -> int:
    offset, count = 0, 0
    while offset < len(raw):
        if len(raw) - offset < 16:
            raise ValueError("truncated oracle corpus header")
        first, second = struct.unpack_from("<QQ", raw, offset)
        size = second if output else first
        offset += 16
        if size > len(raw) - offset:
            raise ValueError("truncated oracle corpus payload")
        offset += size
        count += 1
    return count


def executable(name: str) -> Path:
    selected = shutil.which(name)
    if selected is None:
        raise FileNotFoundError("required compiler executable unavailable: " + name)
    # Keep a rustup shim's argv[0] while reporting its resolved bytes separately.
    return Path(selected).absolute()


def check_input_pins(output: Path, report: dict) -> None:
    if sources() != report["source_sha256"]:
        raise ValueError("source inputs differ from the completed native phase")
    if "qualification_pipeline" in report:
        from hia_native_pipeline import verify_pipeline_receipts
        verify_pipeline_receipts(output, report)
    originals = check_original_sources(ROOT)
    if report.get("inventory", {}).get("original_sources") != originals:
        raise ValueError("original Rust reference inventory differs from the native phase")
    bootstrap = output / "build/bootstrap/bootstrap.json"
    if sha(bootstrap) != report.get("compiler_bootstrap_sha256"):
        raise ValueError("compiler bootstrap receipt differs from the native phase")
    for label in ("B1", "B2", "B3"):
        if sha(bootstrap.with_name(label + ".image.bin")) != report["compiler_image_sha256"]:
            raise ValueError("native compiler fixed-point image changed")
    boot = json.loads(bootstrap.read_bytes())
    cold = validate_cold_evidence(output / "compiler-cold.json", dependency=boot["dependency"],
                                  compiler_sha256=report["compiler_image_sha256"])
    if (report.get("matching_source_full_cold_qualified") is not True
            or report.get("compiler_cold_status") != "PASS"
            or report.get("compiler_cold_evidence") != cold):
        raise ValueError("required matching-source full cold evidence differs")
    if (report.get("retained_python_comparison_status") != "PASS"
            or report.get("original_python_comparisons") != python_reference_evidence(output, report)):
        raise ValueError("required retained-Python IO/stat-version/local-service evidence differs")
    if report.get("native_composition_evidence") != native_composition_evidence(output, report):
        raise ValueError("required native composition evidence differs")
    if report.get("multi_read_controller_evidence") != multi_read_controller_evidence(output, report):
        raise ValueError("required multi-read controller evidence differs")
    if report.get("operation_kdf_evidence") != operation_kdf_evidence(output, report):
        raise ValueError("required operation KDF primitive/binding evidence differs")
    if report.get("operation_aead_evidence") != operation_aead_evidence(output, report):
        raise ValueError("required operation AEAD/authentication evidence differs")
    if report.get("operation_nonce_evidence") != operation_nonce_evidence(output, report):
        raise ValueError("required operation nonce state/ELF evidence differs")
    if report.get("operation_record_evidence") != operation_record_evidence(output, report):
        raise ValueError("required operation record composition/reference evidence differs")
    if report.get("file_info_evidence") != file_info_evidence(output, report):
        raise ValueError("required file-info controller/metadata/deadline evidence differs")
    if report.get("system_entropy_evidence") != entropy_evidence(output, report):
        raise ValueError("required entropy compiler/effect/transport/trace evidence differs")
    if report.get("operation_scope_evidence") != operation_scope_evidence(output, report):
        raise ValueError("required private scope lifetime/composition/reference-domain evidence differs")
    if report.get("editable_content_evidence") != editable_content_evidence(output, report):
        raise ValueError("required editable state/byte-preservation/static-image evidence differs")
    if report.get("line_verify_evidence") != line_verify_evidence(output, report):
        raise ValueError("required line-ID verification/diagnostic/index evidence differs")
    if report.get("batch_plan_evidence") != batch_plan_evidence(output, report):
        raise ValueError("required complete batch input/endpoint/large-result evidence differs")
    if report.get("batch_apply_evidence") != batch_apply_evidence(output, report):
        raise ValueError("required batch application complete native execution evidence differs")
    if report.get("atomic_write_evidence") != atomic_write_evidence(output, report):
        raise ValueError("required atomic policy, kernel, boundary or refusal evidence differs")
    if "atomic_write" in report.get("original_rust_comparisons", {}):
        rustc = Path(report["rust_compiler"]["invocation_path"])
        if report["original_rust_comparisons"]["atomic_write"] != atomic_write_original_evidence(output, report, rustc):
            raise ValueError("required actual atomic original invocation or retained corpus differs")
    if report.get("view_render_evidence") != view_render_evidence(output, report):
        raise ValueError("required complete view byte-domain/cache-plan/transport evidence differs")
    if report.get("json_evidence") != json_evidence(output, report):
        raise ValueError("required JSON actual native/ELF/corpus evidence differs")
    if report.get("request_context_evidence") != request_context_evidence(output, report):
        raise ValueError("required request context state/response/transport evidence differs")
    check_request_original_receipts(ROOT, output, report, completed_test_summary)
    if report.get("result_publication_evidence") != result_publication_evidence(output, report):
        raise ValueError("required result publication construction/ELF/write evidence differs")
    check_publication_original_receipts(ROOT, output, report, completed_test_summary)
    if report.get("request_scope_evidence") != request_scope_evidence(output, report):
        raise ValueError("required request continuation/cache lease/native refusal evidence differs")
    check_request_scope_original_receipts(ROOT, output, report, completed_test_summary)
    if report.get("execution_evidence") != execution_evidence(output, report):
        raise ValueError("required execution typed/core/controller evidence differs")
    if report.get("effect_fence_evidence") != effect_fence_evidence(output, report):
        raise ValueError("required effect fence actual process/lifetime/kernel evidence differs")
    if report.get("config_evidence") != config_evidence(output, report):
        raise ValueError("required configuration native evidence differs")
    if "runtime_config" in report.get("original_rust_comparisons", {}):
        if report["original_rust_comparisons"]["runtime_config"] != retained_config_original(output, report):
            raise ValueError("required complete original configuration evidence differs")
    if "execution_shadow" in report.get("original_rust_comparisons", {}):
        if report["original_rust_comparisons"]["execution_shadow"] != retained_execution_original(output, report):
            raise ValueError("required complete original execution replay changed")
    check_json_original_receipts(ROOT, output, report, completed_test_summary)
    if report.get("history_evidence") != history_evidence(output, report):
        raise ValueError("required history state/original-domain/static-image evidence differs")
    if report.get("session_evidence") != session_evidence(output, report):
        raise ValueError("required session state, latch, full corpus and executable evidence differs")
    if "session_workdir" in report.get("original_rust_comparisons", {}):
        import hia_native_session_qualification as session_qualification
        rustc = Path(report["rust_compiler"]["invocation_path"])
        actual = session_qualification.retained_original(ROOT, output, report, rustc, completed_test_summary)
        if report["original_rust_comparisons"]["session_workdir"] != actual:
            raise ValueError("required actual session original invocation changed")
    if report.get("view_cache_evidence") != view_cache_evidence(output, report):
        raise ValueError("required cache state/lifecycle/view-plan/transport evidence differs")
    if report.get("operation_scope_os_evidence") != operation_scope_os_evidence(output, report):
        raise ValueError("required actual OS entropy/scope/custody evidence differs")
    if report.get("caller_authority_evidence") != caller_authority_evidence(output, report):
        raise ValueError("required caller authority/source/image/OS/complete-corpus evidence differs")
    for collection in ("rust_oracle_inputs", "python_reference_inputs"):
        for relative, expected in report[collection].items():
            path = Path(relative)
            if path.is_absolute() or ".." in path.parts or sha(output / path) != expected:
                raise ValueError("retained native reference corpus changed: " + relative)
    if set(report.get("native_parallel_receipts", {})) != {
            name + ".execution.json" for name in PARALLEL_NATIVE_SUITES}:
        raise ValueError("independent native process receipt inventory differs")
    for relative, expected in report["native_parallel_receipts"].items():
        if Path(relative).name != relative or sha(output / relative) != expected:
            raise ValueError("independent native process receipt changed")
        receipt = json.loads((output / relative).read_bytes())
        rows = receipt.get("checks", [])
        if (len(rows) != 1 or rows[0] not in report["checks"] or rows[0].get("exit_code") != 0
                or rows[0].get("timed_out") is not False or rows[0].get("start_error")):
            raise ValueError("independent native process did not finish successfully")
    if report.get("original_rust_comparisons"):
        receipts = report.get("rust_parallel_receipts", {})
        expected_receipts = {value[0] for value in PARALLEL_RUST_RECIPES.values()}
        if set(receipts) != expected_receipts:
            raise ValueError("independent original reference receipt inventory differs")
        for key, (name, expected) in PARALLEL_RUST_RECIPES.items():
            path = output / name
            if sha(path) != receipts[name]:
                raise ValueError("independent original reference receipt changed")
            private = json.loads(path.read_bytes())
            rows = [row for row in private.get("checks", []) if row["name"] in expected]
            if ([row["name"] for row in rows] != list(expected)
                    or any(row not in report["checks"] or row["exit_code"] != 0
                           or row["timed_out"] is not False for row in rows)):
                raise ValueError("independent original reference completion differs: " + key)
    declared = {item["key"]: item for item in MODULES}
    for key, item in report["modules"].items():
        expected = declared[key]
        relative = Path(item["manifest"])
        if (item.get("source") != expected["source"]
                or item.get("builder") != expected.get("builder", "borrowed_bytes")
                or relative.is_absolute() or ".." in relative.parts):
            raise ValueError("compiled module registry or retained path differs: " + key)
        manifest = output / relative
        if sha(manifest) != item["sha256"]:
            raise ValueError("compiled module manifest changed")
        module = json.loads(manifest.read_bytes())
        if (module.get("compiler_commit") != HEPTA_COMMIT
                or module.get("compiler_sha256") != report["compiler_image_sha256"]):
            raise ValueError("compiled module compiler identity changed")
        if item.get("builder") in {"composition", "record_composition", "scope_composition", "scope_os_composition", "entropy", "authority_composition", "batch_plan", "batch_apply", "atomic_write", "history", "execution_shadow", "effect_fence", "runtime_config", "result_publication", "session_workdir", "request_scope"}:
            # The appropriate fixed table, all child source/image pairs,
            # packer and executable were revalidated above, including its suite.
            continue
        if item.get("builder") == "io":
            if (module.get("schema") != "hepta.runtime.native-io.v1"
                    or module.get("executable") != "native-read.elf"
                    or module.get("policy_manifest") != "policy.json"
                    or sha(manifest.parent / "native-read.elf") != module["executable_sha256"]
                    or sha(manifest.parent / "policy.json") != module["policy_manifest_sha256"]):
                raise ValueError("native IO executable or policy manifest changed")
            for kind in ("policy", "packer"):
                if (sha(manifest.parent / (kind + ".hepta")) != module[kind + "_source_sha256"]
                        or sha(ROOT / "native" / ("io_" + kind + ".hepta")) != module[kind + "_source_sha256"]):
                    raise ValueError("native IO source changed: " + kind)
            policy = json.loads((manifest.parent / "policy.json").read_bytes())
            if (policy.get("source") != "policy.hepta" or policy.get("image") != "policy.image.bin"
                    or policy.get("compiler_commit") != HEPTA_COMMIT
                    or policy.get("compiler_sha256") != report["compiler_image_sha256"]
                    or policy.get("source_sha256") != module["policy_source_sha256"]
                    or sha(manifest.parent / "policy.image.bin") != policy.get("image_sha256")):
                raise ValueError("native IO policy image changed")
            continue
        for label in ("source", "image"):
            if sha(manifest.parent / module[label]) != module[label + "_sha256"]:
                raise ValueError("compiled module artifact changed: " + label)
        standalone = module.get("standalone")
        if standalone and sha(manifest.parent / standalone["path"]) != standalone["sha256"]:
            raise ValueError("compiled standalone executable changed")


def rust_compile(output: Path, report: dict, rustc: Path, *, key: str,
                 source: Path, binary: Path, extra: tuple[str, ...] = (), edition: str = "2021") -> None:
    if binary.exists():
        raise ValueError("oracle executable already exists: " + str(binary))
    record_check(output, report, name=key + "-compile",
                 command=[str(rustc), "-O", "--edition=" + edition, *extra, str(source), "-o", str(binary)],
                 timeout=120)


def compare_bytes(output: Path, report: dict, rustc: Path) -> dict:
    folder = output / "rust-oracle"
    corpus = json.loads((folder / "native-corpus.json").read_bytes())
    if corpus["schema"] != "hepta.runtime.bytes-native-tests.v1":
        raise ValueError("unknown byte corpus schema")
    values = {}
    for name in ("input.bin.gz", "native-output.bin.gz"):
        packed = (folder / name).read_bytes()
        raw = gzip.decompress(packed)
        entry = corpus["corpus"][name]
        if (digest(packed), len(packed), digest(raw), len(raw)) != (
                entry["sha256"], entry["compressed_bytes"], entry["raw_sha256"], entry["raw_bytes"]):
            raise ValueError("byte corpus metadata mismatch: " + name)
        values[name] = raw
    wire, expected = values["input.bin.gz"], values["native-output.bin.gz"]
    count = packet_count(wire, output=False)
    counts = corpus["counts"]
    if (count <= 0 or count != counts["rust_oracle_cases"]
            or packet_count(expected, output=True) != count
            or counts["native_calls"] != count + counts["byte_extension_cases"]):
        raise ValueError("byte corpus case accounting differs")
    module_path = output / report["modules"]["runtime_bytes"]["manifest"]
    if corpus["module"] != json.loads(module_path.read_bytes()):
        raise ValueError("byte corpus belongs to a different native module")
    binary = folder / "oracle"
    source = ROOT / "tests/hia_native/oracle_runtime_bytes.rs"
    rust_compile(output, report, rustc, key="runtime-bytes-rust", source=source, binary=binary)
    row = record_check(output, report, name="runtime-bytes-rust-compare",
                       command=[str(binary)], input_bytes=wire, timeout=60)
    result = {"status": "PASS" if row.stdout == expected and not row.stderr else "FAIL",
              "rust_oracle_cases": count, "native_cases_added_by_replay": 0,
              "input_sha256": digest(wire), "native_output_sha256": digest(expected),
              "rust_output_sha256": digest(row.stdout), "oracle_source_sha256": sha(source),
              "oracle_executable_sha256": sha(binary)}
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["status"] != "PASS":
        raise ValueError("original Rust byte oracle disagrees with the native corpus")
    return result


def compare_text(output: Path, report: dict, rustc: Path) -> dict:
    folder = output / "text-rust-oracle"
    corpus = json.loads((folder / "native-corpus.json").read_bytes())
    wire = (folder / "requests.hex").read_bytes()
    expected = (folder / "native-output.txt").read_bytes()
    source = ROOT / "tests/hia_native/oracle_text_budget.rs"
    if corpus.get("schema") != "hepta.runtime.native-corpus.v1" or corpus.get("component") != "text_budget":
        raise ValueError("unknown text corpus schema")
    if (digest(wire), len(wire), digest(expected), len(expected)) != (
            corpus["requests_sha256"], corpus["requests_bytes"],
            corpus["native_output_sha256"], corpus["native_output_bytes"]):
        raise ValueError("text corpus metadata mismatch")
    count = len(wire.splitlines())
    if count <= 0 or count != corpus["cases"] or len(expected.splitlines()) != count:
        raise ValueError("text corpus case accounting differs")
    if corpus["source_sha256"] != sha(ROOT / "native/text_budget.hepta") or corpus["oracle_sha256"] != sha(source):
        raise ValueError("text corpus source identity differs")
    module = json.loads((output / report["modules"]["text_budget"]["manifest"]).read_bytes())
    if corpus["image_sha256"] != module["image_sha256"]:
        raise ValueError("text corpus belongs to a different native image")
    if (corpus["original_truncation_sha256"] != sha(ROOT / "src/utils/truncation.rs")
            or corpus["original_line_hash_sha256"] != sha(ROOT / "src/utils/line_hash.rs")):
        raise ValueError("original text reference source identity differs")
    binary = folder / "oracle"
    rust_compile(output, report, rustc, key="text-budget-rust", source=source, binary=binary,
                 extra=("-C", "overflow-checks=off"))
    row = record_check(output, report, name="text-budget-rust-compare",
                       command=[str(binary)], input_bytes=wire, timeout=60)
    result = {"status": "PASS" if row.stdout == expected and not row.stderr else "FAIL",
              "rust_oracle_cases": count, "native_cases_added_by_replay": 0,
              "input_sha256": digest(wire), "native_output_sha256": digest(expected),
              "rust_output_sha256": digest(row.stdout), "oracle_source_sha256": sha(source),
              "oracle_executable_sha256": sha(binary)}
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["status"] != "PASS":
        raise ValueError("original Rust text oracle disagrees with the native corpus")
    return result


def compare_endpoint(output: Path, report: dict, rustc: Path) -> dict:
    folder = output / "endpoint-rust-oracle"
    metadata = json.loads((folder / "native-corpus.json").read_bytes())
    packed = (folder / "endpoint_cases.jsonl.gz").read_bytes()
    wire = gzip.decompress(packed)
    if metadata.get("schema") != "hepta.runtime.native-corpus.v1":
        raise ValueError("unknown endpoint corpus schema")
    entry = metadata["corpus"]
    if (digest(packed), len(packed), digest(wire), len(wire)) != (
            entry["gzip_sha256"], entry["gzip_bytes"], entry["raw_sha256"], entry["raw_bytes"]):
        raise ValueError("endpoint corpus metadata mismatch")
    count = len(wire.splitlines())
    if count <= 0 or count != metadata["rust_oracle_cases"]:
        raise ValueError("endpoint corpus case accounting differs")
    if metadata["source_sha256"] != sha(ROOT / "native/line_endpoint.hepta"):
        raise ValueError("endpoint corpus source differs")
    cargo = executable("cargo")
    env = dict(os.environ)
    env.update({"HIA_REFERENCE_RUNTIME": str(ROOT), "RUSTC": str(rustc)})
    manifest = ROOT / "tests/hia_native/endpoint_oracle/Cargo.toml"
    target = folder / "target"
    record_check(output, report, name="line-endpoint-rust-compile",
                 command=[str(cargo), "build", "--locked", "--release", "--manifest-path", str(manifest),
                          "--target-dir", str(target)], env=env, timeout=180)
    binary = target / "release/hia-line-endpoint-reference"
    row = record_check(output, report, name="line-endpoint-rust-compare",
                       command=[str(binary)], input_bytes=wire, timeout=60)
    result = json.loads(row.stdout)
    if result.get("status") != "PASS" or result.get("rust_oracle_cases") != count or row.stderr:
        raise ValueError("original Rust endpoint oracle disagrees with the native corpus")
    result.update({"native_cases_added_by_replay": 0, "input_sha256": digest(wire),
                   "oracle_executable_sha256": sha(binary), "cargo_manifest_sha256": sha(manifest),
                   "cargo_lock_sha256": sha(manifest.with_name("Cargo.lock"))})
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def compare_delta(output: Path, report: dict, rustc: Path) -> dict:
    folder = output / "delta-rust-oracle"
    corpus = json.loads((folder / "native-corpus.json").read_bytes())
    wire = (folder / "requests.hex").read_bytes()
    expected = (folder / "native-output.txt").read_bytes()
    source = ROOT / "tests/hia_native/oracle_delta.rs"
    if (corpus.get("schema") != "hepta.runtime.native-corpus.v1"
            or corpus.get("component") != "delta"
            or corpus.get("requests_file") != "requests.hex"
            or corpus.get("native_output_file") != "native-output.txt"):
        raise ValueError("unknown delta corpus schema")
    if (digest(wire), len(wire), digest(expected), len(expected)) != (
            corpus["requests_sha256"], corpus["requests_bytes"],
            corpus["native_output_sha256"], corpus["native_output_bytes"]):
        raise ValueError("delta corpus metadata mismatch")
    count = len(wire.splitlines())
    if count <= 0 or count != corpus["cases"] or len(expected.splitlines()) != count:
        raise ValueError("delta corpus case accounting differs")
    if corpus["source_sha256"] != sha(ROOT / "native/delta.hepta") or corpus["oracle_sha256"] != sha(source):
        raise ValueError("delta corpus source identity differs")
    module = json.loads((output / report["modules"]["delta"]["manifest"]).read_bytes())
    if corpus["image_sha256"] != module["image_sha256"]:
        raise ValueError("delta corpus belongs to a different native image")
    if (corpus["original_commit"] != RUNTIME_BASE_COMMIT
            or corpus["original_delta_sha256"] != sha(ROOT / "src/mcp/fs/delta.rs")
            or corpus["original_line_hash_sha256"] != sha(ROOT / "src/utils/line_hash.rs")):
        raise ValueError("original delta reference source identity differs")
    if corpus["rust_compile_flags"] != ["--edition=2021", "-O", "-C", "overflow-checks=off"]:
        raise ValueError("delta reference release semantics differ")
    binary = folder / "oracle"
    rust_compile(output, report, rustc, key="delta-rust", source=source, binary=binary,
                 extra=("-C", "overflow-checks=off"))
    row = record_check(output, report, name="delta-rust-compare",
                       command=[str(binary)], input_bytes=wire, timeout=60)
    result = {"status": "PASS" if row.stdout == expected and not row.stderr else "FAIL",
              "rust_oracle_cases": count, "native_cases_added_by_replay": 0,
              "input_sha256": digest(wire), "native_output_sha256": digest(expected),
              "rust_output_sha256": digest(row.stdout), "oracle_source_sha256": sha(source),
              "oracle_executable_sha256": sha(binary)}
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["status"] != "PASS":
        raise ValueError("original Rust delta oracle disagrees with the native corpus")
    return result


def compare_codec(output: Path, report: dict, rustc: Path) -> dict:
    folder = output / "codec-rust-oracle"
    metadata = json.loads((folder / "native-corpus.json").read_bytes())
    if metadata.get("schema") != "hepta.runtime.native-codec-corpus.v1":
        raise ValueError("unknown codec corpus schema")
    packed = (folder / "codec_cases.jsonl.gz").read_bytes()
    wire = gzip.decompress(packed)
    entry = metadata["corpus"]
    if (digest(packed), len(packed), digest(wire), len(wire)) != (
            entry["gzip_sha256"], entry["gzip_bytes"], entry["raw_sha256"], entry["raw_bytes"]):
        raise ValueError("codec corpus metadata mismatch")
    count = wire.count(b"\n")
    if count <= 0 or not wire.endswith(b"\n") or count != metadata["counts"]["rust_oracle_cases"]:
        raise ValueError("codec corpus case accounting differs")
    source = ROOT / "tests/hia_native/oracle_binary_codec.rs"
    manifest = ROOT / "tests/hia_native/codec_oracle/Cargo.toml"
    composition = ROOT / "native/binary_codec_composition.json"
    module = json.loads((output / report["modules"]["binary_codec"]["manifest"]).read_bytes())
    for key, expected in (("source_sha256", module["source_sha256"]),
                          ("image_sha256", module["image_sha256"]),
                          ("oracle_source_sha256", sha(source)),
                          ("cargo_manifest_sha256", sha(manifest)),
                          ("cargo_lock_sha256", sha(manifest.with_name("Cargo.lock"))),
                          ("composition_sha256", sha(composition))):
        if metadata[key] != expected:
            raise ValueError("codec corpus source identity differs: " + key)
    cargo = executable("cargo")
    env = dict(os.environ)
    env["RUSTC"] = str(rustc)
    target = folder / "target"
    record_check(output, report, name="binary-codec-rust-compile",
                 command=[str(cargo), "build", "--locked", "--release", "--manifest-path", str(manifest),
                          "--target-dir", str(target)], env=env, timeout=180)
    binary = target / "release/hia-binary-codec-reference"
    row = record_check(output, report, name="binary-codec-rust-compare",
                       command=[str(binary)], input_bytes=wire, timeout=90)
    result = json.loads(row.stdout)
    if result.get("status") != "PASS" or result.get("rust_oracle_cases") != count or row.stderr:
        raise ValueError("independent Rust codec oracle disagrees with the native corpus")
    result.update({"native_cases_added_by_replay": 0, "input_sha256": digest(wire),
                   "oracle_source_sha256": sha(source), "oracle_executable_sha256": sha(binary),
                   "reference_kind": "independent locked Rust crates; original binary policy is Python",
                   "cargo_manifest_sha256": sha(manifest), "cargo_lock_sha256": sha(manifest.with_name("Cargo.lock")),
                   "python_native_test_observation": {"version": metadata["python_reference"],
                       "operation": metadata["running_python_policy"],
                       "cases": metadata["counts"]["running_python_cases"],
                       "scope": "only the observed CPython padding policy was compared directly"}})
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def compare_policy(output: Path, report: dict, rustc: Path) -> dict:
    folder = output / "policy-rust-oracle"
    corpus = json.loads((folder / "native-corpus.json").read_bytes())
    wire = (folder / "requests.hex").read_bytes()
    expected = (folder / "native-output.txt").read_bytes()
    source = ROOT / "tests/hia_native/oracle_policy.rs"
    if (corpus.get("schema") != "hepta.runtime.native-corpus.v1" or corpus.get("component") != "policy"
            or corpus.get("requests_file") != "requests.hex"
            or corpus.get("native_output_file") != "native-output.txt"):
        raise ValueError("unknown policy corpus schema")
    if (digest(wire), len(wire), digest(expected), len(expected)) != (
            corpus["requests_sha256"], corpus["requests_bytes"],
            corpus["native_output_sha256"], corpus["native_output_bytes"]):
        raise ValueError("policy corpus metadata mismatch")
    count = len(wire.splitlines())
    if count <= 0 or count != corpus["cases"] or len(expected.splitlines()) != count:
        raise ValueError("policy corpus case accounting differs")
    module = json.loads((output / report["modules"]["policy"]["manifest"]).read_bytes())
    if (corpus["source_sha256"] != sha(ROOT / "native/policy.hepta")
            or corpus["oracle_sha256"] != sha(source) or corpus["image_sha256"] != module["image_sha256"]
            or corpus["original_commit"] != RUNTIME_BASE_COMMIT
            or corpus["original_config_sha256"] != sha(ROOT / "src/mcp/runtime/config.rs")
            or corpus["composition_sha256"] != sha(ROOT / "native/policy_provenance.json")):
        raise ValueError("policy corpus original/native source identity differs")
    if corpus["rust_compile_flags"] != ["--edition=2021", "-O", "-C", "overflow-checks=off"]:
        raise ValueError("policy reference release semantics differ")
    binary = folder / "oracle"
    rust_compile(output, report, rustc, key="policy-rust", source=source, binary=binary,
                 extra=("-C", "overflow-checks=off"))
    row = record_check(output, report, name="policy-rust-compare", command=[str(binary)],
                       input_bytes=wire, timeout=60)
    result = {"status": "PASS" if row.stdout == expected and not row.stderr else "FAIL",
              "rust_oracle_cases": count, "native_cases_added_by_replay": 0,
              "input_sha256": digest(wire), "native_output_sha256": digest(expected),
              "rust_output_sha256": digest(row.stdout), "oracle_source_sha256": sha(source),
              "oracle_executable_sha256": sha(binary)}
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["status"] != "PASS":
        raise ValueError("original Rust policy oracle disagrees with the native corpus")
    return result


def compare_multi_read(output: Path, report: dict, rustc: Path) -> dict:
    """Compare unchanged original typed validation, never synthetic file reads."""
    folder = output / "multi-read-rust-oracle"
    corpus = json.loads((folder / "native-corpus.json").read_bytes())
    if (corpus.get("schema") != "hepta.runtime.multi-read-validation-corpus.v1"
            or corpus.get("cases") != 1689
            or corpus.get("original_source") != "src/mcp/runtime/multi_read.rs"
            or corpus.get("original_source_sha256") != sha(ROOT / "src/mcp/runtime/multi_read.rs")
            or corpus.get("source_sha256") != sha(ROOT / "native/multi_read_service.hepta")):
        raise ValueError("multi-read validation corpus source or scope differs")
    module_path = output / report["modules"]["multi_read_service"]["manifest"]
    module = json.loads(module_path.read_bytes())
    if corpus.get("image_sha256") != module["image_sha256"]:
        raise ValueError("multi-read validation corpus belongs to a different image")
    values = {}
    for name in ("requests.hex.gz", "native-output.txt.gz"):
        packed = (folder / name).read_bytes()
        if digest(packed) != corpus["artifacts"].get(name):
            raise ValueError("multi-read validation compressed corpus differs: " + name)
        values[name] = gzip.decompress(packed)
    wire, expected = values["requests.hex.gz"], values["native-output.txt.gz"]
    if (digest(wire) != corpus.get("request_raw_sha256")
            or digest(expected) != corpus.get("native_output_raw_sha256")
            or len(expected) != corpus.get("native_output_bytes")
            or not wire.endswith(b"\n") or not expected.endswith(b"\n")
            or len(wire.splitlines()) != corpus["cases"] or len(expected.splitlines()) != corpus["cases"]):
        raise ValueError("multi-read validation native case accounting differs")
    source = ROOT / "tests/hia_native/oracle_multi_read.rs"
    binary = folder / "oracle"
    rust_compile(output, report, rustc, key="multi-read-rust", source=source, binary=binary, edition="2024")
    row = record_check(output, report, name="multi-read-rust-compare", command=[str(binary)],
                       input_bytes=wire, timeout=60)
    result = {"status": "PASS" if row.stdout == expected and not row.stderr else "FAIL",
              "rust_oracle_cases": corpus["cases"], "native_cases_added_by_replay": 0,
              "actual_filesystem_cases": 0, "scope": "unchanged original validate after typed DTO admission",
              "input_sha256": digest(wire), "native_output_sha256": digest(expected),
              "rust_output_sha256": digest(row.stdout), "oracle_source_sha256": sha(source),
              "oracle_executable_sha256": sha(binary)}
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["status"] != "PASS":
        raise ValueError("original Rust multi-read validation disagrees with the native corpus")
    return result


def compare_operation_kdf(output: Path, report: dict, rustc: Path) -> dict:
    """Run locked ring plus the complete unchanged original crypto module."""
    evidence = operation_kdf_evidence(output, report)
    if evidence != report.get("operation_kdf_evidence"):
        raise ValueError("operation KDF native evidence changed before Rust replay")
    folder = output / "operation-kdf-rust-oracle"
    wire = gzip.decompress((folder / "kdf_cases.jsonl.gz").read_bytes())
    if digest(wire) != evidence["input_sha256"]:
        raise ValueError("operation KDF input corpus changed before Rust replay")
    manifest = ROOT / "tests/hia_native/kdf_oracle/Cargo.toml"
    target = folder / "target"
    if target.exists():
        raise ValueError("operation KDF reference target directory already exists")
    cargo = executable("cargo")
    env = qualification_env()
    env.update({"HIA_REFERENCE_RUNTIME": str(ROOT), "RUSTC": str(rustc)})
    record_check(output, report, name="operation-kdf-rust-compile",
                 command=[str(cargo), "build", "--locked", "--release", "--manifest-path", str(manifest),
                          "--target-dir", str(target)], env=env, timeout=180)
    binary = target / "release/hia-operation-kdf-reference"
    row = record_check(output, report, name="operation-kdf-rust-compare",
                       command=[str(binary)], input_bytes=wire, env=env, timeout=60)
    observed = json.loads(row.stdout)
    expected = {"status": "PASS", "rust_oracle_cases": 1364, "original_owner_calls": 405,
                "original_record_key_cipher_comparisons": 28,
                "output_sha256": evidence["native_output_sha256"], "native_cases_added_by_replay": 0}
    result = {**observed, "status": "PASS" if observed == expected and not row.stderr else "FAIL",
              "input_sha256": evidence["input_sha256"],
              "native_output_sha256": evidence["native_output_sha256"],
              "oracle_executable_sha256": sha(binary),
              "oracle_sources_sha256": evidence["oracle_sources_sha256"],
              "original_source": evidence["original_source"],
              "composition_sha256": evidence["composition_sha256"],
              "corpus_metadata_sha256": evidence["corpus_metadata_sha256"],
              "reference_kind": "locked ring primitives and complete unchanged original operation_crypto.rs",
              "scope": "internal derivation/binding bytes and opaque original record-key equivalence; no native AEAD or scope lifecycle qualification"}
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["status"] != "PASS":
        raise ValueError("original Rust operation KDF owner or output accounting differs")
    return result


def compare_operation_aead(output: Path, report: dict, rustc: Path) -> dict:
    """Replay native bytes through ring and the unchanged original seal/open owners."""
    evidence = operation_aead_evidence(output, report)
    if evidence != report.get("operation_aead_evidence"):
        raise ValueError("operation AEAD native evidence changed before Rust replay")
    folder = output / "operation-aead-rust-oracle"
    wire = gzip.decompress((folder / "aead_cases.jsonl.gz").read_bytes())
    if digest(wire) != evidence["input_sha256"]:
        raise ValueError("operation AEAD input corpus changed before Rust replay")
    manifest = ROOT / "tests/hia_native/aead_oracle/Cargo.toml"
    target = folder / "target"
    if target.exists():
        raise ValueError("operation AEAD reference target directory already exists")
    cargo = executable("cargo")
    env = qualification_env()
    env.update({"HIA_REFERENCE_RUNTIME": str(ROOT), "RUSTC": str(rustc)})
    record_check(output, report, name="operation-aead-rust-compile",
                 command=[str(cargo), "build", "--locked", "--release", "--manifest-path", str(manifest),
                          "--target-dir", str(target)], env=env, timeout=180)
    binary = target / "release/hia-operation-aead-reference"
    row = record_check(output, report, name="operation-aead-rust-compare",
                       command=[str(binary)], input_bytes=wire, env=env, timeout=60)
    observed = json.loads(row.stdout)
    expected = {"status": "PASS", "rust_oracle_cases": 1841, "encryption_cases": 684,
                "decryption_cases": 684, "refusal_cases": 473,
                "original_seal_calls": 33, "original_open_calls": 33,
                "original_authentication_refusals": 11,
                "output_sha256": evidence["native_output_sha256"], "native_cases_added_by_replay": 0}
    result = {**observed, "status": "PASS" if observed == expected and not row.stderr else "FAIL",
              "input_sha256": evidence["input_sha256"],
              "native_output_sha256": evidence["native_output_sha256"],
              "oracle_executable_sha256": sha(binary),
              "oracle_sources_sha256": evidence["oracle_sources_sha256"],
              "original_source": evidence["original_source"],
              "composition_sha256": evidence["composition_sha256"],
              "corpus_metadata_sha256": evidence["corpus_metadata_sha256"],
              "reference_kind": "locked ring ChaCha20-Poly1305 and complete unchanged original seal/open owners",
              "scope": "byte primitive interoperability with synthetic entropy; no native nonce custody or scope lifecycle qualification"}
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["status"] != "PASS":
        raise ValueError("original Rust operation AEAD owner or output accounting differs")
    return result


def compare_operation_nonce(output: Path, report: dict, rustc: Path) -> dict:
    """Execute the unchanged Rust binding and NonceLedger on each retained session."""
    evidence = operation_nonce_evidence(output, report)
    if evidence != report.get("operation_nonce_evidence"):
        raise ValueError("operation nonce native evidence changed before Rust replay")
    folder = output / "operation-nonce-rust-oracle"
    wire = gzip.decompress((folder / "nonce_cases.jsonl.gz").read_bytes())
    if digest(wire) != evidence["input_sha256"]:
        raise ValueError("operation nonce input corpus changed before Rust replay")
    manifest = ROOT / "tests/hia_native/nonce_oracle/Cargo.toml"
    target = folder / "target"
    if target.exists():
        raise ValueError("operation nonce reference target directory already exists")
    cargo = executable("cargo")
    env = qualification_env()
    env.update({"HIA_REFERENCE_RUNTIME": str(ROOT), "RUSTC": str(rustc)})
    record_check(output, report, name="operation-nonce-rust-compile",
                 command=[str(cargo), "build", "--locked", "--release", "--manifest-path", str(manifest),
                          "--target-dir", str(target)], env=env, timeout=180)
    binary = target / "release/hia-operation-nonce-reference"
    row = record_check(output, report, name="operation-nonce-rust-compare",
                       command=[str(binary)], input_bytes=wire, env=env, timeout=60)
    observed = json.loads(row.stdout)
    expected = {"status": "PASS", "rust_oracle_cases": 17811, "original_binding_calls": 17611,
                "original_nonce_reservations": 17470, "accepted_reservations": 17183,
                "nonce_refusals": 287, "sessions": 8,
                "output_sha256": evidence["native_output_sha256"], "native_cases_added_by_replay": 0}
    result = {**observed, "status": "PASS" if observed == expected and not row.stderr else "FAIL",
              "input_sha256": evidence["input_sha256"],
              "native_output_sha256": evidence["native_output_sha256"],
              "oracle_executable_sha256": sha(binary),
              "oracle_sources_sha256": evidence["oracle_sources_sha256"],
              "original_source": evidence["original_source"],
              "composition_sha256": evidence["composition_sha256"],
              "composition_fixture": evidence["composition_fixture"],
              "corpus_metadata_sha256": evidence["corpus_metadata_sha256"],
              "reference_kind": "complete unchanged original TrustedResultBinding and NonceLedger",
              "scope": "serial reservation and original scope budget; no entropy, production locking or key lifetime qualification"}
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["status"] != "PASS":
        raise ValueError("original Rust nonce ledger or output accounting differs")
    return result


def compare_operation_record(output: Path, report: dict, rustc: Path) -> dict:
    """Replay the complete original binding/AAD and seal/open byte owners."""
    evidence = operation_record_evidence(output, report)
    if evidence != report.get("operation_record_evidence"):
        raise ValueError("operation record native evidence changed before Rust replay")
    folder = output / "operation-record-rust-oracle"
    wire = gzip.decompress((folder / "record_cases.jsonl.gz").read_bytes())
    if digest(wire) != evidence["input_sha256"]:
        raise ValueError("operation record input corpus changed before Rust replay")
    manifest = ROOT / "tests/hia_native/record_oracle/Cargo.toml"
    target = folder / "target"
    if target.exists():
        raise ValueError("operation record reference target directory already exists")
    cargo = executable("cargo")
    env = qualification_env()
    env.update({"HIA_REFERENCE_RUNTIME": str(ROOT), "RUSTC": str(rustc)})
    record_check(output, report, name="operation-record-rust-compile",
                 command=[str(cargo), "build", "--locked", "--release", "--manifest-path", str(manifest),
                          "--target-dir", str(target)], env=env, timeout=180)
    binary = target / "release/hia-operation-record-reference"
    row = record_check(output, report, name="operation-record-rust-compare",
                       command=[str(binary)], input_bytes=wire, env=env, timeout=60)
    observed = json.loads(row.stdout)
    expected = {"status": "PASS", "rust_oracle_cases": 823, "refusal_cases": 365,
                "original_binding_constructor_calls": 164, "original_binding_aad_calls": 109,
                "original_seal_calls": 177, "original_open_calls": 353,
                "original_preflight_seal_calls": 8, "original_preflight_entropy_reached": 3,
                "original_verified_scope_constructor_calls": 6, "original_owner_calls": 817,
                "output_sha256": evidence["native_output_sha256"], "native_cases_added_by_replay": 0}
    result = {**observed, "status": "PASS" if observed == expected and not row.stderr else "FAIL",
              "input_sha256": evidence["input_sha256"],
              "native_output_sha256": evidence["native_output_sha256"],
              "oracle_executable_sha256": sha(binary), "oracle_sources_sha256": evidence["oracle_sources_sha256"],
              "original_source": evidence["original_source"], "composition_sha256": evidence["composition_sha256"],
              "composition_fixture": evidence["composition_fixture"],
              "corpus_metadata_sha256": evidence["corpus_metadata_sha256"],
              "original_domain_rows": 702, "adapter_only_rows": 121,
              "reference_kind": "complete unchanged original TrustedResultBinding, AAD, seal_with_entropy and open",
              "scope": "internal byte owner with fresh synthetic scope per row; persistent capability/entropy/nonce lifetime remains separate"}
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["status"] != "PASS":
        raise ValueError("original Rust record owner, domain or output accounting differs")
    return result


def compare_system_entropy(output: Path, report: dict, rustc: Path) -> dict:
    """Build unchanged SystemEntropy and replay all owned-child Linux backend cases."""
    evidence = entropy_evidence(output, report)
    if evidence != report.get("system_entropy_evidence"):
        raise ValueError("entropy native evidence changed before original replay")
    folder = output / ENTROPY_FOLDER
    manifest = ROOT / "tests/hia_native/entropy_oracle/Cargo.toml"
    target = folder / "target"
    if target.exists():
        raise ValueError("entropy original reference target directory already exists")
    env = qualification_env()
    # Test the locked default Linux backend, without inherited custom cfg/target
    # selection. Its actual Cargo fingerprint and syscall trace are checked too.
    removed = sorted(key for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET") if key in env)
    for key in removed:
        env.pop(key)
    env.update({"HIA_REFERENCE_RUNTIME": str(ROOT), "RUSTC": str(rustc)})
    record_check(output, report, name="system-entropy-rust-compile",
                 command=[str(executable("cargo")), "build", "--locked", "--release",
                          "--manifest-path", str(manifest), "--target-dir", str(target)], env=env, timeout=180)
    binary = target / "release/hia-system-entropy-reference"
    binary_hash = sha(binary)
    fingerprints = list((target / "release/.fingerprint").glob("getrandom-*/lib-getrandom.json"))
    if len(fingerprints) != 1:
        raise ValueError("entropy original requires exactly one default getrandom backend")
    fingerprint = entropy_object(fingerprints[0])
    if fingerprint.get("features") != "[]" or fingerprint.get("rustflags") != []:
        raise ValueError("entropy original getrandom feature/cfg backend differs")
    generated = list((target / "release/build").glob("hia-system-entropy-reference-*/out/original_operation_reference.rs"))
    expected_source = (b"#[allow(dead_code)]\nmod original {\n"
                       + (ROOT / ENTROPY_ORIGINAL_SOURCE).read_bytes() + b"\n"
                       + (ROOT / "tests/hia_native/entropy_oracle/original_access.rs").read_bytes() + b"\n}\n")
    if len(generated) != 1 or generated[0].read_bytes() != expected_source:
        raise ValueError("entropy oracle did not retain the complete unchanged original module")
    env.update({"HIA_ENTROPY_REFERENCE_BINARY": str(binary), "HIA_ENTROPY_REFERENCE_SHA256": binary_hash,
                "HIA_ENTROPY_KERNEL_REPORT": str(folder / "kernel-original.json")})
    record_check(output, report, name="system-entropy-rust-compare",
                 command=[sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/test_entropy_kernel_backend.py")],
                 env=env, timeout=180)
    check, observed = completed_test_summary(output, report, "system-entropy-rust-compare")
    retained_original = entropy_object(folder / "kernel-original.json")
    if {key: value for key, value in retained_original.items() if key != "traces"} != observed:
        raise ValueError("entropy original full trace receipt differs from its completed process")
    original = normalized_kernel_report(ROOT, retained_original, original=True, binary_sha256=binary_hash)
    native = normalized_kernel_report(ROOT, entropy_object(folder / KERNEL_RECEIPT), original=False,
                                       binary_sha256=evidence["artifacts"]["binary_sha256"], artifacts=evidence["artifacts"])
    if original["traces"] != native["traces"] or original["sha256"] != native["sha256"]:
        raise ValueError("entropy original and native Linux backend traces differ")
    if sha(binary) != binary_hash or entropy_evidence(output, report) != evidence:
        raise ValueError("entropy source, observed native corpus or original binary changed during replay")
    result = {"schema": "hepta.runtime.system-entropy-rust-comparison.v1", "status": "PASS",
              "reference_kind": "complete unchanged original SystemEntropy with locked default Linux ring/getrandom backend",
              "tests_run": 8, "processes": 25, "request_frames": 56, "original_owner_calls": 56,
              "successful_outputs": 46, "entropy_refusals": 10, "native_cases_added_by_replay": 0,
              "normalized_trace_sha256": original["sha256"], "normalized_syscall_traces_match": True,
              "normal_random_bytes_equality_claimed": False, "normalization": original["normalization"],
              "native_counts": native["counts"], "original_counts": original["counts"],
              "corpus_metadata_sha256": evidence["corpus_sha256"],
              "native_report_sha256": sha(folder / KERNEL_RECEIPT),
              "original_report_sha256": sha(folder / "kernel-original.json"),
              "original_stdout_sha256": check["stdout_sha256"], "original_stderr_sha256": check["stderr_sha256"],
              "oracle_executable_sha256": binary_hash, "source_sha256": evidence["source_sha256"],
              "generated_original_module_sha256": sha(generated[0]),
              "getrandom_fingerprint_sha256": sha(fingerprints[0]),
              "getrandom_features": [], "getrandom_rustflags": [],
              "oracle_dependencies": entropy_dependencies(ROOT), "cleared_backend_overrides": removed,
              "original_runtime_lock_identical": False, "full_runtime_lock_build_claimed": False,
              "thread_safe_workspace_claimed": False, "production_activated": False, "whole_runtime_replaced": False}
    with (folder / "rust-comparison.json").open("x") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def compare_operation_scope(output: Path, report: dict, rustc: Path) -> dict:
    """Replay complete live original scopes, clones and nonces on the declared domain."""
    evidence = operation_scope_evidence(output, report)
    if evidence != report.get("operation_scope_evidence"):
        raise ValueError("scope native histories changed before original Rust replay")
    folder = output / SCOPE_FOLDER
    wire = gzip.decompress((folder / "scope_cases.jsonl.gz").read_bytes())
    if digest(wire) != evidence["input_sha256"]:
        raise ValueError("scope reference history changed before original Rust replay")
    manifest = ROOT / "tests/hia_native/scope_oracle/Cargo.toml"
    target = folder / "target"
    if target.exists():
        raise ValueError("scope original reference target directory already exists")
    env = qualification_env()
    env.update({"HIA_REFERENCE_RUNTIME": str(ROOT), "RUSTC": str(rustc)})
    record_check(output, report, name="operation-scope-rust-compile",
                 command=[str(executable("cargo")), "build", "--locked", "--release",
                          "--manifest-path", str(manifest), "--target-dir", str(target)], env=env, timeout=180)
    generated = list((target / "release/build").glob("hia-operation-scope-reference-*/out/original_operation_reference.rs"))
    expected_source = (b"#[allow(dead_code)]\nmod original {\n"
                       + (ROOT / "src/mcp/runtime/operation_crypto.rs").read_bytes() + b"\n"
                       + (ROOT / "tests/hia_native/scope_oracle/original_access.rs").read_bytes() + b"\n}\n")
    if len(generated) != 1 or generated[0].read_bytes() != expected_source:
        raise ValueError("scope oracle did not retain the complete unchanged original module")
    binary = target / "release/hia-operation-scope-reference"
    binary_hash = sha(binary)
    row = record_check(output, report, name="operation-scope-rust-compare",
                       command=[str(binary)], input_bytes=wire, env=env, timeout=60)
    observed = json.loads(row.stdout)
    expected = {"status": "PASS", **SCOPE_ORACLE_COUNTS, "output_sha256": evidence["native_output_sha256"]}
    if (row.stderr or observed != expected
            or any(type(observed.get(key)) is not int for key in SCOPE_ORACLE_COUNTS)
            or sha(binary) != binary_hash or operation_scope_evidence(output, report) != evidence):
        raise ValueError("scope original owner, exact result, lifetime or exclusion-domain accounting differs")
    result = {**observed, "schema": "hepta.runtime.operation-scope-rust-comparison.v1",
              "input_sha256": evidence["input_sha256"], "oracle_executable_sha256": binary_hash,
              "oracle_sources_sha256": evidence["oracle_sources_sha256"],
              "generated_original_module_sha256": sha(generated[0]),
              "original_source_sha256": evidence["original_source_sha256"],
              "corpus_metadata_sha256": evidence["corpus_metadata_sha256"],
              "native_domains": evidence["domains"],
              "reference_kind": "complete unchanged original private scope, real live clones and nonce sets with deterministic entropy",
              "real_os_entropy_connected": False, "concurrent_shared_capability_qualified": False,
              "production_activated": False, "whole_runtime_replaced": False}
    with (folder / "rust-comparison.json").open("x") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def compare_operation_scope_os(output: Path, report: dict, rustc: Path, *, report_path: Path | None = None) -> dict:
    evidence = operation_scope_os_evidence(output, report)
    if evidence != report.get("operation_scope_os_evidence"):
        raise ValueError("OS scope native source or complete traces changed before original Rust comparison")
    folder = output / SCOPE_OS_FOLDER
    manifest = ROOT / "tests/hia_native/scope_os_oracle/Cargo.toml"
    target = folder / "target"
    if target.exists():
        raise ValueError("OS scope original reference target directory already exists")
    env = qualification_env()
    removed = sorted(key for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET") if key in env)
    for key in removed:
        env.pop(key)
    env.update({"HIA_REFERENCE_RUNTIME": str(ROOT), "RUSTC": str(rustc)})
    record_check(output, report, name="operation-scope-os-rust-compile",
                 command=[str(executable("cargo")), "build", "--locked", "--release",
                          "--manifest-path", str(manifest), "--target-dir", str(target)], env=env, timeout=180, report_path=report_path)
    generated = list((target / "release/build").glob("hia-operation-scope-os-reference-*/out/original_operation_reference.rs"))
    expected_source = (b"#[allow(dead_code)]\nmod original {\n"
                       + (ROOT / "src/mcp/runtime/operation_crypto.rs").read_bytes() + b"\n"
                       + (ROOT / "tests/hia_native/scope_os_oracle/original_access.rs").read_bytes() + b"\n}\n")
    if len(generated) != 1 or generated[0].read_bytes() != expected_source:
        raise ValueError("OS scope oracle did not retain the complete unchanged original module")
    fingerprints = list((target / "release/.fingerprint").glob("getrandom-*/lib-getrandom.json"))
    if len(fingerprints) != 1:
        raise ValueError("OS scope original requires exactly one default getrandom backend")
    fingerprint = json.loads(fingerprints[0].read_bytes())
    if fingerprint.get("features") != "[]" or fingerprint.get("rustflags") != []:
        raise ValueError("OS scope original getrandom feature/cfg backend differs")
    binary = target / "release/hia-operation-scope-os-reference"
    binary_hash = sha(binary)
    native_manifest = output / report["modules"]["operation_scope_os"]["manifest"]
    artifact = scope_os_profile(ROOT, native_manifest)
    env.update({"HIA_SCOPE_OS_MANIFEST": str(native_manifest), "HIA_SCOPE_OS_REFERENCE_BINARY": str(binary),
                "HIA_SCOPE_OS_REFERENCE_SHA256": binary_hash,
                "HIA_SCOPE_OS_RESULT": str(folder / SCOPE_OS_PAIRED_RECEIPT)})
    record_check(output, report, name="operation-scope-os-rust-compare",
                 command=[sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/test_scope_os.py")],
                 env=env, timeout=180, report_path=report_path)
    check, summary = completed_test_summary(output, report, "operation-scope-os-rust-compare")
    retained = json.loads((folder / SCOPE_OS_PAIRED_RECEIPT).read_bytes())
    if {key: value for key, value in retained.items() if key != "cases"} != summary:
        raise ValueError("OS scope paired raw observations differ from completed process stdout")
    paired = scope_os_paired_evidence(ROOT, folder, artifact, binary_hash)
    if sha(binary) != binary_hash or operation_scope_os_evidence(output, report) != evidence:
        raise ValueError("OS scope source, observed native corpus or original binary changed during comparison")
    result = {**paired, "schema": "hepta.runtime.operation-scope-os-rust-comparison.v1",
              "reference_kind": "complete unchanged original ResultCryptoScope with default Linux SystemEntropy and live original clones",
              "native_corpus_sha256": evidence["corpus_sha256"],
              "generated_original_module_sha256": sha(generated[0]),
              "getrandom_fingerprint_sha256": sha(fingerprints[0]),
              "getrandom_features": [], "getrandom_rustflags": [], "cleared_backend_overrides": removed,
              "original_stdout_sha256": check["stdout_sha256"], "original_stderr_sha256": check["stderr_sha256"],
              "real_os_entropy_connected": True, "original_runtime_lock_identical": False,
              "concurrent_shared_capability_qualified": False, "production_activated": False, "whole_runtime_replaced": False}
    with (folder / "rust-comparison.json").open("x") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def compare_history(output: Path, report: dict, rustc: Path) -> dict:
    return compare_history_original(ROOT, output, report, rustc, completed_test_summary,
                                    record_check, qualification_env())


def compare_view_cache(output: Path, report: dict, rustc: Path) -> dict:
    return compare_cache_original(ROOT, output, report, rustc, completed_test_summary,
                                  record_check, qualification_env())


def batch_replay_stream_identity(path: Path, maximum: int) -> tuple[int, str]:
    if path.is_symlink() or not path.is_file() or path.resolve() != path.absolute():
        raise ValueError("batch original output must be a regular unsymlinked stream")
    size, identity = 0, hashlib.sha256()
    with gzip.open(path, "rb") as stream:
        while raw := stream.read(1 << 20):
            size += len(raw)
            if size > maximum:
                raise ValueError("batch original output exceeds the complete native byte domain")
            identity.update(raw)
    return size, identity.hexdigest()


def compare_batch_plan(output: Path, report: dict, rustc: Path) -> dict:
    evidence = batch_plan_evidence(output, report)
    if evidence != report.get("batch_plan_evidence"):
        raise ValueError("batch native source, complete streams or actual artifacts changed before original replay")
    folder = output / BATCH_PLAN_FOLDER
    cargo = executable(str(rustc.with_name("cargo")))
    cargo_hash = sha(cargo)
    build_dir = folder / "original-build"
    # The component's build routine creates the source-bound receipt from the
    # actual locked Cargo invocation. It has its own retained stdout/stderr.
    # This outer check records that completed process separately from replay.
    build_program = "\n".join((
        "import json, sys",
        "from pathlib import Path",
        "root, destination = Path(sys.argv[1]), Path(sys.argv[2])",
        "sys.path.insert(0, str(root / 'tests/hia_native'))",
        "from compare_batch_plan_original import build_original",
        "destination.mkdir(parents=True, exist_ok=False)",
        "binary, receipt = build_original(root, root, destination, cargo=sys.argv[3], rustc=sys.argv[4])",
        "print(json.dumps(receipt, sort_keys=True))",
    ))
    env = qualification_env()
    compiled = record_check(output, report, name="batch-plan-rust-compile",
        command=[sys.executable, "-I", "-B", "-c", build_program,
                 str(ROOT), str(build_dir), str(cargo), str(rustc)], env=env, timeout=180)
    build = json.loads(compiled.stdout)
    source_map = {name: row["sha256"] for name, row in BATCH_PLAN_ORIGINALS.items()}
    source_map.update({name: sha(ROOT / name) for name in (
        "tests/hia_native/oracle_batch_plan.rs", "tests/hia_native/batch_plan_oracle/Cargo.toml",
        "tests/hia_native/batch_plan_oracle/Cargo.lock")})
    binary = build_dir / "target/release/hia-batch-plan-reference"
    expected_command = [str(cargo), "build", "--release", "--locked", "--manifest-path",
                        str(ROOT / "tests/hia_native/batch_plan_oracle/Cargo.toml")]
    if (compiled.stderr or build.get("schema") != "hepta.runtime.batch-plan.original-build.v1"
            or build.get("status") != "PASS" or build.get("exit_code") != 0
            or build.get("timed_out") is not False or build.get("command") != expected_command
            or build.get("source_map") != source_map
            or build.get("oracle_sha256") != source_map["tests/hia_native/oracle_batch_plan.rs"]
            or build.get("binary_sha256") != sha(binary)
            or build.get("stdout_sha256") != sha(build_dir / "build.stdout")
            or build.get("stderr_sha256") != sha(build_dir / "build.stderr")
            or json.loads((build_dir / "build.json").read_bytes()) != build):
        raise ValueError("batch actual locked Cargo compilation receipt differs")
    replay = folder / "original-replay"
    row = record_check(output, report, name="batch-plan-rust-compare",
        command=[sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/compare_batch_plan_original.py"),
                 "--source-root", str(ROOT), "--runtime", str(ROOT), "--corpus", str(folder),
                 "--output", str(replay), "--binary", str(binary),
                 "--build-receipt", str(build_dir / "build.json")], env=env, timeout=180)
    observed = json.loads(row.stdout)
    if (row.stderr or observed.get("schema") != "hepta.runtime.batch-plan.original-comparison.v1"
            or observed.get("status") != "PASS" or type(observed.get("original_rows")) is not int
            or observed["original_rows"] != BATCH_PLAN_ROWS or observed.get("rows_expected") != BATCH_PLAN_ROWS
            or observed.get("output_complete") is not True or observed.get("exit_code") != 0
            or observed.get("stream_errors") != [] or observed.get("timeout_seconds") != 180
            or observed.get("stdout_bytes") != evidence["native_output_bytes"]
            or observed.get("stdout_sha256") != evidence["native_output_sha256"]
            or observed.get("native_corpus_sha256") != evidence["corpus_metadata_sha256"]
            or observed.get("binary_sha256") != build["binary_sha256"]
            or observed.get("compilation") != "reused actual source-matched compiled binary; no fresh compilation claim"
            or json.loads((replay / "comparison.json").read_bytes()) != observed
            or json.loads((replay / "build.json").read_bytes()) != build
            or batch_replay_stream_identity(replay / "original-output.bin.gz", evidence["native_output_bytes"]) != (
                evidence["native_output_bytes"], evidence["native_output_sha256"])
            or sha(binary) != build["binary_sha256"] or sha(cargo) != cargo_hash
            or batch_plan_evidence(output, report) != evidence):
        raise ValueError("original batch complete ordered responses or source custody differ")
    result = {"schema": "hepta.runtime.batch-plan-rust-comparison.v1", "status": "PASS",
              "cases": BATCH_PLAN_ROWS, "native_cases_added_by_replay": 0,
              "reference_kind": "unchanged original batch preflight, operation parsing and endpoint planning blocks",
              "compiled_by_qualification_recipe": True,
              "replay_uses_this_recipe_binary": True,
              "original_output_sha256": observed["stdout_sha256"],
              "native_output_sha256": evidence["native_output_sha256"],
              "output_bytes": evidence["native_output_bytes"],
              "corpus_metadata_sha256": evidence["corpus_metadata_sha256"],
              "oracle_executable_sha256": build["binary_sha256"], "cargo_executable_sha256": cargo_hash,
              "original_build_receipt_sha256": sha(build_dir / "build.json"),
              "original_replay_receipt_sha256": sha(replay / "comparison.json"),
              "source_bindings": observed["source_bindings"],
              "complete_original_tool_parity": False, "production_activated": False, "whole_runtime_replaced": False}
    with (folder / "rust-comparison.json").open("x") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def compare_batch_apply(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_batch_apply_qualification as q
    evidence = batch_apply_evidence(output, report)
    if evidence != report.get("batch_apply_evidence"):
        raise ValueError("batch application native evidence changed before original replay")
    project = output / "batch-apply-rust-reference"
    folder = output / "batch-apply"
    q.prepare_original_reference(project, evidence["native_evidence"], folder / "corpus", folder / "artifacts",
                                 source_root=ROOT)
    command = [sys.executable, "-I", "-B", str(project / "driver.py"), "--manifest", str(project / "input.json"),
               "--rustc", str(rustc), "--output", str(project / "replay")]
    record_check(output, report, name="batch-apply-rust-compare", command=command, timeout=180,
                 env=qualification_env())
    check, summary = completed_test_summary(output, report, "batch-apply-rust-compare")
    if (q.canonical(summary) != q.canonical(q.json_file(project / "replay/result.json"))
            or (output / "batch-apply-rust-compare.stderr").read_bytes() != b""
            or check["command"] != command or check["timeout_seconds"] != 180):
        raise ValueError("batch application original driver differs from its actual process")
    result = q.original_comparison_evidence(project, source_root=ROOT)
    if batch_apply_evidence(output, report) != evidence:
        raise ValueError("batch application native evidence changed during original replay")
    return {**result, "original_stdout_sha256": check["stdout_sha256"],
            "original_stderr_sha256": check["stderr_sha256"]}


def atomic_write_original_command(output: Path, report: dict, rustc: Path) -> list[str]:
    cargo = executable(str(rustc.with_name("cargo")))
    return [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/compare_atomic_write_original.py"),
            "--runtime", str(ROOT), "--native-manifest", str(output / report["modules"]["atomic_write"]["manifest"]),
            "--policy-corpus", str(output / "atomic-write/policy"), "--output", str(output / "atomic-write-original"),
            "--rustc", str(rustc), "--cargo", str(cargo)]


def atomic_write_original_evidence(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_atomic_write_qualification as q
    folder = output / "atomic-write-original"
    command = atomic_write_original_command(output, report, rustc)
    completed = atomic_write_completed_process(output, report, "atomic-write-rust-compare", command,
                                               phase="original_rust_comparison")
    evidence = q.original_comparison_evidence(folder, output / report["modules"]["atomic_write"]["manifest"],
        output / "atomic-write/policy", source_root=ROOT, reference_root=ROOT,
        stdout=output / "atomic-write-rust-compare.stdout")
    retained = q.obj(folder / "result.json")
    for name, path in (("rustc", rustc), ("cargo", Path(command[-1]))):
        if any(retained[name].get(key) != value for key, value in q.file_record(path).items()):
            raise ValueError("atomic original compiler or Cargo executable changed")
    fixtures = tuple(f"atomic-write-original/{kind}-kernel/{index:04d}-{case['name']}/fixture"
                     for kind in ("native", "original") for index, case in enumerate(q.case_module.cases()))
    atomic_write_retire_fixtures(output, fixtures, folder / "retired-fixtures.json", evidence)
    return {"schema": "hepta.runtime.atomic-write-required-original.v1", "status": "PASS",
        "reference_kind": "complete unchanged Linux Local atomic_write, actual std::Path and std::io properties",
        "compiled_by_qualification_recipe": True, "completed_process": completed, "reference_evidence": evidence,
        "retained_files_sha256": atomic_write_retained_files(output, folder, fixtures=fixtures),
        "rust_path_cases": 88807, "original_atomic_write_requests": 171, "kernel_state_and_trace_comparisons": 151,
        "paired_native_atomic_write_requests": 171, "native_phase_cases_added_by_reference": 0,
        "original_error_display_property_rows": 4095, "original_nul_and_writezero_properties": 2,
        "complete_original_tool_parity": False, "remote_ssh_parity": False,
        "production_activated": False, "whole_runtime_replaced": False}


def compare_atomic_write(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_atomic_write_qualification as q
    native = atomic_write_evidence(output, report)
    if native != report.get("atomic_write_evidence"):
        raise ValueError("atomic native execution evidence changed before original replay")
    record_check(output, report, name="atomic-write-rust-compare",
        command=atomic_write_original_command(output, report, rustc), timeout=180, env=qualification_env())
    folder = output / "atomic-write-original"
    completed = q.original_comparison_evidence(folder, output / report["modules"]["atomic_write"]["manifest"],
        output / "atomic-write/policy", source_root=ROOT, reference_root=ROOT,
        stdout=output / "atomic-write-rust-compare.stdout")
    fixtures = tuple(f"atomic-write-original/{kind}-kernel/{index:04d}-{case['name']}/fixture"
                     for kind in ("native", "original") for index, case in enumerate(q.case_module.cases()))
    atomic_write_retire_fixtures(output, fixtures, folder / "retired-fixtures.json", completed, create=True)
    result = atomic_write_original_evidence(output, report, rustc)
    if atomic_write_evidence(output, report) != native:
        raise ValueError("atomic native execution evidence changed during original replay")
    return result


def compare_line_verify(output: Path, report: dict, rustc: Path) -> dict:
    evidence = line_verify_evidence(output, report)
    if evidence != report.get("line_verify_evidence"):
        raise ValueError("line verification native evidence changed before original replay")
    folder = output / "line-verify-rust-oracle"
    source = ROOT / "tests/hia_native/oracle_line_verify.rs"
    binary = folder / "oracle"
    rust_compile(output, report, rustc, key="line-verify-rust", source=source, binary=binary,
                 extra=("-C", "overflow-checks=off"))
    binary_hash = sha(binary)
    with gzip.open(folder / "requests.hex.gz", "rb") as handle:
        wire = handle.read(evidence["input_bytes"] + 1)
    with gzip.open(folder / "native-output.txt.gz", "rb") as handle:
        expected = handle.read(evidence["native_output_bytes"] + 1)
    if ((len(wire), digest(wire)) != (evidence["input_bytes"], evidence["input_sha256"])
            or (len(expected), digest(expected)) != (evidence["native_output_bytes"], evidence["native_output_sha256"])):
        raise ValueError("line verification original-domain corpus changed before replay")
    row = record_check(output, report, name="line-verify-rust-compare", command=[str(binary)],
                       input_bytes=wire, timeout=60)
    if (row.stdout != expected or row.stderr or sha(binary) != binary_hash
            or line_verify_evidence(output, report) != evidence):
        raise ValueError("complete original line verification/diagnostic/index bytes differ")
    result = {"status": "PASS", "rust_oracle_cases": evidence["captured_native_cases"],
              "native_cases_added_by_replay": 0, "input_sha256": digest(wire),
              "native_output_sha256": digest(expected), "rust_output_sha256": digest(row.stdout),
              "oracle_source_sha256": sha(source), "oracle_executable_sha256": binary_hash,
              "original_source_sha256": evidence["original_source_sha256"],
              "scope": evidence["scope"], "complete_original_tool_parity": False,
              "production_activated": False}
    (folder / "rust-comparison.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def compare_editable_content(output: Path, report: dict, rustc: Path) -> dict:
    evidence = editable_content_evidence(output, report)
    if evidence != report.get("editable_content_evidence"):
        raise ValueError("editable native state history changed before original Rust replay")
    folder = output / EDITABLE_FOLDER
    target = folder / "target"
    if target.exists():
        raise ValueError("editable original reference target already exists")
    manifest = ROOT / "tests/hia_native/editable_oracle/Cargo.toml"
    env = qualification_env()
    env.update({"RUSTC": str(rustc), "RUSTFLAGS": "-C overflow-checks=off"})
    record_check(output, report, name="editable-content-rust-compile",
                 command=[str(executable("cargo")), "build", "--locked", "--release",
                          "--manifest-path", str(manifest), "--target-dir", str(target)], env=env, timeout=180)
    binary = target / "release/hia-editable-original-reference"
    binary_hash = sha(binary)
    row = record_check(output, report, name="editable-content-rust-compare",
                       command=[str(binary)], input_bytes=(folder / "requests.hex").read_bytes(), env=env, timeout=60)
    if (row.stderr or row.stdout != (folder / "native-output.txt").read_bytes()
            or row.stdout.count(b"\n") != EDITABLE_CASES or sha(binary) != binary_hash
            or editable_content_evidence(output, report) != evidence):
        raise ValueError("original EditableContent complete ordered responses differ")
    result = {"schema": "hepta.runtime.editable-rust-comparison.v1", "status": "PASS",
              "cases": EDITABLE_CASES, "native_cases_added_by_replay": 0,
              "reference_kind": "unchanged original EditableContent and incoming-line methods with typed test transport",
              "input_sha256": evidence["input_sha256"], "native_output_sha256": evidence["native_output_sha256"],
              "original_output_sha256": digest(row.stdout), "oracle_executable_sha256": binary_hash,
              "oracle_sources_sha256": evidence["oracle_sources_sha256"],
              "original_source_sha256": evidence["original_source_sha256"],
              "corpus_metadata_sha256": evidence["corpus_metadata_sha256"],
              "complete_original_tool_parity": False, "production_activated": False, "whole_runtime_replaced": False}
    with (folder / "rust-comparison.json").open("x") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def compare_view_render(output: Path, report: dict, rustc: Path) -> dict:
    evidence = view_render_evidence(output, report)
    if evidence != report.get("view_render_evidence"):
        raise ValueError("view native read snapshots or rendered bytes changed before original Rust replay")
    folder = output / VIEW_FOLDER
    source = ROOT / "tests/hia_native/oracle_view_render.rs"
    binary = folder / "original-view.elf"
    rust_compile(output, report, rustc, key="view-render-rust", source=source, binary=binary,
                 extra=("-C", "overflow-checks=off"))
    binary_hash = sha(binary)
    replay = folder / "original-replay"
    row = record_check(output, report, name="view-render-rust-compare",
        command=[sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/compare_view_original.py"),
                 "--source", str(source), "--binary", str(binary),
                 "--requests", str(folder / "requests.hex.gz"),
                 "--expected", str(folder / "native-output.txt.gz"),
                 "--metadata", str(folder / "native-corpus.json"), "--output", str(replay)],
        env=qualification_env(), timeout=60)
    observed = json.loads(row.stdout)
    if (row.stderr or observed.get("status") != "PASS" or type(observed.get("cases")) is not int
            or observed["cases"] != VIEW_CASES or observed.get("run_exit_code") != 0
            or observed.get("compiled_by_qualification_recipe") is not True
            or observed.get("native_and_rust_output_sha256") != evidence["native_output_sha256"]
            or observed.get("raw_output_bytes") != evidence["native_output_bytes"]
            or observed.get("executable", {}).get("sha256") != binary_hash
            or observed.get("inputs_before") != observed.get("inputs_after")
            or json.loads((replay / "result.json").read_bytes()) != observed
            or view_stream_identity(replay / "rust-output.txt.gz", evidence["native_output_bytes"]) != (
                evidence["native_output_bytes"], evidence["native_output_sha256"])
            or sha(binary) != binary_hash or view_render_evidence(output, report) != evidence):
        raise ValueError("original view complete ordered responses or source custody differ")
    result = {"schema": "hepta.runtime.view-render-rust-comparison.v1", "status": "PASS",
              "cases": VIEW_CASES, "native_cases_added_by_replay": 0,
              "reference_kind": "unchanged original range, file render, cache, delta and result gate methods with independent read fixtures",
              "input_sha256": evidence["input_sha256"], "native_output_sha256": evidence["native_output_sha256"],
              "original_output_sha256": observed["native_and_rust_output_sha256"],
              "oracle_executable_sha256": binary_hash, "oracle_sources_sha256": evidence["oracle_sources_sha256"],
              "original_sources_sha256": evidence["original_sources_sha256"],
              "corpus_metadata_sha256": evidence["corpus_metadata_sha256"],
              "original_replay_receipt_sha256": sha(replay / "result.json"),
              "complete_original_tool_parity": False, "production_activated": False, "whole_runtime_replaced": False}
    with (folder / "rust-comparison.json").open("x") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def compare_caller_authority(output: Path, report: dict, rustc: Path, *, report_path: Path | None = None) -> dict:
    cargo = executable(str(rustc.with_name("cargo")))
    executable(str(rustc.with_name("cargo-fmt")))
    rustfmt = executable(str(rustc.with_name("rustfmt")))

    def environment():
        # Cargo can prefer its home-directory proxy over PATH. RUSTFMT pins
        # the actual formatter even when that proxy dispatches cargo-fmt.
        env = qualification_env()
        env["PATH"] = str(cargo.parent) + os.pathsep + env.get("PATH", os.defpath)
        env["RUSTFMT"] = str(rustfmt)
        return env

    def capture(*args, **kwargs):
        return record_check(*args, **kwargs, report_path=report_path)

    return compare_authority_original(ROOT, output, report, rustc, record_check=capture,
        completed_test_summary=completed_test_summary, qualification_env=environment, cargo=cargo)


def compare_fence_json(output: Path, report: dict, rustc: Path) -> dict:
    return compare_json_original(ROOT, output, report, rustc, executable(str(rustc.with_name("cargo"))),
        "fence_json", completed=completed_test_summary, record_check=record_check, environment=qualification_env)


def compare_serde_json(output: Path, report: dict, rustc: Path) -> dict:
    return compare_json_original(ROOT, output, report, rustc, executable(str(rustc.with_name("cargo"))),
        "serde_json", completed=completed_test_summary, record_check=record_check, environment=qualification_env)


def compare_request_context(output: Path, report: dict, rustc: Path) -> dict:
    return compare_request_original(ROOT, output, report, rustc, executable(str(rustc.with_name("cargo"))),
        "request_context", completed=completed_test_summary, record_check=record_check, environment=qualification_env)


def compare_response_hints(output: Path, report: dict, rustc: Path) -> dict:
    return compare_request_original(ROOT, output, report, rustc, executable(str(rustc.with_name("cargo"))),
        "response_hints", completed=completed_test_summary, record_check=record_check, environment=qualification_env)


def compare_result_publication(output: Path, report: dict, rustc: Path) -> dict:
    return compare_publication_original(ROOT, output, report, rustc, executable(str(rustc.with_name("cargo"))),
        completed=completed_test_summary, record_check=record_check, environment=qualification_env)


def compare_request_scope(output: Path, report: dict, rustc: Path) -> dict:
    return compare_request_scope_original(ROOT, output, report, rustc, executable(str(rustc.with_name("cargo"))),
        completed=completed_test_summary, record_check=record_check, environment=qualification_env)


def retained_execution_original(output: Path, report: dict) -> dict:
    import hia_native_execution_qualification as q
    name = "execution-shadow-rust-compare"
    check, summary = completed_test_summary(output, report, name)
    folder = output / "execution-shadow-rust-reference"
    result = q.original_evidence(ROOT, output / q.FOLDER, folder, stdout=output / (name + ".stdout"))
    q.exact(summary, result["report"], "actual original aggregate stdout differs")
    if (check.get("timeout_seconds") != 180 or not 0 < check.get("elapsed_seconds", 0) < 180
            or check.get("stderr_bytes") != 0 or check["stdout_bytes"] != (output / (name + ".stdout")).stat().st_size):
        raise ValueError("execution original aggregate process differs")
    command = check["command"]
    expected = [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/compare_execution_original.py"),
                "--runtime", str(ROOT), "--corpus", str(output / q.FOLDER), "--output", str(folder),
                "--rustc", report["rust_compiler"]["invocation_path"]]
    if len(command) != len(expected) + 2 or command[:len(expected)] != expected or command[-2] != "--cargo":
        raise ValueError("execution original aggregate invocation differs")
    return {**result, "completed_process": {key: check[key] for key in
            ("command", "exit_code", "timed_out", "timeout_seconds", "stdout_bytes", "stderr_bytes", "stdout_sha256", "stderr_sha256")}}


def compare_execution(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_execution_qualification as q
    before = execution_evidence(output, report)
    if before != report.get("execution_evidence"):
        raise ValueError("execution native evidence changed before original replay")
    cargo = executable(str(rustc.with_name("cargo")))
    command = [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/compare_execution_original.py"),
               "--runtime", str(ROOT), "--corpus", str(output / q.FOLDER),
               "--output", str(output / "execution-shadow-rust-reference"), "--rustc", str(rustc), "--cargo", str(cargo)]
    record_check(output, report, name="execution-shadow-rust-compare", command=command, timeout=180,
                 env=qualification_env())
    result = retained_execution_original(output, report)
    if execution_evidence(output, report) != before:
        raise ValueError("execution native evidence changed during original replay")
    return result


def retained_config_original(output: Path, report: dict) -> dict:
    import hia_native_config_qualification as q
    return q.original_evidence(ROOT, output, report, completed_test_summary)


def compare_config(output: Path, report: dict, rustc: Path) -> dict:
    before = config_evidence(output, report)
    if before != report.get("config_evidence"):
        raise ValueError("configuration native evidence changed before original replay")
    cargo = executable(str(rustc.with_name("cargo")))
    command = [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/compare_config_original.py"),
               "--repo", str(ROOT), "--native-results", str(output / "config-native/result.json"),
               "--output", str(output / "config-original"), "--cargo", str(cargo), "--rustc", str(rustc)]
    record_check(output, report, name="config-rust-compare", command=command, timeout=180,
                 env=qualification_env())
    result = retained_config_original(output, report)
    if config_evidence(output, report) != before:
        raise ValueError("configuration native evidence changed during original replay")
    return result


def compare_effect_fence(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_effect_fence_qualification as q
    return q.compare_original(ROOT, output, report, rustc,
                              q.completed_process, record_check, qualification_env())


def compare_session_workdir(output: Path, report: dict, rustc: Path) -> dict:
    import hia_native_session_qualification as q
    return q.compare_original(ROOT, output, report, rustc, completed_test_summary,
                              record_check, qualification_env())


RECIPES = {"runtime_bytes": compare_bytes, "text_budget": compare_text,
           "request_context": compare_request_context, "response_hints": compare_response_hints,
           "result_publication": compare_result_publication,
           "request_scope_lifecycle": compare_request_scope,
           "line_verify": compare_line_verify, "batch_plan": compare_batch_plan, "batch_apply": compare_batch_apply,
           "atomic_write": compare_atomic_write,
           "editable_content": compare_editable_content, "view_render": compare_view_render,
           "view_cache": compare_view_cache, "history": compare_history, "session_workdir": compare_session_workdir,
           "fence_json": compare_fence_json, "serde_json": compare_serde_json, "execution_shadow": compare_execution,
           "effect_fence": compare_effect_fence, "runtime_config": compare_config,
           "operation_scope_os": compare_operation_scope_os,
           "line_endpoint": compare_endpoint, "delta": compare_delta, "binary_codec": compare_codec,
           "policy": compare_policy, "multi_read_service": compare_multi_read,
           "operation_kdf": compare_operation_kdf, "operation_aead": compare_operation_aead,
           "operation_nonce": compare_operation_nonce, "operation_record": compare_operation_record,
           "system_entropy": compare_system_entropy, "operation_scope": compare_operation_scope,
           "caller_authority": compare_caller_authority}
# Protocol is a new, explicitly limited service. Its original line-hash owner
# is covered by the bytes oracle; parser/lifecycle behavior has direct tests.
NEW_COMPONENTS = {"runtime_protocol"}
# These are checked in check_input_pins against the native process evidence and
# original Python source identities. They are not counted as Rust comparisons.
PYTHON_REFERENCE_COMPONENTS = {"native_io", "stat_version", "local_service", "file_info_service"}


PARALLEL_RUST_RECIPES = {
    "operation_scope_os": ("operation-scope-os-rust.execution.json",
        ("operation-scope-os-rust-compile", "operation-scope-os-rust-compare")),
    "caller_authority": ("caller-authority-rust.execution.json",
        ("caller-authority-rust-format", "caller-authority-rust-compile",
         "caller-authority-rust-compare", "caller-authority-rust-kernel")),
}


def run_rust_recipes(output: Path, report: dict, rustc: Path) -> None:
    """Overlap the two independent OS references with private report writers.

    Their Cargo targets, native corpus and raw process files are distinct. JSON
    stays in the main ordered stream and shares its one fresh build. Workers
    receive immutable native evidence snapshots. The caller collects every
    completed check in declaration order, including failures during draining.
    """
    selected = {key: value for key, value in PARALLEL_RUST_RECIPES.items()
                if key in report["modules"] and key in RECIPES}
    if not selected:
        raise ValueError("independent OS reference recipes are missing")
    receipts, futures, collected = {}, {}, set()
    report["rust_parallel_receipts"] = {}
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="hia-original-os") as pool:
        for key, (name, expected) in selected.items():
            private = copy.deepcopy(report)
            original_checks = copy.deepcopy(private["checks"])
            path = output / name
            receipts[key] = (private, original_checks, path, expected)
            futures[key] = pool.submit(RECIPES[key], output, private, rustc, report_path=path)
        def collect(key):
            private, original_checks, path, expected = receipts[key]
            result, failure = None, None
            try:
                result = futures[key].result()
            except Exception as error:
                failure = error
            if private["checks"][:len(original_checks)] != original_checks:
                raise ValueError("independent original reference modified native process evidence")
            checks = private["checks"][len(original_checks):]
            names = [row["name"] for row in checks]
            if (not checks or names != list(expected[:len(checks)]) or len(checks) > len(expected)
                    or any(name in {row["name"] for row in report["checks"]} for name in names)
                    or json.loads(path.read_bytes()) != private):
                raise ValueError("independent original reference process receipts differ: " + key)
            report["checks"].extend(checks)
            if failure is None:
                if (len(checks) != len(expected)
                        or any(row["exit_code"] != 0 or row["timed_out"] is not False for row in checks)):
                    raise ValueError("independent original reference did not complete: " + key)
                report["original_rust_comparisons"][key] = result
            report["rust_parallel_receipts"][path.name] = sha(path)
            collected.add(key)
            save_report(output / "result.json", report)
            return failure
        try:
            for key in report["modules"]:
                if key in futures:
                    failure = collect(key)
                    if failure is not None:
                        raise failure
                elif key in RECIPES:
                    report["original_rust_comparisons"][key] = RECIPES[key](output, report, rustc)
                    save_report(output / "result.json", report)
        finally:
            for key in futures:
                if key not in collected:
                    try:
                        failure = collect(key)
                        if failure is not None:
                            report.setdefault("rust_parallel_drain_errors", []).append(
                                {"name": key, "type": type(failure).__name__, "message": str(failure)})
                    except Exception as error:
                        report.setdefault("rust_parallel_drain_errors", []).append(
                            {"name": key, "type": type(error).__name__, "message": str(error)})
            save_report(output / "result.json", report)


def run(output: Path, rustc_name: str) -> dict:
    report_path = output / "result.json"
    report = json.loads(report_path.read_bytes())
    if (report.get("schema") != "hepta.runtime.hia-native-qualification.v1"
            or report.get("status") != "NATIVE_COMPONENTS_PASS"
            or report.get("native_components_status") != "PASS"
            or report.get("rust_comparison_status") != "PENDING"):
        raise ValueError("only a completed native phase with a pending Rust comparison can advance")
    started = time.monotonic()
    report.update({"status": "RUNNING", "phase": "original_rust_comparison",
                   "rust_comparison_status": "RUNNING", "original_rust_comparisons": {}})
    save_report(report_path, report)
    try:
        if set(report["modules"]) != {item["key"] for item in MODULES}:
            raise ValueError("completed native phase module inventory differs")
        check_input_pins(output, report)
        unknown = set(report["modules"]) - RECIPES.keys() - NEW_COMPONENTS - PYTHON_REFERENCE_COMPONENTS
        if unknown:
            raise ValueError("missing original reference recipe: " + ", ".join(sorted(unknown)))
        rustc = executable(rustc_name)
        compiler_sha = sha(rustc)
        version = record_check(output, report, name="original-rust-compiler-version",
                               command=[str(rustc), "--version", "--verbose"], timeout=15)
        report["rust_compiler"] = {"invocation_path": str(rustc), "resolved_path": str(rustc.resolve()),
                                   "invocation_executable_sha256": compiler_sha,
                                   "version": version.stdout.decode("utf-8")}
        run_rust_recipes(output, report, rustc)
        if set(report["original_rust_comparisons"]) != RECIPES.keys():
            raise ValueError("not all required Rust reference recipes completed")
        check_input_pins(output, report)
        if sha(rustc) != compiler_sha:
            raise ValueError("original Rust compiler executable changed during comparison")
        report["rust_comparison_status"] = "PASS"
        report["status"] = "PASS"
        report["phase"] = "complete"
    except BaseException as exc:
        report["status"] = "FAIL"
        report["rust_comparison_status"] = "FAIL"
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        (output / "rust-comparison-failure.txt").write_text(traceback.format_exc())
    report["rust_comparison_elapsed_seconds"] = time.monotonic() - started
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    save_report(report_path, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="completed native-phase directory")
    parser.add_argument("--rustc", default="rustc", help="Rust compiler executable; CI supplies its pinned path")
    args = parser.parse_args()
    result = run(args.output.resolve(strict=True), args.rustc)
    summary = {"status": result["status"], "rust_comparison_status": result["rust_comparison_status"],
               "compiler_cold_status": result.get("compiler_cold_status"),
               "retained_python_comparison_status": result.get("retained_python_comparison_status"),
               "report": str(args.output.resolve() / "result.json"),
               "check_processes": len(result["checks"]), "whole_runtime_replaced": False}
    if result["status"] != "PASS":
        summary["error"] = result.get("error")
        summary["failed_processes"] = [
            {key: row.get(key) for key in ("name", "exit_code", "timed_out", "start_error",
                                          "elapsed_seconds", "timeout_seconds")}
            for row in result["checks"]
            if row.get("exit_code") != 0 or row.get("timed_out") is not False or row.get("start_error")]
    print(json.dumps(summary, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

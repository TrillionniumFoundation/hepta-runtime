"""Finish native qualification with original owners and independent Rust references.

The aggregate result can become PASS only after all required recipes match the
retained native corpus. Replaying a corpus does not add new native test cases.
"""
from __future__ import annotations

import argparse
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
from qualify_hia_runtime_native import (MODULES, multi_read_controller_evidence, native_composition_evidence,
                                       operation_aead_evidence, operation_kdf_evidence, operation_nonce_evidence,
                                       python_reference_evidence, qualification_env,
                                       record_check, save_report, sha, sources)
from check_hia_native_inventory import RUNTIME_BASE_COMMIT, check_original_sources
from hia_native_build import HEPTA_COMMIT
from hia_native_cold import validate_cold_evidence


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
    for collection in ("rust_oracle_inputs", "python_reference_inputs"):
        for relative, expected in report[collection].items():
            path = Path(relative)
            if path.is_absolute() or ".." in path.parts or sha(output / path) != expected:
                raise ValueError("retained native reference corpus changed: " + relative)
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
        if item.get("builder") == "composition":
            # The exact six-image authority table, all child source/image pairs,
            # packer and executable were revalidated above, including the suite.
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


RECIPES = {"runtime_bytes": compare_bytes, "text_budget": compare_text,
           "line_endpoint": compare_endpoint, "delta": compare_delta, "binary_codec": compare_codec,
           "policy": compare_policy, "multi_read_service": compare_multi_read,
           "operation_kdf": compare_operation_kdf, "operation_aead": compare_operation_aead,
           "operation_nonce": compare_operation_nonce}
# Protocol is a new, explicitly limited service. Its original line-hash owner
# is covered by the bytes oracle; parser/lifecycle behavior has direct tests.
NEW_COMPONENTS = {"runtime_protocol"}
# These are checked in check_input_pins against the native process evidence and
# original Python source identities. They are not counted as Rust comparisons.
PYTHON_REFERENCE_COMPONENTS = {"native_io", "stat_version", "local_service"}


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
        for key in report["modules"]:
            if key in RECIPES:
                report["original_rust_comparisons"][key] = RECIPES[key](output, report, rustc)
                save_report(report_path, report)
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
    print(json.dumps({"status": result["status"], "rust_comparison_status": result["rust_comparison_status"],
                      "compiler_cold_status": result.get("compiler_cold_status"),
                      "retained_python_comparison_status": result.get("retained_python_comparison_status"),
                      "report": str(args.output.resolve() / "result.json"),
                      "check_processes": len(result["checks"]), "whole_runtime_replaced": False}, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

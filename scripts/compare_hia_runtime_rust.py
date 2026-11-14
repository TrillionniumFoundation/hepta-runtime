"""Finish native qualification by executing original Rust function oracles.

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
from qualify_hia_runtime_native import MODULES, record_check, save_report, sha, sources
from check_hia_native_inventory import check_original_sources


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
    for relative, expected in report["rust_oracle_inputs"].items():
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or sha(output / path) != expected:
            raise ValueError("retained native oracle corpus changed: " + relative)
    for item in report["modules"].values():
        manifest = output / item["manifest"]
        if sha(manifest) != item["sha256"]:
            raise ValueError("compiled module manifest changed")
        module = json.loads(manifest.read_bytes())
        for label in ("source", "image"):
            if sha(manifest.parent / module[label]) != module[label + "_sha256"]:
                raise ValueError("compiled module artifact changed: " + label)


def rust_compile(output: Path, report: dict, rustc: Path, *, key: str,
                 source: Path, binary: Path, extra: tuple[str, ...] = ()) -> None:
    if binary.exists():
        raise ValueError("oracle executable already exists: " + str(binary))
    record_check(output, report, name=key + "-compile",
                 command=[str(rustc), "-O", "--edition=2021", *extra, str(source), "-o", str(binary)],
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


RECIPES = {"runtime_bytes": compare_bytes, "text_budget": compare_text, "line_endpoint": compare_endpoint}
# Protocol is a new, explicitly limited service. Its original line-hash owner
# is covered by the bytes oracle; parser/lifecycle behavior has direct tests.
NEW_COMPONENTS = {"runtime_protocol"}


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
        unknown = set(report["modules"]) - RECIPES.keys() - NEW_COMPONENTS
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
                      "report": str(args.output.resolve() / "result.json"),
                      "check_processes": len(result["checks"]), "whole_runtime_replaced": False}, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

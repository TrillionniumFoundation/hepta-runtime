#!/usr/bin/env python3
"""Verify the actual private07 archive locally, preserving original outcomes.

Reuses the already reviewed complete gzip/member verifier. Only trusted local,
SHA-bound pure validators are imported; archive code is never executed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tarfile
import types

HERE = Path(__file__).resolve().parent
CAPACITY = HERE.parent
HELPER_SHA = "34ce88cc28da10e1167dabaf6e3480aa42f5e6e76a29472d93959334aa9ec2ed"
EXPORTER_SHA = "0a96aaf09eb16aa7affca5a27d4abbc17cf34cea4d7dc709eb9c16b436b169e4"
INPUT_SHA = "1a89622435fb05faa40fb596aac52709534a9bb5f3a636917e56781931700dce"
REPORT_SHA = "da54b40a6e32106b4862a7bb4143a096e667840b663fbae3be544ce1dd110413"
JOB = "1a1ac1a134e-fc05-5238"
TERMINAL_SHA = "426afc97696ba18e4d1fd2f72986740f873d9e0d2ff42b901fac9e91258ac5ff"
READ_SHA = "bb3bfada0a43a824ff69b54855eb9ec75630bbde706760114abf5af19d07fdd2"
BUILD04_FILES = {
    "actual-failed-build-04.stderr": (664, "58ae5631834c75effae305d1282f9784147119e759ea8cecc93be956621196a5"),
    "actual-failed-build-04.json": (6231, "8ef9ba80b85555884cc3f7900ac0ec3c09ccb276efc45672b4a8027beaa9faa5"),
    "actual-failed-build-04-terminal.json": (726, "7eef820d0e4cdc9893b026e14f0ebed1400719e1073cd08fc495afbda4b4475a"),
    "actual-compiler-state-probe-04.json": (1402, "7c96d64443d09f5334735b75be6f66fc2aead112ad4ef1fe8120601f937ea919"),
    "actual-compiler-state-probe-04-terminal.raw.json": (954, "0fd8d05154d6302114182afbd58ab0f5d4150cba27fbef9e57beb1d73627f46e"),
}
VALIDATORS = {
    "02": (CAPACITY / "mechanism-monitor-02/validate_compiler_monitor.py",
           "f6887620b5b421da497f709dcd02110cc1e89ab47bb00ac4087f82d3bf3cb4fe"),
    "03": (CAPACITY / "mechanism-phase-03/validate_compiler_monitor.py",
           "d2cd009adf1f35a394ffddcc8f8646cc0c1b856b78181ca321ea68f6468218b2"),
}


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def basic_read(path, maximum=16 * 1024**2):
    """Same descriptor/path-bound local input pattern as the R26 consumer."""
    path = Path(path).absolute()
    need(path.resolve(strict=True) == path, "direct original local file required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
             and 0 <= before.st_size <= maximum, "unsafe or oversized local input")
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(maximum + 1)
        fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        stamp = lambda value: {key: getattr(value, key) for key in fields}
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             "original local file changed")
    finally:
        os.close(fd)
    return {"local_path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "descriptor_identity": stamp(before)}, raw


def pin(value):
    return {key: value[key] for key in ("bytes", "sha256")}


def check_body(raw, expected):
    need({"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} == pin(expected),
         "original retained bytes differ from bound identity")


def load_local(path, expected):
    identity, raw = basic_read(path, 131072)
    need(identity["sha256"] == expected, "trusted local consumer dependency differs")
    module = types.ModuleType("private07_local_" + path.stem)
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module, identity


def verify_native07(exporter, report_raw, terminal_raw, read_raw):
    operation = exporter.validate_operation({"executed": True, "job_id": JOB,
        "terminal_raw": terminal_raw.decode(), "terminal_pin": exporter.byte_pin(terminal_raw), "reason": None})
    need(operation["state"] == "succeeded" and operation["exit_code"] == 0
         and operation["native_logs_lossless_complete"] is True, "original private07 strong success missing")
    dto = json.loads(read_raw)
    need(dto["job_id"] == JOB and dto["audit_recorded"] is True, "native read belongs to another operation")
    streams = {}
    for name in ("stdout", "stderr"):
        row = dto[name]
        raw = bytes.fromhex(row["bytes_hex"])
        need(row["offset"] == 0 and row["next_offset"] == row["size"] == len(raw) and row["eof"] is True
             and row["text"].encode() == raw
             and operation["terminal_original"]["log_bytes"][name] == {"seen": len(raw), "stored": len(raw)},
             "original private07 native stream incomplete")
        streams[name] = exporter.byte_pin(raw)
        if name == "stdout":
            footer = json.loads(raw)
            need(footer["passed"] is True and footer["export_completed"] is True
                 and footer["report"]["source_path"] == str(exporter.OUT / "report.json"),
                 "original private07 footer differs")
            check_body(report_raw, footer["report"])
        else:
            need(not raw, "original private07 stderr differs")
    return {"operation": operation, "streams": streams}


def verify_build(revision, build, qualification, files, omissions, manifest, root):
    private = root / ("mechanism-diagnostic-" + revision)
    source = private / "source"
    source_map = build["diagnostic"].get("source_after", build["diagnostic"].get("source_tested", build["diagnostic"].get("source_before_format")))
    need(isinstance(source_map, dict) and len(source_map) == 224, "original diagnostic source map missing")
    for relative, expected in source_map.items():
        row = files["source-" + revision + "/" + relative]
        need(row["source_path"] == str(source / relative) and row["sha256"] == expected,
             "complete compiler input map differs")
    for name, expected in qualification["harness_after"].items():
        row = files["source-" + revision + "/tools/x230/20261028/" + name]
        need(row["sha256"] == expected and row["source_path"] == str(source / "tools/x230/20261028" / name),
             "original qualification harness differs")
    logs = 0
    for stage in build["stages"]:
        for stream in ("stdout", "stderr"):
            expected = stage.get(stream)
            if expected is None:
                continue
            path = Path(expected["path"])
            need(path.parent == private / "build-logs", "original stage log escaped fixed build directory")
            row = files["build-" + revision + "/build-logs/" + path.name]
            need(row["source_path"] == str(path) and pin(row) == pin(expected), "complete original stage log differs")
            logs += 1
    cache = [row for row in manifest["excluded_cache_trees"] if row["path"] == str(private / "target-build")]
    need(len(cache) == 1 and type(cache[0]["exists"]) is bool, "original cache presence record missing")
    if cache[0]["exists"]:
        need(isinstance(cache[0]["directory_identity"], dict), "present cache lacks original identity")
    else:
        need(cache[0]["directory_identity"] is None and cache[0]["path"] in manifest["recorded_absent_paths"],
             "absent cache was assigned a fabricated identity")
    binaries = []
    if build.get("test_binary"):
        item = build["test_binary"]
        binaries.append(("test-library", item["path"], item))
    if build["diagnostic"].get("binary"):
        item = build["diagnostic"]["binary"]
        binaries.append(("retained-runtime", item["path"], item))
    if any(stage["name"] == "release" and stage.get("returncode") == 0 for stage in build["stages"]):
        binaries.extend((name, str(private / "target-build" / name), None)
                        for name in ("release/hepta-runtime", "release/hepta-runtime-jobctl", "release/examples/native_process_driver"))
    identities = []
    for label, path, expected in binaries:
        name = "binary-identities-" + revision + "/" + label
        need(name in omissions and name not in files, "reported actual ELF identity was skipped or body included")
        row = omissions[name]
        need(row["source_path"] == path and row["is_elf"] is True and row["bytes"] >= 4
             and row["original_identity"]["st_size"] == row["bytes"], "reported original ELF binding differs")
        need(expected is None or pin(row) == pin(expected), "reported test/runtime ELF SHA differs")
        identities.append(row)
    need({name for name in omissions if name.startswith("binary-identities-" + revision + "/")} ==
         {"binary-identities-" + revision + "/" + label for label, _, _ in binaries}, "original ELF identity set differs")
    return {"source_files": len(source_map), "harness_files": len(qualification["harness_after"]),
            "complete_stage_logs": logs, "cache": cache[0], "original_elf_identities": identities,
            "elf_bodies_present_locally": False, "elf_bodies_rehashed_here": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, help="Optional already downloaded manifest; embedded original is always verified")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    need(not os.path.lexists(args.out), "fresh independent verification output required")
    helper, helper_identity = load_local(HERE / "stable_archive.py", HELPER_SHA)
    exporter, exporter_identity = load_local(HERE / "export_private_diagnostic_07.py", EXPORTER_SHA)
    local_inputs = [helper_identity, exporter_identity, basic_read(Path(__file__))[0]]
    report_identity, report_raw = basic_read(args.report)
    need(report_identity["sha256"] == REPORT_SHA, "actual private07 report SHA differs")
    report = json.loads(report_raw)
    need(report["schema"] == "hepta-r25-private-diagnostic-export/v3" and report["passed"] is True
         and report["export_completed"] is True and report["every_member_verified"] is True
         and report["no_workload_executed"] is True and report["automatic_retries"] == 0
         and report["diagnostic_only"] is True and report["production_candidate"] is False
         and report["baseline_adoption_status"] == "qualified_but_unadopted_R25"
         and report["capacity_admission_made_here"] is False and report["integrity_discrepancies"] == [],
         "actual exporter scope/outcome differs")
    need(report["exporter"]["sha256"] == EXPORTER_SHA and report["archive_helper"]["sha256"] == HELPER_SHA
         and report["input"]["sha256"] == INPUT_SHA, "export source/helper/actual input binding differs")
    terminal_identity, terminal_raw = basic_read(CAPACITY / "actual-private-export-operations-07/native-terminal.json")
    read_identity, read_raw = basic_read(CAPACITY / "actual-private-export-operations-07/native-read.json")
    need(terminal_identity["sha256"] == TERMINAL_SHA and read_identity["sha256"] == READ_SHA,
         "actual original private07 native evidence differs")
    native07 = verify_native07(exporter, report_raw, terminal_raw, read_raw)
    local_inputs.extend((report_identity, terminal_identity, read_identity))
    archive_identity = helper.read(args.archive)[0]
    need(pin(archive_identity) == pin(report["archive"]), "downloaded complete private07 archive differs")
    with tarfile.open(args.archive, "r|gz") as archive:
        first = next(iter(archive))
        need(first.name == "_export-manifest.json" and first.isfile() and first.size == report["manifest"]["bytes"]
             and first.size <= helper.MAX_RETAIN_BYTES, "original embedded manifest is missing or oversized")
        with archive.extractfile(first) as stream:
            manifest_raw = stream.read(first.size + 1)
    check_body(manifest_raw, report["manifest"])
    if args.manifest is not None:
        manifest_identity, external_raw = basic_read(args.manifest)
        need(external_raw == manifest_raw, "downloaded external and embedded manifest differ")
        local_inputs.append(manifest_identity)
    manifest = json.loads(manifest_raw)
    need(manifest["schema"] == "hepta-r25-private-diagnostic-archive/v3"
         and manifest["native_and_mac_companions_required"] is True
         and manifest["capacity_admission_made_here"] is False and manifest["diagnostic_only"] is True
         and manifest["production_candidate"] is False and manifest["original_failed_or_partial_reports_rewritten"] is False
         and manifest["baseline_adoption_status"] == "qualified_but_unadopted_R25", "archive scope differs")
    for key in ("original_build_report_inputs", "phase02_original_report_inputs", "phase02_original_reports", "cost03",
                "phase03_original_report_inputs", "previous_installation_submission", "previous_export06", "phase03_installation",
                "phase03", "phase03_monitor_proof", "phase03_socket_metadata", "integrity_discrepancies"):
        need(manifest[key] == report[key], "manifest/report original outcome differs: " + key)
    need(manifest["previous_installation_submission"] == exporter.PRIOR_UNKNOWN_INSTALL
         and manifest["previous_installation_submission"]["original_strong_terminal_inferred"] is False,
         "original launch_unknown was rewritten or promoted")
    files = manifest["files"]
    omissions = {row["archive_path"]: row for row in manifest["omitted_bodies"]}
    metadata = {row["archive_path"]: row for row in manifest["metadata_only_omissions"]}
    need(len(files) == report["included_files"] and len(omissions) == len(manifest["omitted_bodies"]) == report["omitted_body_count"]
         and len(metadata) == len(manifest["metadata_only_omissions"]) == report["metadata_only_omissions"], "archive counts differ")
    need(not (set(files) & set(omissions) or set(files) & set(metadata) or set(omissions) & set(metadata)),
         "payload and omitted identities overlap")
    origins = {}
    for row in list(files.values()) + list(omissions.values()):
        path = row["source_path"]
        core = {key: row[key] for key in ("source_path", "bytes", "sha256", "original_identity", "is_elf")}
        need(path not in origins or origins[path] == core, "one source has conflicting original identities")
        origins[path] = core
    for name, row in list(omissions.items()) + list(metadata.items()):
        helper.safe_name(name)
        need(row.get("omission_reason"), "omission reason absent")
    captured = set(origins) | {row["source_path"] for row in metadata.values()}
    for tree in manifest["source_trees"].values():
        need(set(tree) == {"files", "directories"} and len(tree["files"]) == len(set(tree["files"]))
             and set(tree["files"]) <= captured, "source inventory has an unaccounted original file")
    proof = helper.verify_archive(args.archive, manifest_raw, files)
    need(proof["verified"] is True and proof["regular_members"] == report["archive_verification"]["regular_members"]
         and proof["gzip_integrity"] == report["archive_verification"]["gzip_integrity"],
         "complete original gzip/member verification differs")

    wanted = {str(exporter.INPUT), str(exporter.EXPORTER), str(exporter.HELPER),
              *(str(exporter.ROOT / "mechanism-tools-05" / name) for name in BUILD04_FILES),
              *(row["source_path"] for row in report["original_build_report_inputs"].values()),
              *(row["path"] for row in exporter.PREVIOUS_EXPORT_FILES.values()),
              *(str(exporter.ROOT / row["relative"]) for row in exporter.PHASE02_PINS.values()),
              *(str(exporter.ROOT / relative) for relative in exporter.FUTURE_REPORTS.values()),
              *(str(exporter.ROOT / "mechanism-monitor-cost-03" / name) for name in
                ("report.json", "compiler-monitor.json", "compiler-monitor-validation.json"))}
    bodies = {}
    with tarfile.open(args.archive, "r|gz") as archive:
        for member in archive:
            original_path = files.get(member.name, {}).get("source_path")
            if original_path not in wanted:
                continue
            need(member.size <= helper.MAX_RETAIN_BYTES, "original structured receipt exceeds bound")
            with archive.extractfile(member) as stream:
                raw = stream.read(member.size + 1)
            check_body(raw, files[member.name])
            need(original_path not in bodies or bodies[original_path] == raw, "duplicate original bytes differ")
            bodies[original_path] = raw
    need(wanted <= set(bodies), "fixed actual original reports/source/input are missing from archive")
    need(hashlib.sha256(bodies[str(exporter.EXPORTER)]).hexdigest() == EXPORTER_SHA
         and hashlib.sha256(bodies[str(exporter.HELPER)]).hexdigest() == HELPER_SHA
         and hashlib.sha256(bodies[str(exporter.INPUT)]).hexdigest() == INPUT_SHA, "archived export source/input differs")
    actual_input = json.loads(bodies[str(exporter.INPUT)])
    local_input_identity, local_input_raw = basic_read(HERE / "actual-input-06.json")
    need(local_input_raw == bodies[str(exporter.INPUT)], "archived actual input differs from fixed late binding")
    local_inputs.append(local_input_identity)
    previous = {}
    for label, expected in exporter.PREVIOUS_EXPORT_FILES.items():
        raw = bodies[expected["path"]]
        check_body(raw, expected)
        need(origins[expected["path"]] == report["previous_export06"]["files"][label], "original failed06 identity differs")
        previous[label] = raw
    previous_proof = exporter.validate_previous_export06(json.loads(previous["report"]), previous["terminal"], json.loads(previous["read"]))
    need(previous_proof == {key: value for key, value in report["previous_export06"].items() if key != "files"},
         "original export06 failure was changed")
    builds = {}
    for label, identity in report["original_build_report_inputs"].items():
        check_body(bodies[identity["source_path"]], identity)
        builds[label] = json.loads(bodies[identity["source_path"]])
    qualification, failed, built = (builds[label] for label in ("qualification", "failed03", "private05"))
    need(all(report["original_build_report_inputs"][label]["sha256"] == expected for label, expected in
             (("qualification", exporter.QUALIFICATION_SHA), ("failed03", exporter.FAILED03_SHA), ("private05", exporter.BUILD05_SHA))),
         "fixed original qualification/build report pins differ")
    need(qualification["qualified"] is True and qualification["source_after"] == qualification["source_tested"]
         and len(qualification["source_after"]) == 221 and len(qualification["harness_after"]) == 19,
         "original qualified but unadopted R25 inputs differ")
    need(failed["passed"] is False and [stage["name"] for stage in failed["stages"]] ==
         ["diagnostic-tool-tests", "format", "fmt-check", "clippy"] and failed["stages"][-1]["returncode"] == 101,
         "original diagnostic03 compiler failure differs")
    need(built["passed"] is True and built["diagnostic_only"] is True and built["production_candidate"] is False
         and len(built["stages"]) == 23 and all(stage["returncode"] == 0 for stage in built["stages"]),
         "original private05 successful stages differ")
    build_proofs = {revision: verify_build(revision, build, qualification, files, omissions, manifest, exporter.ROOT)
                    for revision, build in (("03", failed), ("05", built))}
    need(str(exporter.ROOT / "mechanism-diagnostic-04") in manifest["recorded_absent_paths"]
         and report["original04_private_directory_absent"] is True, "original preflight-failed04 directory absence changed")
    original04 = {}
    for name, (size, expected_sha) in BUILD04_FILES.items():
        raw = bodies[str(exporter.ROOT / "mechanism-tools-05" / name)]
        check_body(raw, {"bytes": size, "sha256": expected_sha})
        original04[name] = raw
    terminal04 = original04["actual-failed-build-04-terminal.json"]
    operation04 = exporter.validate_operation({"executed": True, "job_id": "1a1ab0912c9-fc05-499e",
        "terminal_raw": terminal04.decode(), "terminal_pin": exporter.byte_pin(terminal04), "reason": None})
    failure04 = json.loads(original04["actual-failed-build-04.json"])
    probe04 = json.loads(original04["actual-compiler-state-probe-04.json"])
    need(operation04["state"] == "failed" and operation04["exit_code"] == 1
         and operation04["native_logs_lossless_complete"] is True
         and operation04["terminal_original"]["log_bytes"] ==
             {"stdout": {"seen": 0, "stored": 0}, "stderr": {"seen": 664, "stored": 664}}
         and failure04["terminal"] == operation04["terminal_original"]
         and failure04["before_private_directory_or_Cargo"] is True
         and failure04["probe_result"] == probe04 and probe04["read_only"] is True
         and probe04["compiler_records"] == [] and probe04["signals_sent"] == 0,
         "original04 failure or separate later probe was changed")
    phase02 = {}
    for label, expected in exporter.PHASE02_PINS.items():
        path = str(exporter.ROOT / expected["relative"])
        check_body(bodies[path], expected)
        phase02[label] = {**exporter.parse_original(bodies[path]), "identity": origins[path]}
    need({label: exporter.project_original(document) for label, document in phase02.items()} == report["phase02_original_reports"],
         "original failed phase02 projection differs")
    need(all(phase02[label]["value"]["passed"] is False for label in ("parent_report", "wrapper_report", "bootstrap_final")),
         "known phase02 failure was promoted")
    phase03 = {}
    for label, relative in exporter.FUTURE_REPORTS.items():
        path = str(exporter.ROOT / relative)
        expected = actual_input["phase03"]["file_pins"][label]
        need(expected is not None, "this fixed actual input must preserve all ten existing phase03 documents")
        check_body(bodies[path], expected)
        phase03[label] = {**exporter.parse_original(bodies[path]), "identity": origins[path]}
    installation = exporter.validate_operation(actual_input["phase03"]["installation"])
    operation = exporter.validate_operation(actual_input["phase03"]["operation"])
    need(installation == report["phase03_installation"], "actual successful short-path installation changed")
    cost_path = exporter.ROOT / "mechanism-monitor-cost-03"
    cost = {}
    for name in ("report.json", "compiler-monitor.json", "compiler-monitor-validation.json"):
        raw = bodies[str(cost_path / name)]
        check_body(raw, exporter.COST03["actual_files"][name])
        cost[name] = json.loads(raw)
    validators = {}
    for revision, (path, expected) in VALIDATORS.items():
        validators[revision], identity = load_local(path, expected)
        local_inputs.append(identity)
    limits = cost["report.json"]["limits_unchanged"]
    def validate_ledger(ledger, revision):
        return validators[revision].validate(ledger, limits, ledger["parent_started_monotonic_ns"], ledger["parent_finished_monotonic_ns"])
    cost_validation = validate_ledger(cost["compiler-monitor.json"], "03")
    need(cost_validation == cost["compiler-monitor-validation.json"] == report["cost03"]["independent_validation"]
         and cost_validation["passed"] is True and cost["report.json"]["cost_probe_passed"] is True
         and cost["report.json"]["formal_measurement_passed"] is False
         and cost["report.json"]["capacity_attribution_allowed"] is False
         and cost["report.json"]["raw_cost"] == report["cost03"]["raw_cost"], "separate cost03 proof/scope differs")
    monitor_results = {}
    for revision, documents in (("02", phase02), ("03", phase03)):
        ledger, wrapper = documents["ledger"]["value"], documents["wrapper_report"]["value"]
        validation = validate_ledger(ledger, revision)
        retained = report["phase" + revision + "_monitor_proof"]
        need(validation == documents["validation"]["value"] == retained["independent_validation"],
             "original phase monitor result differs from independent recomputation")
        need(retained["independently_validated"] is (validation["passed"] is True and ledger["passed"] is True),
             "original monitor positive/negative disposition changed")
        for label, field in (("ledger", "monitor_result"), ("validation", "monitor_validation")):
            expected, original = wrapper[field], documents[label]["identity"]
            need(expected["path"] == original["source_path"] and pin(expected) == pin(original)
                 and expected["descriptor_identity"] == original["original_identity"], "original monitor descriptor seal differs")
        for stream in ("stdout", "stderr"):
            expected = wrapper.get("original_parent_" + stream)
            if expected is None:
                continue
            original = origins[expected["path"]]
            need(pin(expected) == pin(original) and expected["descriptor_identity"] == expected["final_descriptor_identity"] == original["original_identity"],
                 "complete original parent stream descriptor seal differs")
        monitor_results[revision] = validation
    recovered = exporter.classify_phase(operation, phase03, report["phase03_monitor_proof"])
    need(recovered == report["phase03"] and recovered["original_positive_chain_reproduced"] is False,
         "original phase03 failed operation/checkpoint/disposition changed")
    need(phase03["parent_checkpoint"]["value"]["passed"] is False
         and not phase03["parent_checkpoint"]["value"].get("finished_utc")
         and phase03["parent_report"]["value"]["passed"] is False
         and phase03["parent_report"]["value"]["attribution_allowed"] is False,
         "partial original checkpoint or completed rejection was promoted")
    for identity in local_inputs:
        need(basic_read(identity["local_path"])[0] == identity, "local verification source/input changed")
    need(helper.read(args.archive)[0] == archive_identity, "archive changed during verification")
    result = {"schema": "hepta-private07-independent-downloaded-archive-verification/v1", "passed": True,
        "source_inputs": local_inputs, "actual_export_native": native07, "archive": archive_identity,
        "manifest": {"archive_member": "_export-manifest.json", **pin(report["manifest"])},
        "independent_archive_validation": proof, "original_exporter_passed": report["passed"],
        "original_export06_failure": previous_proof, "original_unknown_installation_preserved": True,
        "original_builds": build_proofs, "original03_build_passed": False,
        "original04_preflight_failure": {"operation": operation04, "report": failure04,
            "later_readonly_probe": probe04, "original_stderr": exporter.byte_pin(original04["actual-failed-build-04.stderr"]),
            "later_probe_does_not_identify_original_blocking_compiler": True},
        "original05_build_passed": True, "phase02_original_reports": report["phase02_original_reports"],
        "cost03": report["cost03"], "phase_monitor_recomputations": monitor_results, "phase03": recovered,
        "original_outcomes_preserved": True, "compiler_cache_absence_is_not_ELF_omission_permission": True,
        "native_and_mac_companions_still_required": True,
        "native_companions_other_than_export06_and_export07_reaudited_here": False,
        "full_original_workload_transport_or_phase_trace_reanalysis_performed_here": False,
        "archive_code_executed": False, "archives_extracted": False, "remote_actions": 0, "workloads_executed": 0,
        "capacity_attribution_allowed": False, "production_adoption_made_here": False}
    helper.create(args.out, helper.encode(result))
    output_identity, _ = basic_read(args.out)
    print(json.dumps({"passed": True, "original_phase03_positive": False, "receipt": output_identity}, sort_keys=True))


if __name__ == "__main__":
    main()

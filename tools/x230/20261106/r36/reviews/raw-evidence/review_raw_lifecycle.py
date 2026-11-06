#!/usr/bin/env python3
"""Audit actual R36 lifecycle bytes using only trusted, locally frozen auditors.

Select explicit regular archive members into a fresh local data tree. Never
execute archive code, follow embedded absolute paths, or launch any workload.
"""
import ast
import datetime as dt
import hashlib
import importlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
DOWNLOAD = ROOT / "r36-evidence-download"
TRUSTED = ROOT / "r36-control" / "lifecycle-tools-01"
CONTROL = ROOT / "r36-control" / "tools-01"
OUTPUT = Path(__file__).resolve().parent
DATA = ROOT / "r36-raw-lifecycle-data-01"
ARCHIVE = DOWNLOAD / "r36-evidence-01.tar.xz"
EXPECTED_ARCHIVE = {"bytes": 3961240, "sha256": "30ff7e2dae12aa00a0048c9808610a76b17b4a37daa9de32dfab1fea06f2c9c9"}
EXPECTED_EXPORT = {"bytes": 4989, "sha256": "a65780953c78c7cb7482f6565d84b31db4b483e87efddaf8dc353d0e7c6c7c69"}
EXPECTED_MANIFEST = {"bytes": 8397974, "sha256": "f9ae9650c1ff45ddc0dd4169cc9bb1d3eab6fe7f5d432ff3435753e2cafe3913"}
EXPECTED_VERIFICATION = {"bytes": 4314, "sha256": "190827cdfa65dedb634189616d6e0e272609acfe1ecba0e155fa33ef3892debb"}
HOSTS = {"ai395", "mac", "main", "pocket4", "rog", "x230"}
GENERATION_NAMES = ("first-controller", "after-crash-controller", "after-cancel-controller")
BINARIES = {"A": "bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13",
            "B": "c43db0ef333ce7862080157a1a7fa892ae401a065bdfa96d97d4fd29f2a4eccb"}
checks, selected, cached = [], set(), {}


def digest(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def check(name, value):
    checks.append({"name": name, "passed": bool(value)})
    if not value:
        raise ValueError(name)


def identity(path):
    return digest(path.read_bytes())


def literal(path, name):
    found = [n for n in ast.parse(path.read_text()).body if isinstance(n, ast.Assign)
             and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
    check("one trusted literal " + name, len(found) == 1)
    return ast.literal_eval(found[0].value)


archive_raw = ARCHIVE.read_bytes()
check("exact downloaded archive", digest(archive_raw) == EXPECTED_ARCHIVE)
export_raw = (DOWNLOAD / "export-report.json").read_bytes()
check("exact downloaded export report", digest(export_raw) == EXPECTED_EXPORT)
export = json.loads(export_raw)
verification_raw = (DOWNLOAD / "archive-verification.json").read_bytes()
check("exact independent v2 verification receipt", digest(verification_raw) == EXPECTED_VERIFICATION)
verification = json.loads(verification_raw)
check("independent archive verification passed", verification["verified"] is True
      and verification["archive"] == EXPECTED_ARCHIVE and verification["manifest"] == EXPECTED_MANIFEST)
decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=256 * 1024**2)
expanded = decoder.decompress(archive_raw, max_length=512 * 1024**2 + 1)
check("exact bounded single SHA256 XZ", len(expanded) == 68833280 and decoder.eof
      and not decoder.unused_data and decoder.check == lzma.CHECK_SHA256)
archive = tarfile.open(fileobj=io.BytesIO(expanded), mode="r:")
members = archive.getmembers()
names = [member.name for member in members]
check("9448 unique regular canonical members", len(names) == len(set(names)) == 9448 and names[0] == "_export-manifest.json"
      and all(member.type == tarfile.REGTYPE and not member.linkname and not member.pax_headers
              and not PurePosixPath(member.name).is_absolute() and str(PurePosixPath(member.name)) == member.name
              and not any(part in (".", "..") for part in PurePosixPath(member.name).parts)
              and "\\" not in member.name and "\x00" not in member.name for member in members))
member_map = dict(zip(names, members))
manifest_raw = archive.extractfile(member_map["_export-manifest.json"]).read()
check("exact export manifest identity", digest(manifest_raw) == EXPECTED_MANIFEST == export["manifest"])
manifest = json.loads(manifest_raw)
payloads = manifest["payloads"]
check("complete exact tar payload set", len(payloads) == 9447 and names == ["_export-manifest.json"] + sorted(payloads)
      and len(manifest["omissions"]) == 31)


def member_bytes(name):
    check("selected member explicitly listed " + name, name in payloads and name in member_map)
    if name not in cached:
        raw = archive.extractfile(member_map[name]).read()
        check("selected member original hash " + name,
              digest(raw) == {key: payloads[name][key] for key in ("bytes", "sha256")})
        cached[name] = raw
    return cached[name]


def select(name):
    member_bytes(name)
    selected.add(name)


prefix = "r36/lifecycle-abba-01/"
for filename in ("report.json", "round-index.json", "summary.json", "gates.json", "plan.json"):
    select(prefix + filename)
index = json.loads(member_bytes(prefix + "round-index.json"))
phase_names = literal(TRUSTED / "summarize_lifecycle_abba_01.py", "PHASES")
round_reports = []
all_job_ids = []
for number, arm in enumerate("ABBA"):
    round_name = f"round-{number}-{arm}"
    here = prefix + round_name + "/"
    for filename in ("report.json", "independent-summary.json", "topology.json"):
        select(here + filename)
    report = json.loads(member_bytes(here + "report.json"))
    round_reports.append(report)
    check(round_name + " declared final result and binary", report["passed"] is True and report["phase"] == "completed"
          and report["candidate_sha256"] == BINARIES[arm]
          and not any(report.get(key) for key in ("error", "cleanup_error", "final_check_error", "interrupted_shutdown", "phase_measurement_write_errors")))
    check(round_name + " exactly six fixed hosts", set(report["hosts"]) == HOSTS)
    check(round_name + " topology basename", report["topology"]["file"] == "topology.json")
    for phase in phase_names:
        select(here + "phase-" + phase + ".json")
    for host in sorted(HOSTS):
        select(here + host + "-request.json")
        job_id = report["hosts"][host]["job_id"]
        check(round_name + " safe exact job id " + host, re.fullmatch(r"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+", job_id) is not None)
        all_job_ids.append(job_id)
        state_name = here + "state/jobs/" + job_id + ".json"
        select(state_name)
        row = next(row for row in report["controller_records"]["records"] if row["host"] == host)
        state_raw = member_bytes(state_name)
        state = json.loads(state_raw)
        check(round_name + " actual retained controller record " + host,
              row["job_id"] == state["id"] == job_id and state["host"] == host
              and hashlib.sha256(state_raw).hexdigest() == row["sha256"] and row["original_bytes_unchanged"] is True)
    for generation in GENERATION_NAMES:
        for filename in ("transport-responses.jsonl", "transport-responses.index.jsonl", "resource-samples.jsonl", "stderr.log"):
            select(here + generation + "/" + filename)
    for row in report["native_calls"]:
        check(round_name + " native row scope " + str(row["sequence"]), row["host"] in HOSTS
              and row["tool"] in {"process_start", "process_cancel", "process_status", "process_read"}
              and type(row["sequence"]) is int and 1 <= row["sequence"] <= 126)
        filename = f"native-{row['sequence']:04d}-{row['host']}-{row['tool']}.json"
        check(round_name + " exact canonical native filename " + str(row["sequence"]), Path(row["reply_path"]).name == filename)
        select(here + filename)
    for row in report["ssh_calls"]:
        check(round_name + " ssh row scope " + str(row["sequence"]), row["host"] in HOSTS and row["mode"] in {"inspect", "prepare"}
              and type(row["sequence"]) is int and 1 <= row["sequence"] <= 126)
        for stream in ("stdout", "stderr"):
            filename = f"ssh-{row['sequence']:04d}-{row['host']}-{row['mode']}.{stream}"
            check(round_name + " exact SSH filename " + str(row["sequence"]) + stream, Path(row[stream]["path"]).name == filename)
            select(here + filename)
check("24 distinct newly launched jobs", len(all_job_ids) == len(set(all_job_ids)) == 24)

# No archive script is selected or imported. Every data file is newly created.
check("fresh local data tree", not os.path.lexists(DATA))
DATA.mkdir(mode=0o700)
for name in sorted(selected):
    destination = DATA.joinpath(*PurePosixPath(name).parts)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    check("local output remains under fresh tree " + name, destination.parent.resolve().is_relative_to(DATA.resolve()))
    with destination.open("xb") as stream:
        stream.write(cached[name])

# Pin trusted local auditors against the captured manifest; do not import copies
# from the extracted data. Compiler validator is likewise trusted local code.
trusted_manifest_path = TRUSTED / "lifecycle-tools-manifest-01.json"
trusted_manifest = json.loads(trusted_manifest_path.read_bytes())
check("trusted tools manifest bound by index", identity(trusted_manifest_path)
      == {key: index["tools_manifest"][key] for key in ("bytes", "sha256")})
trusted_pins = {}
for filename, pin in trusted_manifest["files"].items():
    check("trusted local lifecycle source " + filename, identity(TRUSTED / filename) == pin)
    trusted_pins[filename] = pin
sys.path.insert(0, str(TRUSTED))
recovery = importlib.import_module("verify_cancel_recovery")
summary_module = importlib.import_module("summarize_lifecycle_abba_01")
gate_module = importlib.import_module("analyze_lifecycle_gates")
for module in (recovery, summary_module, gate_module):
    check("trusted import " + module.__name__, Path(module.__file__).resolve().parent == TRUSTED)
audits = []
for number, arm in enumerate("ABBA"):
    dirname = f"round-{number}-{arm}"
    here = prefix + dirname + "/"
    result = recovery.verify(cached[here + "report.json"], DATA / prefix / dirname)
    original = json.loads(cached[here + "independent-summary.json"])
    check(dirname + " complete original independent raw audit reproduced", result == original and result["verified"] is True)
    audits.append({"round": number, "arm": arm, "source_report": digest(cached[here + "report.json"]),
                   "original_independent_analysis": digest(cached[here + "independent-summary.json"]),
                   "recomputed_value_exact_match": True, "raw_evidence": result["raw_evidence"],
                   "native_calls": result["native_calls"], "independent_ssh_calls": result["independent_ssh_calls"],
                   "new_starts": result["new_starts"], "same_key_lookups": result["same_key_lookups"],
                   "cancellations": result["cancellations"], "automatic_rpc_retries": result["automatic_rpc_retries"],
                   "physical_machine_groups": result["topology_verification"]["physical_machine_groups"],
                   "live_allocator_environments": result["allocator_environment_verification"]["controllers_with_live_environment"]})
actual_index = DATA / prefix / "round-index.json"
recomputed_summary = summary_module.summarize(actual_index)
original_summary = json.loads(cached[prefix + "summary.json"])
check("all 44 raw phase counters/clocks reproduce summary", recomputed_summary == original_summary)
recomputed_gates = gate_module.analyze(actual_index)
original_gates = json.loads(cached[prefix + "gates.json"])
path_relocations = []
for key in ("round_index", "gate_policy"):
    check("gate identity unchanged after local path relocation " + key,
          all(recomputed_gates[key][field] == original_gates[key][field] for field in ("bytes", "sha256")))
    path_relocations.append({"field": key + ".path", "original": original_gates[key]["path"], "local": recomputed_gates[key]["path"]})
    recomputed_gates[key]["path"] = original_gates[key]["path"]
check("exact original gate result after two path-only relocations", recomputed_gates == original_gates)
check("failed required gates retained", recomputed_gates["verified"] is True and recomputed_gates["passed"] is False)
failures = [{"group": name, "gate": gate} for name, value in recomputed_gates["comparisons"].items()
            if value["adoption_required"] for gate, passed in value["gates"].items() if not passed]
check("four original mandatory failures", set((row["group"], row["gate"]) for row in failures) == {
    ("all_operations", "throughput"), ("launch", "throughput"), ("launch", "rpc_p95"),
    ("launch", "controller_cpu_with_declared_tick_tolerance")})

# Re-audit actual compiler monitor ledgers, not just their flags. These pure
# validators operate exclusively on JSON dictionaries, never current processes.
sys.path.insert(0, str(CONTROL))
monitor_module = importlib.import_module("validate_compiler_monitor")
check("trusted compiler validator import", Path(monitor_module.__file__).resolve().parent == CONTROL)
monitor_reviews = []
for campaign in ("campaign-01", "lifecycle-campaign-01"):
    parent = json.loads(member_bytes("r36/" + campaign + "/report.json"))
    m = parent["compiler_monitor"]
    for key in ("ledger", "independent_audit"):
        filename = Path(m[key]["path"]).name
        check(campaign + " fixed compiler artifact basename " + key,
              filename == ("compiler-monitor.json" if key == "ledger" else "compiler-monitor.audit.json"))
        check(campaign + " compiler artifact bound " + key,
              digest(member_bytes("r36/" + campaign + "/" + filename)) == {field: m[key][field] for field in ("bytes", "sha256")})
    ledger = json.loads(member_bytes("r36/" + campaign + "/compiler-monitor.json"))
    result = monitor_module.validate(ledger, m["limits"], m["guarded_body_start_monotonic_ns"], m["guarded_body_end_monotonic_ns"])
    stored = json.loads(member_bytes("r36/" + campaign + "/compiler-monitor.audit.json"))
    check(campaign + " actual compiler ledger independently valid", result["passed"] is True and result["errors"] == [])
    # The original audit is an envelope around the pure validator result.
    check(campaign + " validator pinned", identity(CONTROL / "validate_compiler_monitor.py")
          == {field: m["sources"]["validator"][field] for field in ("bytes", "sha256")})
    monitor_reviews.append({"campaign": campaign, "ledger": m["ledger"], "original_audit": m["independent_audit"],
                            "recomputed": result, "original_audit_value": stored})
outer = json.loads(member_bytes("r36/lifecycle-campaign-01/report.json"))
unknown = outer["stages"][1]["independent_controller_cleanup"]
check("original outer unknown preserved", unknown == "unknown; stage-group absence is insufficient and no workload is retried"
      and outer["passed"] is False and outer["adoption_passed"] is False)

trace_records = sum(trace["trace_records_recomputed"] for audit in audits for trace in audit["raw_evidence"]["resource_traces"])
report = {
    "schema": "hepta-r36-lifecycle-original-raw-independent-review/v1", "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    "raw_lifecycle_evidence_verified": True, "candidate_accepted": False, "original_required_lifecycle_gates_passed": False,
    "archive": EXPECTED_ARCHIVE, "export_report": EXPECTED_EXPORT, "manifest": EXPECTED_MANIFEST,
    "independent_archive_verification": EXPECTED_VERIFICATION,
    "selected_data_members": len(selected), "selected_data_bytes": sum(len(cached[name]) for name in selected),
    "selected_data_inventory_sha256": hashlib.sha256(json.dumps({name: digest(cached[name]) for name in sorted(selected)}, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
    "trusted_local_lifecycle_manifest": identity(trusted_manifest_path), "trusted_local_sources": trusted_pins,
    "trusted_compiler_validator": identity(CONTROL / "validate_compiler_monitor.py"),
    "rounds": audits, "raw_phase_files_verified": 44, "controller_generations": 12,
    "raw_rpc_timestamps_verified": 360, "native_canonical_results_rehashed": 360,
    "raw_transport_frames_rehashed": sum(a["raw_evidence"]["transport"]["frames_rehashed"] for a in audits),
    "ssh_streams_rehashed": sum(a["raw_evidence"]["ssh_streams_rehashed"] for a in audits),
    "resource_trace_records_recomputed": trace_records, "retained_controller_job_records_rehashed": 24,
    "phase_summary_exact_reproduction": True, "gates_exact_reproduction_after_path_only_relocations": True,
    "path_only_relocations": path_relocations, "comparisons": recomputed_gates["comparisons"], "rss": recomputed_gates["rss"],
    "required_failures": failures, "compiler_monitor_raw_reviews": monitor_reviews,
    "original_outer_independent_controller_cleanup": unknown, "original_outer_field_modified": False,
    "source_report_path_fields_followed": False, "archived_code_executed": False, "remote_operations": 0, "workloads_replayed": 0,
    "limitations": ["This is a local re-audit of retained historical bytes; it is not a new live host/process observation.",
                    "Controller/SSH resource traces remain sampled, with their original missing-observation errors retained; no complete cluster resource claim.",
                    "Private profile/config/agent bodies and ELF bodies were deliberately omitted by the archive policy and were not read.",
                    "The outer unknown field remains unchanged. Separate supplemental generation-closure review is reported independently.",
                    "Compiler monitors provide bounded 1 Hz sampled coverage and do not rule out activity between samples."],
    "checks": checks, "check_count": len(checks), "review_script": identity(Path(__file__)),
}
destination = OUTPUT / "raw-lifecycle-review.json"
destination.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n")
print(json.dumps({"raw_lifecycle_evidence_verified": True, "candidate_accepted": False, "checks": len(checks),
                  "selected_members": len(selected), "resource_records": trace_records, "result": identity(destination)}))

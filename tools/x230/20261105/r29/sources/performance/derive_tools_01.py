#!/usr/bin/env python3
"""Local, nonexecuting source derivation from the verified R28 capture pair."""
import ast
import difflib
import hashlib
import json
from pathlib import Path
import pprint

HERE = Path(__file__).resolve().parent
WORK = HERE.parent.parent
OLD = WORK / "r25-integration-audit/r28-performance-export-02"
DELIVERY = WORK / "r25-capacity-audit/r29-acceptance-delivery-01"
ROOT = "/home/qian/hepta-runtime-optimization-20261105-r29"
STAGE = "/home/qian/hepta-runtime-optimization-20261105-r25"


def pin(path):
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def function(source, name):
    node = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == name)
    return "".join(source.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])


def replace_function(source, name, new):
    old = function(source, name)
    assert source.count(old) == 1
    return source.replace(old, new.rstrip() + "\n", 1)


def replace_assignment(source, name, expression):
    node = next(n for n in ast.parse(source).body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
    lines = source.splitlines(keepends=True)
    return "".join(lines[:node.lineno - 1]) + name + " = " + expression + "\n" + "".join(lines[node.end_lineno:])


def once(source, old, new):
    assert source.count(old) == 1, (old[:80], source.count(old))
    return source.replace(old, new)


def write(path, raw):
    if isinstance(raw, str):
        raw = raw.encode()
    with path.open("xb") as stream:
        stream.write(raw)


original = (OLD / "export_r28_performance_02.py").read_text()
assert hashlib.sha256(original.encode()).hexdigest() == "3aaa6744cf49649fe5a94d0e68489a6edfdee772c04aa8dda14141e3556701fb"
source = original.replace("R28", "R29").replace("r28", "r29")
source = source.replace("export_r29_performance_02.py", "export_r29_performance_01.py")
source = source.replace("r29-performance-export-input-02.json", "r29-performance-export-input-01.json")
source = source.replace("tools-02", "tools-01").replace("bundle-02", "bundle-01")
source = source.replace("install_r29_reviewed_tools_02.py", "install_r29_reviewed_tools_01.py")
source = source.replace("r29-installation-qualification-02.json", "r29-installation-qualification-01.json")
source = source.replace("tools-install-02-receipt.json", "tools-install-01-receipt.json")
source = once(source, '"""Fixed complete R29 observation rejection evidence; no workloads, cleanup or adoption."""',
              '"""Fixed complete R29 observation/lifecycle/saturation originals; no workloads or adoption."""')
source = replace_assignment(source, "ORIGINAL_OBSERVATION_JOB", repr("1a1ad77dfe5-fc05-59f9"))
source = replace_assignment(source, "DIRECTORIES", '''{
    "observation": ROOT / "campaign-01",
    "recovery": RECOVERY,
    "lifecycle": ROOT / "lifecycle-campaign-01",
    "lifecycle-abba": ROOT / "lifecycle-abba-01",
    "saturation": ROOT / "cancel-saturation-01",
    "lifecycle-tool-tests": ROOT / "lifecycle-tool-tests-01",
    "campaign-tools": ROOT / "tools-01",
    "boundary-tools": ROOT / "boundary-tools-01",
    "lifecycle-tools": ROOT / "lifecycle-tools-01",
    "lifecycle-launcher-bundle": ROOT / "lifecycle-launcher-bundle-01",
}''')
source = replace_assignment(source, "UNEXECUTED_PATHS", "()")
source = replace_assignment(source, "KNOWN_SUMMARY", "None")
source = replace_assignment(source, "OUTPUT_PREFIXES", repr(("observation/", "recovery/", "lifecycle/", "lifecycle-abba/", "saturation/", "lifecycle-tool-tests/")))
extra = '''
OUTPUT_DIRECTORIES = tuple(DIRECTORIES[name] for name in ("observation", "recovery", "lifecycle", "lifecycle-abba", "saturation", "lifecycle-tool-tests"))
REQUIRED_DIRECTORIES = {"campaign-tools", "lifecycle-tools", "lifecycle-launcher-bundle"}
STAGE_OUTPUT_DIRECTORIES = {"observation01": (ROOT / "campaign-01", RECOVERY),
    "lifecycle01": (ROOT / "lifecycle-campaign-01", ROOT / "lifecycle-abba-01", ROOT / "cancel-saturation-01", ROOT / "lifecycle-tool-tests-01")}
LIFECYCLE_STAGES = ("lifecycle-tool-tests", "normal-lifecycle-abba", "cancel-saturation", "audit-cancel-saturation")
NORMAL_STAGES = tuple(name for n, arm in enumerate("ABBA") for name in (f"canary-{n}-{arm}", f"audit-{n}-{arm}")) + ("summary", "normal-lifecycle-gates")
LIFECYCLE_PHASES = ("prepare", "launch", "before_crash_running", "after_transport_running", "after_crash_running", "same_key_after_crash", "concurrent_cancel", "terminal", "terminal_after_restart", "same_key_after_cancel", "cancel_after_terminal")
BASELINE_RUNTIME_SHA256 = "bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13"
CANONICAL_PREPARATION_VALIDATOR_SHA256 = "2892bd35bb5f1b5a90919e74453a18d5ae6ad738d08fcc780f3c0ac01c67c923"
'''
source = once(source, "def need(value, reason):", extra + "\ndef need(value, reason):")
installation_path = WORK / "benchmark-r29/tools-installation-operations-01/actual-installation-receipt-01.json"
installation = json.loads(installation_path.read_bytes())
assets = {r["path"]: {k: r[k] for k in ("bytes", "sha256")} for r in installation["files"]}
assert len(assets) == 50 and installation["installed"] is True
source = replace_assignment(source, "FROZEN_INSTALLED_ASSETS", pprint.pformat(assets, width=150, sort_dicts=True))
source = replace_assignment(source, "INSTALL_RECEIPT_PIN", repr({k: pin(installation_path)[k] for k in ("bytes", "sha256")}))
qual = WORK / "benchmark-r29/actual-qualification-receipts-01"
refs = {ROOT + "/" + remote: {k: pin(qual / local)[k] for k in ("bytes", "sha256")} for local, remote in (
    ("preparation-01.json", "preparation-01.json"),
    ("qualification-report-01.json", "qualification-01/report.json"),
    ("qualified-source-map-01.json", "qualification-01/source-map.json"),
    ("qualification-native-terminal-01.json", "qualification-terminal-status-01.json"))}
source = replace_assignment(source, "QUALIFICATION_REFERENCES", pprint.pformat(refs, width=140))
source = source.replace("242701117e8595b16167720c05e6602a221c2db272aef67ccb3abd7c1888c9ae", pin(DELIVERY / "install-01/install_r29_reviewed_tools_01.py")["sha256"])
source = source.replace("d5aaf5c3432f39db26de8158bae37aae9a18a17755d59c2927619332822e0779", pin(WORK / "benchmark-r29/actual-installation-input-01/qualification-input-01.json")["sha256"])
new = (HERE / "binding_functions_01.py").read_text()
for name in ("validate_input", "check_original_bindings", "disposition"):
    source = replace_function(source, name, function(new, name))
source = once(source, "def report_projection(value):", function(new, "required_absent_paths") + "\n\ndef report_projection(value):")
source = source.replace("def inspect_monitor(original, get_json, identities, validator):", "def inspect_monitor(name, original, get_json, identities, validator):")
source = once(source, '    output = REPORT_PATHS["observation01"].parent', '    output = REPORT_PATHS[name].parent')
source = once(source, '    identities, payloads, omitted, inventories, absent = {}, {}, {}, {}, []',
              '    identities, payloads, omitted, inventories, absent, originals = {}, {}, {}, {}, [], {}')
source = once(source, '        for path in UNEXECUTED_PATHS:\n            expect_absent(path)',
              '        for path in required_absent_paths(declarations):\n            expect_absent(path)')
source = once(source, '''            raw = bound(row["report"])
            try:
                original = json.loads(raw)
            except (ValueError, UnicodeError):
                pass''', '''            if row["report"] is not None:
                raw = bound(row["report"])
                try:
                    original = json.loads(raw)
                except (ValueError, UnicodeError):
                    pass
            originals[name] = original''')
source = once(source, '''        for label, directory in DIRECTORIES.items():
            snapshot = helper.listing(directory)''', '''        for label, directory in DIRECTORIES.items():
            if not os.path.lexists(directory):
                need(label not in REQUIRED_DIRECTORIES, "required installed tool directory is absent")
                expect_absent(directory)
                continue
            snapshot = helper.listing(directory)''')
source = once(source, 'label in {"observation", "recovery"}', 'label + "/" in OUTPUT_PREFIXES')
source = once(source, '''        monitor = inspect_monitor(get_json(REPORT_PATHS["observation01"]), get_json, identities, validator)
        report["compiler_monitor_verification"] = monitor
        report["candidate_disposition"] = disposition(report["original_outcomes"], monitor)
        bindings = check_original_bindings(get_json, identities, declarations, report["original_outcomes"], monitor)''', '''        monitors = {name: inspect_monitor(name, originals.get(name), get_json, identities, validator)
                    for name in STAGES if declarations[name]["executed"]}
        report["compiler_monitor_verification"] = monitors
        bindings = check_original_bindings(get_json, identities, declarations, report["original_outcomes"], monitors)
        report["candidate_disposition"] = disposition(report["original_outcomes"], monitors, bindings)''')
source = source.replace('"compiler_monitor_verification": monitor,', '"compiler_monitor_verification": monitors,')
source = once(source, '''                      original_inputs_unchanged=True, original_observation_rejection_preserved=True,
                      lifecycle_and_saturation_output_absence_verified=True)''', '''                      original_inputs_unchanged=True, original_outcomes_preserved=True,
                      actual_output_inventory_and_absence_verified=True)''')
ast.parse(source)
write(HERE / "export_r29_performance_01.py", source)
for filename in ("stable_xz_archive.py", "validate_compiler_monitor.py"):
    write(HERE / filename, (OLD / filename).read_bytes())

original_consumer = (OLD / "verify_r28_performance_02.py").read_text()
consumer = original_consumer.replace("R28", "R29").replace("r28", "r29")
consumer = consumer.replace("export_r29_performance_02.py", "export_r29_performance_01.py").replace("tools-02", "tools-01")
consumer = replace_assignment(consumer, "EXPORTER_SHA256", repr(hashlib.sha256(source.encode()).hexdigest()))
consumer = once(consumer, '''        need(len(path.parts) == 2 and str(relative) == original.NATIVE_PATHS["observation01"].name,
             "unsubmitted original native terminal cannot be invented")
        return original.NATIVE_PATHS["observation01"]''', '''        matching = [p for p in original.NATIVE_PATHS.values() if p.name == str(relative)]
        need(len(path.parts) == 2 and len(matching) == 1, "unknown original native terminal namespace")
        return matching[0]''')
consumer = consumer.replace('report["original_observation_rejection_preserved"] is True', 'report["original_outcomes_preserved"] is True')
consumer = once(consumer, '''    need(set(manifest["fixed_directory_inventories"]) == {str(p) for p in original.DIRECTORIES.values()},
         "fixed original directory inventory is incomplete or expanded")''', '''    expected_directories = {str(p) for p in original.DIRECTORIES.values()}
    recorded_directories = set(manifest["fixed_directory_inventories"])
    absent = set(manifest["observed_absent_paths"])
    need(len(absent) == len(manifest["observed_absent_paths"])
         and recorded_directories <= expected_directories
         and recorded_directories.isdisjoint(absent)
         and recorded_directories | (absent & expected_directories) == expected_directories
         and {str(original.DIRECTORIES[name]) for name in original.REQUIRED_DIRECTORIES} <= recorded_directories,
         "fixed original directories lack exact inventory/absence coverage")''')
consumer = once(consumer, '        outcomes = {}', '        outcomes, original_reports = {}, {}')
consumer = once(consumer, '''                raw = body(original.REPORT_PATHS[name])
                need(digest(raw) == {k: row["report"][k] for k in ("bytes", "sha256")}, "original report pin differs")
                try:
                    result = json.loads(raw)
                except (ValueError, UnicodeError):
                    pass
            outcomes[name] =''', '''                if row["report"] is not None:
                    raw = body(original.REPORT_PATHS[name])
                    need(digest(raw) == {k: row["report"][k] for k in ("bytes", "sha256")}, "original report pin differs")
                    try:
                        result = json.loads(raw)
                    except (ValueError, UnicodeError):
                        pass
                original_reports[name] = result
            outcomes[name] =''')
consumer = once(consumer, '''        monitor = original.inspect_monitor(get_json(original.REPORT_PATHS["observation01"]), get_json, identities, validator)
        need(monitor == report["compiler_monitor_verification"] == manifest["compiler_monitor_verification"],
             "source-bound independent original monitor verification differs")
        classification = original.disposition(outcomes, monitor)
        need(classification == report["candidate_disposition"] == manifest["candidate_disposition"],
             "original performance disposition was promoted or changed")
        bindings = original.check_original_bindings(get_json, identities, declarations, outcomes, monitor)''', '''        monitors = {name: original.inspect_monitor(name, original_reports.get(name), get_json, identities, validator)
                    for name in original.STAGES if declarations[name]["executed"]}
        need(monitors == report["compiler_monitor_verification"] == manifest["compiler_monitor_verification"],
             "source-bound independent original monitor verification differs")
        bindings = original.check_original_bindings(get_json, identities, declarations, outcomes, monitors)
        classification = original.disposition(outcomes, monitors, bindings)
        need(classification == report["candidate_disposition"] == manifest["candidate_disposition"],
             "original performance disposition was promoted or changed")''')
consumer = once(consumer, '''        expected = manifest["fixed_directory_inventories"][str(directory)]
        names =''', '''        if str(directory) not in manifest["fixed_directory_inventories"]:
            need(str(directory) in absent and not any(p == str(directory) or p.startswith(str(directory) + "/") for p in identities),
                 "absent original directory has payloads or no absence proof")
            continue
        expected = manifest["fixed_directory_inventories"][str(directory)]
        names =''')
consumer = consumer.replace('for path in original.UNEXECUTED_PATHS:', 'for path in original.required_absent_paths(declarations):')
consumer = once(consumer, '''    need(outcomes["lifecycle01"]["executed"] is False and report["lifecycle_and_saturation_output_absence_verified"] is True,
         "unsubmitted lifecycle/saturation was promoted")''', '''    allowed_absent = expected_directories | {str(original.ROOT / name) for name in original.OPTIONAL_ROOT_FILES}
    allowed_absent |= {str(p) for p in original.required_absent_paths(declarations)}
    need(absent <= allowed_absent and report["actual_output_inventory_and_absence_verified"] is True,
         "original absence proof escaped its exact fixed scope")
    for name in original.STAGES:
        if not declarations[name]["executed"]:
            need(str(original.NATIVE_PATHS[name]) not in identities, "unsubmitted native terminal was invented")''')
consumer = consumer.replace('"compiler_monitor_verification": monitor,', '"compiler_monitor_verification": monitors,')
consumer = once(consumer, '''              "original_observation_rejection_preserved": True, "lifecycle_and_saturation_executed": False,''',
                         '''              "original_outcomes_preserved": True, "actual_output_inventory_and_absence_verified": True,''')
ast.parse(consumer)
write(HERE / "verify_r29_performance_01.py", consumer)

example = {"schema": "hepta-r29-performance-export-input/v1", "root": ROOT,
    "actual_outcomes_supplied": False, "adoption_decision_made_here": False,
    "native_raw_companion_required": True, "Mac_holder_companion_required": True,
    "qualification_ci_companion_required": True, "known_original_summary": None,
    "stages": {"observation01": {"executed": True, "job_id": "1a1ad77dfe5-fc05-59f9", "native_terminal": None, "report": None, "reason": None},
               "lifecycle01": {"executed": None, "job_id": None, "native_terminal": None, "report": None, "reason": None}}}
write(HERE / "actual-export-input-01.example.json", json.dumps(example, indent=2, sort_keys=True) + "\n")
unchanged = []
for name in ("need", "utc", "descriptor", "validate_terminal", "omission_reason", "report_projection", "original_outcome"):
    assert function(original, name) == function(source, name)
    unchanged.append(name)
consumer_unchanged = []
for name in ("need", "digest", "local_read", "reviewed", "original_capture"):
    assert function(original_consumer, name) == function(consumer, name)
    consumer_unchanged.append(name)
canonical = (WORK / "r25-integration-audit/r29-qualification-final-01/canonical-preparation-validator.py").read_text()
parent = (DELIVERY / "tools-01/r29_campaign.py").read_text()
assert function(canonical, "verify_r29_candidate_preparation") == function(parent, "verify_r29_candidate_preparation")
assert pin(HERE / "stable_xz_archive.py")["sha256"] == "8b7aa7ef3b3772da13ea4f7009d8c478e0c92bc207d65db3f45c23453097d7a2"
assert pin(HERE / "validate_compiler_monitor.py")["sha256"] == "d2cd009adf1f35a394ffddcc8f8646cc0c1b856b78181ca321ea68f6468218b2"
proof = {"schema": "hepta-r29-performance-source-derivation/v1", "source_generated_only": True,
    "producer_consumer_or_archived_code_executed": False, "host_calls": 0,
    "original_exporter": pin(OLD / "export_r28_performance_02.py"),
    "original_consumer": pin(OLD / "verify_r28_performance_02.py"),
    "exporter_unchanged_function_bodies": unchanged, "consumer_unchanged_function_bodies": consumer_unchanged,
    "archive_helper_whole_bytes_unchanged": True, "pure_monitor_validator_whole_bytes_unchanged": True,
    "canonical_preparation_validator": pin(WORK / "r25-integration-audit/r29-qualification-final-01/canonical-preparation-validator.py"),
    "canonical_function_exactly_in_bound_parent": True, "canonical_not_reexecuted_in_performance_export": True,
    "actual_installation_receipt": pin(installation_path), "installed_assets": 50,
    "qualification_references": refs, "future_lifecycle_outcome_and_observation_result_not_invented": True,
    "changed_scope": "fixed actual R29 sources plus optional full lifecycle, ABBA, native tool tests and saturation; negatives/partials retained",
    "new_exporter": pin(HERE / "export_r29_performance_01.py"),
    "new_consumer": pin(HERE / "verify_r29_performance_01.py")}
write(HERE / "source-reuse-proof-01.json", json.dumps(proof, indent=2, sort_keys=True) + "\n")
diff = "".join(difflib.unified_diff(original.splitlines(True), source.splitlines(True),
    fromfile="R28/export_r28_performance_02.py", tofile="R29/export_r29_performance_01.py"))
diff += "".join(difflib.unified_diff(original_consumer.splitlines(True), consumer.splitlines(True),
    fromfile="R28/verify_r28_performance_02.py", tofile="R29/verify_r29_performance_01.py"))
write(HERE / "source-delta-01.patch", diff)
print(json.dumps({"generated": True, "exporter": proof["new_exporter"], "consumer": proof["new_consumer"], "no_main_executed": True}))

# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read-only binding of the original zero-stage R31 preflight failure.

The original parent is loaded from hash-checked retained bytes only to reuse its
pure completed-monitor verifier with its original tools-01 paths. Its main,
monitor start, quiescence, and workload entry points are never called here.
"""
R31_FAILED_CAMPAIGN_JOB = "1a1ae37dda9-fc05-5e42"
R31_FAILED_CAMPAIGN_FILES = {
    "report": {"path": str(ROOT / "campaign-01/report.json"), "bytes": 44604,
        "sha256": "8fb90cf4358b210942343c9da76f40d3c3fe61d751c8c68ab00d65110abc46df"},
    "inputs": {"path": str(ROOT / "campaign-inputs-01.json"), "bytes": 15870,
        "sha256": "d9b18804f1e0ced459ef59af53d3245f24bf8bf416b74a9790d9a9280593bfe2"},
    "parent": {"path": str(ROOT / "tools-01/r31_campaign.py"), "bytes": 71126,
        "sha256": "26b9aa885e049074c2170026ce3bbc9d8a5c2ffed6726899b74f836f9a977e93"},
    "native_terminal": {"path": str(ROOT / "observation-holder-native-01.json"), "bytes": 727,
        "sha256": "33b1f440fa260db903c66d8c4472a19abc0a86d07ec9dfde883a4f481b253e96"},
}


def verify_r31_failed_campaign_documents(report, terminal):
    verify_r31_terminal(terminal, R31_FAILED_CAMPAIGN_JOB, "failed", 1)
    need(report.get("schema") == "hepta-r25-observation-campaign-control/v1"
         and report.get("attempt") == "01" and report.get("candidate_release") == "R31"
         and report.get("passed") is False and report.get("observation_gate_passed") is False
         and report.get("stages") == [] and report.get("started_utc") and report.get("finished_utc")
         and report.get("error") == {"type": "RuntimeError", "reason": "private socket directory already exists"}
         and not any(key in report for key in ("stage_plan", "quiescence", "summary", "correctness_stages_completed"))
         and report.get("automatic_retries") == 0 and report.get("production_services_modified") is False
         and all(report.get(key) is True for key in ("inputs_unchanged", "source_inputs_unchanged",
             "baseline_source_inputs_unchanged", "baseline_enablement_verified", "measurement_attribution_valid"))
         and report.get("input_receipt") == R31_FAILED_CAMPAIGN_FILES["inputs"]
         and report.get("launcher_sha256") == R31_FAILED_CAMPAIGN_FILES["parent"]["sha256"],
         "original R31 failure was not the closed, unchanged zero-stage socket preflight")
    need(report["candidate_preparation_gate"]["passed"] is True
         and report["candidate_preparation_gate"]["original_job_id"] == "1a1ae1c32b8-fc05-5d7a",
         "the failed preflight must retain the original successful R31 qualification")


def bind_r31_prior_campaign_failure(inputs, bind):
    need(inputs.get("attempt") == "02", "only the separately named corrected R31 campaign is authorized")
    identities, raw = {}, {}
    for name, pin in R31_FAILED_CAMPAIGN_FILES.items():
        identities[name], raw[name] = bind(pin["path"], pin, retain=True)
    report, terminal, prior = (json.loads(raw[name]) for name in ("report", "native_terminal", "inputs"))
    verify_r31_failed_campaign_documents(report, terminal)
    need(prior.get("attempt") == "01" and prior.get("candidate_release") == "R31"
         and prior["launcher_sha256"] == identities["parent"]["sha256"],
         "the retained failed input is not the original R31 parent attempt")
    for key in ("qualification_launcher", "qualification_input", "candidate_patch",
                "qualification_preparation", "qualification_terminal_status"):
        need(inputs[key] == prior[key], "R31 qualification changed after the failed preflight: " + key)
    reports = inputs.get("qualification_reports", [inputs.get("qualification_report")])
    need(len(reports) == 1 and all(reports[0][key] == prior["qualification_reports"][0][key]
         for key in ("path", "bytes", "sha256")), "corrected campaign must use the same qualified candidate")
    if "baseline" in inputs:
        need(inputs["baseline"] == prior["baseline"], "accepted R24 baseline changed after the failed preflight")
    for key in ("source_inputs", "baseline_source_inputs"):
        expected = report[key]
        need(expected["path"] == str(ROOT / "campaign-01" / (key.replace("_", "-") + ".json")),
             "original preflight source snapshot path differs")
        bind(expected["path"], expected)
    # A failed namespace check precedes all stage directory creation. Retain that
    # fact without deleting, renaming, touching, or adopting any R30 socket path.
    for path in (ROOT / "campaign-01/native-observation", ROOT / "campaign-01/native-boundary",
                 R16 / "r31-cancel-recovery-01"):
        need(not os.path.lexists(path), "original R31 preflight has unexpected workload output")
    original = monitor_module("_r31_original_parent_01_for_receipt_audit", raw["parent"],
                              Path(identities["parent"]["path"]))
    monitor = original.verify_completed_compiler_monitor(report, prior, bind, ROOT / "campaign-01")
    return {"schema": "hepta-r31-campaign-preflight-recovery/v1", "passed": True,
        "original_job_id": R31_FAILED_CAMPAIGN_JOB, "original_files": identities,
        "original_error": report["error"], "original_stages_started": 0,
        "original_quiescence_started": False, "original_monitor_gate": monitor,
        "corrected_attempt": "02", "automatic_retries": 0,
        "correction": "fresh h31 socket namespace and separately named campaign/input/tool/output paths",
        "candidate_source_recompiled": False, "candidate_adopted": False,
        "original_performance_result_available": False,
        "holder_native_scope": "original failed holder job terminal and complete persisted stdout/stderr accounting"}

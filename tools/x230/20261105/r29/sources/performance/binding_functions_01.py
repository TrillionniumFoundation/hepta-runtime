def validate_input(value):
    need(isinstance(value, dict) and value.get("schema") == "hepta-r29-performance-export-input/v1"
         and value.get("root") == str(ROOT) and value.get("actual_outcomes_supplied") is True
         and all(value.get(k) is True for k in ("native_raw_companion_required", "Mac_holder_companion_required",
                                                "qualification_ci_companion_required"))
         and value.get("adoption_decision_made_here") is False
         and set(value.get("stages", {})) == set(STAGES), "actual fixed R29 performance outcomes required")
    rows = value["stages"]
    for name in STAGES:
        row = rows[name]
        need(isinstance(row, dict) and set(row) == {"executed", "job_id", "native_terminal", "report", "reason"}
             and type(row["executed"]) is bool, "fixed stage declaration fields differ")
        if row["executed"]:
            need(isinstance(row["job_id"], str) and JOB.fullmatch(row["job_id"]), "actual original job identity required")
            descriptor(row["native_terminal"], NATIVE_PATHS[name])
            if row["report"] is not None:
                descriptor(row["report"], REPORT_PATHS[name])
            else:
                need(isinstance(row["reason"], str) and row["reason"].strip(),
                     "original report absence needs an explicit actual reason")
        else:
            need(row["job_id"] is row["native_terminal"] is row["report"] is None
                 and isinstance(row["reason"], str) and row["reason"].strip(),
                 "unsubmitted stage must not acquire invented outcomes")
    need(rows["observation01"]["executed"] is True
         and rows["observation01"]["job_id"] == ORIGINAL_OBSERVATION_JOB,
         "the one actual original R29 observation must be retained")
    if rows["lifecycle01"]["executed"]:
        need(rows["lifecycle01"]["job_id"] != ORIGINAL_OBSERVATION_JOB,
             "lifecycle and observation cannot share a native job")
    summary = value.get("known_original_summary")
    if summary is not None:
        descriptor(summary, ROOT / "campaign-01/summary.json")
    return rows


def required_absent_paths(declarations):
    paths = []
    for name in STAGES:
        row = declarations[name]
        if not row["executed"]:
            paths.append(NATIVE_PATHS[name])
            paths.extend(STAGE_OUTPUT_DIRECTORIES[name])
        elif row["report"] is None:
            paths.append(REPORT_PATHS[name])
    return sorted(set(paths), key=str)


def check_original_bindings(get_json, identities, declarations, outcomes, monitors):
    """Bind full original producer files. Negative/partial reports remain negative evidence."""
    def same(path, recorded):
        need(str(path) in identities and isinstance(recorded, dict),
             "original recorded body/identity was not captured: " + str(path))
        actual = identities[str(path)]
        need(actual["sha256"] == recorded["sha256"]
             and ("bytes" not in recorded or actual["bytes"] == recorded["bytes"]),
             "original producer identity differs: " + str(path))
        if "path" in recorded:
            need(recorded["path"] == str(path), "original descriptor path differs: " + str(path))
        return actual

    def maybe(path):
        if str(path) not in identities:
            return None
        try:
            return get_json(path)
        except (ValueError, UnicodeError):
            return None

    def stage_streams(value, directory, expected_names, positive, process_key="owned_process_absent"):
        rows = value.get("stages", [])
        need(isinstance(rows, list) and len(rows) <= len(expected_names)
             and [r.get("name") for r in rows] == list(expected_names[:len(rows)]),
             "original stage order/prefix differs")
        for row in rows:
            for stream in ("stdout", "stderr"):
                if stream in row:
                    same(directory / (row["name"] + "." + stream), row[stream])
                elif positive:
                    need(False, "positive original stage lacks its complete stream binding")
            for record in row.get("output_bindings", []):
                path = Path(record["path"])
                need(any(path.is_relative_to(p) for p in OUTPUT_DIRECTORIES),
                     "original stage output escaped fixed scope")
                same(path, record)
            if positive:
                need(row.get("returncode") == 0 and row.get("waited_and_reaped") is True
                     and row.get(process_key) is True and row.get("owned_process_group_absent") is True
                     and row.get("cleanup_error") is None
                     and ("passed" not in row or row["passed"] is True),
                     "positive original stage custody did not close")
        if positive:
            need(len(rows) == len(expected_names), "positive original stage inventory is incomplete")
        return [r["name"] for r in rows]

    def source_and_binary_bindings(parent, inputs, directory):
        snapshot = get_json(directory / "source-inputs.json")
        need(snapshot["root"] == str(SOURCE) and snapshot["file_count"] == 221
             and {name: pin["sha256"] for name, pin in snapshot["files"].items()} == source_map
             and snapshot["sha256"] == parent["source_inputs_sha256"] == inputs["source_inputs_sha256"],
             "campaign source snapshot is not the actual qualified candidate")
        same(directory / "source-inputs.json", parent["source_inputs"])
        same(directory / "baseline-source-inputs.json", parent["baseline_source_inputs"])
        for name, pin in qualification["binaries"].items():
            need({k: parent["binaries"]["B"][name][k] for k in ("path", "sha256")} ==
                 {k: pin[k] for k in ("path", "sha256")}, "campaign used a different qualified candidate")
            need({k: parent["binaries"]["B"][name][k] for k in ("bytes", "sha256")} ==
                 inputs["candidate_binaries"][name], "campaign candidate size or input hash differs")
        need(parent["binaries"]["A"]["hepta-runtime"]["sha256"] == BASELINE_RUNTIME_SHA256,
             "accepted R24 baseline runtime differs")

    for pathname, pin in FROZEN_INSTALLED_ASSETS.items():
        same(Path(pathname), pin)
    installation = get_json(ROOT / "tools-install-01-receipt.json")
    same(ROOT / "tools-install-01-receipt.json", INSTALL_RECEIPT_PIN)
    need(installation["installed"] is True and installation["installed_file_count"] == 50
         and len(installation["files"]) == 50 and installation["all_files_and_archives_rehashed"] is True
         and {r["path"]: {k: r[k] for k in ("bytes", "sha256")} for r in installation["files"]} == FROZEN_INSTALLED_ASSETS,
         "original 50 installed acceptance assets differ")
    for pathname, expected in FIXED_SUPPORT_SHAS.items():
        same(Path(pathname), {"sha256": expected})
    boundary_present = any(path.startswith(str(ROOT / "boundary-tools-01") + "/") for path in identities)
    if boundary_present:
        for name, expected in BOUNDARY_SHAS.items():
            same(ROOT / "boundary-tools-01" / name, {"sha256": expected})
    for pathname, pin in QUALIFICATION_REFERENCES.items():
        same(Path(pathname), pin)
    qualification = get_json(ROOT / "qualification-01/report.json")
    prep = get_json(ROOT / "preparation-01.json")
    source_map = get_json(ROOT / "qualification-01/source-map.json")
    need(qualification["qualified"] is True and qualification["source"] == str(SOURCE)
         and len(source_map) == 221 and source_map == qualification["source_after"] == qualification["source_tested"] == prep["source_tested"]
         and prep["candidate_qualified"] is True and prep["selected_proposal"] == "shared unfiltered ToolRouter"
         and prep["optional_pidfd_selected"] is False,
         "actual qualified R29 source identity differs")
    input_value = get_json(INPUT)
    if input_value["known_original_summary"] is not None:
        same(ROOT / "campaign-01/summary.json", input_value["known_original_summary"])
    results = {}
    for name in STAGES:
        row, outcome = declarations[name], outcomes[name]
        result = {"executed": row["executed"], "original_bindings_verified": False,
                  "completed_positive_original_verified": False}
        results[name] = result
        if not row["executed"]:
            result.update(unexecuted_original_retained=True, success_inferred=False)
            continue
        parent = maybe(REPORT_PATHS[name])
        result["original_report_present"] = parent is not None
        result["original_report_structured_object"] = isinstance(parent, dict)
        if not isinstance(parent, dict):
            result["binding_error"] = {"type": "OriginalReportUnavailable", "reason": "absent, malformed or nonobject original retained"}
            continue
        positive = outcome["original_positive_report_and_closed_native"]
        try:
            directory = REPORT_PATHS[name].parent
            input_path = ROOT / ("campaign-inputs-01.json" if name == "observation01" else "lifecycle-inputs-01.json")
            parent_path = ROOT / "tools-01" / ("r29_campaign.py" if name == "observation01" else "r29_lifecycle_campaign.py")
            need(parent["schema"] == REPORT_SCHEMAS[name]
                 and parent["launcher_sha256"] == FROZEN_INSTALLED_ASSETS[str(parent_path)]["sha256"],
                 "original source-bound campaign parent differs")
            inputs = get_json(input_path)
            need(inputs["launcher_sha256"] == parent["launcher_sha256"] and inputs["attempt"] == "01",
                 "original campaign input/holder source differs")
            same(input_path, parent["input_receipt"])
            same(directory / "inputs.json", parent["input_receipt"] | {"path": str(directory / "inputs.json")})
            need(parent["automatic_retries"] == 0 and parent["production_services_modified"] is False,
                 "original campaign was retried or changed production")
            expected = OBSERVATION_STAGES if name == "observation01" else LIFECYCLE_STAGES
            result["entered_stages"] = stage_streams(parent, directory, expected, positive)
            if positive:
                need(all(parent.get(k) is True for k in ("inputs_unchanged", "source_inputs_unchanged", "baseline_source_inputs_unchanged")),
                     "positive original lacks final source/input preservation")
                source_and_binary_bindings(parent, inputs, directory)
            if name == "observation01":
                summary = maybe(ROOT / "campaign-01/summary.json")
                result["original_observation_gate_passed"] = parent.get("observation_gate_passed")
                result["original_rejection_reasons"] = parent.get("rejection_reasons")
                if isinstance(summary, dict):
                    need(summary["schema"] == "hepta-r25-observation-gates/v1" and summary["thresholds"] == FROZEN_GATES,
                         "original observation summary thresholds/schema differ")
                    result["original_summary_gate_passed"] = summary.get("observation_gate_passed")
                    result["original_summary_rejection_reasons"] = summary.get("rejection_reasons")
                    for record in summary.get("evidence", {}).values():
                        path = Path(record["path"])
                        need(path.is_relative_to(ROOT / "campaign-01") or path.is_relative_to(RECOVERY),
                             "original summary evidence escaped fixed scope")
                        same(path, record)
                if positive:
                    need(isinstance(summary, dict) and all(parent.get(k) is True for k in
                         ("correctness_stages_completed", "baseline_enablement_verified"))
                         and summary["evidence_verified"] is True and summary["correctness_verified"] is True
                         and type(summary["observation_gate_passed"]) is bool
                         and parent["observation_gate_passed"] is summary["observation_gate_passed"]
                         and parent["rejection_reasons"] == summary["rejection_reasons"]
                         and parent["thresholds"] == FROZEN_GATES,
                         "completed observation result/summary consistency differs")
                    same(ROOT / "campaign-01/summary.json", parent["summary"])
                    need(summary["binary_sha256"]["B"] == qualification["binaries"]["hepta-runtime"]["sha256"]
                         and summary["binary_sha256"]["A"] == BASELINE_RUNTIME_SHA256,
                         "original summary A/B identities differ")
                    if summary["observation_gate_passed"]:
                        need(summary["performance_gates_passed"] is True and summary["rejection_reasons"] == [],
                             "positive observation summary has an original rejection")
            else:
                result["saturation_stage_entered"] = "cancel-saturation" in result["entered_stages"]
                result["saturation_audit_stage_entered"] = "audit-cancel-saturation" in result["entered_stages"]
                normal = maybe(ROOT / "lifecycle-abba-01/report.json")
                index = maybe(ROOT / "lifecycle-abba-01/round-index.json")
                gates = maybe(ROOT / "lifecycle-abba-01/gates.json")
                descriptive = maybe(ROOT / "lifecycle-abba-01/summary.json")
                if isinstance(normal, dict):
                    need(normal["schema"] == "hepta-r25-lifecycle-abba-control/v1"
                         and normal["automatic_retries"] == 0 and normal["order"] == "ABBA",
                         "original normal lifecycle schema/order/retries differ")
                    same(ROOT / "lifecycle-tools-01/lifecycle-tools-manifest-01.json", normal["tools_manifest"])
                    need(normal["baseline"] == parent["binaries"]["A"]["hepta-runtime"]
                         and normal["candidate"] == parent["binaries"]["B"]["hepta-runtime"],
                         "original normal lifecycle A/B artifacts differ from its parent")
                    stage_streams(normal, ROOT / "lifecycle-abba-01", NORMAL_STAGES, positive, "proc_absent")
                    for key, filename in (("plan", "plan.json"), ("round_index", "round-index.json"),
                                          ("summary", "summary.json"), ("normal_lifecycle_gates", "gates.json")):
                        if key in normal:
                            same(ROOT / "lifecycle-abba-01" / filename, normal[key])
                if isinstance(index, dict):
                    need(index["schema"] == "hepta-r25-lifecycle-round-index/v1" and index["closed"] is True
                         and index["order"] == "ABBA" and index["round_count"] == 4 and len(index["rounds"]) == 4
                         and index["automatic_retries"] == 0, "original ABBA round index is not complete")
                    if isinstance(normal, dict):
                        need(all(index[key] == normal[key] for key in ("rounds", "baseline", "candidate", "tools_manifest", "plan")),
                             "original normal/index round or input inventory differs")
                    for number, arm in enumerate("ABBA"):
                        item = index["rounds"][number]
                        round_dir = ROOT / "lifecycle-abba-01" / f"round-{number}-{arm}"
                        need(item["index"] == number and item["arm"] == arm and item["directory"] == round_dir.name,
                             "original round path/order differs")
                        raw_identity = same(round_dir / "report.json", item["report"])
                        same(round_dir / "independent-summary.json", item["independent_analysis"])
                        raw, audit = get_json(round_dir / "report.json"), get_json(round_dir / "independent-summary.json")
                        expected_sha = BASELINE_RUNTIME_SHA256 if arm == "A" else qualification["binaries"]["hepta-runtime"]["sha256"]
                        need(raw["passed"] is True and audit["verified"] is True
                             and raw["candidate_sha256"] == audit["candidate_sha256"] == expected_sha
                             and audit["source_sha256"] == raw_identity["sha256"] and audit["source_bytes"] == raw_identity["bytes"]
                             and raw["automatic_rpc_retries"] == audit["automatic_rpc_retries"] == 0,
                             "original lifecycle raw report/audit binding differs")
                        need(len(item["phase_files"]) == 11 and {Path(p["path"]).name for p in item["phase_files"]} ==
                             {"phase-" + phase + ".json" for phase in LIFECYCLE_PHASES}, "original phase inventory differs")
                        for pin in item["phase_files"]:
                            same(round_dir / Path(pin["path"]).name, pin)
                    if isinstance(descriptive, dict):
                        need(descriptive["verified"] is True and descriptive["round_index_sha256"] ==
                             identities[str(ROOT / "lifecycle-abba-01/round-index.json")]["sha256"],
                             "original descriptive lifecycle summary index differs")
                if isinstance(gates, dict):
                    need(gates["schema"] == "hepta-r25-lifecycle-gates/v1" and gates["verified"] is True,
                         "original normal lifecycle gate schema differs")
                    same(ROOT / "lifecycle-abba-01/round-index.json", gates["round_index"])
                    same(ROOT / "lifecycle-tools-01/lifecycle-gate-policy.json", gates["gate_policy"])
                    result["original_normal_lifecycle_gate_passed"] = gates["passed"]
                saturation = maybe(ROOT / "cancel-saturation-01/report.json")
                independent = maybe(ROOT / "cancel-saturation-01/independent-summary.json")
                if isinstance(independent, dict):
                    pin = identities[str(ROOT / "cancel-saturation-01/report.json")]
                    need(independent["source_sha256"] == pin["sha256"] and independent["source_bytes"] == pin["bytes"],
                         "original saturation independent source differs")
                    result["original_saturation_independently_verified"] = independent.get("verified")
                if positive:
                    obs = get_json(REPORT_PATHS["observation01"])
                    need(results["observation01"]["completed_positive_original_verified"] is True
                         and obs["observation_gate_passed"] is True
                         and monitors["observation01"]["independently_validated"] is True,
                         "positive lifecycle lacks a completed valid observation")
                    same(REPORT_PATHS["observation01"], inputs["observation_campaign"])
                    need(parent["binaries"] == obs["binaries"] and parent["source_inputs_sha256"] == obs["source_inputs_sha256"]
                         and parent["baseline_source_inputs_sha256"] == obs["baseline_source_inputs_sha256"]
                         and parent["observation_gate_verified"] is True and parent["adoption_passed"] is True,
                         "positive lifecycle candidate/observation/adoption binding differs")
                    tests = get_json(ROOT / "lifecycle-tool-tests-01/report.json")
                    need(tests["passed"] is True and tests["tests_run"] == 14
                         and tests["skipped"] == tests["errors"] == tests["failures"] == 0,
                         "the original 14 native harness tests did not all pass")
                    need(isinstance(normal, dict) and normal["passed"] is True and normal["inputs_unchanged"] is True
                         and isinstance(gates, dict) and gates["passed"] is True
                         and isinstance(index, dict) and isinstance(descriptive, dict),
                         "positive original lifecycle lacks complete normal gates")
                    need(isinstance(saturation, dict) and saturation["passed"] is True
                         and isinstance(independent, dict) and independent["verified"] is True
                         and independent["candidate_sha256"] == qualification["binaries"]["hepta-runtime"]["sha256"]
                         and independent["saturation_verification"]["verified"] is True
                         and independent["saturation_verification"]["retired_after_drain_before_restart"] is True,
                         "positive lifecycle lacks the original real saturation proof")
                    same(ROOT / "lifecycle-abba-01/gates.json", parent["normal_lifecycle_gate"])
                    same(ROOT / "cancel-saturation-01/independent-summary.json", parent["saturation_analysis"])
            result["original_bindings_verified"] = True
            result["completed_positive_original_verified"] = bool(positive)
        except (KeyError, TypeError, ValueError, RuntimeError, OSError) as error:
            result["binding_error"] = {"type": type(error).__name__, "reason": str(error)}
    return {"installed_acceptance_assets": 50, "qualified_source_identity_files": 221,
            "canonical_preparation_validator_sha256": CANONICAL_PREPARATION_VALIDATOR_SHA256,
            "canonical_reaudited_here": False,
            "qualified_source_full_bodies_and_tests_in_separate_companion": True,
            "campaigns": results, "original_native_holder_success_is_not_performance_adoption": True,
            "thresholds_modified": False, "tests_or_workloads_reexecuted": False}


def disposition(outcomes, monitors, bindings):
    obs, life = outcomes["observation01"], outcomes["lifecycle01"]
    observation = bindings["campaigns"]["observation01"]
    if observation.get("completed_positive_original_verified") is not True:
        return "observation_failed_incomplete_or_binding_invalid_original_retained"
    if monitors["observation01"].get("independently_validated") is not True or obs["original_report"].get("measurement_attribution_valid") is not True:
        return "observation_measurement_invalid_original_retained"
    if obs["original_report"].get("observation_gate_passed") is False:
        return "observation_rejected_original_retained_lifecycle_unrun" if not life["executed"] else "observation_rejected_lifecycle_execution_discrepancy_retained"
    if not life["executed"]:
        return "observation_passed_lifecycle_unrun_no_adoption"
    lifecycle = bindings["campaigns"]["lifecycle01"]
    if lifecycle.get("completed_positive_original_verified") is not True:
        return "lifecycle_failed_incomplete_or_rejected_original_retained"
    if monitors["lifecycle01"].get("independently_validated") is not True or life["original_report"].get("measurement_attribution_valid") is not True:
        return "lifecycle_measurement_invalid_original_retained"
    return "original_observation_lifecycle_saturation_passed_external_custody_and_QC_still_required"

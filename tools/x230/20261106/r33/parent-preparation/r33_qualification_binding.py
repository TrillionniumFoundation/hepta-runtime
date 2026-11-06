R33_BASELINE_COMMIT = "baab4def80be7af015b2e7a594cb302f66c4130e"
R33_CHANGED_PATHS = {"src/mcp/runtime/ssh_observation_profile.rs",
                     "src/mcp/runtime/ssh_observation_profile_tests.rs"}
R33_QUALIFICATION_STAGES = ["format", "fmt-check", "harness-tests", "clippy",
    "test-build", "isolated-tests", "audit-isolated-tests", "release"]
R33_BASELINE_QUALIFICATION = {
    "path": "/home/qian/hepta-runtime-optimization-20261105-r24/qualification-01/report.json",
    "bytes": 83365,
    "sha256": "bf0c5814d28b163e4a90405026cd4d90e399370d1f910f8ac48cb580af1e4971",
}
R33_ADOPTION_SCOPE = "accepted R24 plus peekable traversal and immutable CString path components only"
R33_OPEN_BLOCKERS = [{
    "id": "saturated-cancellation-capacity",
    "status": "open",
    "scope": "not included in the R33 source change or normal lifecycle adoption",
    "reason": "R33 does not add cancellation reserve capacity; no saturated cancellation proof is claimed",
}]


def verify_r33_terminal(terminal, job_id):
    """Keep the original native job's complete terminal/log requirements."""
    need(isinstance(job_id, str) and re.fullmatch(r"[0-9a-f]{11,16}-[0-9a-f]{4}-[0-9a-f]{4}", job_id),
         "actual original R33 qualification job identity required")
    need(terminal.get("job_id") == job_id and terminal.get("state") == "succeeded"
         and type(terminal.get("exit_code")) is int and terminal["exit_code"] == 0
         and all(terminal.get(key) is False for key in ("automatic_retry", "timed_out", "cancelled"))
         and all(terminal.get(key) is True for key in ("output_complete", "output_durable", "terminal_publication_confirmed"))
         and type(terminal.get("terminal_publication_protocol")) is int and terminal["terminal_publication_protocol"] == 1
         and terminal.get("log_synced") == {"stdout": True, "stderr": True}
         and terminal.get("log_errors") == {"stdout": None, "stderr": None}
         and terminal.get("log_truncated") == {"stdout": False, "stderr": False},
         "original R33 qualification has no complete successful native terminal proof")
    for stream in ("stdout", "stderr"):
        counts = terminal["log_bytes"][stream]
        need(set(counts) == {"seen", "stored"}
             and all(type(value) is int and value >= 0 for value in counts.values())
             and counts["seen"] == counts["stored"], "qualification native log byte custody differs")


def verify_r33_candidate_documents(preparation, terminal, job_id, qualified, tests,
                                   audit, build_inputs, baseline, source_map):
    """Check the R24 ablation and the qualifier's pre/post-format custody."""
    verify_r33_terminal(terminal, job_id)
    need(preparation["schema"] == "hepta-x230-r33-preparation/v1"
         and preparation.get("passed") is True and preparation.get("finished_utc")
         and "error" not in preparation
         and type(preparation.get("qualification_returncode")) is int
         and preparation["qualification_returncode"] == 0
         and type(preparation.get("automatic_retries")) is int and preparation["automatic_retries"] == 0
         and preparation.get("production_services_modified") is False
         and preparation.get("source_baseline") == R33_BASELINE_COMMIT
         and preparation.get("proposal") == "R24 plus R32 peekable traversal and R33 cached CString components; two profile files only",
         "actual R33 preparation did not close successfully for the selected ablation")
    expected_command = ["/usr/bin/python3", "-B", "-u", str(SOURCE / "tools/x230/20261028/qualify.py"),
        "--source", str(SOURCE), "--output", str(CANDIDATE_DIR), "--target", str(ROOT / "target-build"),
        "--cargo-home", "/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02", "--jobs", "2"]
    need(preparation["qualification_command"] == expected_command,
         "the original eight-gate qualifier command differs")
    need(preparation.get("cache_transferred_by_rename") is True
         and type(preparation.get("new_full_cache_copy_bytes")) is int
         and preparation["new_full_cache_copy_bytes"] == 0
         and type(preparation.get("cache_deletions")) is int and preparation["cache_deletions"] == 0
         and preparation.get("cache_to_transfer") == str(R33_CACHE_OWNER / "target-build")
         and preparation.get("first_actual_r33_qualification_required") is True
         and preparation.get("qualification_started") is True
         and preparation.get("free_bytes_before", -1) >= 3 * 1024 ** 3
         and preparation["process_check"]["matched_processes"] == []
         and preparation["process_check"]["compiler_processes"] == [],
         "R33 preparation cache/free-space receipt is incomplete")
    need(build_inputs["schema"] == "hepta-r33-direct-qualification-input/v1"
         and build_inputs["baseline_commit"] == build_inputs["git_parent"] == R33_BASELINE_COMMIT
         and build_inputs["patch_file"] == "combined.patch"
         and build_inputs["added_paths"] == build_inputs["removed_paths"] == []
         and set(build_inputs["changed_paths"]) == R33_CHANGED_PATHS
         and all(build_inputs[key] is False for key in ("r31_pidfd_mixed_in", "cancel_reserve_mixed_in",
                                                       "router_mixed_in", "json_deferral_mixed_in"))
         and HEX.fullmatch(build_inputs["patch_sha256"]), "R33 source input receipt differs")
    before = build_inputs["baseline_compile_inputs"]
    candidate = build_inputs["candidate_compile_inputs"]
    need(isinstance(before, dict) and before and isinstance(candidate, dict)
         and set(before) == set(candidate)
         and all(isinstance(value, str) and HEX.fullmatch(value) for value in before.values())
         and all(isinstance(value, str) and HEX.fullmatch(value) for value in candidate.values())
         and {name for name in before if before[name] != candidate[name]} == R33_CHANGED_PATHS,
         "R33 must change only the selected profile source and tests from R24")
    need(baseline["schema"] == "hepta-x230-composed-qualification/v1"
         and baseline.get("qualified") is True and baseline.get("finished_utc")
         and baseline["source"] == str(BASELINE_ROOT / "source")
         and baseline["source_tested"] == baseline["source_after"] == before,
         "R33 input preimage is not the actual accepted R24 qualification")
    need(qualified["schema"] == "hepta-x230-composed-qualification/v1"
         and qualified.get("qualified") is True and qualified.get("finished_utc")
         and "error" not in qualified and qualified["source"] == str(SOURCE)
         and type(qualified["jobs"]) is int and qualified["jobs"] == 2
         and type(qualified["automatic_test_retries"]) is int and qualified["automatic_test_retries"] == 0
         and qualified["service_changes"] is False,
         "actual R33 composed qualification is incomplete or used another configuration")
    stages = qualified["stages"]
    need([row["name"] for row in stages] == R33_QUALIFICATION_STAGES
         and all(type(row.get("returncode")) is int and row["returncode"] == 0
                 and isinstance(row.get("command"), list) and row["command"]
                 and HEX.fullmatch(row["stdout_sha256"]) and HEX.fullmatch(row["stderr_sha256"])
                 for row in stages), "all eight original R33 qualification stages must pass once")
    need(preparation["source_before_qualification"] == candidate == qualified["source_input"],
         "R33 pre-format compilation inputs differ from the reviewed patch input")
    final_map = qualified["source_after"]
    need(preparation["source_after_qualification"] == qualified["source_tested"] == final_map == source_map
         and set(final_map) == set(before)
         and {name for name in before if final_map[name] != before[name]} == R33_CHANGED_PATHS,
         "R33 final tested source does not preserve the two-file R24 ablation")
    need(qualified["harness_before"] == qualified["harness_after"]
         == baseline["harness_before"] == baseline["harness_after"]
         == build_inputs["qualification_harness_sha256"]
         and qualified["harness_after"].get("qualify.py")
         == "95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d",
         "the original qualification harness differs from accepted R24")
    need(set(qualified["binaries"]) == set(BINARY_NAMES)
         and all(row["path"] == str(CANDIDATE_DIR / name) and HEX.fullmatch(row["sha256"])
                 for name, row in qualified["binaries"].items()), "qualification runtime copy identities differ")
    need(tests["schema"] == "hepta-isolated-libtest/v1" and tests.get("success") is True
         and tests.get("filter") == "" and type(tests.get("retries")) is int
         and tests["retries"] == 0 and tests.get("failed") == 0
         and tests.get("enumeration_errors") == [] and not tests.get("fatal_error"),
         "the complete original isolated test inventory did not pass without retry")
    counts = {name: tests[name] for name in ("passed", "failed", "ignored", "selected")}
    need(all(type(value) is int and value >= 0 for value in counts.values())
         and counts["passed"] > 0
         and counts["selected"] == counts["passed"] + counts["failed"] + counts["ignored"],
         "isolated inventory counts do not reconcile")
    need(audit["schema"] == "hepta-isolated-libtest-audit/v1" and audit.get("success") is True
         and audit.get("expected_filter") == "" and audit.get("errors") == [] and not audit.get("fatal_error")
         and audit.get("evidence") == str(CANDIDATE_DIR / "isolated-tests")
         and audit["auditor_sha256"] == qualified["harness_after"]["audit_isolated_tests.py"]
         and all(audit[name] == value for name, value in counts.items())
         and audit["executed"] == counts["passed"] + counts["failed"],
         "original independent isolated test audit does not match the full successful inventory")
    need(audit["binaries"] and all(row["recorded_before_sha256"] == row["current_after_sha256"]
         and HEX.fullmatch(row["current_after_sha256"]) for row in audit["binaries"]),
         "the original test auditor did not verify test executable custody")
    return {"passed": True, "original_job_id": job_id,
        "selected_proposal": "peekable traversal and immutable CString path components on accepted R24",
        "source_baseline_commit": R33_BASELINE_COMMIT,
        "qualified_source_files": len(final_map), "harness_files": len(qualified["harness_after"]),
        "changed_paths": sorted(R33_CHANGED_PATHS), "stages": R33_QUALIFICATION_STAGES,
        "tests": dict(counts, retries=0), "candidate_adopted": False,
        "adoption_scope": R33_ADOPTION_SCOPE, "saturated_cancellation_verified": False,
        "open_blockers": R33_OPEN_BLOCKERS}


def bind_r33_candidate_preparation(inputs, bind):
    """Bind actual R33 documents with the parent's stable file reader."""
    def document(path, expected=None):
        identity, raw = bind(path, expected, retain=True)
        return identity, json.loads(raw)

    fixed = {"qualification_launcher": ROOT / "prepare_qualify.py",
             "qualification_input": ROOT / "input.json",
             "candidate_patch": ROOT / "combined.patch"}
    for name, path in fixed.items():
        need(inputs[name]["path"] == str(path), "R33 qualification input path differs: " + name)
    launcher_id = bind(fixed["qualification_launcher"], inputs["qualification_launcher"])
    input_id, build_inputs = document(fixed["qualification_input"], inputs["qualification_input"])
    patch_id = bind(fixed["candidate_patch"], inputs["candidate_patch"])
    need(patch_id["sha256"] == build_inputs["patch_sha256"], "reviewed R33 patch bytes differ")
    preparation_pin, terminal_pin = inputs["qualification_preparation"], inputs["qualification_terminal_status"]
    reports = inputs.get("qualification_reports", [inputs.get("qualification_report")])
    need(preparation_pin["path"] == str(ROOT / "preparation.json")
         and terminal_pin["path"] == str(ROOT / "qualification-terminal-status-01.json")
         and len(reports) == 1 and reports[0]["path"] == str(CANDIDATE_DIR / "report.json"),
         "qualification receipts must identify the fresh R33 attempt")
    prep_id, preparation = document(preparation_pin["path"], preparation_pin)
    terminal_id, terminal = document(terminal_pin["path"], terminal_pin)
    qualified_id, qualified = document(reports[0]["path"], reports[0])
    baseline_id, baseline = document(R33_BASELINE_QUALIFICATION["path"], R33_BASELINE_QUALIFICATION)
    source_map_id, source_map = document(CANDIDATE_DIR / "source-map.json")
    test_id, tests = document(CANDIDATE_DIR / "isolated-tests/summary.json")
    audit_id, audit = document(CANDIDATE_DIR / "isolated-tests.audit.json")
    proof = verify_r33_candidate_documents(preparation, terminal, terminal_pin["job_id"], qualified,
        tests, audit, build_inputs, baseline, source_map)
    need(preparation["input_binding"] == input_id
         and preparation["combined_patch"] == patch_id
         and preparation["qualification_report_sha256"] == qualified_id["sha256"]
         and preparation["baseline_qualification"] == build_inputs["baseline_qualification"]
         == R33_BASELINE_QUALIFICATION
         and preparation["qualification_harness_sha256"] == build_inputs["qualification_harness_sha256"],
         "R33 preparation is not bound to the actual reviewed inputs and qualification")
    proof["source_chain_and_cache_owner"] = bind_r33_chain_and_cache_owner(preparation, build_inputs, bind)
    current = source_inputs(SOURCE)
    need(qualification_projection(current) == source_map, "current R33 source differs from the actually tested source map")
    baseline_current = source_inputs(BASELINE_ROOT / "source")
    need(set(current["files"]) == set(baseline_current["files"])
         and {name for name in current["files"] if current["files"][name] != baseline_current["files"][name]}
         == R33_CHANGED_PATHS,
         "R33 changed additional build/config/source inputs outside the selected profile files")
    harness = SOURCE / "tools/x230/20261028"
    need({path.name for path in harness.glob("*.py")} == set(qualified["harness_after"]),
         "the qualified Python harness file set changed")
    for name, expected_sha in qualified["harness_after"].items():
        need(Path(name).name == name, "unsafe qualification harness member")
        bind(harness / name, expected_sha)
    for stage in qualified["stages"]:
        name = stage["name"]
        bind(CANDIDATE_DIR / ("cargo-no-run.jsonl" if name == "test-build" else name + ".stdout"), stage["stdout_sha256"])
        bind(CANDIDATE_DIR / (name + ".stderr"), stage["stderr_sha256"])
    isolated_inputs = {"summary.json", "cargo-artifacts.jsonl", "source-manifest.input", "commands.jsonl", "tests.jsonl"}
    need(set(audit["input_sha256"]) == isolated_inputs,
         "original independent test audit is missing input identities")
    for name, expected_sha in audit["input_sha256"].items():
        bind(CANDIDATE_DIR / "isolated-tests" / name, expected_sha)
    need(audit["input_sha256"]["summary.json"] == test_id["sha256"]
         and audit["input_sha256"]["source-manifest.input"] == source_map_id["sha256"]
         == tests["source_manifest_sha256"], "the isolated test inventory binds another source manifest")
    proof.update(preparation=prep_id, terminal=terminal_id, qualification=qualified_id,
        qualification_launcher=launcher_id, qualification_input=input_id, candidate_patch=patch_id,
        baseline_qualification=baseline_id, isolated_summary=test_id, isolated_audit=audit_id,
        source_map=source_map_id, full_source_inputs_sha256=current["sha256"],
        baseline_full_source_inputs_sha256=baseline_current["sha256"],
        original_auditor_scope="the unchanged qualifier audited the complete inventory and compressed case logs")
    return proof



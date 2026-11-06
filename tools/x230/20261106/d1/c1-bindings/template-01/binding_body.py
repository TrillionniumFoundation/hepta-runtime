def need(value, message):
    if not value:
        raise RuntimeError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def _identity(value, path=None):
    need(isinstance(value, dict) and {"path", "bytes", "sha256"} <= set(value),
         "an actual file identity is required")
    need(isinstance(value["path"], str) and Path(value["path"]).is_absolute()
         and type(value["bytes"]) is int and value["bytes"] >= 0
         and isinstance(value["sha256"], str) and HEX.fullmatch(value["sha256"]),
         "invalid original file identity")
    result = {key: value[key] for key in ("path", "bytes", "sha256")}
    if path is not None:
        need(result["path"] == str(path), "original file path differs: " + str(path))
    return result


def _declared(value, bind, maximum=8 * 1024 * 1024, retain=False):
    pin = _identity(value)
    path = Path(pin["path"])
    need(any(path.is_relative_to(root) for root in (ROOT, BASE, CACHE_OWNER, NEXTEST_ROOT)),
         "input lies outside the fixed experiment or original nextest roots")
    result = bind(path, pin, maximum=maximum, retain=retain)
    identity = result[0] if retain else result
    need(identity == pin, "stable reader returned another identity")
    return result


def _artifact(prerequisites, name, bind, retain=False, maximum=8 * 1024 * 1024):
    need(name in prerequisites["artifact_map"], "required artifact identity is absent: " + name)
    pin = _identity(prerequisites["artifact_map"][name], ROOT / name)
    if name in PINNED:
        need(pin == PINNED[name], "frozen preparation input differs: " + name)
    return _declared(pin, bind, maximum=maximum, retain=retain)


def _document(prerequisites, name, bind):
    identity, raw = _artifact(prerequisites, name, bind, retain=True)
    value = json.loads(raw)
    need(isinstance(value, dict), "expected an original JSON object: " + name)
    return identity, value


def _foundation(prerequisites, require_ci=False):
    need(not sys.flags.optimize, "original assertion-based receipt helpers require normal Python execution")
    need(isinstance(prerequisites, dict)
         and prerequisites.get("schema") == "hepta-d1-c1-prerequisites/v1"
         and prerequisites.get("qualification_sealed") is True,
         "actual D1 qualification prerequisites are not sealed")
    need(prerequisites.get("required_missing_qualification_bindings") == [],
         "qualification prerequisite identities remain missing")
    need(isinstance(prerequisites.get("artifact_map"), dict)
         and set(prerequisites["artifact_map"]) == set(PINNED) | set(QUALIFICATION_ARTIFACTS) | set(CI_ARTIFACTS),
         "the fixed prerequisite artifact map differs")
    for name in (*PINNED, *QUALIFICATION_ARTIFACTS):
        _identity(prerequisites["artifact_map"][name], ROOT / name)
    job = prerequisites.get("qualification_original_job_id")
    need(isinstance(job, str) and JOB.fullmatch(job), "actual D1 qualification job identity is required")
    need(prerequisites.get("performance_acceptance_claim") is False,
         "diagnostic prerequisites must not claim performance adoption")
    if require_ci:
        need(prerequisites.get("exact_ci_sealed") is True
             and prerequisites.get("required_missing_exact_ci_bindings") == [],
             "actual D1 exact-CI prerequisites are not sealed")
        ci_job = prerequisites.get("exact_ci_original_job_id")
        need(isinstance(ci_job, str) and JOB.fullmatch(ci_job) and ci_job != job,
             "a distinct actual exact-CI job identity is required")
        for name in CI_ARTIFACTS:
            _identity(prerequisites["artifact_map"][name], ROOT / name)


def _native(prerequisites, prefix, terminal, bind):
    job_key = "qualification_original_job_id" if prefix == "qualification" else "exact_ci_original_job_id"
    pages_key = "qualification_read_pages" if prefix == "qualification" else "exact_ci_read_pages"
    job = prerequisites[job_key]
    native_terminal(terminal, job)
    need(terminal.get("audit_recorded") is True, "native terminal audit receipt is missing")
    pages = prerequisites.get(pages_key)
    need(isinstance(pages, list) and 1 <= len(pages) <= 64,
         "complete original native read pages are required")
    basename = "qualification-native-read-01" if prefix == "qualification" else "rust-ci-native-read-01"
    names, originals, offsets = set(), [], {"stdout": 0, "stderr": 0}
    streams = {"stdout": [], "stderr": []}
    for number, pin in enumerate(pages):
        identity = _identity(pin)
        path = Path(identity["path"])
        need(path.parent == ROOT and
             re.fullmatch(re.escape(basename) + r"(?:-[0-9]{3})?\.json", path.name) is not None
             and path.name not in names, "unsafe or repeated native read page")
        names.add(path.name)
        actual, raw = _declared(identity, bind, maximum=256 * 1024, retain=True)
        value = json.loads(raw)
        need(value.get("job_id") == job and value.get("audit_recorded") is True,
             "native read page identifies another job")
        for stream in ("stdout", "stderr"):
            channel = value[stream]
            body = bytes.fromhex(channel["bytes_hex"])
            total = terminal["log_bytes"][stream]["stored"]
            need(type(total) is int and 0 <= total <= 1024 * 1024,
                 "native original stream exceeds the declared bound")
            need(type(channel["offset"]) is int and channel["offset"] == offsets[stream]
                 and channel["size"] == total and len(body) <= 16384
                 and channel["next_offset"] == offsets[stream] + len(body) <= total
                 and channel["text"] == body.decode("utf-8", errors="replace")
                 and channel["eof"] is (channel["next_offset"] == total),
                 "native original page has a gap, overlap, changed text or incorrect EOF")
            need(body or offsets[stream] == total, "native page made no progress")
            if number + 1 == len(pages):
                need(channel["eof"] is True, "the original native stream is incomplete")
            offsets[stream] = channel["next_offset"]
            streams[stream].append(body)
        originals.append(actual)
    result = {}
    for stream in streams:
        body = b"".join(streams[stream])
        need(len(body) == offsets[stream] == terminal["log_bytes"][stream]["stored"],
             "native page bytes do not reconcile with the original terminal")
        result[stream] = {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
    return {"job_id": job, "read_pages": originals, "streams": result,
            "complete_original_native_bytes_verified": True, "fabricated_combined_read": False}


def _source_inputs(source, bind):
    # Same complete input scope as the original R35 parent; only its reader is injected.
    need(source.is_absolute() and source.resolve() == source and source.is_dir(),
         "direct qualified source directory missing")
    paths = {source / "Cargo.toml", source / "Cargo.lock"}
    for relative in ("build.rs", "rustfmt.toml", "rust-toolchain", "rust-toolchain.toml", ".cargo/config", ".cargo/config.toml"):
        path = source / relative
        if os.path.lexists(path):
            paths.add(path)
    for relative in ("src", "examples"):
        root = source / relative
        need(root.is_dir() and root.resolve() == root, "source input subtree missing or indirect")
        for directory, subdirs, names in os.walk(root, followlinks=False):
            for name in subdirs:
                need(not (Path(directory) / name).is_symlink(), "symlinked source directory")
            paths.update(Path(directory) / name for name in names)
    files = {}
    for path in sorted(paths):
        identity = bind(path, maximum=16 * 1024 * 1024)
        files[path.relative_to(source).as_posix()] = {key: identity[key] for key in ("bytes", "sha256")}
    return {"root": str(source), "file_count": len(files), "files": files,
            "sha256": hashlib.sha256(canonical(files)).hexdigest(),
            "scope": "Cargo manifests, optional build/toolchain/config inputs, complete src and examples trees"}


def _previous_owner(prerequisites, preparation, build_inputs, bind):
    closure_id, closure = _document(prerequisites, "cache-owner-closure-inputs.json", bind)
    need(closure["schema"] == "hepta-d1-r35-cache-owner-closure/v1"
         and closure["sealed"] is True and closure["required_missing_bindings"] == []
         and closure["cache_owner"] == str(CACHE_OWNER)
         and closure["cache_path"] == str(CACHE_OWNER / "target-build"),
         "the sealed prior cache owner differs")
    need(preparation["cache_owner_closure_input"] == closure_id
         and build_inputs["owner_closure_input_sha256"] == closure_id["sha256"],
         "preparation does not bind the frozen cache-owner input")
    pins = closure["postflight"]
    report_id, report_raw = _declared(pins["report"], bind, retain=True)
    _, native_raw = _declared(pins["native"], bind, retain=True)
    page_raws = [_declared(pin, bind, retain=True)[1] for pin in pins["read_pages"]]
    postflight = postflight_bytes(report_raw, native_raw, page_raws, report_id)
    _declared(postflight["postflight_script"], bind)
    need(closure["inputs"] == postflight["originals"], "the actual old-owner original identity set differs")
    for identity in closure["inputs"].values():
        _declared(identity, bind)
    expected = {"inputs": closure["inputs"], "postflight": pins,
        "qualification_and_exact_ci_succeeded": True, "observation_performance_passed": True,
        "normal_lifecycle_executed": True, "normal_lifecycle_workflow_closed": True,
        "normal_lifecycle_controllers_closed": True, "normal_lifecycle_performance_passed": False,
        "original_required_failed_flags": postflight["normal_lifecycle_required_failed_flags"],
        "owned_agents_reaped": True, "original_auditors_reexecuted": False, "r35_adoption_claimed": False}
    need(preparation["cache_owner_closure"] == expected,
         "actual preparation did not record the frozen old-owner closure")
    need(preparation["cache_transferred_by_rename"] is True
         and preparation["new_full_cache_copy_bytes"] == 0 and preparation["cache_deletions"] == 0
         and preparation["cache_to_transfer"] == str(CACHE_OWNER / "target-build"),
         "the original cache transfer receipt differs")
    target = ROOT / "target-build"
    need(target.resolve() == target and target.is_dir() and not os.path.lexists(CACHE_OWNER / "target-build"),
         "the cache is not at its recorded post-rename location")
    status = target.stat()
    need((status.st_dev, status.st_ino) ==
         (postflight["cache_directory_identity"]["device"], postflight["cache_directory_identity"]["inode"]),
         "the current cache directory is not the original renamed directory")
    retained = preparation["retained_programs"]
    need(isinstance(retained, dict) and len(retained) >= 5
         and all(Path(name).is_relative_to(CACHE_OWNER / "qualification-01")
                 and isinstance(digest, str) and HEX.fullmatch(digest) for name, digest in retained.items()),
         "original retained program custody is incomplete")
    for identity in postflight["retained_release_programs"].values():
        need(retained.get(identity["path"]) == identity["sha256"], "the retained original release copy differs")
        _declared(identity, bind, maximum=64 * 1024 * 1024)
    return {"input": closure_id, "postflight": report_id, "postflight_job_id": OWNER_POSTFLIGHT_JOB,
        "original_identity_count": len(closure["inputs"]), "original_bytes_rebound": True,
        "old_preparer_cache_owner_closed_reexecuted": False,
        "current_cache_path": str(target), "cache_directory_identity_preserved": True,
        "prior_owner_performance_adopted": False, "old_auditors_reexecuted": False,
        "current_machine_idle_claimed": False,
        "retained_release_copies_rehashed": len(postflight["retained_release_programs"]),
        "retained_test_copies": "bound to the successful original preparation receipt; not rehashed by this later binder"}


def bind_d1_qualification(prerequisites, bind):
    """Read-only Q proof. This function does not require or inspect future CI success."""
    _foundation(prerequisites)
    for name in PINNED:
        _artifact(prerequisites, name, bind)
    launcher_id = _artifact(prerequisites, "prepare_qualify.py", bind)
    input_id, build_inputs = _document(prerequisites, "qualification-input.json", bind)
    patch_id = _artifact(prerequisites, "candidate/candidate.patch", bind)
    candidate_id, candidate = _document(prerequisites, "candidate/input.json", bind)
    manifest_id, candidate_manifest = _document(prerequisites, "candidate/package-manifest.json", bind)
    prep_id, preparation = _document(prerequisites, "preparation.json", bind)
    terminal_id, terminal = _document(prerequisites, "qualification-terminal-status-01.json", bind)
    qualified_id, qualified = _document(prerequisites, "qualification-01/report.json", bind)
    map_id, final_map = _document(prerequisites, "qualification-01/source-map.json", bind)
    test_id, tests = _document(prerequisites, "qualification-01/isolated-tests/summary.json", bind)
    audit_id, audit = _document(prerequisites, "qualification-01/isolated-tests.audit.json", bind)
    native = _native(prerequisites, "qualification", terminal, bind)
    baseline_id, baseline_raw = _declared(BASELINE_QUALIFICATION, bind, retain=True)
    baseline = json.loads(baseline_raw)
    need(build_inputs["schema"] == "hepta-d1-direct-qualification-input/v1"
         and build_inputs["sealed"] is True and build_inputs["required_missing_bindings"] == []
         and build_inputs["baseline_commit"] == build_inputs["source_construction_parent"] == BASELINE_COMMIT
         and build_inputs["preparation_tool"] == {"path": "prepare_qualify.py", "bytes": launcher_id["bytes"], "sha256": launcher_id["sha256"]},
         "frozen D1 qualification input differs")
    need(all(build_inputs[name] is None for name in ("actual_d1_qualification", "actual_d1_formatted_map",
         "actual_d1_test_counts", "actual_d1_release_programs")), "historical preparation inputs were rewritten with future results")
    need(candidate["schema"] == "hepta-r24-phase-cost-candidate/v1"
         and candidate["revision"] == candidate_manifest["revision"] == "recovery-02"
         and candidate["baseline_commit"] == candidate["git_parent"] == BASELINE_COMMIT
         and candidate_manifest["schema"] == "hepta-r24-phase-cost-preparation-package/v1"
         and candidate["nondefault_feature"] == "phase-cost-diagnostics"
         and candidate["performance_acceptance_claim"] is False
         and patch_id["sha256"] == candidate["patch_sha256"] and patch_id["bytes"] == candidate["patch_bytes"],
         "the frozen diagnostic candidate and patch do not bind")
    before, preformat = candidate["baseline_compile_inputs"], candidate["candidate_compile_inputs"]
    need(len(before) == 220 and len(preformat) == 222 and set(candidate["changed_paths"]) == CHANGED
         and set(candidate["added_paths"]) == ADDED
         and set(preformat) - set(before) == ADDED and not set(before) - set(preformat)
         and {name for name in preformat if preformat[name] != before.get(name)} == CHANGED,
         "D1 is not the exact thirteen-path/two-addition R24 patch")
    need(baseline["schema"] == "hepta-x230-composed-qualification/v1"
         and baseline.get("qualified") is True and baseline.get("finished_utc")
         and baseline["source"] == str(BASE / "source")
         and baseline["source_tested"] == baseline["source_after"] == before,
         "candidate preimage is not the accepted R24 qualification")
    need(preparation["schema"] == "hepta-x230-d1-preparation/v1"
         and preparation.get("passed") is True and preparation.get("finished_utc")
         and not preparation.get("error") and preparation["qualification_returncode"] == 0
         and preparation["automatic_retries"] == 0 and preparation["production_services_modified"] is False
         and preparation["source_baseline"] == BASELINE_COMMIT
         and preparation["performance_acceptance_claim"] is False
         and preparation["diagnostic_environment_absent"] is True
         and preparation["ordinary_supplemental_executed"] is False
         and preparation["qualification_started"] is True
         and preparation["first_actual_d1_qualification_required"] is True,
         "the actual D1 preparation did not close successfully")
    expected_command = ["/usr/bin/python3", "-B", "-u", str(SOURCE / "tools/x230/20261028/qualify.py"),
        "--source", str(SOURCE), "--output", str(QUALIFICATION), "--target", str(ROOT / "target-build"),
        "--cargo-home", str(CARGO_HOME), "--jobs", "2"]
    need(preparation["qualification_command"] == expected_command
         and preparation["free_bytes_before"] >= 3 * 1024 ** 3
         and preparation["process_check"]["matched_processes"] == []
         and preparation["process_check"]["compiler_processes"] == [],
         "the original qualifier command or preparation guards differ")
    need(preparation["input_binding"] == input_id and preparation["candidate_patch"] == patch_id
         and preparation["qualification_report_sha256"] == qualified_id["sha256"]
         and preparation["baseline_qualification"] == build_inputs["baseline_qualification"] == BASELINE_QUALIFICATION
         and preparation["frozen_candidate_input"] == candidate_id
         and preparation["frozen_candidate_manifest"] == manifest_id,
         "actual preparation does not bind the frozen input and result bytes")
    need(qualified["schema"] == "hepta-x230-composed-qualification/v1"
         and qualified.get("qualified") is True and qualified.get("finished_utc") and not qualified.get("error")
         and qualified["source"] == str(SOURCE) and qualified["jobs"] == 2
         and qualified["automatic_test_retries"] == 0 and qualified["service_changes"] is False,
         "the complete original D1 qualification did not pass")
    need([row["name"] for row in qualified["stages"]] == STAGES
         and all(type(row["returncode"]) is int and row["returncode"] == 0
                 and isinstance(row["command"], list) and row["command"]
                 and HEX.fullmatch(row["stdout_sha256"]) and HEX.fullmatch(row["stderr_sha256"])
                 for row in qualified["stages"]), "the original eight qualification stages differ")
    for row in qualified["stages"]:
        if row["name"] in {"clippy", "test-build", "release"}:
            need({"--all-features", "--offline", "--locked"} <= set(row["command"]),
                 "the original all-features/offline/locked qualification command changed")
    need(preparation["source_before_qualification"] == qualified["source_input"] == preformat
         and preparation["source_after_qualification"] == qualified["source_tested"] == qualified["source_after"] == final_map
         and set(final_map) == set(preformat)
         and {name for name in final_map if final_map[name] != before.get(name)} == CHANGED
         and final_map["Cargo.toml"] == preformat["Cargo.toml"]
         and sum(name.endswith(".py") for name in final_map) == 17,
         "actual formatter/tested source does not preserve the frozen diagnostic change")
    harness = qualified["harness_after"]
    need(len(harness) == 19 and qualified["harness_before"] == harness
         == baseline["harness_before"] == baseline["harness_after"]
         == build_inputs["qualification_harness_sha256"] == preparation["qualification_harness_sha256"]
         and harness["qualify.py"] == "95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d",
         "the original nineteen qualification harnesses changed")
    need(tests["schema"] == "hepta-isolated-libtest/v1" and tests.get("success") is True
         and tests.get("filter") == "" and tests.get("enumeration_errors") == []
         and not tests.get("fatal_error"), "the complete isolated test summary did not pass")
    counts = {name: tests[name] for name in COUNT_KEYS}
    need(all(type(value) is int and value >= 0 for value in counts.values())
         and counts["passed"] > 0 and counts["failed"] == counts["retries"] == 0
         and counts["selected"] == counts["passed"] + counts["ignored"],
         "actual isolated inventory counts do not reconcile without retries")
    need(audit["schema"] == "hepta-isolated-libtest-audit/v1"
         and audit.get("success") is True and audit.get("expected_filter") == ""
         and audit.get("errors") == [] and not audit.get("fatal_error")
         and audit["evidence"] == str(QUALIFICATION / "isolated-tests")
         and audit["auditor_sha256"] == harness["audit_isolated_tests.py"]
         and all(audit[name] == counts[name] for name in ("passed", "failed", "ignored", "selected"))
         and audit["executed"] == counts["passed"] + counts["failed"]
         and audit["binaries"]
         and all(row["recorded_before_sha256"] == row["current_after_sha256"]
                 and HEX.fullmatch(row["current_after_sha256"]) for row in audit["binaries"]),
         "the original full-inventory auditor did not verify the actual tests and executable custody")
    current, baseline_current = _source_inputs(SOURCE, bind), _source_inputs(BASE / "source", bind)
    need({name: row["sha256"] for name, row in current["files"].items()} == final_map
         and {name: row["sha256"] for name, row in baseline_current["files"].items()} == before
         and set(current["files"]) - set(baseline_current["files"]) == ADDED
         and not set(baseline_current["files"]) - set(current["files"])
         and {name for name in current["files"] if current["files"][name] != baseline_current["files"].get(name)} == CHANGED,
         "current full Cargo/config/source inputs differ from the actual qualified patch")
    harness_root = SOURCE / "tools/x230/20261028"
    need({path.name for path in harness_root.glob("*.py")} == set(harness), "current harness file set differs")
    for name, digest in harness.items():
        need(Path(name).name == name, "unsafe original harness name")
        bind(harness_root / name, digest, maximum=8 * 1024 * 1024)
    for stage in qualified["stages"]:
        name = stage["name"]
        bind(QUALIFICATION / ("cargo-no-run.jsonl" if name == "test-build" else name + ".stdout"),
             stage["stdout_sha256"], maximum=128 * 1024 * 1024)
        bind(QUALIFICATION / (name + ".stderr"), stage["stderr_sha256"], maximum=128 * 1024 * 1024)
    expected_isolated = {"summary.json", "cargo-artifacts.jsonl", "source-manifest.input", "commands.jsonl", "tests.jsonl"}
    need(set(audit["input_sha256"]) == expected_isolated, "original test-audit input identities differ")
    for name, digest in audit["input_sha256"].items():
        bind(QUALIFICATION / "isolated-tests" / name, digest, maximum=128 * 1024 * 1024)
    need(audit["input_sha256"]["summary.json"] == test_id["sha256"]
         and audit["input_sha256"]["source-manifest.input"] == map_id["sha256"] == tests["source_manifest_sha256"],
         "isolated inventory uses another original source map")
    need(set(qualified["binaries"]) == set(BINARY_NAMES), "qualified release binary set differs")
    binaries = {}
    for name in BINARY_NAMES:
        row = qualified["binaries"][name]
        need(row["path"] == str(QUALIFICATION / name) and HEX.fullmatch(row["sha256"]),
             "the original qualifier release-copy path/hash differs")
        # The unchanged qualifier records path/SHA only; byte length comes
        # from the parent's stable reader, never from a fabricated report key.
        binaries[name] = bind(QUALIFICATION / name, row["sha256"], maximum=128 * 1024 * 1024)
    owner = _previous_owner(prerequisites, preparation, build_inputs, bind)
    return {"passed": True, "original_job_id": prerequisites["qualification_original_job_id"],
        "tests": counts, "binaries": binaries, "source_tested": final_map,
        "candidate_inputs": {"changed_paths": sorted(CHANGED), "added_paths": sorted(ADDED),
                             "baseline_compile_inputs": before, "candidate_compile_inputs": preformat},
        "source_baseline_commit": BASELINE_COMMIT, "qualified_source_files": len(final_map),
        "harness_files": len(harness), "qualification_harness": harness, "stages": STAGES,
        "preparation": prep_id, "terminal": terminal_id, "qualification": qualified_id,
        "qualification_launcher": launcher_id, "qualification_input": input_id, "candidate_patch": patch_id,
        "baseline_qualification": baseline_id, "isolated_summary": test_id, "isolated_audit": audit_id,
        "source_map": map_id, "full_source_inputs_sha256": current["sha256"],
        "baseline_full_source_inputs_sha256": baseline_current["sha256"], "source_inputs": current,
        "native": native, "source_chain_and_cache_owner": owner,
        "qualified_release_kind": "original all-features diagnostic ELF; mode unset",
        "ordinary_supplemental_claimed": False, "performance_acceptance_claim": False,
        "original_auditors_reexecuted": False}


def qualification_legacy_inputs(prerequisites):
    """The six original materializer inputs, derived from the same frozen Q foundation."""
    _foundation(prerequisites)
    files = prerequisites["artifact_map"]
    terminal = dict(_identity(files["qualification-terminal-status-01.json"]),
                    job_id=prerequisites["qualification_original_job_id"])
    return {"qualification_launcher": _identity(files["prepare_qualify.py"]),
        "qualification_input": _identity(files["qualification-input.json"]),
        "candidate_patch": _identity(files["candidate/candidate.patch"]),
        "qualification_preparation": _identity(files["preparation.json"]),
        "qualification_terminal_status": terminal,
        "qualification_reports": [dict(_identity(files["qualification-01/report.json"]), success_field="qualified")]}


def bind_d1_prerequisites(prerequisites, bind):
    """Add actual native exact-CI closure to the Q-only proof; never launch CI."""
    _foundation(prerequisites, require_ci=True)
    qualification = bind_d1_qualification(prerequisites, bind)
    ci_id, ci = _document(prerequisites, "rust-ci-01/report.json", bind)
    plan_id, plan = _document(prerequisites, "rust-ci-plan-01.json", bind)
    audit_id, audit = _document(prerequisites, "rust-ci-01/nextest-output-audit.json", bind)
    terminal_id, terminal = _document(prerequisites, "rust-ci-native-01.json", bind)
    native = _native(prerequisites, "exact_ci", terminal, bind)
    need(ci["schema"] == "hepta-d1-external-rust-ci/v1" and ci.get("passed") is True
         and ci.get("finished_utc") and not ci.get("error")
         and ci["automatic_retries"] == 0 and ci["production_services_modified"] is False
         and ci["owned_children_closed"] is True and ci["source_inputs_unchanged"] is True
         and ci["home_unchanged"] is True and ci["hosted_actions_passed"] is False
         and ci["original_qualification_job_id"] == qualification["original_job_id"]
         and ci["plan"] == plan_id, "actual native exact-CI receipt is incomplete or identifies another qualification")
    need(plan["schema"] == "hepta-d1-materialized-exact-rust-ci-plan/v1"
         and plan["attempt"] == "01" and plan["executed"] is False and plan["hosted_actions_passed"] is False
         and plan["qualification_job_id"] == qualification["original_job_id"]
         and plan["qualification"] == qualification["qualification"]
         and plan["preparation"] == qualification["preparation"]
         and plan["qualification_terminal_status"] == qualification["terminal"]
         and plan["qualification_counts"] == qualification["tests"]
         and plan["source"] == str(SOURCE) and plan["source_map"] == qualification["source_map"]
         and plan["source_files"] == qualification["source_tested"]
         and plan["qualified_binaries"] == qualification["binaries"]
         and plan["qualification_harness"] == qualification["qualification_harness"]
         and plan["qualification_summary"] == qualification["isolated_summary"]
         and plan["qualification_independent_audit"] == qualification["isolated_audit"],
         "actual CI plan is not bound to the original successful Q")
    need(plan["commands"] == [
            {"workflow_step": "Check all targets", "argv": CI_COMMANDS["cargo-check"], "cwd": str(SOURCE)},
            {"workflow_step": "Test in isolated processes", "argv": CI_COMMANDS["nextest-run"], "cwd": str(SOURCE)}]
         and plan["inventory_command"]["argv"] == CI_COMMANDS["nextest-list"]
         and plan["inventory_command"]["cwd"] == str(SOURCE)
         and plan["inventory_command"]["timeout_seconds"] == 900,
         "the original exact Rust CI commands changed")
    contract = plan["execution_contract"]
    need(contract["fresh_evidence_directory"] == str(ROOT / "rust-ci-01")
         and contract["automatic_retries"] == 0 and contract["cargo_clean"] is False
         and contract["check_timeout_seconds"] == 1800 and contract["inventory_timeout_seconds"] == 900
         and contract["nextest_timeout_seconds"] == 3600 and contract["combined_timeout_seconds"] == 5400
         and contract["outer_budget_seconds"] == 6600
         and contract["retain_full_original_stdout_stderr"] is True
         and contract["no_extra_nextest_filters_or_weaker_flags"] is True,
         "the original native CI execution contract changed")
    need(ci["explicit_environment"] == plan["environment"]
         and all(name not in ci["explicit_environment"] for name in DIAGNOSTIC_ENV),
         "CI environment differs from its plan or enables diagnostic recording")
    for name, expected in CI_ENVIRONMENT.items():
        need(ci["explicit_environment"].get(name) == expected, "the original explicit CI environment differs: " + name)
    need([row["name"] for row in ci["stages"]] == list(CI_COMMANDS), "the original six CI stages differ")
    stage_ids = {}
    version_raw = None
    for stage in ci["stages"]:
        name = stage["name"]
        need(stage["argv"] == CI_COMMANDS[name] and stage["cwd"] == str(SOURCE)
             and stage["returncode"] == 0 and stage["passed"] is True
             and stage["waited_and_reaped"] is True and stage["owned_process_absent"] is True
             and stage["owned_process_group_absent"] is True and stage["timed_out"] is False,
             "an original CI stage did not close once with its original command: " + name)
        stage_ids[name] = {}
        for stream in ("stdout", "stderr"):
            pin = _identity(stage[stream], ROOT / "rust-ci-01" / (name + "." + stream))
            if name == "nextest-version" and stream == "stdout":
                identity, version_raw = _declared(pin, bind, maximum=1024 * 1024, retain=True)
            else:
                identity = _declared(pin, bind, maximum=128 * 1024 * 1024)
            stage_ids[name][stream] = identity
    need(version_raw is not None and version_raw.decode("utf-8").splitlines()[0].startswith("cargo-nextest 0.9.137 "),
         "actual nextest version is not the original 0.9.137 tool")
    need(ci["nextest_output_audit"] == audit and audit["verified"] is True
         and {name: audit[name] for name in COUNT_KEYS} == qualification["tests"]
         and audit["completed_exact_case_count"] == qualification["tests"]["passed"]
         and audit["progress_counter_complete"] is True
         and audit["raw_sha256"] == stage_ids["nextest-run"]["stderr"]["sha256"]
         and audit["raw_bytes"] == stage_ids["nextest-run"]["stderr"]["bytes"],
         "the original nextest audit does not reconcile with actual Q and original raw stderr")
    inventory = ci["structured_inventory"]
    expected = plan["expected_nextest"]
    need(inventory["verified"] is True
         and inventory["total"] == qualification["tests"]["selected"]
         and inventory["ignored"] == qualification["tests"]["ignored"]
         and inventory["case_inventory_sha256"] == audit["case_inventory_sha256"] == expected["case_inventory_sha256"]
         and inventory["original_stdout"] == stage_ids["nextest-list"]["stdout"],
         "the actual original nextest structured inventory differs")
    need({"passed": expected["passed"], "failed": expected["failed"], "ignored": expected["skipped"],
          "selected": expected["total"], "retries": expected["retries"]} == qualification["tests"]
         and len(expected["exact_cases"]) == qualification["tests"]["selected"]
         and sum(row["ignored"] for row in expected["exact_cases"]) == qualification["tests"]["ignored"]
         and hashlib.sha256(json.dumps(expected["exact_cases"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
         == expected["case_inventory_sha256"], "the sealed complete CI case set does not reconcile")
    need(plan["nextest_binary"] == NEXTEST_BINARY, "the original nextest binary pin differs")
    _declared(NEXTEST_BINARY, bind, maximum=64 * 1024 * 1024)
    nextest_receipt = _identity(plan["nextest_install_receipt"], NEXTEST_ROOT / "receipt.json")
    need(nextest_receipt["sha256"] == "2bbae481b3fbc6ac6d06a22bfe22e9500f5190b97ccddb16e8aba1ef1ed34f9d",
         "the original nextest installation receipt changed")
    _declared(nextest_receipt, bind)
    workflow = plan["workflow_binding"]
    need(workflow["canonical"] == CANONICAL_WORKFLOW
         and workflow["canonical_git_blob"] == "34afc29edffd3130df158601c6a14fee5efbf79c"
         and workflow["private_source"] == PRIVATE_SOURCE_WORKFLOW
         and workflow["qualified_source_modified"] is False, "the original workflow closure differs")
    _, workflow_raw = _declared(CANONICAL_WORKFLOW, bind, retain=True)
    need(hashlib.sha1(b"blob " + str(len(workflow_raw)).encode() + b"\0" + workflow_raw).hexdigest()
         == workflow["canonical_git_blob"], "canonical workflow Git blob differs")
    _declared(PRIVATE_SOURCE_WORKFLOW, bind)
    manifest_id = _identity(plan["ci_manifest"])
    need(manifest_id["sha256"] == "bf0df5f7d19ebd149854fbf75887fb0fb136f18a63a0c240abf8420655fb195e",
         "the original 85-input CI manifest changed")
    _declared(manifest_id, bind)
    need(all(identity in plan["input_bindings"] for identity in
         (qualification["qualification"], qualification["preparation"], qualification["terminal"],
          qualification["source_map"], qualification["isolated_summary"], qualification["isolated_audit"])),
         "the original CI plan omits a qualification binding")
    binder_id = bind(ROOT / "rust-ci-prerequisites-01/d1_prerequisites.py", maximum=8 * 1024 * 1024)
    current_binder = bind(Path(__file__).resolve(), maximum=8 * 1024 * 1024)
    need(binder_id in plan["input_bindings"]
         and all(binder_id[key] == current_binder[key] for key in ("bytes", "sha256")),
         "the outer binder differs from the actual CI qualification binder")
    for row in plan["tool_configuration_inventory"]:
        path = Path(row["path"])
        need(path.is_relative_to(SOURCE) and os.path.lexists(path) is row["exists"],
             "qualified source tool configuration presence changed")
        if row["exists"]:
            _declared(_identity(row["identity"], path), bind)
    tools = {}
    for key, filename in (("launcher", "run_rust_ci_01.py"),
                          ("materializer", "materialize_rust_ci_plan_01.py"),
                          ("auditor", "audit_nextest_0137.py")):
        identity = _identity(ci[key], ROOT / "rust-ci-tools-01" / filename)
        tools[key] = _declared(identity, bind)
    need(tools["auditor"]["sha256"] == "03fc242ae6ba3f5fa2fc948d3401e5f93a7a388ee9edb5b703183d6410aab8d2",
         "the original nextest auditor source changed")
    return {"passed": True, "binaries": qualification["binaries"],
        "changed_paths": sorted(CHANGED), "added_paths": sorted(ADDED),
        "baseline_compile_inputs": qualification["candidate_inputs"]["baseline_compile_inputs"],
        "source_tested": qualification["source_tested"], "qualification": qualification,
        "exact_ci": {"passed": True, "original_job_id": prerequisites["exact_ci_original_job_id"],
            "report": ci_id, "plan": plan_id, "audit": audit_id, "terminal": terminal_id,
            "native": native, "tools": tools, "stages": stage_ids, "tests": qualification["tests"],
            "qualification_binder": binder_id,
            "source_inputs_unchanged": True, "owned_children_closed": True,
            "hosted_actions_claimed": False, "original_auditor_reexecuted": False},
        "diagnostic_environment_enabled_during_qualification_or_ci": False,
        "ordinary_supplemental_claimed": False, "performance_acceptance_claim": False}

#!/usr/bin/env python3
"""Static byte/patch checks only; never invokes Rust, a child fixture, or SSH."""
import argparse
import difflib
import hashlib
import json
import re
from pathlib import Path

BASELINE_COMMIT = "baab4def80be7af015b2e7a594cb302f66c4130e"
CHANGED = [
    "src/mcp/runtime/jobs.rs",
    "src/mcp/runtime/ssh.rs",
    "src/mcp/runtime/ssh_direct.rs",
    "src/mcp/runtime/ssh_direct_tests.rs",
]
REFERENCE_INPUT_SHA256 = "3753078ae1fa3dd7c9b2582d2d5a6e01335937b6651c5094314955e16b1af48d"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def span(text, start, end):
    assert text.count(start) == 1, start
    offset = text.index(start)
    return text[offset:text.index(end, offset)]


def between(text, start, end):
    return span(text, start, end)[len(start):]


def apply_exact_unified(original, patch):
    """Apply this generated unified hunk stream, requiring all context bytes."""
    lines = original.splitlines(keepends=True)
    patch_lines = patch.splitlines(keepends=True)
    assert patch_lines[0].startswith("--- a/")
    assert patch_lines[1].startswith("+++ b/")
    cursor = 0
    output = []
    index = 2
    while index < len(patch_lines):
        match = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\n", patch_lines[index])
        assert match, patch_lines[index]
        old_start = int(match[1]) - 1
        old_count = int(match[2] or 1)
        new_start = int(match[3]) - 1
        new_count = int(match[4] or 1)
        assert old_start >= cursor
        output.extend(lines[cursor:old_start])
        assert len(output) == new_start
        cursor = old_start
        seen_old = seen_new = 0
        index += 1
        while index < len(patch_lines) and not patch_lines[index].startswith("@@ "):
            line = patch_lines[index]
            kind, payload = line[0], line[1:]
            assert kind in " +-", line
            if kind in " -":
                assert cursor < len(lines) and lines[cursor] == payload
                cursor += 1
                seen_old += 1
            if kind in " +":
                output.append(payload)
                seen_new += 1
            index += 1
        assert (seen_old, seen_new) == (old_count, new_count)
    output.extend(lines[cursor:])
    return "".join(output)


def verify(root):
    reference_raw = (root / "reference-r33-input.json").read_bytes()
    assert len(reference_raw) == 52436
    assert sha(reference_raw) == REFERENCE_INPUT_SHA256
    reference = json.loads(reference_raw)
    baseline = json.loads((root / "baseline-compile-inputs.json").read_bytes())
    assert baseline == reference["baseline_compile_inputs"]
    assert len(baseline) == 220
    assert reference["baseline_commit"] == BASELINE_COMMIT
    fetched = {}
    for file in sorted((root / "baseline").rglob("*")):
        if file.is_file():
            name = file.relative_to(root / "baseline").as_posix()
            raw = file.read_bytes()
            assert sha(raw) == baseline[name], name
            fetched[name] = {"bytes": len(raw), "sha256": sha(raw)}
    assert len(fetched) == 9
    source_paths = sorted(
        file.relative_to(root / "source").as_posix()
        for file in (root / "source").rglob("*") if file.is_file()
    )
    assert source_paths == CHANGED
    before = {name: (root / "baseline" / name).read_bytes().decode("utf-8") for name in CHANGED}
    after = {name: (root / "source" / name).read_bytes().decode("utf-8") for name in CHANGED}
    candidate = dict(baseline)
    patch_parts = []
    for name in CHANGED:
        assert before[name] != after[name]
        part = "".join(difflib.unified_diff(
            before[name].splitlines(keepends=True), after[name].splitlines(keepends=True),
            fromfile="a/" + name, tofile="b/" + name,
        ))
        assert apply_exact_unified(before[name], part) == after[name], name
        patch_parts.append(part)
        candidate[name] = sha(after[name].encode("utf-8"))
    assert sorted(name for name in baseline if baseline[name] != candidate[name]) == CHANGED
    assert len(candidate) == 220 and set(candidate) == set(baseline)

    old_jobs, jobs = before[CHANGED[0]], after[CHANGED[0]]
    old_cancel = span(old_jobs, "pub async fn cancel_job(", "\nfn inventory_read_slots()")
    new_cancel = span(jobs, "pub async fn cancel_job(", "\nfn inventory_read_slots()")
    expected_cancel = old_cancel.replace(
        'run_jobctl(host, &json!({"op":"cancel","job_id":record.id})).await',
        'super::ssh::run_jobctl_cancel(host, &record.id).await',
    ).replace("\t\trun_python_json(\n", "\t\tsuper::ssh::run_job_cancel_python_json(\n")
    assert new_cancel == expected_cancel
    assert jobs == old_jobs.replace(old_cancel, expected_cancel)
    helpers = {}
    pattern = re.compile(r'^const ([A-Z][A-Z0-9_]*): &str = r(#+)"\n(.*?)^"\2;', re.M | re.S)
    for match in pattern.finditer(old_jobs):
        name, literal = match[1], match[0]
        assert jobs.count(literal) == 1
        helpers[name] = {"bytes": len(literal.encode()), "sha256": sha(literal.encode())}
    assert len(helpers) == 6 and "CANCEL_CODE" in helpers

    old_direct, direct = before[CHANGED[2]], after[CHANGED[2]]
    preserved = {}
    for label, start, end in [
        ("cancellation_commit_and_drop", "const QUEUED:", "\nstruct Leases {"),
        ("child_state_owned_child_and_reap", "struct ChildState {", "\nstruct Core {"),
        ("core_registry_actor_cleanup", "struct Core {", "\nstruct Proxy {"),
        ("target_registry", "\tfn target(", "\n\tasync fn acquire("),
        ("shutdown_join_custody", "\tasync fn shutdown(", "\n}\n\nfn shared()"),
        ("global_owner_freeze_guard", "fn shared()", "\npub(super) async fn capture("),
    ]:
        one = span(old_direct, start, end)
        assert span(direct, start, end) == one, label
        preserved[label] = {"bytes": len(one.encode()), "sha256": sha(one.encode())}
    ordinary = span(old_direct, "\tasync fn acquire(", "\n\tasync fn capture(")
    assert span(direct, "\tasync fn acquire(", "\n\tfn try_ordinary_cancel(") == ordinary.replace(
        "\t\t\t_host: host,", "\t\t\t_host: Some(host),"
    )
    common = span(old_direct, "\t\tlet cancel = Cancellation::new();", "\n\tasync fn shutdown(")
    assert span(direct, "\t\tlet cancel = Cancellation::new();", "\n\tasync fn shutdown(") == common
    preserved["capture_after_admission"] = {"bytes": len(common.encode()), "sha256": sha(common.encode())}
    for constant, value in {"HOST_CONNECTIONS": 2, "GLOBAL_CONNECTIONS": 8, "MAX_ADMITTED": 16,
                            "CANCEL_CONNECTIONS": 1, "MAX_CANCEL_ADMITTED": 8}.items():
        assert f"const {constant}: usize = {value};" in direct
    assert "const OWNER_QUEUE: usize = GLOBAL_CONNECTIONS + CANCEL_CONNECTIONS;" in direct
    assert "mpsc::channel(OWNER_QUEUE)" in direct

    old_ssh, ssh = before[CHANGED[1]], after[CHANGED[1]]
    python_old = span(old_ssh, "pub async fn run_python_json_with_interpreter<", "\npub fn build_exec_command(")
    python_new = span(ssh, "async fn run_python_json_admitted<", "\npub fn build_exec_command(")
    python_old_body = python_old[python_old.index("\n{\n"):]
    python_new_body = python_new[python_new.index("\n{\n"):]
    assert python_new_body == python_old_body.replace(
        "\tlet output = run_capture_until(host, &remote_command, &payload, deadline).await?;",
        "\tlet output =\n\t\trun_capture_admitted_until(host, &remote_command, &payload, deadline, admission).await?;",
    )
    jobctl_old = span(old_ssh, "pub async fn run_jobctl(", "\n#[cfg(test)]")
    jobctl_new = span(ssh, "async fn run_jobctl_admitted(", "\n#[cfg(test)]")
    jobctl_old_body = jobctl_old[jobctl_old.index(" {\n"):]
    jobctl_new_body = jobctl_new[jobctl_new.index(" {\n"):]
    assert jobctl_new_body == jobctl_old_body.replace("run_capture_until(", "run_capture_admitted_until(").replace(
        "\t\tdeadline,\n", "\t\tdeadline,\n\t\tadmission,\n"
    )
    command_old = between(old_ssh, "\tlet mut command = ssh_base(host);", "\tdirect::capture(&host.ssh_target")
    command_new = between(ssh, "\tlet mut command = ssh_base(host);", "\tmatch admission {")
    assert command_old == command_new
    assert ssh.count("DirectAdmission::ExistingJobCancellation") == 3
    assert jobs.count("super::ssh::run_jobctl_cancel(") == 1
    assert jobs.count("super::ssh::run_job_cancel_python_json(") == 1

    old_tests, tests = before[CHANGED[3]], after[CHANGED[3]]
    new_region = span(tests, "fn submit_job_cancel(", "// The independent driver owns both wait receipts.")
    assertions = (
        "\t\tassert_eq!(self.0.cancel_global.available_permits(), CANCEL_CONNECTIONS);\n"
        "\t\tassert_eq!(\n\t\t\tself.0.cancel_admission.available_permits(),\n"
        "\t\t\tMAX_CANCEL_ADMITTED\n\t\t);\n"
    )
    assert tests.count(assertions) == 1
    assert tests.replace(new_region, "").replace(assertions, "") == old_tests
    names = re.findall(r"#\[tokio::test\]\nasync fn (\w+)\(", new_region)
    assert len(names) == len(set(names)) == 8
    checks = {
        "schema": "hepta-r34-static-source-checks/v1",
        "scope": "Byte comparisons and generated-patch reconstruction only; not Rust compilation or test execution.",
        "passed": True,
        "rust_compiled": False,
        "rust_tests_executed": False,
        "benchmarks_executed": False,
        "remote_runtime_calls": 0,
        "baseline_commit": BASELINE_COMMIT,
        "reference_input_sha256": REFERENCE_INPUT_SHA256,
        "baseline_map_count": len(baseline),
        "candidate_map_count": len(candidate),
        "changed_paths": CHANGED,
        "unchanged_compile_inputs": len(baseline) - len(CHANGED),
        "fetched_baseline_files_verified": fetched,
        "jobs_only_two_cancel_dispatch_substitutions": True,
        "embedded_job_python_literals_identical": helpers,
        "preserved_direct_source_regions": preserved,
        "ordinary_acquire_only_host_option_wrap": True,
        "python_and_jobctl_deadlines_serializers_decoders_preserved": True,
        "all_original_direct_tests_preserved": True,
        "new_unexecuted_test_functions": names,
        "patch_reconstructs_all_changed_files": True,
        "profile_and_observation_compile_inputs_unchanged": all(
            baseline[name] == candidate[name] for name in baseline
            if "observation" in name or "profile" in name
        ),
    }
    return candidate, "".join(patch_parts), checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--write", action="store_true", help="Create three new static artifacts exclusively")
    args = parser.parse_args()
    candidate, patch, checks = verify(args.root)
    outputs = {
        "candidate-compile-inputs.json": json.dumps(candidate, sort_keys=True, indent=2) + "\n",
        "candidate.patch": patch,
        "static-checks.json": json.dumps(checks, sort_keys=True, indent=2) + "\n",
    }
    if args.write:
        assert not any((args.root / name).exists() for name in outputs), "static outputs already exist"
        for name, text in outputs.items():
            with (args.root / name).open("x", encoding="utf-8", newline="") as file:
                file.write(text)
    else:
        for name, text in outputs.items():
            assert (args.root / name).read_bytes() == text.encode(), name
    print(json.dumps({"static_checks_passed": True, "rust_executed": False, "files": {
        name: {"bytes": len(text.encode()), "sha256": sha(text.encode())}
        for name, text in outputs.items()
    }}, sort_keys=True))


if __name__ == "__main__":
    main()

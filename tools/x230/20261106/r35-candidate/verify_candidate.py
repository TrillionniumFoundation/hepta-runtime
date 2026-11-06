#!/usr/bin/env python3
"""Read-only R35 byte/patch checks. Does not import or execute runtime code."""
import argparse
import difflib
import hashlib
import json
import re
from pathlib import Path

BASELINE_COMMIT = "baab4def80be7af015b2e7a594cb302f66c4130e"
REFERENCE_SHA256 = "3753078ae1fa3dd7c9b2582d2d5a6e01335937b6651c5094314955e16b1af48d"
CHANGED = [
    "src/mcp/runtime/jobs.rs",
    "src/mcp/runtime/ssh_observation_pool.rs",
    "src/mcp/runtime/ssh_observation_pool_tests.rs",
]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(raw):
    return {"bytes": len(raw), "sha256": sha(raw)}


def replace_once(text, old, new):
    assert text.count(old) == 1, repr(old)
    return text.replace(old, new, 1)


def apply_exact_unified(original, patch):
    """Apply only the supplied hunks, requiring every old/context line."""
    lines = original.splitlines(keepends=True)
    chunks = patch.splitlines(keepends=True)
    assert chunks[0].startswith("--- a/") and chunks[1].startswith("+++ b/")
    cursor, index, output = 0, 2, []
    while index < len(chunks):
        match = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\n", chunks[index])
        assert match, chunks[index]
        old_start, new_start = int(match[1]) - 1, int(match[3]) - 1
        old_count, new_count = int(match[2] or 1), int(match[4] or 1)
        assert old_start >= cursor
        output.extend(lines[cursor:old_start])
        assert len(output) == new_start
        cursor, seen_old, seen_new = old_start, 0, 0
        index += 1
        while index < len(chunks) and not chunks[index].startswith("@@ "):
            kind, payload = chunks[index][0], chunks[index][1:]
            assert kind in " +-"
            if kind in " -":
                assert cursor < len(lines) and lines[cursor] == payload
                cursor += 1
                seen_old += 1
            if kind in " +":
                output.append(payload)
                seen_new += 1
            index += 1
        assert (seen_old, seen_new) == (old_count, new_count)
    return "".join(output + lines[cursor:])


def verify(root):
    reference_raw = (root / "reference-r33-input.json").read_bytes()
    assert len(reference_raw) == 52436 and sha(reference_raw) == REFERENCE_SHA256
    reference = json.loads(reference_raw)
    assert reference["baseline_commit"] == BASELINE_COMMIT
    baseline = json.loads((root / "baseline-compile-inputs.json").read_bytes())
    candidate = json.loads((root / "candidate-compile-inputs.json").read_bytes())
    assert baseline == reference["baseline_compile_inputs"]
    assert len(baseline) == len(candidate) == 220 and set(baseline) == set(candidate)
    assert sorted(key for key in baseline if baseline[key] != candidate[key]) == CHANGED
    fetched = {}
    for file in sorted((root / "baseline").rglob("*")):
        if file.is_file():
            name = file.relative_to(root / "baseline").as_posix()
            raw = file.read_bytes()
            assert sha(raw) == baseline[name], name
            fetched[name] = identity(raw)
    assert len(fetched) == 7
    source_paths = sorted(file.relative_to(root / "source").as_posix()
                          for file in (root / "source").rglob("*") if file.is_file())
    assert source_paths == CHANGED
    before, after, source_identities, parts = {}, {}, {}, []
    for name in CHANGED:
        old = (root / "baseline" / name).read_bytes()
        new = (root / "source" / name).read_bytes()
        assert sha(old) == baseline[name] and sha(new) == candidate[name]
        before[name], after[name] = old.decode("utf-8"), new.decode("utf-8")
        part = "".join(difflib.unified_diff(
            before[name].splitlines(keepends=True), after[name].splitlines(keepends=True),
            fromfile="a/" + name, tofile="b/" + name,
        ))
        assert part and apply_exact_unified(before[name], part) == after[name]
        parts.append(part)
        source_identities[name] = identity(new)
    patch = (root / "candidate.patch").read_bytes()
    assert patch == "".join(parts).encode("utf-8")

    old_jobs, jobs = before[CHANGED[0]], after[CHANGED[0]]
    request = '\tlet request = json!({\n\t\t"job_id": record.id,\n\t\t"job_dir": record.remote_job_dir,\n\t\t"request_digest": record.request_digest,\n\t\t"unit": record.unit,\n\t\t"stdout_offset": params.stdout_offset.unwrap_or(0),\n\t\t"stderr_offset": params.stderr_offset.unwrap_or(0),\n\t\t"limit": params.limit.unwrap_or(65_536).min(MAX_LOG_READ_BYTES),\n\t});\n'
    moved = "".join("\t" + line for line in request.splitlines(keepends=True))
    read_start = old_jobs.index("pub async fn read_job(")
    read_end = old_jobs.index("\nfn retain_observation_after_audit(", read_start)
    read = old_jobs[read_start:read_end]
    new_read = replace_once(read, request, "")
    marker = "\t} else {\n\t\trun_python_json(\n"
    new_read = replace_once(new_read, marker, "\t} else {\n" + moved + "\t\trun_python_json(\n")
    assert jobs == old_jobs[:read_start] + new_read + old_jobs[read_end:]
    original_r26 = (root / "history/originals/r26-selected-change.patch").read_bytes()
    assert original_r26 == parts[0].encode("utf-8")

    helpers = {}
    helper_pattern = re.compile(r'(?ms)^const ([A-Z][A-Z_0-9]*): &str = r(?P<hashes>#+)"(?P<body>.*?)"(?P=hashes);')
    old_helpers = {m[1]: m[0].encode("utf-8") for m in helper_pattern.finditer(old_jobs)}
    new_helpers = {m[1]: m[0].encode("utf-8") for m in helper_pattern.finditer(jobs)}
    assert len(old_helpers) == 6 and old_helpers == new_helpers
    for name, raw in old_helpers.items():
        helpers[name] = identity(raw)

    old_pool, pool = before[CHANGED[1]], after[CHANGED[1]]
    replacements = [
        ("async fn execute(\n\t\tself: Arc<Self>,\n\t\trequest: Request,", "async fn execute(\n\t\tself: Arc<Self>,\n\t\tmut request: Request,"),
        ("self.clone().execute_inner(&request, initial, global).await", "self.clone().execute_inner(&mut request, initial, global).await"),
        ("async fn execute_inner(\n\t\tself: Arc<Self>,\n\t\trequest: &Request,", "async fn execute_inner(\n\t\tself: Arc<Self>,\n\t\trequest: &mut Request,"),
        ("args.push(request.command.clone());", "args.push(std::mem::take(&mut request.command));"),
    ]
    expected = old_pool
    for old, new in replacements:
        expected = replace_once(expected, old, new)
    assert pool == expected
    assert old_pool.count("request.command") == pool.count("request.command") == 1
    assert "impl Drop for Request" not in old_pool and "impl Drop for Request" not in pool

    old_tests, tests = before[CHANGED[2]], after[CHANGED[2]]
    call = "task_core.execute_inner(&request, permit, global).await"
    assert old_tests.count(call) == 2
    expected = old_tests
    for offset in reversed([m.start() for m in re.finditer(re.escape(call), old_tests)]):
        declaration = old_tests.rfind("let request = Request {", 0, offset)
        assert declaration >= 0
        between = old_tests[declaration:offset]
        assert between.count("let request = Request {") == 1
        assert 'command: "NEVER_DISPATCH".into(),' in between
        expected = expected[:offset] + expected[offset:].replace(call, "task_core.execute_inner(&mut request, permit, global).await", 1)
        expected = expected[:declaration] + expected[declaration:].replace("let request = Request {", "let mut request = Request {", 1)
    assert tests == expected
    function_pattern = r"(?m)^(?:async )?fn ([A-Za-z_0-9]+)\s*\("
    assert re.findall(function_pattern, old_tests) == re.findall(function_pattern, tests)
    assertion_pattern = r"(?m)^.*\bassert(?:_eq|_ne)?!.*$"
    assert re.findall(assertion_pattern, old_tests) == re.findall(assertion_pattern, tests)
    return {
        "schema": "hepta-x230-r35-static-source-checks/v1",
        "baseline_commit": BASELINE_COMMIT,
        "passed": True,
        "scope": "Static byte/patch checks only; no Rust, formatter, tests, subprocess fixtures, remote hosts, or benchmark execution.",
        "baseline_compile_input_count": len(baseline),
        "candidate_compile_input_count": len(candidate),
        "changed_paths": CHANGED,
        "added_paths": [], "removed_paths": [],
        "baseline_artifacts": fetched,
        "candidate_sources": source_identities,
        "patch": identity(patch),
        "checks": {
            "accepted_r24_reference_and_full_map_match": True,
            "all_fetched_baseline_files_match_original_map": True,
            "only_three_map_entries_change": True,
            "exact_unified_patch_context_application_matches_full_sources": True,
            "jobs_entire_file_equals_single_seven_field_block_relocation": True,
            "jobs_only_patch_is_byte_identical_to_original_r26_selected_delta": True,
            "all_six_embedded_jobs_helper_constants_are_byte_identical": True,
            "pool_entire_file_equals_four_limited_ownership_replacements": True,
            "command_has_exactly_one_production_use_and_no_request_drop_impl": True,
            "tests_entire_file_equals_two_mut_declarations_and_two_mut_borrows": True,
            "pool_test_function_names_and_assertion_lines_unchanged": True,
        },
        "unchanged_embedded_jobs_helpers": helpers,
        "historical_r26_selected_delta": identity(original_r26),
        "rust_format_executed": False, "rust_compiled": False,
        "rust_tests_executed": False, "benchmarks_executed": False,
        "qualification": None, "rust_ci": None, "performance_evidence": None,
        "adopted": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    options = parser.parse_args()
    print(json.dumps(verify(options.root), indent=2, sort_keys=True) + "\n", end="")

#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Inspect package bytes and completed original CI documents without running them."""
import ast
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT = HERE / "sealed-01"
REMOTE = "/home/qian/hepta-runtime-optimization-20261106-r35"


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def write(name, value):
    raw = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    with (OUT / name).open("xb") as stream:
        stream.write(raw)


def main():
    manifest_raw = (OUT / "launcher-seal-manifest.json").read_bytes()
    manifest = json.loads(manifest_raw)
    operator = json.loads((OUT / "operator-argv.json").read_bytes())
    package = json.loads((OUT / "package-identity.json").read_bytes())
    assert operator == manifest["commands"] == package["commands"]
    assert manifest["exact_ci_final_result"] is None
    installer_raw = (OUT / "install_r35_mac_launchers_01.py").read_bytes()
    installer_ast = ast.parse(installer_raw)
    constants = {n.targets[0].id: ast.literal_eval(n.value) for n in installer_ast.body
                 if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                 and n.targets[0].id in ("PACKAGE", "ARCHIVE_BASE64")}
    assert constants["PACKAGE"] == package
    raw = base64.b64decode(constants["ARCHIVE_BASE64"], validate=True)
    assert raw == (OUT / "r35-mac-launchers-01.tar.gz").read_bytes()
    assert identity(raw) == package["archive"]
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
        expanded = stream.read(512 * 1024 + 1)
    assert len(expanded) <= 512 * 1024
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
        members = archive.getmembers()
        assert len(members) == 5 and {m.name for m in members} == set(package["members"])
        for member in members:
            assert member.isfile() and member.size <= 128 * 1024 and Path(member.name).name == member.name
            body = archive.extractfile(member).read(128 * 1024 + 1)
            assert body == (OUT / member.name).read_bytes()
            assert identity(body) == package["members"][member.name]
    assert sum(pin["bytes"] for pin in package["members"].values()) == package["expanded_file_bytes"] == 133091
    for name in ("held_agent_campaign_02.py", "r35_campaign.py", "r35_lifecycle_campaign.py"):
        assert (OUT / name).read_bytes() == (ROOT / "r35-observation-template-01/mac-launchers-01" / name).read_bytes()
    calls = {ast.unparse(n.func) for n in ast.walk(installer_ast) if isinstance(n, ast.Call)}
    assert not calls & {"exec", "eval", "subprocess.run", "subprocess.Popen", "os.system", "runpy.run_path", "importlib.import_module"}

    expected_ci = {
        "report.json": (14132, "b619804c79479d2bb529e363d8fa48520b8ef9f351a99729ccba77d5510fec5f"),
        "rust-ci-plan-01.json": (554743, "4cc92edbd1b8052e73aed5ede9987a6d56684e2a621b1cf5b0577ad4b307bb28"),
        "nextest-output-audit.json": (719, "545fd10013d912be0e9297429b606e376cbea7bac55b62f78f76c881fe1ffba3"),
        "rust-ci-native-01.json": (731, "c19d3490b283df287ba2743d3385f26a83144505ef36ccc874e218359cc94746"),
        "rust-ci-native-read-01.json": (5126, "31a962dfcbc55ce22b4bb81f5fa05aaacf018c13f17d2dc3f3b49e933d30977b"),
    }
    files = {}
    for name, (size, sha) in expected_ci.items():
        body = (ROOT / "r35-exact-ci-originals-01" / name).read_bytes()
        assert identity(body) == {"bytes": size, "sha256": sha}
        files[name] = body
    docs = {name: json.loads(body) for name, body in files.items()}
    report, plan, audit = (docs[n] for n in ("report.json", "rust-ci-plan-01.json", "nextest-output-audit.json"))
    native, read = docs["rust-ci-native-01.json"], docs["rust-ci-native-read-01.json"]
    assert native["job_id"] == read["job_id"] == manifest["exact_ci_original_job_id"] == "1a1af88c330-fc05-696f"
    assert native["state"] == "succeeded" and type(native["exit_code"]) is int and native["exit_code"] == 0
    assert all(native[k] is True for k in ("output_complete", "output_durable", "terminal_publication_confirmed"))
    assert native["terminal_publication_protocol"] == 1
    assert all(native[k] is False for k in ("automatic_retry", "cancelled", "timed_out"))
    streams = {}
    for name in ("stdout", "stderr"):
        row = read[name]
        body = bytes.fromhex(row["bytes_hex"])
        assert row["offset"] == 0 and row["next_offset"] == row["size"] == len(body)
        assert row["eof"] is True and row["text"].encode() == body
        assert native["log_bytes"][name] == {"seen": len(body), "stored": len(body)}
        assert native["log_synced"][name] is True and native["log_errors"][name] is None and native["log_truncated"][name] is False
        streams[name] = identity(body)
    assert streams["stdout"]["bytes"] == 1541 and streams["stderr"]["bytes"] == 0
    assert report["schema"] == "hepta-r35-external-rust-ci/v1" and report["attempt"] == "01"
    assert report["passed"] is True and report.get("error") is None and report["finished_utc"]
    assert report["source_inputs_unchanged"] is True and report["owned_children_closed"] is True
    assert report["automatic_retries"] == 0 and report["hosted_actions_passed"] is False
    names = ["cargo-version", "rustc-version", "nextest-version", "cargo-check", "nextest-list", "nextest-run"]
    assert [row["name"] for row in report["stages"]] == names
    for row in report["stages"]:
        assert type(row["returncode"]) is int and row["returncode"] == 0
        assert all(row[k] is True for k in ("passed", "waited_and_reaped", "owned_process_absent", "owned_process_group_absent"))
        assert row["timed_out"] is False and row.get("cleanup_error") is None and row.get("error") is None
    assert report["nextest_output_audit"] == audit and audit["verified"] is True
    counts = {k: audit[k] for k in ("passed", "failed", "ignored", "selected", "retries")}
    assert counts == manifest["qualification_counts"] and audit["success_status_counts"] == {"PASS": 1645}
    assert plan["schema"] == "hepta-r35-materialized-exact-rust-ci-plan/v1" and plan["attempt"] == "01"
    assert plan["qualification_job_id"] == manifest["qualification_job_id"] and plan["qualification_counts"] == counts
    assert report["plan"] == dict(path=REMOTE + "/rust-ci-plan-01.json", **identity(files["rust-ci-plan-01.json"]))
    for key, rel in (("qualification", "qualification-01/report.json"),
                     ("qualification_terminal_status", "qualification-terminal-status-01.json"),
                     ("source_map", "qualification-01/source-map.json")):
        assert plan[key] == manifest["qualification_originals"][rel]
    assert plan["source_files"] == json.loads((ROOT / "r35-qualified-originals-01/source-map.json").read_bytes())
    assert plan["qualified_binaries"] == manifest["candidate_binaries"]

    closure = {
        "schema": "hepta-r35-mac-launcher-exact-ci-prerequisite-closure/v1",
        "original_ci_job_id": native["job_id"], "original_qualification_job_id": manifest["qualification_job_id"],
        "recorded_ci_result": "passed", "counts": counts,
        "original_documents": {name: identity(body) for name, body in files.items()},
        "original_native_streams": streams,
        "original_stage_results": [{k: row[k] for k in ("name", "returncode", "passed", "waited_and_reaped", "owned_process_absent", "owned_process_group_absent")} for row in report["stages"]],
        "reported_source_inputs_unchanged": True, "reported_owned_children_closed": True,
        "source_map_sha256": plan["source_map"]["sha256"], "qualified_binaries": plan["qualified_binaries"],
        "frozen_launcher_seal_manifest": identity(manifest_raw), "frozen_package_archive": package["archive"],
        "frozen_manifest_pending_ci_snapshot_preserved": True,
        "operator_argv_matches_frozen_manifest_and_actual_original_materializer_inputs": True,
        "observation_or_lifecycle_started_by_this_task": False,
        "target_programs_or_auditors_reexecuted": False, "remote_calls": 0,
        "scope_limits": [
            "The five original CI documents and complete original native progress streams were read locally; raw Cargo/nextest stage log bodies were not reread by this note.",
            "The original report, audit and plan establish the recorded CI result; this note does not rerun a tool or claim current machine idleness.",
            "The root coordinator separately preserves and verifies the complete original CI log archive before closing the API/compiler window and starting held observation.",
            "No performance, observation gate, lifecycle result, adoption or hosted GitHub Actions success is claimed.",
        ],
    }
    write("ci-prerequisite-closure-01.json", closure)
    write("LOCAL_STATIC_CHECKS.json", {
        "schema": "hepta-r35-mac-launcher-package-static-verification/v1",
        "package": package["archive"], "installer": identity(installer_raw),
        "package_member_count": 5, "package_expanded_file_bytes": 133091, "expanded_tar_bytes": len(expanded),
        "checks": {
            "all_five_tar_members_equal_exact_frozen_local_files": True,
            "original_holder_and_two_reviewed_parent_scripts_byte_identical": True,
            "operator_argv_and_actual_original_materializer_inputs_match": True,
            "parent_original_native_and_installed_receipt_identities_bound_by_local_constructor": True,
            "all_seven_actual_Q_originals_and_actual_postflight_three_ELFs_bound": True,
            "actual_R35_installed_lifecycle_three_tool_pins_used": True,
            "CI_pending_manifest_snapshot_not_overwritten_after_original_completion": True,
            "fixed_five_member_names_no_links_or_paths_and_bounded_gzip_tar": True,
            "installer_AST_has_no_target_program_or_SSH_execution": True,
            "separate_actual_CI_closure_note_preserves_frozen_package": True,
        },
        "local_preparation_history": [{
            "event": "initial supplementary receipt-check stdin helper failed before creating any supplemental output",
            "error": "KeyError: 'error'",
            "cause": "The local check directly indexed the optional original successful report error key.",
            "correction": "Use get for optional report/stage error fields; no original report, installer, packaged script, native task, or measurement was changed or repeated.",
        }],
        "package_constructor_executed_locally_once": True,
        "installer_holder_parent_materializer_or_CI_executed_by_this_task": False,
        "tar_members_extracted_to_filesystem": 0, "remote_calls": 0,
        "independent_peer_scope": "audit_acceptance independently reported no blocking finding after exact archive/member/source and installer safety checks; no peer receipt is synthesized here.",
    })
    print(json.dumps({"verified_local_bytes": True, "original_ci_job_id": native["job_id"],
                      "ci_counts": counts, "package_files": 5, "target_programs_executed": 0, "remote_calls": 0}))


if __name__ == "__main__":
    main()

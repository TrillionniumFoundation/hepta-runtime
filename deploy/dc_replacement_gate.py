#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Evidence-based, read-only DC → Hepta replacement gate.

This deliberately *does not* run tools, reconfigure permissions or stop DC.
A model-origin bounded success is evidence only for that tested operation, not
a global approval for a name, target host, argument family or privileged action.
"""
import argparse
import hashlib
import json
import pathlib
from collections import Counter
from mcp_tool_contract import ToolContract

ROOT = pathlib.Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs/qualification/dc-functional-parity-crosswalk-20261013.json"
CONTRACT = ROOT / "deploy/contracts/hepta-runtime-full-operator-v4.json"

EXPECTED_DC = (
    "list_devices", "who_am_i", "get_tool_result", "list_remote_tool_calls",
    "ping", "shutdown", "get_config", "set_config_value", "read_file",
    "read_multiple_files", "write_file", "write_pdf", "create_directory",
    "list_directory", "move_file", "start_search", "get_more_search_results",
    "stop_search", "list_searches", "get_file_info", "edit_block",
    "start_process", "read_process_output", "interact_with_process",
    "force_terminate", "list_sessions", "list_processes", "kill_process",
    "get_usage_stats", "get_recent_tool_calls", "give_feedback_to_desktop_commander",
)
STATES = frozenset(("bounded", "partial", "unimplemented", "vendor_specific"))
REQUIRED_RECEIPTS = frozenset((
    "dc-parity-v4-model-origin-tool-ledger-v3-20261013.json",
    "dc-parity-v4-chatgpt-model-origin-accepted-20261013.json",
))

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def evaluate(ledger, contract, *, evidence_root=ROOT):
    """Return explicit deficits; never silently promote partial to passed."""
    problems = []
    if ledger.get("schema") != "hepta-dc-functional-crosswalk-v1":
        problems.append("Unsupported or missing DC crosswalk schema")
    if ledger.get("dc_tool_count") != len(EXPECTED_DC) or ledger.get("hepta_tool_count") != 50:
        problems.append("The reported tool counts do not match the reviewed versions")
    tools = contract.get("tools")
    if contract.get("tool_count") != 50 or not isinstance(tools, list) or len(tools) != 50:
        problems.append("The pinned installed Hepta contract is not the reviewed 50-tool v4 catalog.")
        tools = tools if isinstance(tools, list) else []
    toolnames = [x.get("name") for x in tools if isinstance(x, dict)]
    unique = set(toolnames)
    if len(unique) != 50:
        problems.append("A Hepta tool definition is missing or duplicated.")
    try:
        ToolContract(contract)
    except (ValueError, TypeError, KeyError) as error:
        problems.append("The embedded Hepta contract is invalid: " + type(error).__name__)
    if contract.get("catalog_sha256") != ledger.get("pinned_hepta_catalog_sha256"):
        problems.append("Pinned v4 catalog digest differs from the signed-off ledger.")
    entries = ledger.get("entries")
    if not isinstance(entries, list):
        entries = []
        problems.append("Missing DC crosswalk entries.")
    dc_names = [item.get("dc_tool") for item in entries if isinstance(item, dict)]
    if set(dc_names) != set(EXPECTED_DC) or len(dc_names) != len(EXPECTED_DC):
        problems.append("Every one of the 31 Desktop Commander tools must appear exactly once.")
    classifications = Counter()
    for item in entries:
        if not isinstance(item, dict):
            problems.append("Malformed DC mapping entry.")
            continue
        name = item.get("dc_tool")
        status = item.get("status")
        if status not in STATES:
            problems.append(f"{name}: unsupported parity classification")
            continue
        classifications[status] += 1
        equivalents = item.get("hepta_tools")
        if not isinstance(equivalents, list) or len(equivalents) != len(set(equivalents)):
            problems.append(f"{name}: invalid replacement tool list")
            equivalents = []
        for tool in equivalents:
            if tool not in unique:
                problems.append(f"{name}: alleged Hepta equivalent {tool!r} is not in the pinned contract")
        if status == "bounded" and not equivalents:
            problems.append(f"{name}: bounded parity requires one actual Hepta operation")
        if not isinstance(item.get("limits"), str) or not item["limits"].strip():
            problems.append(f"{name}: operation semantics/limits are required")
        if status != "bounded" and not str(item.get("next_gate", "")).strip():
            problems.append(f"{name}: remaining parity gate is not described")
        receipt = item.get("evidence")
        if status == "bounded" and not receipt:
            problems.append(f"{name}: bounded parity cannot be claimed without a frozen evidence receipt")
        if receipt:
            if not isinstance(receipt, dict) or set(receipt) != {"path", "sha256"}:
                problems.append(f"{name}: evidence must be a path and digest")
                continue
            path = pathlib.Path(receipt["path"])
            if path.is_absolute() or ".." in path.parts or not path.as_posix().startswith("docs/qualification/"):
                problems.append(f"{name}: evidence path not confined to immutable qualification directory")
                continue
            full = evidence_root / path
            if not full.is_file() or sha256(full) != receipt["sha256"]:
                problems.append(f"{name}: evidence receipt missing or changed")
    sources = ledger.get("source_receipts") or {}
    for source in REQUIRED_RECEIPTS:
        ref = sources.get(source)
        if not isinstance(ref, dict) or set(ref) != {"path", "sha256"}:
            problems.append(f"Frozen source receipt {source} is not pinned")
            continue
        path = pathlib.Path(ref["path"])
        if (path.name != source or path.is_absolute() or ".." in path.parts or
                not path.as_posix().startswith("docs/qualification/") or
                not (evidence_root / path).is_file() or
                sha256(evidence_root / path) != ref["sha256"]):
            problems.append(f"Frozen source receipt {source} is changed or absent")

    unresolved = [item["dc_tool"] for item in entries if isinstance(item, dict)
                  and item.get("status") in ("partial", "unimplemented")]
    forced_holds = (
        "independent_dc_off_smoke",
        "workflow_restart_recovery",
        "cutover_rollback_drill",
        "audit_and_search_session_gap",
        "privileged_action_policy_review",
        "vendor_specific_retirement_decision",
    )
    gates = ledger.get("cutover_gates") or {}
    unknown = set(gates) ^ set(forced_holds)
    if unknown:
        problems.append("Cutover evidence gates are missing or unexpected.")
    approvals = ledger.get("cutover_evidence") or {}
    for name in forced_holds:
        if type(gates.get(name)) is not bool:
            problems.append(f"{name}: explicit boolean cutover state required")
        if gates.get(name) is True:
            receipt = approvals.get(name)
            if not isinstance(receipt, dict) or set(receipt) != {"path", "sha256"}:
                problems.append(f"{name}: positive gate requires a frozen evidence reference")
            else:
                path = pathlib.Path(receipt["path"])
                if (path.is_absolute() or ".." in path.parts or
                        not path.as_posix().startswith("docs/qualification/") or
                        not (evidence_root / path).is_file() or
                        sha256(evidence_root / path) != receipt["sha256"]):
                    problems.append(f"{name}: frozen cutover receipt is invalid")
    replacement_ready = not problems and not unresolved and all(gates.get(k) is True for k in forced_holds)
    if ledger.get("full_replacement_claimed") is True and not replacement_ready:
        problems.append("Crosswalk falsely asserts full replacement before evidence gates pass")
        replacement_ready = False
    return {
        "schema": "hepta-dc-replacement-gate-v1",
        "original_dc_tool_count": len(EXPECTED_DC),
        "installed_hepta_tool_count": len(unique),
        "categories": dict(sorted(classifications.items())),
        "functional_parity_unresolved": unresolved,
        "requirements": list(forced_holds),
        "integrity_problems": problems,
        "full_dc_replacement_qualified": replacement_ready,
        "statement": (
            "Qualified for the exact described bounded actions only; vendor-specific "
            "operations cannot be silently represented as portable Hepta capabilities."
        ),
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=pathlib.Path, default=LEDGER)
    parser.add_argument("--contract", type=pathlib.Path, default=CONTRACT)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    ledger = json.loads(args.ledger.read_text())
    contract = json.loads(args.contract.read_text())
    value = evaluate(ledger, contract)
    result = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        if args.output.exists():
            raise ValueError("Refusing to overwrite a prior frozen gate report")
        args.output.write_text(result)
    print(result, end="")
    if value["integrity_problems"]:
        raise SystemExit(2)

if __name__ == "__main__":
    main()

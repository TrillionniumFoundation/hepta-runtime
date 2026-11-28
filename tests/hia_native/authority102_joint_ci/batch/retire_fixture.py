"""Retire only the exact fixture after complete files and process exit are read."""
from pathlib import Path
import os
from receipt_support import PIN, put, regular, read_json, require
import qualify_public as capture
import read_public


def retire(folder):
    folder = Path(folder)
    report = read_json(folder / "result.json")
    require(report["status"] == "PASS" and report["process"]["exit_code"] == 0
        and report["process"]["pipe_eof"] == {"stdout": True, "stderr": True}, "retirement before actual exit")
    root = Path(report["fixture"])
    require(root.is_absolute() and root.resolve(strict=True) == root, "exact owned fixture root")
    owned = capture.common.OwnedFixture(root)
    before = capture.whole_snapshot(owned)
    require(before == report["final_filesystem"], "fixture changed after complete captured final state")
    read_public.filesystem(before, str(root), report["effective_uid"])
    parent = capture.common.OwnedFixture(root.parent)
    removed = parent.remove_tree(os.fsencode(root))
    require(not root.exists() and not root.is_symlink(), "exact completed fixture was not retired")
    row = {"schema": "hepta.runtime.batch-public-fixture-retirement.v1", "status": "PASS",
        "fixture": str(root), "capture": PIN(regular(folder / "result.json")),
        "complete_final_snapshot": before, "removed": removed, "fixture_absent_after": True,
        "other_fixture_paths_touched": False}
    put(folder / "retirement.json", row)
    return row


def verify(folder, capture_report):
    folder = Path(folder)
    row = read_json(folder / "retirement.json")
    require(row["schema"] == "hepta.runtime.batch-public-fixture-retirement.v1" and row["status"] == "PASS"
        and row["fixture"] == capture_report["fixture"]
        and row["capture"] == PIN(regular(folder / "result.json"))
        and row["complete_final_snapshot"] == capture_report["final_filesystem"]
        and row["fixture_absent_after"] is True and row["other_fixture_paths_touched"] is False,
        "exact completed fixture retirement")
    nodes = row["complete_final_snapshot"][0]["nodes"]
    root = os.fsencode(row["fixture"])
    expected = {}
    for node in nodes:
        relative = bytes.fromhex(node["relative_hex"])
        path = root + (b"/" + relative if relative else b"")
        expected[path.hex()] = {"path_hex": path.hex(), **{key: node[key] for key in ("device", "inode", "mode")}}
    removed = row["removed"]
    require(type(removed) is list and len(removed) == len(expected)
        and len({item["path_hex"] for item in removed}) == len(expected)
        and {item["path_hex"]: item for item in removed} == expected,
        "retirement omitted or added a fixture object")
    seen = set()
    for item in removed:
        path = bytes.fromhex(item["path_hex"])
        require(all(not bytes.fromhex(name).startswith(path + b"/") or name in seen for name in expected),
            "retirement removed a parent before its captured child")
        seen.add(item["path_hex"])
    return {"status": "PASS", "retired_nodes": len(removed), "process_launches": 0}

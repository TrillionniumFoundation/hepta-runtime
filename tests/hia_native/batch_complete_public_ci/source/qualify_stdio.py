"""Exercise the real JSON-lines entry without private selectors."""
from pathlib import Path
import argparse
import json
import os
import time
import qualify_public as public

common, cases = public.common, public.cases


def requests(modern):
    rows = []
    if not modern:
        rows += [("initialize", cases.encode(cases.initialize(1)) + b"\n", True),
            ("initialized", b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n', False)]
    data = [
        ("typed-path-error", "batch_edit", {"path": [], "operations": []}),
        ("insert-start", "batch_edit", {"path": "target", "operations": [{"operation": "insert", "start": 0, "content": "hello"}]}),
        ("view-after-batch", "view", {"file_path": "target"}),
        ("insert-lines", "batch_edit", {"path": "target", "operations": [{"operation": "insert", "start": -1, "content": ["tail", "last"]}]}),
        ("undo-second", "text_editor", {"command": "undo_edit", "path": "target"}),
        ("undo-first", "text_editor", {"command": "undo_edit", "path": "target"}),
        ("empty-operations", "batch_edit", {"path": "target", "operations": []}),
        ("stale-line-id", "batch_edit", {"path": "target", "operations": [{"operation": "replace", "start": "1:00", "content": "bad"}]}),
        ("path-hoist", "batch_edit", {"operations": [{"path": "target", "operation": "insert", "start": 0, "content": "hoisted"}]}),
        ("undo-hoisted", "text_editor", {"command": "undo_edit", "path": "target"}),
        ("typed-content-error", "batch_edit", {"path": "target", "operations": [{"operation": "insert", "start": 0, "content": 7}]}),
        ("raw-value-content", "batch_edit", {"path": "target", "operations": [{"operation": "insert", "start": 0, "content": {"$serde_json::private::RawValue": '"raw"'}}]}),
        ("undo-raw-value", "text_editor", {"command": "undo_edit", "path": "target"}),
    ]
    for index, (name, tool, arguments) in enumerate(data):
        rows.append((name, cases.tool_wire(100 + index, cases.encode(arguments), name=tool, modern=modern), True))
    return rows


def execute(role, binary, fixture, output, era):
    binary, fixture, output = Path(binary).resolve(strict=True), Path(fixture).absolute(), Path(output).absolute()
    common.need(role in ("native", "original") and era in ("legacy", "modern"), "stdio lane")
    output.mkdir(parents=True, exist_ok=False)
    owned = common.OwnedFixture(fixture, create=True)
    tool = common.capture_tool(binary, output, role)
    actions = owned.actions([{"kind": "write", "path_hex": os.fsencode(fixture / "target").hex(),
        "data_hex": b"alpha\nbeta\n".hex()}])
    rows = requests(era == "modern")
    report = {"schema": "hepta.runtime.batch-public-stdio-capture.v1", "status": "RUNNING", "role": role,
        "era": era, "fixture": str(fixture), "effective_uid": os.geteuid(), "binary": tool,
        "case_count": len(rows), "completed_cases": 0, "events": [], "actions": actions,
        "driver_sources": {name: common.file_pin(Path(__file__).parent / name) for name in
            ("qualify_stdio.py", "qualify_public.py", "public_cases.py", "public_observations.py",
             "capture/capture_common.py", "capture/capture_fixture.py",
             "corpus/state_reference/observations.py", "corpus/state_reference/native_observations.py")},
        "private_selectors_used": False, "per_exchange_deadline_seconds": 60,
        "outer_lane_deadline_seconds": 180, "public_batch_qualified": False, "whole_runtime_replaced": False}
    started, provider, failed = time.monotonic(), None, True
    try:
        provider = common.RecordedPublicProcess(output / "process", binary, fixture, strace="/usr/bin/strace", trace=False) \
            if role == "native" else public.Original(output / "process", binary, fixture)
        for name, wire, response in rows:
            common.need(time.monotonic() - started < 180, "complete stdio lane exceeded 180 seconds")
            before = public.whole_snapshot(owned)
            if role == "native":
                row, replies = provider.exchange(wire, response_count=int(response))
                body = b"".join(replies)
                common.need(bool(body) == response and row["transport"] == ("response" if response else "notification"),
                    "actual complete stdio response")
                exchange = row["index"]
            else:
                record = provider.wire(0, wire, response)
                exchange, body = record["exchange"], record["wire"]
            after = public.whole_snapshot(owned)
            report["events"].append({"name": name, "exchange": exchange, "request": common.sha(wire),
                "response_hex": body.hex(), "before_filesystem": before, "after_filesystem": after})
            report["completed_cases"] += 1
        report["final_filesystem"] = public.whole_snapshot(owned)
        failed = False
    except BaseException as error:
        report["failure"] = repr(error)
        raise
    finally:
        close_error = None
        if provider is not None:
            try:
                report["process"] = provider.close(failed=failed)
            except BaseException as error:
                failed, close_error = True, error
                report["close_failure"] = repr(error)
        report.update(status="FAIL" if failed else "PASS", elapsed_seconds=time.monotonic() - started)
        common.check_tool(tool)
        (output / "result.json").write_bytes(common.canonical(report))
        if close_error is not None:
            raise close_error
    print(json.dumps({key: report[key] for key in ("status", "role", "era", "case_count", "completed_cases")}, sort_keys=True))
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--role", choices=("native", "original"), required=True)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--fixture", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--era", choices=("legacy", "modern"), required=True)
    a = p.parse_args()
    execute(a.role, a.binary, a.fixture, a.output, a.era)

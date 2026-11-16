"""Run full declared inputs through actual public HIA or current SDK sessions.

This driver supplies inputs, fixture actions, and read-only observations. It
does not compute a tool result. Each SDK exchange retains the original 60 s
deadline. The caller applies the independent complete-lane 180 s process gate.
"""
from pathlib import Path
import argparse
import gzip
import json
import os
import struct
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "capture"))
import capture_common as common
import capture_fixture as fixture_io
import public_cases as cases
import public_observations as observations

DOMAINS = {"typed-legacy": 417, "typed-modern": 417, "filesystem": 926, "session": 17}


def case_rows(domain, fixture):
    if domain in ("typed-legacy", "typed-modern"):
        return list(cases.typed_rows())
    if domain == "filesystem":
        return list(cases.body_rows(fixture))
    if domain == "session":
        return list(cases.session_rows(fixture))
    raise ValueError("unknown complete public domain")


def whole_snapshot(owned):
    owned.owned(os.fsencode(owned.root), allow_root=True)
    # The parent's read-only snapshot entry point is used for this exact child;
    # no sibling is listed or read and no mutation is delegated to that parent.
    parent = common.OwnedFixture(owned.root.parent)
    return parent.snapshot([os.fsencode(owned.root).hex()])


def cache_set(path, content):
    key, value = path.encode(), content.encode()
    return b"HVCACH01" + struct.pack("<5Q", 2, 0, len(key), len(value), 0) + key + value


class Native:
    def __init__(self, output, binary, cwd):
        self.io = fixture_io.RecordedFixtureProcess(output, binary, cwd, strace="/usr/bin/strace", trace=False)

    def observe(self):
        refs, bodies = [], []
        for session in (0, 1):
            row, body = self.io.call(session, 33, b"")
            common.need(row["header"]["native_return"] == 0, "actual native observer result")
            refs.append(row["index"]); bodies.append(body)
        row, shared = self.io.call(0, 41, b"")
        refs.append(row["index"])
        return {"exchanges": refs, "state": observations.native_state(bodies, shared)}

    def wire(self, session, raw, response):
        row, body = self.io.public(session, raw)
        common.need(bool(body) == response, "public native response presence differs from declared input shape")
        return {"exchange": row["index"], "wire": body}

    def seed(self, session, raw):
        row, body = self.io.call(session, 32, raw)
        common.need(body == b"HVCAR001" + b"\0" * 24 and row["header"]["native_return"] == 32,
            "actual native cache fixture setup failed")
        return {"exchange": row["index"], "wire": body}

    def close(self, failed):
        return self.io.close(failed=failed)


class Original:
    def __init__(self, output, binary, cwd, *, session_count=2):
        common.need(os.environ.get("GITHUB_ACTIONS") == "true", "original reference execution is CI-only")
        common.need(type(session_count) is int and session_count in (1, 2), "explicit original fixture session count")
        self.session_count = session_count
        extra = () if session_count == 2 else ("--fixture-single-session",)
        self.io = common.RecordedPublicProcess(output, binary, cwd, strace="/usr/bin/strace", trace=False, extra_argv=extra)
        self.sequence = 0

    def command(self, kind, session, raw=b"", response=False):
        command = {"id": self.sequence, "session": session, "kind": kind}
        if kind != "observe":
            command.update(wire_hex=raw.hex(), response=response)
        self.sequence += 1
        receipt, lines = self.io.exchange(cases.encode(command) + b"\n")
        common.need(receipt["transport"] == "response" and len(lines) == 1, "complete actual original fixture response")
        parsed = json.loads(lines[0])
        state = observations.original_state(parsed, command, session_count=self.session_count)
        body = bytes.fromhex(parsed["output_hex"])
        return {"exchange": receipt["index"], "wire": body, "state": state}

    def observe(self):
        row = self.command("observe", 0)
        common.need(row["wire"] == b"", "original observer emitted an unexpected result")
        return {"exchanges": [row["exchange"]], "state": row["state"]}

    def wire(self, session, raw, response):
        row = self.command("wire", session, raw, response)
        common.need(bool(row["wire"]) == response, "original SDK response presence differs from declared shape")
        return {key: row[key] for key in ("exchange", "wire")}

    def seed(self, session, raw):
        row = self.command("cache", session, raw)
        common.need(row["wire"] == b"HVCAR001" + b"\0" * 24, "actual original cache fixture setup failed")
        return {key: row[key] for key in ("exchange", "wire")}

    def close(self, failed):
        return self.io.close(failed=failed)


def pins(raw):
    return {"bytes": len(raw), "sha256": common.sha(raw)}


def execute(role, binary, fixture, output, domain):
    binary = Path(binary).resolve(strict=True)
    fixture, output = Path(fixture).absolute(), Path(output).absolute()
    common.need(role in ("native", "original") and domain in DOMAINS, "selected public provider/domain")
    common.need(not output.is_relative_to(fixture) and not fixture.is_relative_to(output), "fixture/evidence separation")
    output.mkdir(parents=True, exist_ok=False)
    owned = common.OwnedFixture(fixture, create=True)
    tool = common.capture_tool(binary, output, role)
    rows = case_rows(domain, fixture)
    common.need(len(rows) == DOMAINS[domain], "complete public input count")
    provider = None
    report = {"schema": "hepta.runtime.batch-public-complete-capture.v2", "status": "RUNNING", "role": role,
        "domain": domain, "case_count": len(rows), "fixture": str(fixture), "effective_uid": os.geteuid(),
        "binary": tool, "per_exchange_deadline_seconds": 60, "outer_lane_deadline_seconds": 180,
        "public_batch_qualified": False, "full_async_cancellation_qualified": False,
        "remote_sftp_qualified": False, "whole_runtime_replaced": False}
    report["driver_sources"] = {name: common.file_pin(ROOT / name) for name in
        ("qualify_public.py", "public_cases.py", "public_observations.py", "capture/capture_common.py",
         "capture/capture_fixture.py", "corpus/state_reference/native_observations.py",
         "corpus/state_reference/observations.py")}
    (output / "result.json").write_bytes(common.canonical(report))
    failed = True
    started = time.monotonic()
    stream = common.Stream(output / "events.jsonl.gz")
    completed = 0
    initial = []
    try:
        provider = (Native if role == "native" else Original)(output / "process", binary, fixture)
        # Both real SDK sessions are admitted before eventual EOF. The modern
        # lane keeps session 0 uninitialized until its first inline tool call.
        for session in ((1,) if domain == "typed-modern" else (0, 1)):
            for wire, response in ((cases.encode(cases.initialize(10 + session)) + b"\n", True),
                    (b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n', False)):
                record = provider.wire(session, wire, response)
                initial.append({"session": session, "input": pins(wire), "exchange": record["exchange"],
                    "response": pins(record["wire"])})
        for index, row in enumerate(rows):
            common.need(time.monotonic() - started < 180, "complete public lane exceeded 180 seconds")
            actions = owned.actions(row["actions"])
            seeds = []
            for seed in row.get("seed") or []:
                raw = cache_set(seed["path"], seed["content"])
                result = provider.seed(seed["session"], raw)
                seeds.append({"input": pins(raw), "exchange": result["exchange"], "response": pins(result["wire"])})
            before_tree = whole_snapshot(owned)
            before = provider.observe()
            wire = cases.tool_wire(1000 + index, row["raw_arguments"], name=row.get("tool", "batch_edit"),
                modern=domain == "typed-modern", metadata=row.get("metadata"))
            result = provider.wire(row.get("session", 0), wire, row["response"])
            recovery = None
            if not row["response"]:
                # A following actual response proves that a declared discard
                # did not hide a deferred reply or close this same session.
                ping = cases.encode({"jsonrpc": "2.0", "id": 100000 + index, "method": "ping"}) + b"\n"
                recovered = provider.wire(row.get("session", 0), ping, True)
                common.need(json.loads(recovered["wire"])["id"] == 100000 + index, "discard recovery returned a stale response")
                recovery = {"input": pins(ping), "exchange": recovered["exchange"], "response": pins(recovered["wire"])}
            after = provider.observe()
            after_tree = whole_snapshot(owned)
            cleanup_actions = owned.actions(row["after_actions"])
            after_cleanup_tree = whole_snapshot(owned)
            record = {"index": index, "name": row["name"], "domain": row["domain"],
                "original_case_id": row.get("original_case_id"), "session": row.get("session", 0),
                "input": pins(wire), "exchange": result["exchange"], "response": pins(result["wire"]),
                "actions": actions, "seeds": seeds, "before": before, "after": after,
                "before_filesystem": before_tree, "after_filesystem": after_tree,
                "after_actions": cleanup_actions, "after_cleanup_filesystem": after_cleanup_tree, "recovery": recovery}
            stream.write(common.canonical(record))
            completed += 1
        report["final_filesystem"] = whole_snapshot(owned)
        report["final_observation"] = provider.observe()
        failed = False
    except BaseException as error:
        report["failure"] = repr(error)
        raise
    finally:
        close_error = None
        if provider is not None:
            try:
                report["process"] = provider.close(failed)
            except BaseException as error:
                close_error = error
                failed = True
                report["close_failure"] = repr(error)
        report.update(status="FAIL" if failed else "PASS", completed_cases=completed, initial=initial,
            events=stream.close(), elapsed_seconds=time.monotonic() - started)
        common.check_tool(tool)
        (output / "result.json").write_bytes(common.canonical(report))
        if close_error is not None:
            raise close_error
    print(json.dumps({key: report[key] for key in ("status", "role", "domain", "case_count", "completed_cases", "elapsed_seconds")}, sort_keys=True))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("native", "original"), required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--domain", choices=DOMAINS, required=True)
    args = parser.parse_args()
    execute(args.role, args.binary, args.fixture, args.output, args.domain)

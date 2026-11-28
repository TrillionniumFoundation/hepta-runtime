"""Read every byte of the additional actual public JSON-lines gate."""
from pathlib import Path
from receipt_support import PIN, regular, require
import read_public as full
import qualify_stdio as capture

DRIVERS = {"qualify_stdio.py", "qualify_public.py", "public_cases.py", "public_observations.py",
    "capture/capture_common.py", "capture/capture_fixture.py",
    "corpus/state_reference/observations.py", "corpus/state_reference/native_observations.py"}


class Capture:
    file, json = full.Capture.file, full.Capture.json

    def __init__(self, folder, source, binary):
        self.folder, self.source = Path(folder).resolve(strict=True), Path(source).resolve(strict=True)
        self.artifacts = {}
        self.report = self.json("result.json")
        r = self.report
        self.role = r["role"]
        require(r["schema"] == "hepta.runtime.batch-public-stdio-capture.v2" and r["status"] == "PASS"
            and self.role in ("native", "original") and r["era"] in ("legacy", "modern")
            and r["original_fixture_sessions"] == (1 if self.role == "original" else None)
            and r["private_selectors_used"] is False and r["public_batch_qualified"] is False
            and r["whole_runtime_replaced"] is False and r["per_exchange_deadline_seconds"] == 60
            and r["outer_lane_deadline_seconds"] == 180 and full.number(r["elapsed_seconds"], 180),
            "complete ordinary stdio capture")
        require(set(r["driver_sources"]) == DRIVERS, "executed stdio input closure")
        for name, identity in r["driver_sources"].items():
            require(PIN(regular(self.source / name)) == identity and
                regular(self.source / name) == regular(Path(__file__).parent / name), "stdio source identity")
        full.open_process(self, binary, single_reference_session=self.role == "original")
        self.rows = capture.requests(r["era"] == "modern")
        self.exchanges = self.json("process/exchanges.json")
        require(len(self.exchanges) == len(self.rows) == len(r["events"]) == r["case_count"] == r["completed_cases"]
            == self.process["exchanges"], "complete fixed stdio exchange set")
        expected_action = {"kind": "write", "path_hex": bytes(str(Path(r["fixture"]) / "target"), "utf-8").hex(),
            "data_hex": b"alpha\nbeta\n".hex()}
        full.Capture.actions(r["actions"], [expected_action])

    def records(self):
        for index, ((name, raw, response), event, exchange) in enumerate(zip(self.rows, self.report["events"], self.exchanges, strict=True)):
            require(event["name"] == name and event["exchange"] == index and event["request"] == full.common.sha(raw),
                "stdio input ordering")
            expected_keys = {"index", "deadline_seconds", "elapsed_seconds", "timed_out", "transport", "error",
                "attempted_input", "accepted_input", "stdout_range", "stderr_range", "responses", "stdout_eof", "stderr_eof"}
            require(set(exchange) == expected_keys and exchange["index"] == index and exchange["deadline_seconds"] == 60
                and full.number(exchange["elapsed_seconds"], 60) and exchange["timed_out"] is False
                and exchange["error"] is None and exchange["stdout_eof"] is False and exchange["stderr_eof"] is False,
                "actual complete public stdio exchange")
            if self.role == "native":
                wanted = raw
                command = None
                require(exchange["transport"] == ("response" if response else "notification"), "actual native public response presence")
            else:
                command = {"id": index, "session": 0, "kind": "wire", "wire_hex": raw.hex(), "response": response}
                wanted = full.cases.encode(command) + b"\n"
                require(exchange["transport"] == "response", "actual current SDK carrier response")
            for field, stream_name in (("attempted_input", "attempted-stdin"), ("accepted_input", "stdin")):
                stream = self.streams[stream_name]
                require(exchange[field] == {"offset": stream.offset, **PIN(wanted)} and stream.take(len(wanted)) == wanted,
                    "complete regenerated stdio request")
            for field, stream_name in (("stdout_range", "stdout"), ("stderr_range", "stderr")):
                span, stream = exchange[field], self.streams[stream_name]
                require(set(span) == {"offset", "bytes"} and span["offset"] == stream.offset, "contiguous public stream")
                chunk = stream.take(span["bytes"])
                if stream_name == "stderr":
                    require(chunk == b"", "ordinary public stderr must be empty")
                else:
                    output = chunk
            require(exchange["responses"] == ([PIN(output)] if output else []), "complete public output line")
            if output:
                require(output.endswith(b"\n") and b"\n" not in output[:-1], "one exact public JSON line")
                parsed = full.decode(output)
            if self.role == "original":
                full.observations.original_state(parsed, command, session_count=1)
                output = full.hex_bytes(parsed["output_hex"])
            require(bool(output) == response and full.hex_bytes(event["response_hex"]) == output, "actual SDK/public wire")
            trees = []
            for key in ("before_filesystem", "after_filesystem"):
                tree = full.filesystem(event[key], self.report["fixture"], self.report["effective_uid"])
                trees.append(tree)
            yield {"name": name, "request": raw, "wire": output,
                "filesystem": full.common.structural_snapshots(trees)}

    def finish(self):
        for name, stream in self.streams.items():
            rest = stream.identity["uncompressed"]["bytes"] - stream.offset
            require(rest == 0, "unclaimed public stdio stream tail: " + name)
            stream.finish()
        full.filesystem(self.report["final_filesystem"], self.report["fixture"], self.report["effective_uid"])
        return {"status": "PASS", "role": self.role, "era": self.report["era"], "actual_exchanges": len(self.rows),
            "private_selectors_used": False, "binary": self.binary, "process_launches": 0,
            "artifact_sha256": {name: item["sha256"] for name, item in sorted(self.artifacts.items())}}


def inspect(folder, source, binary):
    item = Capture(folder, source, binary)
    list(item.records())
    return item.finish()


def compare(native_folder, original_folder, source, native_binary, original_binary):
    left, right = Capture(native_folder, source, native_binary), Capture(original_folder, source, original_binary)
    require(left.role == "native" and right.role == "original" and left.report["era"] == right.report["era"]
        and left.report["fixture"] == right.report["fixture"] and left.report["effective_uid"] == right.report["effective_uid"],
        "ordinary public SDK paired fixture")
    count = 0
    for a, b in zip(left.records(), right.records(), strict=True):
        require(a == b, "ordinary public SDK difference: " + a["name"])
        count += 1
    a, b = left.finish(), right.finish()
    require(full.common.structural_snapshots([left.report["final_filesystem"]]) ==
        full.common.structural_snapshots([right.report["final_filesystem"]]), "ordinary public final filesystem")
    return {"status": "PASS", "actual_exchanges_per_provider": count, "native": a, "original": b,
        "process_launches": 0, "full_async_cancellation_qualified": False, "whole_runtime_replaced": False}

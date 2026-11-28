"""Complete portable native-pump capture admission and retained-original comparison."""
from pathlib import Path
import math
from common import ROOT, encoded, loads, pin, read, require, files, source
from callable_commands import commands
from protocol import cases
import read_callable_build
import read_callable
import read_transport_controls
import retained_original


def prepare(retained):
    return retained_original.prepare(retained)


def custody(root, metadata):
    rows = loads(read(root / "processes/processes.json"))
    expected = commands(metadata)
    require(metadata["commands"] == expected and len(rows) == len(expected) == 5,
            "complete fixed native producer process inventory")
    require(type(metadata["root_pid"]) is int and metadata["root_pid"] > 1 and
            type(metadata["root_pgid"]) is int and metadata["root_pgid"] > 1,
            "actual owning producer process")
    expected_files = {"processes.json"}
    output = {}
    for row, command in zip(rows, expected):
        name = command["name"]
        require(row["name"] == name and row["argv"] == command["argv"] and row["cwd"] == command["cwd"] and
                type(row["timeout_seconds"]) is int and row["timeout_seconds"] == command["timeout"] and
                row["exit_code"] == 0 and type(row["exit_code"]) is int and row["timed_out"] is False and
                row["completed"] is True and row["stdin"] is None and
                type(row["elapsed_seconds"]) in (int, float) and math.isfinite(row["elapsed_seconds"]) and
                0 < row["elapsed_seconds"] <= row["timeout_seconds"], "same complete invocation and unchanged deadline")
        require(all(type(row[k]) is int and row[k] > 1 for k in ("pid", "parent_pid", "pgid")) and
                row["pid"] == row["pgid"] and row["parent_pid"] == metadata["root_pid"] and
                row["pid"] != row["parent_pid"], "actual owned process group and parent custody")
        streams = {}
        for kind in ("stdout", "stderr"):
            filename = name + "." + kind
            raw = read(root / "processes" / filename)
            require(row[kind] == dict(file=filename, **pin(raw)), "complete actual process stream")
            streams[kind] = raw
            expected_files.add(filename)
        output[name] = dict(row=row, **streams)
    require(set(files(root / "processes")) == expected_files, "complete exact native process stream set")
    version = output["strace-version"]
    require(version["stdout"].startswith(b"strace -- version ") and version["stderr"] == b"",
            "actual independent syscall-observer version")
    report_names = {"native-build": "build/BUILD.json", "native-observed": "native-observed/NATIVE.json",
                    "native-observer-off": "native-observer-off/NATIVE.json",
                    "native-controls": "transport-controls/CONTROLS.json"}
    domain = cases(ROOT)
    markers = b"".join(("AUDIT_PUMP_%s %d %d\n" % (phase, ci, 1 + ci * 100 + si)).encode()
        for ci, case in enumerate(domain) for si in range(len(case["steps"])) for phase in ("BEGIN", "END"))
    for name, path in report_names.items():
        report = loads(read(root / path))
        require(output[name]["stdout"] == encoded(report), "entire actual stdout equals retained producer report")
        require(output[name]["stderr"] == (markers if name in ("native-observed", "native-observer-off") else b""),
                "all expected stderr markers, no unbound diagnostics")
        if name == "native-build":
            assembler = report["assembler"]
            expected_root = metadata["producer_root"] + "/build/assembler"
            require(assembler[0]["argv"] == ["/usr/bin/as", "--64", "--fatal-warnings", "-o",
                    expected_root + "/adapter.o", metadata["source_root"] + "/authoring/audit_record_callable.S"],
                    "actual assembler input/output are bound to the producer command roots")
            continue
        process = output[name]["row"]
        require(report["source_root"] == metadata["source_root"] and
                report["build_root"] == metadata["producer_root"] + "/build" and
                report["output_root"] == metadata["producer_root"] + "/" +
                ("transport-controls" if name == "native-controls" else name) and
                report["pgid"] == process["pid"] and report["uid"] == metadata["uid"] and
                report["gid"] == metadata["gid"], "all actual native process/capture roots and identity")
        if name == "native-observer-off":
            require(report["parent_pid"] == process["pid"] and type(report["pid"]) is int and
                    report["pid"] > 1 and report["pid"] != process["pid"],
                    "actual strace child remains in the original owned process group")
        else:
            require(report["pid"] == process["pid"] and report["parent_pid"] == process["parent_pid"],
                    "actual direct native process identity")
        key = "fixture" if name == "native-controls" else "root"
        require(report[key] == metadata["control_fixture" if name == "native-controls" else "owned_fixture"],
                "all actual owned fixture roots bound to immutable argv")
    return output


def verify(root, prepared):
    metadata = loads(read(root / "CAPTURE.json"))
    require(metadata["schema"] == "hepta.audit-record-callable.capture.v1" and metadata["status"] == "PASS" and
            metadata["source_manifest_sha256"] == source() and metadata["original_rust_replay"] == 0 and
            metadata["audit_trace_environment_absent"] is True and metadata["whole_audit_caller_qualified"] is False and
            metadata["public_handler_qualified"] is False and metadata["whole_runtime_replaced"] is False,
            "exact successful private native callable capture")
    require(files(root, ("CAPTURE.json",)) == metadata["files"], "every complete physical capture file and mode")
    require(files(root / "source") == files(ROOT), "the complete current frozen source is the actual producer source")
    process = custody(root, metadata)
    compiled = read_callable_build.verify(root / "build")
    image = compiled["image"]
    observed = read_callable.verify(root / "native-observed", image, observed=True)
    off = read_callable.verify(root / "native-observer-off", image, observed=False, peer=observed,
        trace=root / "native-observer-off.strace", stderr=root / "processes/native-observer-off.stderr")
    controls = read_transport_controls.verify(root / "transport-controls", image, observed)
    original_result = retained_original.compare(prepared, observed)
    require(original_result["original"]["durable_syscalls"] == off["observer_off_durable_syscalls"] == 608,
            "actual observer-off and retained original full durable order")
    concise = lambda value: {key: item for key, item in value.items()
                             if key not in ("observations", "events", "per_case_counts")}
    return dict(schema="hepta.audit-record-callable.readback.v1", status="PASS", source_manifest_sha256=source(),
        actual_producer_processes=5, fresh_build=compiled, observed=concise(observed), observer_off=concise(off),
        transport_controls=controls, retained_original=original_result,
        original_rust_replay=0, native_or_rust_executions=0, reader_writes=0,
        qualified_scope="native ordinary record I/O pump with complete observer-off retained-original comparison",
        archive_and_hot_cache_qualified=False, begin_finish_caller_qualified=False,
        public_handler_qualified=False, whole_runtime_replaced=False)

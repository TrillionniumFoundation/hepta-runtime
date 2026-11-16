"""Normal CI ownership for the shared public Batch graph and SDK comparison.

The public and observer executables are the registered runtime compositions.
This owner adds no alias image or builder. Native capture precedes a fresh
original build; all retained entry points read complete bytes without running
HIA, Rust, or a fixture reconstruction.
"""
from contextlib import contextmanager
from pathlib import Path
import hashlib
import importlib.util
import json
import math
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
import traceback

import hia_native_batch_public_fixtures as fixtures
from hia_native_runtime_mcp_evidence import decode
from hia_native_runtime_mcp_original import CARGO_SHA, RUSTC_SHA

FOLDER = "batch-public"
ORACLE = "tests/hia_native/batch_public_oracle"
NATIVE_TEST = "test_batch_public.py"
NATIVE_CONTROLS = "test_batch_public_evidence.py"
ORIGINAL_CHECK = "batch-public-original"
ORIGINAL_CONTROLS = "test_batch_public_original_evidence.py"
ORIGINAL_TEST = "test_batch_public_original.py"
READBACK_CHECK = "batch-public-retained-readbacks"
READBACK_DRIVER = ORACLE + "/main_readbacks.py"
PUBLIC_MANIFEST = "build/runtime_mcp-bundle/runtime-mcp/manifest.json"
PRIVATE_MANIFEST = "build/filesystem-public-bundle/runtime-mcp/manifest.json"
SOURCE_FILES = ("scripts/hia_native_batch_public_pipeline.py",
                "scripts/hia_native_batch_public_fixtures.py")


def need(value, message):
    if not value:
        raise ValueError("public Batch pipeline: " + message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                       allow_nan=False, separators=(",", ":")) + "\n").encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def exact(actual, expected, message):
    need(canonical(actual) == canonical(expected), message)


def regular(path):
    path = Path(path).absolute()
    need(path.resolve(strict=True) == path and stat.S_ISREG(path.lstat().st_mode),
         "owned regular input required: " + str(path))
    need(path.stat().st_uid == os.getuid(), "input belongs to a different account")
    return path


def pin(path):
    path = regular(path)
    with path.open("rb") as stream:
        return {"bytes": os.fstat(stream.fileno()).st_size,
                "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}


def object_at(path):
    value = decode(regular(path).read_bytes())
    canonical(value)
    return value


def write_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical(value))


def process(command, cwd, folder):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=False)
    start = time.monotonic_ns()
    child = None
    code, timed, error = None, False, None
    try:
        with (folder / "stdout.bin").open("xb") as stdout, (folder / "stderr.bin").open("xb") as stderr:
            child = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                code = child.wait(timeout=180)
            except subprocess.TimeoutExpired:
                timed = True
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                code = child.wait(timeout=5)
    except BaseException:
        error = traceback.format_exc()
    end = time.monotonic_ns()
    row = {"command": list(map(str, command)), "cwd": str(cwd),
           "pid": None if child is None else child.pid, "exit_code": code,
           "timed_out": timed, "start_error": error, "timeout_seconds": 180,
           "started_monotonic_ns": start, "finished_monotonic_ns": end,
           "elapsed_seconds": (end - start) / 1e9,
           "stdout": pin(folder / "stdout.bin"), "stderr": pin(folder / "stderr.bin")}
    write_new(folder / "PROCESS.json", row)
    need(code == 0 and not timed and error is None, "actual child failed; complete process evidence retained")
    need((folder / "stderr.bin").read_bytes() == b"", "actual child emitted unexpected diagnostics")
    return row


@contextmanager
def reader(root):
    """Confine the standalone reader's generic module names to this call."""
    folder = Path(root) / ORACLE / "readers"
    names = ("capture_format", "trace_evidence", "state_comparison", "strict_public")
    previous = {name: sys.modules.pop(name, None) for name in names}
    old_path = list(sys.path)
    try:
        sys.path.insert(0, str(folder))
        spec = importlib.util.spec_from_file_location("strict_public", folder / "strict_public.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules["strict_public"] = module
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.path[:] = old_path
        for name in names:
            sys.modules.pop(name, None)
            if previous[name] is not None:
                sys.modules[name] = previous[name]


def request(root, output):
    root, output = Path(root).absolute(), Path(output).absolute()
    base = output / FOLDER
    return {"qualification_source": str(root / ORACLE / "readers"),
            "native_source": str(root / ORACLE / "native"),
            "native_output": str(base / "native"),
            "native_receipt": str(base / "native-process/PROCESS.json"),
            "graph": str(base / "graph"),
            "original_source": str(root / ORACLE / "original"),
            "original_output": str(base / "original"),
            "original_receipt": str(base / "original-process/PROCESS.json"),
            "origins": [[str(root), str(root)], [str(output), str(output)]]}


def roots(root, output):
    prepared = object_at(Path(output) / FOLDER / "prepared.json")
    old_root, old_output = Path(prepared["source_root"]), Path(prepared["output_root"])
    need(old_root.is_absolute() and old_output.is_absolute() and
         ".." not in old_root.parts and ".." not in old_output.parts,
         "canonical recorded execution roots")
    req = request(old_root, old_output)
    req["origins"] = [[str(old_root), str(Path(root).absolute())],
                      [str(old_output), str(Path(output).absolute())]]
    return prepared, old_root, old_output, req


def raw_native(root, req):
    native = {k: req[k] for k in ("qualification_source", "native_source", "native_output",
                                 "native_receipt", "graph", "origins")}
    native["causal_source"] = req["original_source"]
    with reader(root) as module:
        return module.native_evidence(**native)


def prepare(root, output, public_manifest, private_manifest):
    root, output = Path(root).absolute(), Path(output).absolute()
    public_manifest, private_manifest = Path(public_manifest).absolute(), Path(private_manifest).absolute()
    exact([str(public_manifest), str(private_manifest)],
          [str(output / PUBLIC_MANIFEST), str(output / PRIVATE_MANIFEST)], "registered shared graph locations")
    import qualify_hia_runtime_native as qualification
    need(qualification.ROOT == root, "actual qualification checkout differs")
    table = {name: pin(root / name) for name in qualification.sources()}
    exact({n: p["sha256"] for n, p in table.items()}, qualification.sources(),
          "complete source closure changed during graph binding")
    base = output / FOLDER
    base.mkdir(parents=True, exist_ok=False)
    graph = {"schema": "hepta.runtime.batch-public-main-graph.v1", "runtime_root": str(root),
             "source_files": table,
             "public_manifest": {"path": str(public_manifest), **pin(public_manifest)},
             "private_manifest": {"path": str(private_manifest), **pin(private_manifest)}}
    write_new(base / "graph/GRAPH.json", graph)
    write_new(base / "prepared.json", {"schema": "hepta.runtime.batch-public-main-prepared.v1",
              "source_root": str(root), "output_root": str(output), "python": sys.executable,
              "graph": pin(base / "graph/GRAPH.json"), "whole_runtime_replaced": False})
    write_new(base / "REQUEST.json", request(root, output))


def test_commands(root, output, report, *, strace="/usr/bin/strace"):
    root, output = Path(root), Path(output)
    exact([report["modules"][k]["manifest"] for k in ("runtime_mcp", "filesystem_public")],
          [PUBLIC_MANIFEST, PRIVATE_MANIFEST], "registered public and private compositions")
    prefix = [sys.executable, "-I", "-B"]
    return {NATIVE_TEST: [*prefix, str(root / "tests/hia_native" / NATIVE_TEST),
                         "--output", str(output), "--public-manifest", str(output / PUBLIC_MANIFEST),
                         "--fixture-manifest", str(output / PRIVATE_MANIFEST), "--strace", strace],
            NATIVE_CONTROLS: [*prefix, str(root / "tests/hia_native" / NATIVE_CONTROLS),
                              "--output", str(output)]}


def run_native(root, output, public_manifest, private_manifest, strace):
    root, output = Path(root).absolute(), Path(output).absolute()
    prepare(root, output, public_manifest, private_manifest)
    req = request(root, output)
    source = Path(req["native_source"])
    command = [sys.executable, "-I", "-B", str(source / "capture_native.py"),
               "--source", str(source), "--graph", req["graph"],
               "--output", req["native_output"], "--strace", str(strace)]
    process(command, source, output / FOLDER / "native-process")
    admitted = raw_native(root, req)
    write_new(output / FOLDER / "NATIVE-EVIDENCE.json", admitted)
    retirement = fixtures.native(output, str(output), admitted, create=True)
    write_new(output / FOLDER / "NATIVE-RETIREMENT.json", retirement)
    summary = {"schema": "hepta.runtime.batch-public-main-native.v1", "status": "PASS",
               "scenarios": 15, "steps": 133, "public_attempts": 123, "fixture_controls": 10,
               "evidence": pin(output / FOLDER / "NATIVE-EVIDENCE.json"),
               "fixture_retirement": pin(output / FOLDER / "NATIVE-RETIREMENT.json"),
               "execution_source_root": str(root), "execution_output_root": str(output),
               "errors": 0, "failures": 0, "skipped": 0,
               "fresh_original_comparison": False, "production_handler_complete": False,
               "whole_runtime_replaced": False}
    write_new(output / FOLDER / "NATIVE-SUMMARY.json", summary)
    print(json.dumps(summary, sort_keys=True))


class Inputs:
    def __init__(self, origins):
        self.origins = sorted([(Path(a), Path(b)) for a, b in origins],
                              key=lambda pair: len(pair[0].parts), reverse=True)
        self.artifacts = {}

    def file(self, path):
        path = Path(path)
        need(path.is_absolute() and ".." not in path.parts, "canonical recorded artifact name")
        for old, new in self.origins:
            if path == old or old in path.parents:
                return regular(new / path.relative_to(old))
        raise ValueError("public Batch input has no explicit retained root: " + str(path))

    def raw(self, path):
        raw = self.file(path).read_bytes()
        self.artifacts[str(path)] = {"bytes": len(raw), "sha256": sha(raw)}
        return raw

    def object(self, path):
        value = decode(self.raw(path))
        canonical(value)
        return value


def bind_graph(root, output, report, overrides=()):
    prepared, old_root, old_output, req = roots(root, output)
    req["origins"] = [*overrides, *req["origins"]]
    files = Inputs(req["origins"])
    prepared = files.object(old_output / FOLDER / "prepared.json")
    exact(sorted(prepared), sorted(("schema", "source_root", "output_root", "python", "graph", "whole_runtime_replaced")),
          "complete prepared graph fields")
    exact([prepared["schema"], prepared["source_root"], prepared["output_root"], prepared["whole_runtime_replaced"]],
          ["hepta.runtime.batch-public-main-prepared.v1", str(old_root), str(old_output), False],
          "actual selected graph execution roots")
    graph_raw = files.raw(old_output / FOLDER / "graph/GRAPH.json")
    exact({"bytes": len(graph_raw), "sha256": sha(graph_raw)}, prepared["graph"], "prepared graph bytes")
    graph = decode(graph_raw)
    exact(sorted(graph), sorted(("schema", "runtime_root", "source_files", "public_manifest", "private_manifest")),
          "complete graph binding fields")
    exact([graph["schema"], graph["runtime_root"]],
          ["hepta.runtime.batch-public-main-graph.v1", str(old_root)], "actual selected source root")
    exact({name: row["sha256"] for name, row in graph["source_files"].items()}, report["source_sha256"],
          "entire graph source closure differs from the registered qualification inputs")
    for name, expected in graph["source_files"].items():
        relative = Path(name)
        need(not relative.is_absolute() and ".." not in relative.parts and relative.as_posix() == name,
             "relative source path")
        raw = files.raw(old_root / relative)
        exact({"bytes": len(raw), "sha256": sha(raw)}, expected, "complete selected source bytes: " + name)
    for key, member, relative in (("public_manifest", "runtime_mcp", PUBLIC_MANIFEST),
                                  ("private_manifest", "filesystem_public", PRIVATE_MANIFEST)):
        selected = report["modules"][member]
        exact(selected["manifest"], relative, "registered shared graph path")
        raw = files.raw(old_output / relative)
        exact({"path": str(old_output / relative), "bytes": len(raw), "sha256": sha(raw)}, graph[key],
              "selected complete shared graph manifest")
        exact(sha(raw), selected["sha256"], "registered shared graph identity")
    saved_request = files.object(old_output / FOLDER / "REQUEST.json")
    exact({k: v for k, v in saved_request.items() if k != "origins"},
          {k: v for k, v in req.items() if k != "origins"}, "actual public Batch request roots")
    return prepared, old_root, old_output, req, files


def native_component(root, output, report, overrides=()):
    _, old_root, old_output, req, files = bind_graph(root, output, report, overrides)
    admitted = raw_native(root, req)
    exact(files.object(old_output / FOLDER / "NATIVE-EVIDENCE.json"), admitted,
          "complete native evidence object")
    if overrides:
        from unittest.mock import patch
        original = fixtures.archive.artifact

        def artifact(base, name):
            if Path(base).absolute() == Path(output).absolute():
                return files.file(old_output / name)
            return original(base, name)

        with patch.object(fixtures.archive, "artifact", artifact):
            retirement = fixtures.native(output, str(old_output), admitted)
    else:
        retirement = fixtures.native(output, str(old_output), admitted)
    exact(files.object(old_output / FOLDER / "NATIVE-RETIREMENT.json"), retirement,
          "complete native fixture retirement")
    return admitted, retirement, files


def minimal_report(output):
    graph = object_at(Path(output) / FOLDER / "graph/GRAPH.json")
    return {"source_sha256": {n: v["sha256"] for n, v in graph["source_files"].items()},
            "modules": {"runtime_mcp": {"manifest": PUBLIC_MANIFEST, "sha256": graph["public_manifest"]["sha256"]},
                        "filesystem_public": {"manifest": PRIVATE_MANIFEST, "sha256": graph["private_manifest"]["sha256"]}}}


def wrapper(output, report, completed, name, command, expected, *, phase):
    rows = [row for row in report.get("checks", ()) if row.get("name") == name]
    need(len(rows) == 1, "exactly one actual wrapper is required: " + name)
    row = rows[0]
    exact(row.get("command"), command, "actual wrapper argv: " + name)
    exact(row.get("phase"), phase, "actual wrapper phase: " + name)
    elapsed = row.get("elapsed_seconds")
    need(type(row.get("exit_code")) is int and row["exit_code"] == 0
         and row.get("timed_out") is False and not row.get("start_error")
         and type(row.get("timeout_seconds")) is int and row["timeout_seconds"] == 180
         and type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 < elapsed <= 180,
         "wrapper failed or changed its deadline: " + name)
    for stream in ("stdout", "stderr"):
        raw = regular(Path(output) / (name + "." + stream)).read_bytes()
        exact({"bytes": row.get(stream + "_bytes"), "sha256": row.get(stream + "_sha256")},
              {"bytes": len(raw), "sha256": sha(raw)}, "complete actual wrapper stream")
        if stream == "stderr":
            need(raw == b"", "wrapper emitted diagnostics")
        else:
            exact(decode(raw), expected, "complete actual wrapper summary")
    exact(row.get("summary"), expected, "recorded wrapper summary copy")
    if completed is not None:
        exact(list(completed(Path(output), report, name)), [row, expected], "completed wrapper callback")
    return row


def artifact_inventory(root, output, old_root, old_output, artifacts, added=()):
    sources, retained = {}, {}
    files = Inputs([(str(old_root), str(root)), (str(old_output), str(output))])
    for name, expected in artifacts.items():
        path = Path(name)
        actual = pin(files.file(path))
        exact(actual, expected, "retained complete artifact changed: " + name)
        if old_root in path.parents:
            sources[str(path.relative_to(old_root))] = actual["sha256"]
        elif old_output in path.parents:
            retained[str(path.relative_to(old_output))] = actual
        else:
            raise ValueError("retained public Batch artifact escaped declared roots")
    for name in added:
        path = Path(name)
        need(not path.is_absolute() and ".." not in path.parts, "relative retained artifact")
        retained[name] = pin(Path(output) / name)
    return sources, {n: row["sha256"] for n, row in sorted(retained.items())}, [
        {"path": n, **row} for n, row in sorted(retained.items())]


NATIVE_CONTROL_NAMES = ("graph-source-omission", "graph-unexecuted-root", "native-source-byte",
                        "private-elf-byte", "native-process-timeout", "native-process-boolean-pid",
                        "missing-native-blob", "native-fixture-archive-byte")


def native_mutations(name, files, old_root, old_output, admitted):
    base = old_output / FOLDER
    graph_path, prepared_path = base / "graph/GRAPH.json", base / "prepared.json"
    if name in ("graph-source-omission", "graph-unexecuted-root"):
        graph = files.object(graph_path)
        if name == "graph-source-omission":
            graph["source_files"].pop(sorted(graph["source_files"])[0])
        else:
            graph["runtime_root"] = str(old_root.with_name(old_root.name + "-never-executed"))
        raw = canonical(graph)
        prepared = files.object(prepared_path)
        prepared["graph"] = {"bytes": len(raw), "sha256": sha(raw)}
        return [(graph_path, raw), (prepared_path, canonical(prepared))]
    if name == "native-source-byte":
        target = old_root / ORACLE / "native/capture_native.py"
    elif name == "private-elf-byte":
        target = Path(files.object(base / "native/RESULT.json")["native_elf"]["path"])
    elif name in ("native-process-timeout", "native-process-boolean-pid"):
        target = base / "native-process/PROCESS.json"
        value = files.object(target)
        value["timed_out" if name == "native-process-timeout" else "pid"] = True
        return [(target, canonical(value))]
    elif name == "missing-native-blob":
        names = sorted(n for n in admitted["artifact_sha256"]
                       if Path(n).parent == base / "native/blobs")
        need(names, "actual full native blob inventory")
        return [(Path(names[0]), None)]
    else:
        need(name == "native-fixture-archive-byte", "source-declared native control")
        target = base / "native-fixtures.bin.gz"
    raw = files.raw(target)
    need(raw, "actual nonempty mutation target")
    return [(target, bytes([raw[0] ^ 1]) + raw[1:])]


def reject_native(root, output, report, overrides):
    try:
        native_component(root, output, report, overrides)
    except (ValueError, KeyError, FileNotFoundError, UnicodeDecodeError, OSError, EOFError) as error:
        return {"exception": type(error).__name__, "message": str(error)}
    raise ValueError("corrupted complete public Batch native evidence was admitted")


def run_native_controls(root, output):
    root, output = Path(root).absolute(), Path(output).absolute()
    report = minimal_report(output)
    admitted, retirement, _ = native_component(root, output, report)
    _, old_root, old_output, req = roots(root, output)
    files = Inputs(req["origins"])
    folder = output / FOLDER / "native-controls"
    folder.mkdir(exist_ok=False)
    write_new(folder / "REFERENCE.json", report)
    started = time.monotonic_ns()
    rows = []
    for name in NATIVE_CONTROL_NAMES:
        target = folder / name
        target.mkdir()
        mutations, overrides = [], []
        for index, (origin, replacement) in enumerate(native_mutations(name, files, old_root, old_output, admitted)):
            original = files.raw(origin)
            physical = target / ("replacement-%02d.bin" % index)
            if replacement is not None:
                with physical.open("xb") as stream:
                    stream.write(replacement)
            mutations.append({"target": str(origin), "file": str(physical.relative_to(output)),
                              "before": {"bytes": len(original), "sha256": sha(original)},
                              "after": None if replacement is None else pin(physical)})
            overrides.append([str(origin), str(physical)])
        begin = time.monotonic_ns()
        refused = reject_native(root, output, report, overrides)
        end = time.monotonic_ns()
        row = {"name": name, "status": "REJECTED", **refused, "mutations": mutations,
               "started_monotonic_ns": begin, "finished_monotonic_ns": end}
        write_new(target / "RESULT.json", row)
        rows.append(row)
    exact(native_component(root, output, report)[:2], (admitted, retirement),
          "all original native inputs unchanged after physical controls")
    result = {"schema": "hepta.runtime.batch-public-main-native-controls.v1", "status": "PASS",
              "pid": os.getpid(), "command": sys.argv, "cwd": os.getcwd(),
              "started_monotonic_ns": started, "finished_monotonic_ns": time.monotonic_ns(),
              "reference": pin(folder / "REFERENCE.json"), "rows": rows,
              "new_native_calls": 0, "new_original_processes": 0}
    write_new(folder / "RESULT.json", result)
    summary = {"schema": result["schema"], "status": "PASS", "controls": len(rows),
               "evidence": pin(folder / "RESULT.json"), "new_native_calls": 0, "new_original_processes": 0,
               "errors": 0, "failures": 0, "skipped": 0}
    write_new(folder / "SUMMARY.json", summary)
    print(json.dumps(summary, sort_keys=True))


def native_control_evidence(root, output, report, admitted):
    _, old_root, old_output, req = roots(root, output)
    folder = Path(output) / FOLDER / "native-controls"
    value = object_at(folder / "RESULT.json")
    reference = object_at(folder / "REFERENCE.json")
    expected_reference = {"source_sha256": report["source_sha256"], "modules": {
        k: {field: report["modules"][k][field] for field in ("manifest", "sha256")}
        for k in ("runtime_mcp", "filesystem_public")}}
    exact(reference, expected_reference, "actual native controls used the registered source and graph identities")
    exact(value["reference"], pin(folder / "REFERENCE.json"), "complete native control input")
    exact([value[k] for k in ("schema", "status", "new_native_calls", "new_original_processes")],
          ["hepta.runtime.batch-public-main-native-controls.v1", "PASS", 0, 0], "native control boundary")
    exact(value["command"], [str(old_root / "tests/hia_native" / NATIVE_CONTROLS), "--output", str(old_output)],
          "actual source-owned native control command")
    exact(value["cwd"], str(old_root), "actual native control cwd")
    need(type(value["pid"]) is int and value["pid"] > 0, "actual native control process identity")
    begin, end = value["started_monotonic_ns"], value["finished_monotonic_ns"]
    need(type(begin) is type(end) is int and 0 < begin < end, "actual native control clocks")
    exact([row["name"] for row in value["rows"]], list(NATIVE_CONTROL_NAMES), "every declared native control")
    files = Inputs(req["origins"])
    added = [FOLDER + "/native-controls/" + n for n in ("RESULT.json", "REFERENCE.json", "SUMMARY.json")]
    previous = begin
    for row in value["rows"]:
        name = row["name"]
        case = folder / name
        exact(object_at(case / "RESULT.json"), row, "complete physical native control record")
        added.append(FOLDER + "/native-controls/" + name + "/RESULT.json")
        need(row["status"] == "REJECTED" and type(row["message"]) is str and row["message"],
             "actual native refusal diagnostic")
        start, finish = row["started_monotonic_ns"], row["finished_monotonic_ns"]
        need(type(start) is type(finish) is int and previous <= start < finish <= end,
             "native controls remain within their actual parent interval")
        previous = finish
        changes = native_mutations(name, files, old_root, old_output, admitted)
        need(len(changes) == len(row["mutations"]), "complete physical native mutations")
        overrides = []
        for i, ((target, expected), mutation) in enumerate(zip(changes, row["mutations"])):
            relative = FOLDER + "/native-controls/" + name + "/replacement-%02d.bin" % i
            exact([mutation["target"], mutation["file"]], [str(target), relative], "exact native mutation target")
            raw = files.raw(target)
            exact(mutation["before"], {"bytes": len(raw), "sha256": sha(raw)}, "complete native mutation preimage")
            physical = Path(output) / relative
            if expected is None:
                need(mutation["after"] is None and not os.path.lexists(physical), "actual missing native artifact")
            else:
                need(regular(physical).read_bytes() == expected, "complete source-declared native mutation")
                exact(pin(physical), mutation["after"], "complete native replacement bytes")
                added.append(relative)
            overrides.append([str(target), str(physical)])
        replay = reject_native(root, output, reference, overrides)
        exact(replay["exception"], row["exception"], "retained native corruption is still refused")
    summary = {"schema": value["schema"], "status": "PASS", "controls": len(value["rows"]),
               "evidence": pin(folder / "RESULT.json"), "new_native_calls": 0, "new_original_processes": 0,
               "errors": 0, "failures": 0, "skipped": 0}
    exact(object_at(folder / "SUMMARY.json"), summary, "complete native control summary")
    return value, summary, added


def native_evidence(root, output, report, completed):
    root, output = Path(root).absolute(), Path(output).absolute()
    prepared, old_root, old_output, req = roots(root, output)
    admitted, retirement, files = native_component(root, output, report)
    controls, control_summary, added = native_control_evidence(root, output, report, admitted)
    summary = {"schema": "hepta.runtime.batch-public-main-native.v1", "status": "PASS",
               "scenarios": 15, "steps": 133, "public_attempts": 123, "fixture_controls": 10,
               "evidence": pin(output / FOLDER / "NATIVE-EVIDENCE.json"),
               "fixture_retirement": pin(output / FOLDER / "NATIVE-RETIREMENT.json"),
               "execution_source_root": str(old_root), "execution_output_root": str(old_output),
               "errors": 0, "failures": 0, "skipped": 0,
               "fresh_original_comparison": False, "production_handler_complete": False,
               "whole_runtime_replaced": False}
    exact(object_at(output / FOLDER / "NATIVE-SUMMARY.json"), summary, "complete native summary")
    selected = object_at(output / FOLDER / "native/SELECTED-STRACE.json")
    commands = test_commands(old_root, old_output, report, strace=selected["path"])
    commands = {k: [prepared["python"], *v[1:]] for k, v in commands.items()}
    checks = [wrapper(output, report, completed, NATIVE_TEST, commands[NATIVE_TEST], summary, phase="native_components"),
              wrapper(output, report, completed, NATIVE_CONTROLS, commands[NATIVE_CONTROLS], control_summary,
                      phase="native_components")]
    exact([checks[1].get("pid"), checks[1].get("cwd")], [controls["pid"], str(old_root)],
          "native physical controls belong to their actual registered wrapper")
    raw_artifacts = {**admitted["artifact_sha256"], **files.artifacts}
    for name in retirement["artifact_sha256"]:
        raw_artifacts[str(old_output / name)] = pin(output / name)
    added += [FOLDER + "/" + name for name in ("prepared.json", "REQUEST.json", "graph/GRAPH.json",
              "NATIVE-EVIDENCE.json", "NATIVE-RETIREMENT.json", "NATIVE-SUMMARY.json")]
    added += [name + "." + stream for name in (NATIVE_TEST, NATIVE_CONTROLS) for stream in ("stdout", "stderr")]
    sources, artifacts, rows = artifact_inventory(root, output, old_root, old_output, raw_artifacts, added)
    return {"schema": "hepta.runtime.batch-public-main-native-qualification.v1", "status": "PASS",
            "execution_source_root": str(old_root), "execution_output_root": str(old_output),
            "native": admitted, "fixture_retirement": retirement, "native_controls": controls,
            "actual_wrappers": checks, "source_sha256": sources,
            "artifact_sha256": artifacts, "artifacts": rows,
            "fresh_original_comparison": False, "production_handler_complete": False,
            "public_async_dispatch_covered": False, "whole_runtime_replaced": False,
            "new_native_calls": 0, "new_original_processes": 0}


def selected_report(report):
    names = {NATIVE_TEST, NATIVE_CONTROLS, ORIGINAL_CHECK, ORIGINAL_CONTROLS}
    return {"source_sha256": report["source_sha256"],
            "modules": {key: {field: report["modules"][key][field]
                               for field in ("manifest", "sha256")}
                        for key in ("runtime_mcp", "filesystem_public")},
            "checks": [row for row in report["checks"] if row["name"] in names],
            "rust_compiler": report["rust_compiler"]}


def original_command(root, output, prepared):
    original = object_at(Path(output) / FOLDER / "ORIGINAL-PREPARED.json")
    return [prepared["python"], "-I", "-B", str(Path(root) / "tests/hia_native" / ORIGINAL_TEST),
            "--output", str(output), "--rustc", original["rustc"],
            "--cargo", original["cargo"], "--strace", original["strace"]]


def raw_original(root, req):
    with reader(root) as module:
        return module.evidence(**req)


def selected_tools(output, report):
    value = object_at(Path(output) / FOLDER / "original/TOOLS.json")
    selected = object_at(Path(output) / FOLDER / "ORIGINAL-PREPARED.json")
    for name, expected in (("rustc", RUSTC_SHA), ("cargo", CARGO_SHA)):
        row = value[name]
        exact(row["invocation"], selected[name], "actual selected original tool: " + name)
        exact(row["sha256"], expected, "fixed Rust 1.95 executable: " + name)
        exact(pin(Path(output) / FOLDER / "original" / ("tool-" + name)),
              {key: row[key] for key in ("bytes", "sha256")}, "entire retained original tool")
    exact([value["rustc"]["invocation"], value["rustc"]["sha256"]],
          [report["rust_compiler"]["invocation_path"],
           report["rust_compiler"]["invocation_executable_sha256"]],
          "same explicitly selected main Rust compiler")
    exact(value["strace"]["invocation"], selected["strace"], "selected original syscall observer")
    return value


def target_inventory(target):
    need(target.is_dir() and not target.is_symlink() and target.stat().st_uid == os.getuid(),
         "exclusive original Cargo target")
    result = {}
    for path in sorted(target.rglob("*")):
        info = path.lstat()
        need(info.st_uid == os.getuid() and not stat.S_ISLNK(info.st_mode),
             "Cargo target contains an unowned or linked entry")
        name = str(path.relative_to(target))
        if stat.S_ISREG(info.st_mode):
            result[name] = {"kind": "file", "mode": stat.S_IMODE(info.st_mode), **pin(path)}
        else:
            need(stat.S_ISDIR(info.st_mode), "Cargo target contains a nonregular build artifact")
            result[name] = {"kind": "directory", "mode": stat.S_IMODE(info.st_mode)}
    need(result, "actual fresh Cargo target cannot be empty")
    return result


def retire_target(output, binding):
    target = Path(output) / FOLDER / "original/target"
    table = target_inventory(target)
    receipt = {"schema": "hepta.runtime.batch-public-cargo-retirement.v1", "status": "PASS",
               "target": str(target), "entries": table,
               "complete_original_evidence_sha256": sha(canonical(binding)),
               "retained_reference": pin(target.parent / "reference.elf"),
               "retained_compiler_info": pin(target.parent / "target.rustc_info.json")}
    write_new(target.parent / "TARGET-RETIREMENT.json", receipt)
    exact(target_inventory(target), table, "Cargo intermediates unchanged before retirement")
    shutil.rmtree(target)
    need(not os.path.lexists(target), "fresh Cargo intermediates remain")


def original_component(root, output, report):
    prepared, old_root, old_output, req = roots(root, output)
    selected = object_at(Path(output) / FOLDER / "ORIGINAL-PREPARED.json")
    exact(sorted(selected), sorted(("schema", "source_root", "output_root", "rustc", "cargo", "strace")),
          "complete actual original invocation selection")
    exact([selected["schema"], selected["source_root"], selected["output_root"]],
          ["hepta.runtime.batch-public-main-original-prepared.v1", str(old_root), str(old_output)],
          "actual original source and output roots")
    reference = object_at(Path(output) / FOLDER / "ORIGINAL-REFERENCE.json")
    expected_reference = selected_report(report)
    expected_reference["checks"] = [row for row in expected_reference["checks"]
                                    if row["name"] in (NATIVE_TEST, NATIVE_CONTROLS)]
    exact(reference, expected_reference, "complete native-first original input reference")
    value = raw_original(root, req)
    exact(value, object_at(Path(output) / FOLDER / "ORIGINAL-EVIDENCE.json"),
          "complete original comparison object")
    native, retirement, _ = native_component(root, output, report)
    retired = fixtures.original(output, str(old_output), native, retirement, value)
    exact(retired, object_at(Path(output) / FOLDER / "ORIGINAL-RETIREMENT.json"),
          "entire original and reconstructed native fixture archive")
    target = object_at(Path(output) / FOLDER / "original/TARGET-RETIREMENT.json")
    exact({key: val for key, val in target.items() if key != "entries"}, {
        "schema": "hepta.runtime.batch-public-cargo-retirement.v1", "status": "PASS",
        "target": str(old_output / FOLDER / "original/target"),
        "complete_original_evidence_sha256": sha(canonical(value)),
        "retained_reference": pin(Path(output) / FOLDER / "original/reference.elf"),
        "retained_compiler_info": pin(Path(output) / FOLDER / "original/target.rustc_info.json")},
        "fresh Cargo intermediate retirement is bound to full admitted output")
    need(type(target["entries"]) is dict and target["entries"], "complete Cargo retirement inventory")
    for name, row in target["entries"].items():
        relative = Path(name)
        need(not relative.is_absolute() and ".." not in relative.parts and name == str(relative),
             "owned relative Cargo intermediate")
        need(row["kind"] in ("file", "directory") and type(row["mode"]) is int,
             "actual Cargo intermediate kind and mode")
        if row["kind"] == "file":
            need(type(row["bytes"]) is int and row["bytes"] >= 0 and
                 type(row["sha256"]) is str and len(row["sha256"]) == 64,
                 "complete retired Cargo intermediate pin")
    need(not os.path.lexists(Path(output) / FOLDER / "original/target"),
         "Cargo intermediates must remain absent during retained reads")
    selected_tools(output, report)
    summary = {"schema": "hepta.runtime.batch-public-main-original.v1", "status": "PASS",
               "actual_original_processes": 19, "fresh_locked_builds": 1,
               "sdk_processes": 15, "steps": 133, "public_attempts": 123,
               "original_evidence": pin(Path(output) / FOLDER / "ORIGINAL-EVIDENCE.json"),
               "fixture_retirement": pin(Path(output) / FOLDER / "ORIGINAL-RETIREMENT.json"),
               "cargo_retirement": pin(Path(output) / FOLDER / "original/TARGET-RETIREMENT.json"),
               "execution_source_root": str(old_root), "execution_output_root": str(old_output),
               "errors": 0, "failures": 0, "skipped": 0,
               "production_handler_complete": False, "whole_runtime_replaced": False}
    return value, retired, summary


def run_original(root, output, rustc, cargo, strace):
    root, output = Path(root).absolute(), Path(output).absolute()
    prepared, old_root, old_output, req = roots(root, output)
    exact([str(root), str(output)], [str(old_root), str(old_output)],
          "original replay requires actual execution roots")
    report = object_at(output / FOLDER / "ORIGINAL-REFERENCE.json")
    native = native_evidence(root, output, report, None)
    selected = object_at(output / FOLDER / "ORIGINAL-PREPARED.json")
    exact([str(rustc), str(cargo), str(strace)], [selected[n] for n in ("rustc", "cargo", "strace")],
          "actual original wrapper selection")
    exact(pin(rustc)["sha256"], RUSTC_SHA, "fixed selected Rust 1.95 binary")
    exact(pin(cargo)["sha256"], CARGO_SHA, "fixed selected Cargo 1.95 binary")
    fixtures.restore(output, str(output), native["native"], native["fixture_retirement"])
    source = root / ORACLE / "original"
    command = [prepared["python"], "-I", "-B", str(source / "run_original.py")]
    arguments = {"source": source, "native-source": req["native_source"],
                 "native-output": req["native_output"], "native-receipt": req["native_receipt"],
                 "graph": req["graph"], "output": req["original_output"],
                 "cargo": cargo, "rustc": rustc, "strace": strace}
    for key, value in arguments.items():
        command.extend(["--" + key, str(value)])
    process(command, source, output / FOLDER / "original-process")
    value = raw_original(root, req)
    write_new(output / FOLDER / "ORIGINAL-EVIDENCE.json", value)
    retired = fixtures.original(output, str(output), native["native"], native["fixture_retirement"],
                                value, create=True)
    write_new(output / FOLDER / "ORIGINAL-RETIREMENT.json", retired)
    retire_target(output, value)
    _, _, summary = original_component(root, output, report)
    write_new(output / FOLDER / "ORIGINAL-SUMMARY.json", summary)
    print(json.dumps(summary, sort_keys=True))


def original_control_evidence(root, output):
    _, _, old_output, req = roots(root, output)
    with reader(root) as module:
        spec = importlib.util.spec_from_file_location("_batch_public_main_controls",
                 Path(root) / ORACLE / "readers/qualification/consumer.py")
        consumer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(consumer)
        return consumer.controls_evidence(request=req, controls=old_output / FOLDER / "controls",
            receipt=old_output / FOLDER / "controls-process/PROCESS.json", origins=req["origins"])


def run_original_controls(root, output):
    root, output = Path(root).absolute(), Path(output).absolute()
    prepared, old_root, old_output, req = roots(root, output)
    exact([str(root), str(output)], [str(old_root), str(old_output)], "actual physical control roots")
    reference = object_at(output / FOLDER / "ORIGINAL-REFERENCE.json")
    original_component(root, output, reference)
    command = [prepared["python"], "-I", "-B", str(root / ORACLE / "readers/test_evidence.py"),
               "--request", str(output / FOLDER / "REQUEST.json"),
               "--baseline", str(output / FOLDER / "ORIGINAL-EVIDENCE.json"),
               "--output", str(output / FOLDER / "controls")]
    process(command, output / FOLDER, output / FOLDER / "controls-process")
    value = original_control_evidence(root, output)
    write_new(output / FOLDER / "ORIGINAL-CONTROLS-EVIDENCE.json", value)
    mirror = output / FOLDER / "controls/mirror"
    files = Inputs(req["origins"])
    table = {}
    for name, expected in value["artifact_sha256"].items():
        copied = mirror / Path(name).relative_to("/")
        if copied.is_file():
            exact(pin(copied), pin(files.file(name)), "derived control mirror retains admitted bytes")
            table[str(copied.relative_to(mirror))] = pin(copied)
    need(table, "actual complete-binding control mirror")
    write_new(output / FOLDER / "controls/MIRROR-RETIREMENT.json", {
        "schema": "hepta.runtime.batch-public-control-mirror-retirement.v1", "status": "PASS",
        "origin": str(mirror), "copied_files": table,
        "complete_controls_evidence_sha256": sha(canonical(value))})
    shutil.rmtree(mirror)
    summary = {"schema": "hepta.runtime.batch-public-main-original-controls.v1", "status": "PASS",
               "groups": 6, "controls": 36,
               "complete_evidence": pin(output / FOLDER / "ORIGINAL-CONTROLS-EVIDENCE.json"),
               "new_native_calls": 0, "new_original_processes": 0,
               "errors": 0, "failures": 0, "skipped": 0}
    write_new(output / FOLDER / "ORIGINAL-CONTROLS-SUMMARY.json", summary)
    print(json.dumps(summary, sort_keys=True))


def retained_base(root, output, report, completed=None):
    root, output = Path(root).absolute(), Path(output).absolute()
    prepared, old_root, old_output, _ = roots(root, output)
    native = native_evidence(root, output, report, completed)
    original, retirement, summary = original_component(root, output, report)
    exact(object_at(output / FOLDER / "ORIGINAL-SUMMARY.json"), summary, "complete original wrapper summary")
    controls = original_control_evidence(root, output)
    exact(controls, object_at(output / FOLDER / "ORIGINAL-CONTROLS-EVIDENCE.json"),
          "complete original control evidence object")
    control_summary = {"schema": "hepta.runtime.batch-public-main-original-controls.v1", "status": "PASS",
                       "groups": 6, "controls": 36,
                       "complete_evidence": pin(output / FOLDER / "ORIGINAL-CONTROLS-EVIDENCE.json"),
                       "new_native_calls": 0, "new_original_processes": 0,
                       "errors": 0, "failures": 0, "skipped": 0}
    exact(object_at(output / FOLDER / "ORIGINAL-CONTROLS-SUMMARY.json"), control_summary,
          "complete original control wrapper summary")
    mirror = object_at(output / FOLDER / "controls/MIRROR-RETIREMENT.json")
    expected_copies = {str(Path(name).relative_to("/")): row for name, row in original["artifact_sha256"].items()}
    exact(mirror, {"schema": "hepta.runtime.batch-public-control-mirror-retirement.v1", "status": "PASS",
                  "origin": str(old_output / FOLDER / "controls/mirror"), "copied_files": expected_copies,
                  "complete_controls_evidence_sha256": sha(canonical(controls))},
          "entire independently consumed physical control mirror retirement")
    need(not os.path.lexists(output / FOLDER / "controls/mirror"), "derived control mirror remains")
    command = original_command(old_root, output, prepared)
    command[command.index("--output") + 1] = str(old_output)
    checks = [wrapper(output, report, completed, ORIGINAL_CHECK, command, summary,
                      phase="original_rust_comparison"),
              wrapper(output, report, completed, ORIGINAL_CONTROLS,
                      [prepared["python"], "-I", "-B", str(old_root / "tests/hia_native" / ORIGINAL_CONTROLS),
                       "--output", str(old_output)], control_summary, phase="original_rust_comparison")]
    artifacts = {**controls["artifact_sha256"], **original["artifact_sha256"]}
    for name in (*native["artifact_sha256"], *retirement["artifact_sha256"]):
        artifacts[str(old_output / name)] = pin(output / name)
    added = [FOLDER + "/" + n for n in ("ORIGINAL-PREPARED.json", "ORIGINAL-REFERENCE.json",
             "ORIGINAL-EVIDENCE.json", "ORIGINAL-RETIREMENT.json", "ORIGINAL-SUMMARY.json",
             "ORIGINAL-CONTROLS-EVIDENCE.json", "ORIGINAL-CONTROLS-SUMMARY.json",
             "original/TARGET-RETIREMENT.json", "controls/MIRROR-RETIREMENT.json")]
    added += [name + "." + stream for name in (ORIGINAL_CHECK, ORIGINAL_CONTROLS) for stream in ("stdout", "stderr")]
    sources, artifacts, rows = artifact_inventory(root, output, old_root, old_output, artifacts, added)
    exact(sources, report["source_sha256"], "whole main source closure in original qualification")
    return {"schema": "hepta.runtime.batch-public-main-base-qualification.v1", "status": "PASS",
            "execution_source_root": str(old_root), "execution_output_root": str(old_output),
            "native": native, "original": original, "original_controls": controls["evidence_controls"],
            "original_fixture_retirement": retirement, "actual_original_wrappers": checks,
            "source_sha256": sources, "artifact_sha256": artifacts, "artifacts": rows,
            "fresh_original_comparison_complete": True, "actual_original_sdk_executed": True,
            "public_async_dispatch_covered": False, "ordinary_public_stdio_transport_covered": False,
            "production_handler_complete": False, "whole_runtime_replaced": False,
            "old_stack_removal_qualified": False, "production_activated": False,
            "new_native_calls": 0, "new_original_processes": 0}


def readback_evidence(root, output, report, baseline, completed=None):
    prepared, old_root, old_output, _ = roots(root, output)
    folder = Path(output) / FOLDER / "readbacks"
    value = object_at(folder / "RESULT.json")
    workspace = old_output.with_name(old_output.name + "-batch-public-readbacks")
    exact([value[key] for key in ("schema", "status", "workspace", "execution_source_root",
                                 "execution_output_root", "actual_absent_root_reads", "new_native_calls",
                                 "new_original_processes")],
          ["hepta.runtime.batch-public-main-readbacks.v1", "PASS", str(workspace), str(old_root),
           str(old_output), 2, 0, 0], "complete whole-main readback boundary")
    reference = selected_report(report)
    exact(object_at(folder / "REFERENCE.json"), reference, "actual complete readback reference")
    exact(object_at(folder / "BASELINE.json"), baseline, "actual full readback baseline")
    for name, field in (("REFERENCE.json", "reference"), ("BASELINE.json", "baseline"), ("COPY-PINS.json", "copy_pins")):
        exact(pin(folder / name), value[field], "complete actual readback input")
    copies = {"source/" + name: pin(Path(root) / name) for name in baseline["source_sha256"]}
    copies.update({"output/" + row["path"]: {k: row[k] for k in ("bytes", "sha256")}
                   for row in baseline["artifacts"]})
    exact(object_at(folder / "COPY-PINS.json"), copies, "entire source and artifact copy plan")
    before = value["root_identities_before"]
    exact(sorted(before), sorted((str(old_root), str(old_output))), "only the actual two roots were renamed")
    for row in before.values():
        exact(sorted(row), sorted(("device", "inode", "mode", "uid", "gid")), "complete root identity")
        need(all(type(v) is int and v >= 0 for v in row.values()) and stat.S_ISDIR(row["mode"]),
             "actual original root inode identity")
    exact(object_at(folder / "ROOTS-BEFORE.json"), before, "retained pre-rename root identities")
    exact(value["root_identities_after"], before, "both original root inodes were restored")
    exact(value["retired_copy_roots"], [str(workspace / ("read-" + str(i))) for i in (1, 2)],
          "only the two complete derived copies were retired")
    need(type(value["read_processes"]) is list and len(value["read_processes"]) == 2,
         "two actual independent child processes")
    previous = 0
    for index, row in enumerate(value["read_processes"], 1):
        directory = workspace / ("read-" + str(index))
        missing = [old_root, old_output] + ([workspace / "read-1"] if index == 2 else [])
        command = [prepared["python"], "-I", "-B", str(directory / "source" / READBACK_DRIVER),
                   "--read", "--index", str(index), "--output", str(directory / "output"),
                   "--reference", str(workspace / "REFERENCE.json"), "--baseline", str(workspace / "BASELINE.json"),
                   "--result", str(workspace / ("result-" + str(index)) / "EVIDENCE.json")]
        for path in missing:
            command.extend(["--absent", str(path)])
        process_row = row["process"]
        with reader(root) as module:
            module.actual_process(process_row, command, directory / "source")
        need(process_row["started_monotonic_ns"] >= previous, "readbacks are actually ordered")
        previous = process_row["finished_monotonic_ns"]
        process_folder, result_folder = folder / ("process-" + str(index)), folder / ("result-" + str(index))
        exact(object_at(process_folder / "PROCESS.json"), process_row, "actual readback receipt")
        exact(object_at(result_folder / "EVIDENCE.json"), baseline, "entire absent-root main qualification")
        result = object_at(result_folder / "READ.json")
        exact(row["result"], result, "actual readback result record")
        begin, end = result["started_monotonic_ns"], result["finished_monotonic_ns"]
        need(type(begin) is type(end) is int and
             process_row["started_monotonic_ns"] <= begin < end <= process_row["finished_monotonic_ns"],
             "actual pure read interval belongs to its child")
        exact(result, {"schema": "hepta.runtime.batch-public-main-absent-read.v1", "status": "PASS",
              "index": index, "pid": process_row["pid"], "command": command[3:],
              "cwd": str(directory / "source"), "started_monotonic_ns": begin, "finished_monotonic_ns": end,
              "complete_evidence": pin(result_folder / "EVIDENCE.json"),
              "copy_inventory_sha256": sha(canonical(copies)), "actual_absent_paths": list(map(str, missing)),
              "entire_object_equal": True, "native_execution_forbidden": True, "filesystem_writes_forbidden": True,
              "new_native_calls": 0, "new_original_processes": 0}, "complete independently executed readback")
        for stream in ("stdout", "stderr"):
            exact(pin(process_folder / (stream + ".bin")), process_row[stream], "complete readback child stream")
        exact(object_at(process_folder / "stdout.bin"), result, "whole actual readback stdout")
        need((process_folder / "stderr.bin").read_bytes() == b"", "readback child diagnostics")
        need(not os.path.lexists(folder / ("read-" + str(index))), "derived readback copy remains")
    need(not os.path.lexists(folder / "read-1-held"), "held first readback remains")
    summary = {"schema": value["schema"], "status": "PASS", "actual_absent_root_reads": 2,
               "complete_evidence": pin(folder / "RESULT.json"),
               "new_native_calls": 0, "new_original_processes": 0,
               "errors": 0, "failures": 0, "skipped": 0}
    exact(object_at(folder / "SUMMARY.json"), summary, "complete main readback summary")
    command = [prepared["python"], "-I", "-B", str(old_root / READBACK_DRIVER),
               "--output", str(old_output), "--reference", str(old_output / FOLDER / "READBACK-REFERENCE.json"),
               "--baseline", str(old_output / FOLDER / "READBACK-BASE.json")]
    check = wrapper(output, report, completed, READBACK_CHECK, command, summary, phase="original_rust_comparison")
    exact(object_at(Path(output) / FOLDER / "READBACK-REFERENCE.json"), reference, "actual readback parent reference")
    exact(object_at(Path(output) / FOLDER / "READBACK-BASE.json"), baseline, "actual readback parent baseline")
    expected_files = {"REFERENCE.json", "BASELINE.json", "COPY-PINS.json", "ROOTS-BEFORE.json", "RESULT.json", "SUMMARY.json"}
    expected_files.update("process-%d/%s" % (i, name) for i in (1, 2)
                          for name in ("PROCESS.json", "stdout.bin", "stderr.bin"))
    expected_files.update("result-%d/%s" % (i, name) for i in (1, 2) for name in ("EVIDENCE.json", "READ.json"))
    exact(sorted(str(path.relative_to(folder)) for path in folder.rglob("*") if path.is_file()),
          sorted(expected_files), "all retained readback files and no intermediate copies")
    added = [FOLDER + "/readbacks/" + name for name in sorted(expected_files)]
    added += [FOLDER + "/READBACK-REFERENCE.json", FOLDER + "/READBACK-BASE.json",
              READBACK_CHECK + ".stdout", READBACK_CHECK + ".stderr"]
    return value, check, added


def retained_original(root, output, report, completed=None):
    root, output = Path(root).absolute(), Path(output).absolute()
    base = retained_base(root, output, report, completed)
    reads, check, added = readback_evidence(root, output, report, base, completed)
    artifacts = {row["path"]: {key: row[key] for key in ("bytes", "sha256")} for row in base["artifacts"]}
    artifacts.update({name: pin(output / name) for name in added})
    return {"schema": "hepta.runtime.batch-public-main-original-qualification.v1", "status": "PASS",
            "complete_base": base, "actual_absent_root_readbacks": reads, "actual_readback_wrapper": check,
            "source_sha256": base["source_sha256"],
            "artifact_sha256": {name: row["sha256"] for name, row in sorted(artifacts.items())},
            "artifacts": [{"path": name, **row} for name, row in sorted(artifacts.items())],
            "fresh_original_comparison_complete": True, "actual_original_sdk_executed": True,
            "public_async_dispatch_covered": False, "ordinary_public_stdio_transport_covered": False,
            "production_handler_complete": False, "whole_runtime_replaced": False,
            "old_stack_removal_qualified": False, "production_activated": False,
            "new_native_calls": 0, "new_original_processes": 0}


def execute_original(root, output, report, rustc, *, record_check, completed, qualification_env=None):
    root, output, rustc = Path(root).absolute(), Path(output).absolute(), Path(rustc).absolute()
    prepared, old_root, old_output, _ = roots(root, output)
    exact([str(root), str(output)], [str(old_root), str(old_output)], "actual original qualification roots")
    native = native_evidence(root, output, report, completed)
    exact(native, report["batch_public_evidence"], "complete native-first public Batch qualification")
    strace = shutil.which("strace")
    need(strace is not None, "actual original syscall observer unavailable")
    strace = str(Path(strace).resolve())
    write_new(output / FOLDER / "ORIGINAL-PREPARED.json", {
        "schema": "hepta.runtime.batch-public-main-original-prepared.v1",
        "source_root": str(root), "output_root": str(output),
        "rustc": str(rustc), "cargo": str(rustc.with_name("cargo")), "strace": strace})
    write_new(output / FOLDER / "ORIGINAL-REFERENCE.json", selected_report(report))
    record_check(output, report, name=ORIGINAL_CHECK, command=original_command(root, output, prepared), timeout=180)
    command = [prepared["python"], "-I", "-B", str(root / "tests/hia_native" / ORIGINAL_CONTROLS),
               "--output", str(output)]
    record_check(output, report, name=ORIGINAL_CONTROLS, command=command, timeout=180)
    base = retained_base(root, output, report, completed)
    write_new(output / FOLDER / "READBACK-BASE.json", base)
    write_new(output / FOLDER / "READBACK-REFERENCE.json", selected_report(report))
    command = [prepared["python"], "-I", "-B", str(root / READBACK_DRIVER),
               "--output", str(output), "--reference", str(output / FOLDER / "READBACK-REFERENCE.json"),
               "--baseline", str(output / FOLDER / "READBACK-BASE.json")]
    record_check(output, report, name=READBACK_CHECK, command=command, timeout=180)
    return retained_original(root, output, report, completed)

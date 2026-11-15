"""Qualification wiring for the public filesystem graph and its real observer.

The ordinary service and private two-session carrier share freshly compiled
HIA images. The native stage has no original-response input. The original stage
rebuilds the unchanged Rust reference only after all native processes terminate.
"""
from pathlib import Path
import importlib.util
import json
import math
import os
import shutil
import stat
import sys

import hia_native_filesystem_public_reference_source as reference_source
from hia_native_filesystem_public_build import dual_build_evidence

KEY = "filesystem_public"
FOLDER = "filesystem-public"
PUBLIC_MANIFEST = "build/runtime_mcp-bundle/runtime-mcp/manifest.json"
FIXTURE_MANIFEST = "build/filesystem-public-bundle/runtime-mcp/manifest.json"
NATIVE_TEST = "test_filesystem_public.py"
ORIGINAL_CHECK = "filesystem-public-original"
CONTROLS_TEST = "test_filesystem_public_original_evidence.py"
DRIVERS = "tests/hia_native/filesystem_public"
PAIR = FOLDER + "/PAIR-BINDING.json"
BUILD = FOLDER + "/BUILD-EVIDENCE.json"
NATIVE_INVOCATION = FOLDER + "/native-invocation.json"
ORIGINAL_INVOCATION = FOLDER + "/original-invocation.json"
NATIVE_ADMISSION = FOLDER + "/NATIVE-ADMISSION.json"
PLAN = FOLDER + "/original-controls-plan.json"
DRIVER_FILES = ("capture_common.py", "capture_fixture.py", "native_capture.py", "replay_original.py",
                "strict_fixture.py", "strict_native.py", "strict_native_provenance.py",
                "strict_observations.py", "strict_original.py", "strict_trace.py", "strict_transport.py",
                "test_native_evidence.py")
SOURCE_FILES = (
    "scripts/hia_native_filesystem_public_build.py", "scripts/hia_native_filesystem_public_pipeline.py",
    "scripts/hia_native_filesystem_public_fixtures.py", "scripts/hia_native_filesystem_public_reference_source.py",
    "scripts/hia_native_runtime_mcp_fixtures.py", "scripts/hia_native_runtime_mcp_evidence.py",
    "tests/hia_native/test_filesystem_public.py", "tests/hia_native/test_filesystem_public_original.py",
    "tests/hia_native/test_filesystem_public_original_evidence.py",
    DRIVERS + "/source_manifest.json", DRIVERS + "/README.md",
    *(DRIVERS + "/" + name for name in DRIVER_FILES),
)


def need(value, message):
    reference_source.need(value, message)


def read(root, name):
    return reference_source.regular(root, name).read_bytes()


def object_at(root, name):
    return reference_source.decode(read(root, name))


def write_new(path, value):
    raw = reference_source.canonical(value)
    path = Path(path)
    if path.exists() or path.is_symlink():
        need(not path.is_symlink() and path.read_bytes() == raw, "existing qualification input differs: " + str(path))
    else:
        with path.open("xb") as stream:
            stream.write(raw)


def exact(left, right, label):
    need(reference_source.canonical(left) == reference_source.canonical(right), label)


def load(root, name, namespace):
    path = reference_source.regular(root, name)
    raw = path.read_bytes()
    spec = importlib.util.spec_from_file_location(namespace, path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def producer_sources(root):
    manifest = object_at(root, DRIVERS + "/source_manifest.json")
    exact(sorted(manifest), sorted(DRIVER_FILES), "complete frozen SDK producer/reader inventory")
    for name, expected in manifest.items():
        exact(reference_source.pin(read(root, DRIVERS + "/" + name)), expected,
              "frozen SDK producer/reader source: " + name)
    return manifest


def selected_strace():
    path = shutil.which("strace")
    need(path is not None, "the registered view partition requires an installed strace executable")
    return str(Path(path).absolute())


def invocation(root, output, phase, argv, command):
    need(phase in ("native", "original"), "unknown actual invocation phase")
    root, output = Path(root).absolute(), Path(output).absolute()
    need(Path.cwd() == root, "actual wrapper cwd differs from registered checkout")
    path = NATIVE_INVOCATION if phase == "native" else ORIGINAL_INVOCATION
    document = dict(schema="hepta.runtime.filesystem-public-wrapper-invocation.v1", phase=phase,
                    execution_source_root=str(root), execution_output_root=str(output),
                    pid=os.getpid(), argv=list(argv), python=sys.executable, python_version=sys.version,
                    cwd=str(Path.cwd()), exec_cwd=str(root / DRIVERS), exec_command=list(command),
                    cgroup=Path("/proc/self/cgroup").read_text())
    write_new(output / path, document)
    return document


def prepare_native(root, output, public_manifest, fixture_manifest):
    root, output = Path(root).absolute(), Path(output).absolute()
    need(Path(public_manifest) == output / PUBLIC_MANIFEST, "formal public build location")
    need(Path(fixture_manifest) == output / FIXTURE_MANIFEST, "formal observer build location")
    producer_sources(root)
    reference_source.materialize(root, output)
    build = dual_build_evidence(root, public_manifest, fixture_manifest)
    need(build.get("status") == "PASS", "public/observer build admission")
    public = reference_source.decode(Path(public_manifest).read_bytes())
    private = reference_source.decode(Path(fixture_manifest).read_bytes())
    need(public["source_binding"] == private["source_binding"], "shared source closure")
    binaries = {}
    for kind, manifest, bundle in (("public", Path(public_manifest), public),
                                   ("fixture", Path(fixture_manifest), private)):
        executable = manifest.parent / bundle["elf"]
        raw = executable.read_bytes()
        need(reference_source.pin(raw) == {"bytes": bundle["elf_bytes"], "sha256": bundle["elf_sha256"]},
             "built executable bytes")
        binaries[kind] = {"manifest": str(manifest), "manifest_sha256": reference_source.pin(manifest.read_bytes())["sha256"],
                          "elf": str(executable), "elf_bytes": len(raw),
                          "elf_sha256": reference_source.pin(raw)["sha256"]}
    pair = {"source_binding": public["source_binding"], "executables": binaries}
    write_new(output / PAIR, pair)
    write_new(output / BUILD, build)
    return pair


def producer_command(root, output, public_manifest, fixture_manifest, strace):
    root, output = Path(root).absolute(), Path(output).absolute()
    pair = object_at(output, PAIR)
    need(pair["executables"]["public"]["manifest"] == str(public_manifest)
         and pair["executables"]["fixture"]["manifest"] == str(fixture_manifest), "capture build pair differs")
    values = {
        "reference-source": output / reference_source.FOLDER,
        "reference-reader": root / reference_source.ORACLE / "strict_reference.py",
        "native-source": root, "native-build-result": output / PAIR,
        "fixture-build": fixture_manifest, "public-build": public_manifest,
        "fixture-binary": pair["executables"]["fixture"]["elf"],
        "public-binary": pair["executables"]["public"]["elf"],
        "output": output / FOLDER / "native",
        "strace": Path(strace).absolute(),
    }
    return [sys.executable, "-I", "-B", str(root / DRIVERS / "native_capture.py"),
            *(part for key, value in values.items() for part in ("--" + key, str(value)))]


def test_commands(root, output, report, *, strace=None):
    root, output = Path(root), Path(output)
    public = report["modules"]["runtime_mcp"]
    fixture = report["modules"][KEY]
    need(public["manifest"] == PUBLIC_MANIFEST and fixture["manifest"] == FIXTURE_MANIFEST,
         "registered public/observer manifest paths")
    need(fixture.get("builder") == KEY and fixture.get("source") == "native/filesystem_gateway.hepta",
         "registered private observer owner")
    return {NATIVE_TEST: [sys.executable, "-I", "-B", str(root / "tests/hia_native" / NATIVE_TEST),
                         "--output", str(output), "--public-manifest", str(output / PUBLIC_MANIFEST),
                         "--fixture-manifest", str(output / FIXTURE_MANIFEST),
                         "--strace", selected_strace() if strace is None else str(Path(strace).absolute())]}


def mapper(root, output, old_root, old_output):
    """Read only the two admitted physical roots; never try an old-path fallback."""
    root, output = Path(root).absolute(), Path(output).absolute()
    pairs = [(Path(old_output), output, "output"), (output, output, "output"),
             (Path(old_root), root, "source"), (root, root, "source")]
    pairs.sort(key=lambda row: len(row[0].parts), reverse=True)
    artifacts = {"source": {}, "output": {}}
    cache = {}

    def select(path):
        path = Path(path)
        need(path.is_absolute() and ".." not in path.parts, "read origin is not absolute and owned")
        for origin, physical, kind in pairs:
            if path.is_relative_to(origin):
                name = path.relative_to(origin).as_posix()
                reference_source.relative(name)
                return physical, kind, name
        raise ValueError("FS public evidence: unmapped recorded origin: " + str(path))

    def read_bytes(path):
        physical, kind, name = select(path)
        key = (kind, name)
        if key not in cache:
            raw = read(physical, name)
            cache[key] = raw
            artifacts[kind][name] = reference_source.pin(raw)
        return cache[key]
    return read_bytes, select, artifacts


def stable_build(value, root, output, old_root, old_output):
    """Normalize only current reader locations, retaining actual receipt origins."""
    result = dict(value)
    entries = {}
    for name, info in value["artifacts"].items():
        path = Path(name)
        if path.is_relative_to(output):
            key = str(Path(old_output) / path.relative_to(output))
        elif path.is_relative_to(root):
            key = str(Path(old_root) / path.relative_to(root))
        else:
            key = name
        need(key not in entries or entries[key] == info, "colliding retained build artifact")
        entries[key] = info
    result["artifacts"] = dict(sorted(entries.items()))
    result["artifact_sha256"] = {name: info["sha256"] for name, info in sorted(entries.items())}
    return result


def original_arguments(root, output):
    root, output = Path(root).absolute(), Path(output).absolute()
    return dict(native_capture=output / FOLDER / "native", reference_source=output / reference_source.FOLDER,
                original_reader=root / reference_source.ORACLE / "strict_reference.py",
                producer_source=root / DRIVERS, native_source=root,
                build_reader=root / "scripts/hia_native_filesystem_public_build.py",
                build_primitive=root / "scripts/hia_native_runtime_mcp_evidence.py")


def wrapper(output, report, completed, name, command, expected):
    rows = [row for row in report.get("checks", ()) if row.get("name") == name]
    need(len(rows) == 1, "one actual complete wrapper: " + name)
    row = rows[0]
    exact(row.get("command"), command, "actual wrapper argv: " + name)
    exact(row.get("phase"), "native_components" if name == NATIVE_TEST else "original_rust_comparison",
          "actual wrapper phase: " + name)
    need(type(row.get("exit_code")) is int and row["exit_code"] == 0
         and row.get("timed_out") is False and row.get("timeout_seconds") == 180
         and type(row["timeout_seconds"]) is int and not row.get("start_error"),
         "actual wrapper completion/deadline: " + name)
    elapsed = row.get("elapsed_seconds")
    need(type(elapsed) in (float, int) and math.isfinite(elapsed) and 0 < elapsed <= 180,
         "actual finite wrapper elapsed: " + name)
    artifacts = {}
    streams = {}
    for kind in ("stdout", "stderr"):
        raw = read(output, name + "." + kind)
        wanted = {"bytes": row.get(kind + "_bytes"), "sha256": row.get(kind + "_sha256")}
        exact(reference_source.pin(raw), wanted, "complete actual wrapper stream: " + name)
        artifacts[name + "." + kind] = reference_source.pin(raw)
        streams[kind] = raw
    exact(reference_source.decode(streams["stdout"]), expected, "complete actual wrapper summary: " + name)
    exact(row.get("summary"), expected, "retained wrapper summary: " + name)
    need(streams["stderr"] == b"", "actual wrapper diagnostics: " + name)
    if completed is not None:
        exact(list(completed(output, report, name)), [row, expected], "completed wrapper callback: " + name)
    return row, artifacts


def native_evidence(root, output, report, completed):
    root, output = Path(root).absolute(), Path(output).absolute()
    producer_sources(root)
    reference = reference_source.verify_materialized(root, output)
    captured = object_at(output, FOLDER + "/native/SOURCE.json")
    native = object_at(output, FOLDER + "/native/NATIVE.json")
    actual = object_at(output, NATIVE_INVOCATION)
    old_root, old_output = Path(actual["execution_source_root"]), Path(actual["execution_output_root"])
    for path in (old_root, old_output):
        need(path.is_absolute() and ".." not in path.parts, "actual source/output origin")
    exact(reference["proof"]["execution_source_root"], str(old_root), "reference source materialization origin")
    exact(reference["proof"]["execution_output_root"], str(old_output), "reference output materialization origin")
    exact(captured["native_source_root"], str(old_root), "native source origin")
    exact(captured["driver_source_root"], str(old_root / DRIVERS), "native producer origin")
    exact(captured["reference_source_root"], str(old_output / reference_source.FOLDER), "native reference-input origin")
    exact(captured["reference_reader"]["path"], str(old_root / reference_source.ORACLE / "strict_reference.py"),
          "native reference reader origin")
    exact(native["fixture_root"], str(old_output / FOLDER / "native/fixtures"), "actual owned fixture origin")
    pair = object_at(output, PAIR)
    reader, locate, mapped = mapper(root, output, old_root, old_output)
    for kind, key, relative in (("public", "runtime_mcp", PUBLIC_MANIFEST), ("fixture", KEY, FIXTURE_MANIFEST)):
        module = report["modules"][key]
        exact([module.get("manifest"), module.get("builder")], [relative, key], "formal dual build registration")
        exact(reference_source.pin(read(output, relative))["sha256"], module.get("sha256"), "formal dual build digest")
        exact(pair["executables"][kind]["manifest"], str(old_output / relative), "actual built manifest origin")
        exact(captured["builds"][kind]["path"], str(old_output / relative), "executed build manifest origin")
    build = dual_build_evidence(root, old_output / PUBLIC_MANIFEST, old_output / FIXTURE_MANIFEST,
                               read_bytes=reader)
    build = stable_build(build, root, output, old_root, old_output)
    exact(object_at(output, BUILD), build, "complete build proof retained before execution")
    sdk = load(root, DRIVERS + "/strict_native.py", "_hia_filesystem_public_native")
    admitted = sdk.native_evidence(**original_arguments(root, output), artifact_reader=reader)
    admitted = reference_source.decode(reference_source.canonical(admitted))
    need(admitted.get("status") == "PASS", "complete native-only SDK evidence")
    exact(native["counts"], dict(groups=12, scenarios=28, steps=332, public_calls=323, private_controls=9),
          "complete native SDK input domain")
    exact([native["actual_native_processes"], native["new_rust_processes"], native["fresh_compiles"]], [54, 0, 0],
          "actual capture process domain")
    exact(native["actual_tool_version_processes"], 1, "actual selected tracer version process")
    need(native["original_replayed"] is False and native["original_comparison_complete"] is False
         and native["all_processes_terminated"] is True, "native-only completed capture")
    command = [actual["python"], "-I", "-B", *actual["argv"]]
    expected_command = test_commands(old_root, old_output, report, strace=captured["strace"]["path"])[NATIVE_TEST]
    expected_command[0] = actual["python"]
    exact(command, expected_command, "source-owned wrapper invocation")
    exact([actual["schema"], actual["phase"], actual["cwd"], actual["exec_cwd"]],
          ["hepta.runtime.filesystem-public-wrapper-invocation.v1", "native", str(old_root), str(old_root / DRIVERS)],
          "actual wrapper identity")
    host = object_at(output, FOLDER + "/native/HOST.json")
    producer = object_at(output, FOLDER + "/native/remote-process.json")
    need(type(actual["pid"]) is int and actual["pid"] > 0 and actual["pid"] == producer["pid"],
         "exec preserved the actual wrapper process")
    exact(actual["cgroup"], producer["cgroup"], "actual same-process cgroup observation")
    exact(actual["exec_command"], [actual["python"], "-I", "-B", *producer["argv"]],
          "actual exec'd native producer command")
    exact(host["cwd"], actual["exec_cwd"], "actual exec'd native producer cwd")
    summary = {key: value for key, value in native.items() if key not in ("artifacts", "completed_case_ids")}
    check, outer = wrapper(output, report, completed, NATIVE_TEST, command, summary)
    artifacts = dict(mapped["output"])
    source_pins = dict(reference["source_sha256"])
    source_pins.update({name: info["sha256"] for name, info in mapped["source"].items()})
    for name in SOURCE_FILES:
        source_pins[name] = reference_source.pin(read(root, name))["sha256"]
    for name, info in native["artifacts"].items():
        path = FOLDER + "/native/" + name
        raw = read(output, path)
        exact(reference_source.pin(raw), info, "complete declared native capture artifact")
        artifacts[path] = reference_source.pin(raw)
    for name in (PAIR, BUILD, NATIVE_INVOCATION, FOLDER + "/native/NATIVE.json"):
        artifacts[name] = reference_source.pin(read(output, name))
    for name, digest in reference["artifact_sha256"].items():
        artifacts[name] = {"sha256": digest, "bytes": reference["artifact_bytes"][name]}
    artifacts.update(outer)
    exact({name: report.get("source_sha256", {}).get(name) for name in source_pins}, source_pins,
          "all formal native source identities")
    return dict(schema="hepta.runtime.filesystem-public-native-qualification.v1", status="PASS",
                execution_source_root=str(old_root), execution_output_root=str(old_output),
                native=admitted, build=build, reference_source=reference, actual_native_wrapper=check,
                source_sha256=dict(sorted(source_pins.items())),
                artifact_sha256={name: info["sha256"] for name, info in sorted(artifacts.items())},
                artifact_bytes={name: info["bytes"] for name, info in sorted(artifacts.items())},
                ordinary_native_processes=26, private_two_session_native_processes=28,
                actual_tracer_version_processes=1,
                public_attempts=323, private_fixture_controls=9,
                fresh_shared_member_compiles=58, additional_observer_member_compiles=0,
                original_comparison_complete=False, new_rust_processes=0,
                live_fixture_required=False, whole_runtime_replaced=False,
                old_stack_removal_qualified=False, production_activated=False)


def native_fixture_evidence(root, output, report, completed, *, create=False, native=None):
    import hia_native_filesystem_public_fixtures as fixtures
    native = native_evidence(root, output, report, completed) if native is None else native
    return fixtures.retirement(root, output, native, create=create)


def original_command(root, output, rustc, cargo, strace):
    root, output = Path(root).absolute(), Path(output).absolute()
    values = {"reference-source": output / reference_source.FOLDER,
              "reference-reader": root / reference_source.ORACLE / "strict_reference.py",
              "native-capture": output / FOLDER / "native", "native-admission": output / NATIVE_ADMISSION,
              "output": output / FOLDER / "original", "cargo": Path(cargo).absolute(),
              "rustc": Path(rustc).absolute(), "strace": Path(strace).absolute()}
    return [sys.executable, "-I", "-B", str(root / DRIVERS / "replay_original.py"),
            *(part for key, value in values.items() for part in ("--" + key, str(value)))]


def full_original(root, output, native):
    old_root, old_output = native["execution_source_root"], native["execution_output_root"]
    read_bytes, locate, files = mapper(root, output, old_root, old_output)
    sdk = load(root, DRIVERS + "/strict_native.py", "_hia_filesystem_public_complete")
    arguments = original_arguments(root, output)
    arguments.update(original_capture=Path(output) / FOLDER / "original", original_driver_source=Path(root) / DRIVERS)
    value = sdk.evidence(**arguments, artifact_reader=read_bytes)
    value = reference_source.decode(reference_source.canonical(value))
    for key in ("source_graph_admitted", "whole_original_response_and_state_comparison_complete",
                "syscall_and_continuation_evidence_admitted", "formal_fresh_member_qualification"):
        need(value.get(key) is True, "complete original qualification: " + key)
    need(value.get("status") == "PASS" and value.get("original_full_router_executed") is False,
         "original qualification scope")
    reference = value["comparison"]["original_evidence"]
    exact([reference["actual_processes"], reference["fresh_locked_builds"], reference["version_processes"],
           reference["actual_rust_replays"]], [32, 1, 3, 28], "fresh original process topology")
    return value


def relocation_inventory(plan, full, source, read_bytes):
    """Bind every role copy, including multiple copies of the same source.

    The frozen producer keeps the first role in its origin lookup, but keeps
    every physical role in copy_pins. Neither table may silently drop aliases.
    """
    origins, copies, pins = {}, {}, {}

    def add(origin, target):
        origin, target = Path(origin), Path(target)
        need(origin.is_absolute() and ".." not in origin.parts, "relocation source origin")
        name = target.as_posix()
        reference_source.relative(name)
        identity = reference_source.pin(read_bytes(origin))
        need(name not in pins or pins[name] == identity, "conflicting retained role copies")
        origins.setdefault(str(origin), name)
        copies[name] = str(origin)
        pins[name] = identity

    native_root = Path(plan["native_source"])
    producer = Path(plan["producer_source"])
    admission = ("strict_native.py", "strict_native_provenance.py", "strict_observations.py",
                 "strict_trace.py", "strict_original.py", "strict_fixture.py", "strict_transport.py",
                 "test_native_evidence.py")
    for name in admission:
        add(producer / name, Path("admission") / name)
    build_paths = {}
    for key, fallback in (("build_reader", "admission/dual_build_evidence.py"),
                          ("build_primitive", "admission/qualification-reader-v1.py")):
        origin = Path(plan[key])
        target = (Path("native-source") / origin.relative_to(native_root)
                  if origin.is_relative_to(native_root) else Path(fallback))
        add(origin, target)
        build_paths[key] = target.as_posix()
    add(plan["original_reader"], "original-reader/strict_reference.py")
    for name in (*full["provenance"]["exact_artifact_names"], "NATIVE.json"):
        add(Path(plan["native_capture"]) / name, Path("native") / name)
    for name in source["driver_sources"]:
        add(producer / name, Path("native-producer") / name)
    prefixes = (("reference-source/", "reference_source", "reference"),
                ("producer-source/", "original_driver_source", "original-producer"),
                ("original-capture/", "original_capture", "original"))
    for name in full["comparison"]["original_evidence"]["artifact_sha256"]:
        for prefix, key, destination in prefixes:
            if name.startswith(prefix):
                relative = name[len(prefix):]
                add(Path(plan[key]) / relative, Path(destination) / relative)
    for name in source["native_source_files"]:
        add(native_root / name, Path("native-source") / name)
    add(native_root / "native/runtime_mcp_sources.json", "native-source/native/runtime_mcp_sources.json")
    for index, origin in enumerate(full["build"]["artifacts"]):
        if not origin.startswith("build-reader/") and origin not in origins:
            add(origin, Path("external") / ("%04d" % index) / Path(origin).name)
    arguments = dict(native_capture="native", original_capture="original", reference_source="reference",
                     original_reader="original-reader/strict_reference.py", producer_source="native-producer",
                     original_driver_source="original-producer", native_source="native-source", **build_paths)
    blocked = [plan[key] for key in ("native_capture", "original_capture", "reference_source",
               "original_reader", "producer_source", "original_driver_source", "native_source",
               "build_reader", "build_primitive")]
    blocked.extend(full["build"]["artifacts"])
    return dict(files=origins, arguments=arguments, blocked_original_paths=sorted(set(blocked)),
                copy_pins=pins), copies


def controls_evidence(root, output, native, full, report, completed):
    root, output = Path(root).absolute(), Path(output).absolute()
    old_root, old_output = Path(native["execution_source_root"]), Path(native["execution_output_root"])
    prefix = FOLDER + "/original-controls"
    result = object_at(output, prefix + "/RESULT.json")
    wanted = dict(schema="hepta.runtime.filesystem-sdk-native-evidence-controls.v1", status="PASS",
                  groups=6, controls=42, actual_reader_child_processes=2, actual_native_processes=0,
                  actual_rust_processes=0, new_compiler_processes=0, formal_fresh_member_qualification=True,
                  fresh_cold_qualification=False,
                  whole_original_domain_cases=323, private_fixture_controls=9)
    exact({key: result.get(key) for key in wanted}, wanted, "complete physical refusal and relocation scope")
    elapsed = result.get("elapsed_seconds")
    need(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 < elapsed <= 180,
         "actual finite evidence-control elapsed")
    groups = dict(process_contract=8, receipt_semantics=13, observer_state=6, source_and_build=8,
                  files_and_json=5, whole_streams=2)
    exact(result["group_counts"], groups, "all actual refusal categories")
    baseline_raw = read(output, prefix + "/BASELINE.json")
    exact(reference_source.pin(baseline_raw), result["baseline"], "complete controls baseline bytes")
    exact(reference_source.decode(baseline_raw), full, "controls consumed complete current original evidence")
    native_baseline_raw = read(output, prefix + "/NATIVE-BASELINE.json")
    exact(reference_source.pin(native_baseline_raw), result["native_only_baseline"], "complete controls native-only baseline bytes")
    exact(reference_source.decode(native_baseline_raw), native["native"], "controls consumed complete native-only evidence")
    refusal_raw = read(output, prefix + "/REFUSALS.json")
    exact(reference_source.pin(refusal_raw), result["refusals"], "complete refusal stream")
    refused = reference_source.decode(refusal_raw)
    exact({key: refused[key] for key in ("groups", "actual_native_processes", "actual_rust_processes")},
          dict(groups=groups, actual_native_processes=0, actual_rust_processes=0), "refusal stream scope")
    events = refused["controls"]
    need(type(events) is list and len(events) == len({row["name"] for row in events}) == 42,
         "every distinct actual refusal")
    artifacts = {}

    def retained(name):
        path = prefix + "/" + name
        raw = read(output, path)
        artifacts[path] = reference_source.pin(raw)
        return raw

    for row in events:
        need(type(row.get("rejected")) is str and row["rejected"]
             and type(row.get("message")) is str and row["message"], "actual refusal exception")
        need(type(row.get("physical_files")) is dict and row["physical_files"], "actual changed evidence files")
        dt = row.get("elapsed_seconds")
        need(type(dt) in (int, float) and math.isfinite(dt) and 0 < dt <= 180, "finite actual refusal duration")
        reference_source.relative(row["name"])
        exact(reference_source.decode(retained("controls/" + row["name"] + "/REFUSAL.json")), row,
              "individual physical refusal receipt")
    exact({name: sum(row["group"] == name for row in events) for name in groups}, groups,
          "actual refusal counts independently derived")
    source = object_at(output, prefix + "/SOURCE.json")
    names = ("strict_native.py", "strict_native_provenance.py", "strict_observations.py", "strict_trace.py",
             "strict_original.py", "strict_fixture.py", "strict_transport.py", "test_native_evidence.py")
    pins = {name: reference_source.pin(read(root, DRIVERS + "/" + name)) for name in names}
    exact(source["files"], pins, "actual physical-control source closure")
    exact(result["source_files"], pins, "retained physical-control source closure")
    plan = object_at(output, PLAN)
    exact(source["actual_plan"], plan, "source-owned actual complete original-control plan")
    expected_plan = {key: str(value) for key, value in original_arguments(old_root, old_output).items()}
    expected_plan.update(original_capture=str(old_output / FOLDER / "original"), original_driver_source=str(old_root / DRIVERS))
    exact(plan, expected_plan, "fixed complete original-control inputs")
    processes, relocations = result["actual_processes"], result["relocations"]
    need(type(processes) is list and type(relocations) is list and len(processes) == len(relocations) == 2,
         "two actual independent relocated reader invocations")
    python = None
    for index, (process, relocated) in enumerate(zip(processes, relocations, strict=True), 1):
        name = "relocation-%d" % index
        copied = old_output / prefix / ("relocated-one" if index == 1 else "relocated-two")
        directory = old_output / prefix / name
        command = process["command"]
        need(type(command) is list and command and type(command[0]) is str and Path(command[0]).is_absolute(),
             "actual relocated Python invocation")
        if python is None:
            python = command[0]
        exact(command, [python, "-I", "-B", str(copied / "admission/test_native_evidence.py"),
                        "--relocation-child", str(copied), "--output", str(directory / "EVIDENCE.json")],
              "fixed actual relocated reader command")
        exact(process["cwd"], str(copied), "actual relocated reader cwd")
        need(type(process["exit_code"]) is int and process["exit_code"] == 0 and process["timed_out"] is False
             and type(process["timeout_seconds"]) is int and process["timeout_seconds"] == 180,
             "actual relocated reader completion")
        dt = process["elapsed_seconds"]
        need(type(dt) in (int, float) and math.isfinite(dt) and 0 < dt <= 180, "actual relocated reader duration")
        exact(reference_source.decode(retained(name + "/PROCESS.json")), process, "actual relocated receipt bytes")
        out, err = retained(name + "/stdout.bin"), retained(name + "/stderr.bin")
        exact([reference_source.pin(out), reference_source.pin(err)], [process["stdout"], process["stderr"]],
              "complete actual relocated reader streams")
        need(err == b"", "relocated reader emitted diagnostics")
        exact(reference_source.decode(out), dict(status="PASS", proof_sha256=reference_source.pin(reference_source.canonical(full))["sha256"],
              original_path_read_attempts=0, native_processes=0, rust_processes=0), "actual offline reader result")
        proof = retained(name + "/EVIDENCE.json")
        exact(reference_source.decode(proof), full, "complete relocated source/output object")
        native_proof = retained(name + "/NATIVE-EVIDENCE.json")
        exact(reference_source.decode(native_proof), native["native"], "complete relocated native-only object")
        exact(relocated, dict(root=str(copied), proof=reference_source.pin(proof), entire_object_equal=True,
                             native_only_proof=reference_source.pin(native_proof), native_only_original_output_open_denied=True,
                             original_path_reads_denied=True, live_fixture_required=False), "actual relocation scope")
    need(not (output / prefix / "relocated-one").exists() and not (output / prefix / "relocated-one").is_symlink(),
         "first relocated evidence root was not removed")
    mapping = reference_source.decode(retained("relocated-two/mapping.json"))
    read_bytes, _, _ = mapper(root, output, old_root, old_output)
    source = object_at(output, FOLDER + "/native/SOURCE.json")
    expected_mapping, copies = relocation_inventory(plan, full, source, read_bytes)
    exact(mapping, expected_mapping, "complete relocated artifact and role-copy inventory")
    for target, origin in copies.items():
        reference_source.relative(target)
        actual = retained("relocated-two/" + target)
        exact(reference_source.pin(actual), mapping["copy_pins"][target], "complete relocated copy identity")
        need(actual == read_bytes(Path(origin)), "relocated copy differs from fully admitted source/artifact")
    # Control receipts retain only relative bundle mappings. Their original
    # absolute names remain unchanged and are never opened by this reader.
    for name in ("RESULT.json", "SOURCE.json", "BASELINE.json", "NATIVE-BASELINE.json", "REFUSALS.json", "remote-process.json"):
        retained(name)
    check_command = [python, "-I", "-B", str(old_root / "tests/hia_native" / CONTROLS_TEST),
                     "--plan", str(old_output / PLAN), "--output", str(old_output / prefix)]
    summary = {key: result[key] for key in ("status", "groups", "controls", "actual_reader_child_processes", "elapsed_seconds")}
    check, outer = wrapper(output, report, completed, CONTROLS_TEST, check_command, summary)
    artifacts.update(outer)
    return result, check, artifacts


def retained_original(root, output, report, completed):
    root, output = Path(root).absolute(), Path(output).absolute()
    native = native_evidence(root, output, report, completed)
    exact(native, report.get("filesystem_public_evidence"), "native evidence before original admission")
    retired = native_fixture_evidence(root, output, report, completed, native=native)
    exact(retired, report.get("filesystem_public_fixture_retirement"), "native fixture admission before original")
    full = full_original(root, output, native)
    reference = full["comparison"]["original_evidence"]
    actual = object_at(output, ORIGINAL_INVOCATION)
    old_root, old_output = Path(native["execution_source_root"]), Path(native["execution_output_root"])
    original = object_at(output, FOLDER + "/original/ORIGINAL.json")
    rustc, cargo = original["rustc_executable"]["path"], original["cargo_executable"]["path"]
    strace = original["strace_executable"]["path"]
    exact(rustc, report["rust_compiler"]["invocation_path"], "same selected original compiler")
    command = [actual["python"], "-I", "-B", str(old_root / "tests/hia_native/test_filesystem_public_original.py"),
               "--output", str(old_output), "--rustc", rustc, "--cargo", cargo, "--strace", strace]
    exact([actual["python"], "-I", "-B", *actual["argv"]], command, "actual original wrapper command")
    exact([actual["schema"], actual["phase"], actual["execution_source_root"], actual["execution_output_root"],
           actual["cwd"], actual["exec_cwd"]],
          ["hepta.runtime.filesystem-public-wrapper-invocation.v1", "original", str(old_root), str(old_output),
           str(old_root), str(old_root / DRIVERS)], "actual original wrapper origin")
    producer = object_at(output, FOLDER + "/original/remote-process.json")
    exact(actual["pid"], producer["pid"], "same actual original exec process")
    exact(actual["cgroup"], producer["cgroup"], "actual original cgroup")
    exact(actual["exec_command"], [actual["python"], "-I", "-B", *producer["argv"]], "actual original exec argv")
    summary = {key: value for key, value in original.items() if key != "artifacts"}
    check, artifacts = wrapper(output, report, completed, ORIGINAL_CHECK, command, summary)
    import hia_native_filesystem_public_fixtures as fixtures
    reconstruction = fixtures.retained_original(output, native, retired)
    controls, control_check, control_artifacts = controls_evidence(root, output, native, full, report, completed)
    artifacts.update(control_artifacts)
    for name, digest in reference["artifact_sha256"].items():
        kind, relative = name.split("/", 1)
        if kind == "reference-source":
            target = reference_source.FOLDER + "/" + relative
        elif kind == "native-capture":
            target = FOLDER + "/native/" + relative
        elif kind == "original-capture":
            target = FOLDER + "/original/" + relative
        elif kind == "producer-source":
            exact(reference_source.pin(read(root, DRIVERS + "/" + relative))["sha256"], digest, "current original driver source")
            continue
        elif kind == "original-reader":
            exact(reference_source.pin(read(root, reference_source.ORACLE + "/" + relative))["sha256"], digest,
                  "current unchanged original reader")
            continue
        else:
            raise ValueError("unexpected original artifact namespace: " + kind)
        body = read(output, target)
        exact(reference_source.pin(body), {"bytes": reference["artifact_bytes"][name], "sha256": digest},
              "complete original artifact")
        artifacts[target] = reference_source.pin(body)
    exact(object_at(output, NATIVE_ADMISSION), native["native"], "the complete native admission supplied before Rust")
    need(read(output, NATIVE_ADMISSION) == read(output, FOLDER + "/original/NATIVE-ADMISSION.json"),
         "actual original retained its complete native predecessor")
    for name in (ORIGINAL_INVOCATION, PLAN, NATIVE_ADMISSION):
        artifacts[name] = reference_source.pin(read(output, name))
    for name, digest in reconstruction["artifact_sha256"].items():
        body = read(output, name)
        exact(reference_source.pin(body)["sha256"], digest, "complete original fixture archive")
        artifacts[name] = reference_source.pin(body)
    return dict(schema="hepta.runtime.filesystem-public-original-qualification.v1", status="PASS",
                native_evidence_sha256=reference_source.pin(reference_source.canonical(native))["sha256"],
                original=full, controls=controls, actual_original_wrapper=check, actual_controls_wrapper=control_check,
                native_fixture_retirement=retired, reconstruction=reconstruction,
                fresh_original_builds=1, actual_original_processes=32, actual_original_scenarios=28,
                complete_original_public_attempts=323, separate_private_fixture_controls=9,
                ordinary_stdio_attempts=317, ordinary_filesystem_controls=5,
                original_comparison_complete=True, source_sha256=native["source_sha256"],
                artifact_sha256={name: info["sha256"] for name, info in sorted(artifacts.items())},
                artifact_bytes={name: info["bytes"] for name, info in sorted(artifacts.items())},
                new_native_processes=0, new_rust_processes=0, live_fixture_required=False,
                whole_runtime_replaced=False, old_stack_removal_qualified=False, production_activated=False)


def execute_original(root, output, report, rustc, record_check, completed):
    root, output, rustc = Path(root).absolute(), Path(output).absolute(), Path(rustc).absolute()
    native = native_evidence(root, output, report, completed)
    exact(native, report.get("filesystem_public_evidence"), "native evidence before fresh original execution")
    retired = native_fixture_evidence(root, output, report, completed, native=native)
    exact(retired, report.get("filesystem_public_fixture_retirement"), "native fixture before fresh original execution")
    write_new(output / NATIVE_ADMISSION, native["native"])
    import hia_native_filesystem_public_fixtures as fixtures
    with fixtures.original_fixture(root, output, native, retired):
        command = [sys.executable, "-I", "-B", str(root / "tests/hia_native/test_filesystem_public_original.py"),
                   "--output", str(output), "--rustc", str(rustc), "--cargo", str(rustc.with_name("cargo")),
                   "--strace", selected_strace()]
        record_check(output, report, name=ORIGINAL_CHECK, command=command, timeout=180)
        # All actual process groups and their full streams are admitted before
        # any replay fixture is archived or the held native tree is restored.
        full_original(root, output, native)
    plan = original_arguments(root, output)
    plan.update(original_capture=output / FOLDER / "original", original_driver_source=root / DRIVERS)
    write_new(output / PLAN, {key: str(value) for key, value in plan.items()})
    command = [sys.executable, "-I", "-B", str(root / "tests/hia_native" / CONTROLS_TEST),
               "--plan", str(output / PLAN), "--output", str(output / FOLDER / "original-controls")]
    record_check(output, report, name=CONTROLS_TEST, command=command, timeout=180)
    return retained_original(root, output, report, completed)

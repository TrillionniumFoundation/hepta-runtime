"""Strict native binary64 and unchanged-original Bellman numerical evidence."""
from __future__ import annotations
import contextlib, gzip, hashlib, io, json, math, os, runpy, stat, struct, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FOLDER = "bellman-native"
REFERENCE = "tests/hia_native/bellman/reference/weight_bellman.rs"
ORIGINAL_COMMIT = "737acf6f901e46c57b0b4374e323e0d1132e0d49"
ORIGINAL_SHA256 = "254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7"
ORACLE_SHA256 = "0efec1261edbd1b49fdccf2519cd7d1f472c6f7bafae36e96bc66428fc29c34c"
MODULES = (
    {"key": "finite_binary64", "name": "finite-binary64", "source": "native/finite_binary64.hepta",
     "standalone": "filter", "manifest_env": "HIA_BINARY64_MANIFEST", "test": "test_finite_binary64.py"},
    {"key": "bellman_core", "name": "bellman-core", "source": "native/bellman_core.hepta",
     "standalone": "filter", "manifest_env": "HIA_BELLMAN_MANIFEST", "test": "test_bellman_core.py",
     "additional_tests": ("test_bellman_signed_zero.py",)},
)
SUITES = {
    "arithmetic": ("test_finite_binary64.py", "qualify_binary64.py", "finite_binary64"),
    "bellman": ("test_bellman_core.py", "qualify_bellman.py", "bellman_core"),
    "signed-zero": ("test_bellman_signed_zero.py", "qualify_signed_zero.py", "bellman_core"),
}
TESTS = tuple(row[0] for row in SUITES.values())
SCOPE = {"whole_handler_replaced": False, "whole_runtime_replaced": False,
         "production_activated": False, "old_stack_removal_qualified": False,
         "native_cases_added_by_reference": 0}
INPUT_PINS = {
    "arithmetic": (3979440, "96e7f081c93f05e928d63c29a2f206cbbd4c825c70ec4d5bef079fa1b7f262bb"),
    "bellman": (14699496, "baa93183b25f1990218cb04b36bf3850a1533f39ab0a8f385d3bd46c57a4450a"),
    "signed-zero": (93696, "0284e6240aac2a92424c0db558c9e8bfa2d40f814ac2ec9b0722b40b57fa8472"),
}
OUTPUT_PINS = {
    "arithmetic": (1326480, "7a65e997fb51d4d00c4fb93d8aade2b7e5272626c504c5dc4646708da210c82d"),
    "bellman": (917678, "81a09bb71a6b57116a1c936f9208dcf8f231e7da03d3e2f8123e4df03b163432"),
    "signed-zero": (18432, "8d32c174885e7205d203216f390ca81f5806d7b681305136eee4c7aed99e3877"),
}
COUNTS = {"arithmetic": 165810, "bellman": 299, "signed-zero": 64}
STATIC_NAMES = ("original-known", "original-ties", "original-maximum-4096")

def digest(raw): return hashlib.sha256(raw).hexdigest()
def identity(raw): return {"bytes": len(raw), "sha256": digest(raw)}
def read(path):
    path = Path(path).absolute()
    if path.resolve() != path or not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("Bellman evidence is not a regular unsymlinked file: " + str(path))
    return path.read_bytes()
def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError("duplicate Bellman evidence field")
            result[key] = value
        return result
    def finite(value): raise ValueError("nonfinite Bellman evidence field")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=finite)
def exact(actual, expected, message):
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if encode(actual) != encode(expected): raise ValueError(message)

def source_evidence(root=ROOT):
    root = Path(root).resolve()
    component_raw = read(root / "native/bellman_core_component.json")
    component = decode(component_raw)
    locations = {
        "finite_binary64.hepta": "native/finite_binary64.hepta",
        "bellman_core.hepta": "native/bellman_core.hepta",
        "bellman_core_abi.md": "native/bellman_core_abi.md",
        "hia_native_bellman_build.py": "scripts/hia_native_bellman_build.py",
        **{name: "tests/hia_native/bellman/" + name for name in (
            "qualify_binary64.py", "qualify_bellman.py", "qualify_signed_zero.py", "make_bellman_oracle.py")},
    }
    actual = {name: identity(read(root / path)) for name, path in locations.items()}
    exact(component.get("files"), actual, "Bellman component source closure differs")
    from hia_native_build import HEPTA_COMMIT
    if (component.get("original_commit") != ORIGINAL_COMMIT
            or component.get("original_sha256") != ORIGINAL_SHA256
            or component.get("compiler_commit") != HEPTA_COMMIT):
        raise ValueError("Bellman original/compiler pin differs")
    for key in ("production_call_sites_replaced", "whole_handler_replaced", "production_activated",
                "old_stack_removal_qualified"):
        if component.get(key) is not False: raise ValueError("unqualified Bellman production claim")
    inventory = decode(read(root / "native/migration.json"))
    target_raw = read(root / "native/migration_target.json")
    exact(inventory.get("migration_target"), {"path": "native/migration_target.json",
          "sha256": digest(target_raw)}, "Bellman migration target binding differs")
    target = decode(target_raw)
    if target.get("target_commit") != ORIGINAL_COMMIT:
        raise ValueError("Bellman original is not the declared migration target")
    rows = [row for row in target["source_files"] if row["path"] == "src/mcp/weight_bellman.rs"]
    original = read(root / REFERENCE)
    blob = hashlib.sha1(b"blob " + str(len(original)).encode() + b"\0" + original).hexdigest()
    if digest(original) != ORIGINAL_SHA256 or len(rows) != 1:
        raise ValueError("Bellman original reference copy differs")
    exact(rows[0], {"path": "src/mcp/weight_bellman.rs", "mode": "100644", "git_blob": blob,
                   "bytes": len(original)}, "Bellman original copy differs from current target Git blob")
    return {"component_sha256": digest(component_raw), "migration_target_sha256": digest(target_raw),
            "original_commit": ORIGINAL_COMMIT, "original_source": REFERENCE,
            "original_sha256": ORIGINAL_SHA256, "original_git_blob": blob,
            "compiler_commit": component["compiler_commit"],
            "compiler_image_sha256": component["compiler_image_sha256"],
            "shared_helper_graph_sha256": component["shared_integer_arithmetic_graph_sha256"],
            "source_files": actual}

def module_evidence(output, report, key):
    item = next(item for item in MODULES if item["key"] == key)
    relative = "build/modules/" + item["name"] + "/manifest.json"
    row = report["modules"][key]
    raw = read(Path(output) / relative)
    if (row.get("manifest") != relative or row.get("sha256") != digest(raw)
            or row.get("source") != item["source"] or row.get("builder") != "borrowed_bytes"):
        raise ValueError("Bellman module is not the registered standard-profile build")
    metadata = decode(raw)
    source = source_evidence()
    if (metadata.get("name") != item["name"] or metadata.get("compiler_commit") != source["compiler_commit"]
            or metadata.get("compiler_sha256") != source["compiler_image_sha256"]
            or metadata.get("source_sha256") != source["source_files"][Path(item["source"]).name]["sha256"]
            or (metadata.get("input_capacity"), metadata.get("output_capacity"), metadata.get("workspace_capacity"))
            != (8 << 20, 8 << 20, 32 << 20)):
        raise ValueError("Bellman module source/compiler/profile differs")
    from hia_native_loader import NativeModule
    NativeModule(Path(output) / relative, manifest_sha256=digest(raw))
    standalone = metadata.get("standalone")
    if (type(standalone) is not dict or standalone.get("transport") != "filter"
            or standalone.get("runtime_python_required") is not False
            or standalone.get("runtime_libc_required") is not False):
        raise ValueError("Bellman standalone transport is not the native filter")
    elf = (Path(output) / relative).parent / standalone["path"]
    if elf.name != item["name"] + ".elf" or digest(read(elf)) != standalone["sha256"]:
        raise ValueError("Bellman standalone executable differs")
    return {"manifest": relative, "manifest_sha256": digest(raw),
            "source_sha256": metadata["source_sha256"], "image_sha256": metadata["image_sha256"],
            "compiler_commit": metadata["compiler_commit"], "compiler_sha256": metadata["compiler_sha256"],
            "standalone": str(elf.relative_to(output)), "standalone_sha256": standalone["sha256"]}

def packet_counts(raw, *, output):
    at = count = errors = 0
    while at < len(raw):
        header = 16 if output else 8
        if len(raw) - at < header: raise ValueError("truncated Bellman stream header")
        if output:
            kind, size = struct.unpack_from("<QQ", raw, at)
            if kind not in (0, 1): raise ValueError("unknown Bellman output kind")
            errors += kind
        else: size, = struct.unpack_from("<Q", raw, at)
        at += header
        if size > len(raw) - at: raise ValueError("truncated Bellman stream payload")
        at += size
        count += 1
    return count, errors

def corpus_evidence(base, kind, manifest_sha):
    folder = Path(base) / kind
    raw = read(folder / "report.json")
    report = decode(raw)
    names = {"inputs.bin", "native.bin", {
        "arithmetic": "reference.bin", "bellman": "python-reference.bin", "signed-zero": "inputs.bin.gz"}[kind]}
    captured = {name: identity(read(folder / name)) for name in names}
    exact(report.get("files"), captured, "Bellman captured corpus files differ")
    if report.get("status") != "PASS" or report.get("manifest_sha256") != manifest_sha:
        raise ValueError("Bellman corpus status or native module identity differs")
    for name, pin in (("inputs.bin", INPUT_PINS[kind]), ("native.bin", OUTPUT_PINS[kind])):
        exact(captured[name], {"bytes": pin[0], "sha256": pin[1]}, "Bellman complete fixed corpus differs")
    inputs = read(folder / "inputs.bin")
    native = read(folder / "native.bin")
    if kind == "arithmetic":
        exact({key: report.get(key) for key in ("operations", "counts", "total", "parameter_controls")},
              {"operations": ["add", "subtract", "multiply", "divide", "compare"],
               "counts": [33162] * 5, "total": 165810, "parameter_controls": 7},
              "binary64 arithmetic domain or refusal coverage differs")
        if native != read(folder / "reference.bin") or len(inputs) != 24 * COUNTS[kind]:
            raise ValueError("binary64 complete hardware reference stream differs")
    else:
        if (type(report.get("native_graph_cases")) is not int or report["native_graph_cases"] != COUNTS[kind]
                or packet_counts(inputs, output=False) != (COUNTS[kind], 0)
                or packet_counts(native, output=True) != (COUNTS[kind], 25 if kind == "bellman" else 0)):
            raise ValueError("Bellman graph/refusal stream coverage differs")
        if kind == "bellman":
            if (native != read(folder / "python-reference.bin") or type(report.get("refusal_controls")) is not int
                    or report["refusal_controls"] != 10):
                raise ValueError("Bellman independent output or capacity controls differ")
            sys.path.insert(0, str(ROOT / "tests/hia_native/bellman"))
            from qualify_bellman import corpus
            if [row["name"] for row in report.get("cases", [])] != [name for name, _, _ in corpus()]:
                raise ValueError("Bellman case order differs")
        elif gzip.decompress(read(folder / "inputs.bin.gz")) != inputs:
            raise ValueError("signed-zero retained compressed input differs")
    return {"status": "PASS", "cases": COUNTS[kind], "report_sha256": digest(raw), "files": captured}

def static_evidence(output, module, *, execute=False):
    sys.path.insert(0, str(ROOT / "tests/hia_native/bellman"))
    from qualify_bellman import corpus, pack_graph, reference
    result = {}
    folder = Path(output) / FOLDER / "static"
    if execute: folder.mkdir()
    executable = Path(output) / module["standalone"]
    for name, graph, _ in corpus():
        if name not in STATIC_NAMES: continue
        wire, expected = pack_graph(graph), reference(graph)
        receipt = {"command": [str(executable)], "exit_code": 0, "timeout_seconds": 30,
                   "stdin": identity(wire), "stdout": identity(expected), "stderr": identity(b""),
                   "executable_sha256": module["standalone_sha256"]}
        if execute:
            (folder / (name + ".input")).write_bytes(wire)
            process = subprocess.run([str(executable)], input=wire, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, timeout=30)
            (folder / (name + ".stdout")).write_bytes(process.stdout)
            (folder / (name + ".stderr")).write_bytes(process.stderr)
            actual = dict(receipt, exit_code=process.returncode,
                          stdout=identity(process.stdout), stderr=identity(process.stderr))
            (folder / (name + ".json")).write_text(json.dumps(actual, indent=2) + "\n")
        exact(decode(read(folder / (name + ".json"))), receipt, "Bellman static process invocation/result differs")
        if (read(folder / (name + ".input")) != wire or read(folder / (name + ".stdout")) != expected
                or read(folder / (name + ".stderr"))):
            raise ValueError("Bellman actual static process bytes differ")
        result[name] = receipt
    return result

def checked_process(output, report, name, command, *, phase, timeout, stdin=None, empty_stderr=True):
    matches = [row for row in report["checks"] if row["name"] == name]
    if len(matches) != 1: raise ValueError("Bellman requires one completed process: " + name)
    row = matches[0]
    stdout = read(Path(output) / (name + ".stdout"))
    stderr = read(Path(output) / (name + ".stderr"))
    fields = ("name", "command", "phase", "exit_code", "timed_out", "timeout_seconds",
              "stdout_bytes", "stderr_bytes", "stdout_sha256", "stderr_sha256")
    exact({key: row.get(key) for key in fields},
          {"name": name, "command": command, "phase": phase, "exit_code": 0, "timed_out": False,
           "timeout_seconds": timeout, "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
           "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr)},
          "Bellman process command, completion or captured bytes differ: " + name)
    elapsed = row.get("elapsed_seconds")
    if ("start_error" in row or type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0
            or (empty_stderr and stderr)):
        raise ValueError("Bellman process completion differs: " + name)
    if stdin is not None: exact(row.get("stdin"), identity(stdin), "Bellman original invocation input differs")
    return {key: row[key] for key in fields}, stdout

def run_native(kind):
    """Environment adapter for one standard aggregate suite; run actual HIA."""
    name, driver, key = SUITES[kind]
    output = Path(os.environ["HIA_BELLMAN_QUALIFICATION_OUTPUT"]).resolve()
    source = source_evidence()
    report = {"modules": {}}
    for item in MODULES:
        manifest = Path(os.environ[item["manifest_env"]]).resolve()
        report["modules"][item["key"]] = {
            "manifest": str(manifest.relative_to(output)), "sha256": digest(read(manifest)),
            "source": item["source"], "builder": "borrowed_bytes"}
    modules = {item["key"]: module_evidence(output, report, item["key"]) for item in MODULES}
    from hia_native_bellman_build import helper_graphs
    graph_sha = helper_graphs(Path(os.environ["HIA_HEPTA_DIR"]), ROOT / MODULES[0]["source"], ROOT / MODULES[1]["source"])
    if graph_sha != source["shared_helper_graph_sha256"]: raise ValueError("Bellman source helper graphs differ")
    base = output / FOLDER
    base.mkdir(exist_ok=True)
    argv = [str(ROOT / "tests/hia_native/bellman" / driver), "--runtime", str(ROOT),
            "--manifest", str(output / modules[key]["manifest"]), "--output", str(base / kind)]
    previous, captured = sys.argv, io.StringIO()
    sys.path.insert(0, str(ROOT / "tests/hia_native/bellman"))
    try:
        sys.argv = argv
        with contextlib.redirect_stdout(captured): runpy.run_path(argv[0], run_name="__main__")
    finally:
        sys.argv = previous
        (base / (kind + ".driver.stdout")).write_text(captured.getvalue())
    corpus = corpus_evidence(base, kind, modules[key]["manifest_sha256"])
    retained = decode(read(base / kind / "report.json"))
    if kind == "bellman": retained = {k: v for k, v in retained.items() if k != "cases"}
    exact(decode(captured.getvalue()), retained, "Bellman driver stdout differs from retained report")
    summary = {"schema": "hepta.runtime.hia-bellman-native-suite.v1", "status": "PASS", "suite": name,
               "reference_kind": "independent CPython hardware binary64", "source": source,
               "modules": modules, "shared_helper_graph_sha256": graph_sha, "corpus": corpus, **SCOPE}
    if kind == "bellman": summary["static_executions"] = static_evidence(output, modules[key], execute=True)
    (base / (kind + ".suite.json")).write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))

def native_evidence(output, report):
    output = Path(output).resolve()
    source = source_evidence()
    modules = {item["key"]: module_evidence(output, report, item["key"]) for item in MODULES}
    retained = {}
    for kind, (name, _, key) in SUITES.items():
        command = [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native" / name)]
        process, stdout = checked_process(output, report, name, command, phase="native_components", timeout=180)
        corpus = corpus_evidence(output / FOLDER, kind, modules[key]["manifest_sha256"])
        expected = {"schema": "hepta.runtime.hia-bellman-native-suite.v1", "status": "PASS", "suite": name,
                    "reference_kind": "independent CPython hardware binary64", "source": source,
                    "modules": modules, "shared_helper_graph_sha256": source["shared_helper_graph_sha256"],
                    "corpus": corpus, **SCOPE}
        if kind == "bellman": expected["static_executions"] = static_evidence(output, modules[key])
        exact(decode(read(output / FOLDER / (kind + ".suite.json"))), expected, "Bellman retained suite differs")
        exact(decode(stdout), expected, "Bellman complete native stdout differs")
        row = next(row for row in report["checks"] if row["name"] == name)
        exact(row.get("summary"), expected, "Bellman process summary differs")
        driver = decode(read(output / FOLDER / (kind + ".driver.stdout")))
        child = decode(read(output / FOLDER / kind / "report.json"))
        exact(driver, {k: v for k, v in child.items() if k != "cases"} if kind == "bellman" else child,
              "Bellman retained driver stdout differs")
        retained[kind] = {"process": process, "suite": expected}
    return {"status": "PASS", "source": source, "modules": modules, "native_suites": retained,
            "arithmetic_reference_kind": "independent CPython hardware binary64",
            "original_rust_replay_required": True, **SCOPE}

def original_commands(output, rustc):
    folder = Path(output) / "bellman-original"
    oracle = folder / "bellman_original_oracle.rs"
    commands = {
        "bellman-rust-version": ([str(rustc), "--version", "--verbose"], 15),
        "bellman-rust-extract": ([sys.executable, "-I", "-B", str(ROOT / "tests/hia_native/bellman/make_bellman_oracle.py"),
                                  "--original", str(ROOT / REFERENCE), "--output", str(folder)], 180),
    }
    for label, flags in (("debug", []), ("optimized", ["-O"])):
        binary = folder / ("oracle-" + label)
        commands["bellman-rust-build-" + label] = ([str(rustc), "--edition=2021", *flags, str(oracle), "-o", str(binary)], 180)
        commands["bellman-rust-replay-" + label] = ([str(binary)], 180)
    return commands

def compare_original(output, report, rustc):
    import qualify_hia_runtime_native as q
    output = Path(output).resolve()
    native_evidence(output, report)
    folder = output / "bellman-original"
    folder.mkdir()
    inputs = b"".join(read(output / FOLDER / kind / "inputs.bin") for kind in ("bellman", "signed-zero"))
    expected = b"".join(read(output / FOLDER / kind / "native.bin") for kind in ("bellman", "signed-zero"))
    (folder / "inputs.bin").write_bytes(inputs)
    (folder / "expected-native.bin").write_bytes(expected)
    compiler_before = digest(Path(rustc).read_bytes())
    for name, (command, timeout) in original_commands(output, rustc).items():
        replay = "-replay-" in name
        result = q.record_check(output, report, name=name, command=command, timeout=timeout,
                                input_bytes=inputs if replay else None)
        if replay:
            report["checks"][-1]["stdin"] = identity(inputs)
            q.save_report(output / "result.json", report)
            if result.stdout != expected or result.stderr:
                raise ValueError("Bellman complete actual original output differs: " + name)
        elif name == "bellman-rust-version" and not result.stdout.startswith(b"rustc 1.95.0 "):
            raise ValueError("Bellman original requires Rust 1.95.0")
    if digest(Path(rustc).read_bytes()) != compiler_before: raise ValueError("Bellman compiler changed during replay")
    return original_evidence(output, report, rustc)

def original_evidence(output, report, rustc):
    output = Path(output).resolve()
    native = native_evidence(output, report)
    folder = output / "bellman-original"
    expected_input = b"".join(read(output / FOLDER / kind / "inputs.bin") for kind in ("bellman", "signed-zero"))
    expected_output = b"".join(read(output / FOLDER / kind / "native.bin") for kind in ("bellman", "signed-zero"))
    if (read(folder / "inputs.bin") != expected_input or read(folder / "expected-native.bin") != expected_output
            or packet_counts(expected_input, output=False) != (363, 0)
            or packet_counts(expected_output, output=True) != (363, 25)):
        raise ValueError("Bellman original replay corpus differs")
    program = read(folder / "bellman_original_oracle.rs")
    extraction = decode(read(folder / "bellman_original_oracle.json"))
    if (digest(program) != ORACLE_SHA256 or extraction.get("oracle_sha256") != ORACLE_SHA256
            or extraction.get("original_sha256") != ORIGINAL_SHA256 or extraction.get("original_commit") != ORIGINAL_COMMIT):
        raise ValueError("Bellman original numerical extraction differs")
    original = read(ROOT / REFERENCE).decode()
    pieces = {}
    for name in ("finite", "deadline", "validate", "action_value", "choose"):
        start = original.index("fn " + name + "(")
        end = original.index("\n}\n", start) + 3
        pieces[name] = original[start:end].encode()
    start = original.index("\tlet mut plans = Vec::with_capacity(dims.states);")
    end = original.index("\n\tdeadline(end)?;\n\tOk(json!", start) + len("\n\tdeadline(end)?;")
    pieces["solve_numerical_body"] = original[start:end].encode()
    exact(extraction.get("unchanged_extractions"), {name: identity(value) for name, value in pieces.items()},
          "Bellman unchanged original function identities differ")
    if any(program.count(value) != 1 for value in pieces.values()):
        raise ValueError("Bellman original function was replaced or duplicated")
    processes = {}
    for name, (command, timeout) in original_commands(output, rustc).items():
        replay = "-replay-" in name
        process, stdout = checked_process(output, report, name, command, phase="original_rust_comparison", timeout=timeout,
                                          stdin=expected_input if replay else None, empty_stderr="-build-" not in name)
        if replay and stdout != expected_output: raise ValueError("Bellman actual original Rust stream differs")
        if name == "bellman-rust-version" and not stdout.startswith(b"rustc 1.95.0 "):
            raise ValueError("Bellman original requires Rust 1.95.0")
        if name == "bellman-rust-extract" and stdout != (str(folder / "bellman_original_oracle.rs") + "\n").encode():
            raise ValueError("Bellman extraction process output differs")
        processes[name] = process
    compiler = {"invocation_path": str(rustc), "resolved_path": str(Path(rustc).resolve()),
                "invocation_sha256": digest(Path(rustc).read_bytes()),
                "resolved_sha256": digest(Path(rustc).resolve().read_bytes())}
    version = read(output / "bellman-rust-version.stdout").decode()
    return {"status": "PASS", "reference_kind": "unchanged current-target Rust numerical owner",
            "original_commit": ORIGINAL_COMMIT, "original_sha256": ORIGINAL_SHA256,
            "target_binding": native["source"], "module_manifest_sha256": native["modules"]["bellman_core"]["manifest_sha256"],
            "graph_cases": 363, "semantic_refusals": 25, "compiler": compiler, "compiler_version": version,
            "extraction": extraction, "input_stream": identity(expected_input), "native_output_stream": identity(expected_output),
            "binaries": {label: identity(read(folder / ("oracle-" + label))) for label in ("debug", "optimized")},
            "processes": processes, **SCOPE}

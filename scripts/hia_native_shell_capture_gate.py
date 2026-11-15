"""Bind closed HIA capture leaves into standard runtime qualification."""
from __future__ import annotations

import importlib
import importlib.util
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
KINDS = ("path", "mkdir", "file", "prepare")
LEAF_KINDS = ("path", "mkdir", "file")
KEYS = tuple("shell_capture_" + kind for kind in KINDS)
MODULES = tuple({
    "key": "shell_capture_" + kind, "name": "shell-capture-" + kind,
    "source": "native/shell_capture_" + kind + ".hepta",
    "builder": "shell_capture_" + kind,
    "manifest_env": "HIA_SHELL_CAPTURE_" + kind.upper() + "_MANIFEST",
    "test": "shell_capture_path.py" if kind == "path" else "shell_capture_" + kind + "_state.py",
    **({} if kind == "path" else {
        "additional_tests": ("shell_capture_" + kind + "_io.py",),
        "companion_sources": ("native/shell_capture_" + kind + "_packer.hepta",)}),
} for kind in KINDS)
TESTS = tuple(name for item in MODULES for name in (item["test"], *item.get("additional_tests", ())))
SCRIPTS = ("hia_native_shell_capture_gate.py", "shell_capture_mkdir_adapter.S", "shell_capture_file_adapter.S",
           "shell_capture_prepare_adapter.S", "qualify_hia_shell_capture_prepare_original.py") + tuple(
    "hia_native_shell_capture_" + kind + "_" + role + ".py"
    for kind in KINDS for role in ("build", "reference", "qualification")
    if (kind, role) != ("prepare", "qualification"))
ORACLE_SOURCES = tuple("tests/oracles/shell_capture_prepare/" + name for name in (
    "README.md", "source_manifest.json", "src/main.rs", "review/tokio_fs_mod.rs"))
SCOPE = {"whole_runtime_replaced": False, "production_activated": False,
         "production_shell_execution_qualified": False, "old_stack_removal_qualified": False,
         "capture_preparation_qualified": False, "registry_publication_qualified": False,
         "native_phase_cases_added_by_reference": 0}


def kind_for(key):
    if key not in KEYS:
        raise ValueError("unregistered capture owner")
    return key.removeprefix("shell_capture_")


def script_name(kind, role):
    if kind not in KINDS or role not in ("build", "reference", "qualification"):
        raise ValueError("unregistered capture script")
    if (kind, role) == ("prepare", "qualification"):
        return "qualify_hia_shell_capture_prepare_original"
    return "hia_native_shell_capture_" + kind + "_" + role


def script(kind, role):
    return importlib.import_module(script_name(kind, role))


def original_case_specs(kind):
    specs = suite("shell_capture_" + kind + "_io.py").case_specs()
    if kind == "prepare":
        return [spec for spec in specs if not spec["native_only_controlled_race"]]
    field = "original_fresh_cache_comparable" if kind == "mkdir" else "original_file_operation"
    return [spec for spec in specs if spec[field]]


def native_progress_field(kind):
    return {"mkdir": "result", "file": "results", "prepare": "counts"}[kind]


def suite(name):
    if name not in TESTS:
        raise ValueError("unregistered capture suite")
    identifier = "hia_capture_registered_" + name.removesuffix(".py")
    spec = importlib.util.spec_from_file_location(identifier, ROOT / "tests/hia_native" / name)
    if spec is None or spec.loader is None:
        raise ValueError("capture suite cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[identifier] = module
    spec.loader.exec_module(module)
    return module


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate capture process JSON field")
            result[key] = value
        return result

    def nonfinite(value):
        raise ValueError("nonfinite capture process JSON value")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)


def exact(left, right, message):
    # Canonical JSON distinguishes bool/int and int/float, unlike Python ==.
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if encode(left) != encode(right):
        raise ValueError(message)


def process_kind(name):
    for kind in KINDS:
        if name in ("shell-capture-" + kind + "-rust-build", "shell-capture-" + kind + "-rust-compare"):
            return kind
    for item in MODULES:
        if name in (item["test"], *item.get("additional_tests", ())):
            return kind_for(item["key"])
    return None


def progress_records(name, stdout):
    kind = process_kind(name)
    if kind is None:
        raise ValueError("unknown capture process protocol")
    rows = [strict_json(line) for line in stdout.splitlines()]
    if not rows or any(type(row) is not dict for row in rows):
        raise ValueError("capture process output is not complete JSON object framing")
    native_io = name == "shell_capture_" + kind + "_io.py"
    original_io = kind != "path" and name == "shell-capture-" + kind + "-rust-compare"
    if native_io or original_io:
        specs = suite("shell_capture_" + kind + "_io.py").case_specs()
        if original_io:
            specs = original_case_specs(kind)
        if len(rows) != len(specs) + 1:
            raise ValueError("capture process omitted, duplicated or appended progress records")
        for row, spec in zip(rows[:-1], specs):
            if native_io:
                field = native_progress_field(kind)
                if (set(row) != {"name", "status", field} or row["name"] != spec["name"]
                        or row["status"] != "PASS"):
                    raise ValueError("capture native progress order or protocol differs")
            elif (set(row) != {"case", "status", "syscalls"} or row["case"] != spec["name"]
                    or row["status"] != "ORIGINAL_PAIR_PASS"
                    or type(row["syscalls"]) is not int or row["syscalls"] < 0):
                raise ValueError("capture original progress order or protocol differs")
    elif len(rows) != 1:
        raise ValueError("capture process has extra result records")
    if rows[-1].get("status") != "PASS":
        raise ValueError("capture process did not publish a successful complete result")
    return rows


def bind_process_output(output, name, expected):
    actual = progress_records(name, (output / (name + ".stdout")).read_bytes())
    exact(actual, expected, "capture complete process output differs from independent evidence")


def build(key, hepta, build_root):
    kind = kind_for(key)
    children = ({child + "_manifest": Path(build_root).absolute() / ("shell-capture-" + child) / "manifest.json"
                 for child in LEAF_KINDS} if kind == "prepare" else {})
    return getattr(script(kind, "build"), "build_shell_capture_" + kind)(
        hepta, build_root, source_root=ROOT, **children)


def build_child_arguments(key, build_root):
    if kind_for(key) != "prepare":
        return []
    return [arg for child in LEAF_KINDS for arg in (
        "--" + child + "-manifest", str(Path(build_root).absolute() / ("shell-capture-" + child) / "manifest.json"))]


def manifest_for(output, report, key):
    kind = kind_for(key)
    relative = Path("build") / ("shell-capture-" + kind) / "manifest.json"
    expected = output.absolute() / relative
    row = report["modules"][key]
    if (type(row.get("manifest")) is not str
            or row["manifest"] not in (str(relative), str(expected))
            or expected.is_symlink() or expected.resolve(strict=True) != expected):
        raise ValueError("capture manifest is not this qualification's registered build")
    digest = hashlib.sha256(expected.read_bytes()).hexdigest()
    if type(row.get("sha256")) is not str or row["sha256"] != digest:
        raise ValueError("capture module manifest identity differs")
    if kind == "prepare":
        top = strict_json(expected.read_bytes())
        if (set(top.get("children", {})) != set(LEAF_KINDS)
                or top.get("child_origins") != {child: "provided" for child in LEAF_KINDS}):
            raise ValueError("capture prepare must use the three registered leaves from this gate")
        for child in LEAF_KINDS:
            leaf = manifest_for(output, report, "shell_capture_" + child)
            raw = leaf.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            binding = top["children"][child]
            if (top.get(child + "_manifest") != str(leaf)
                    or top.get(child + "_manifest_sha256") != digest
                    or binding.get("manifest") != str(leaf)):
                raise ValueError("capture prepare child is not this qualification's registered leaf")
            exact(binding.get("manifest_pin"), {"bytes": len(raw), "sha256": digest},
                  "capture prepare registered child identity differs")
    return expected


def test_commands(output, report):
    result = {}
    for item in MODULES:
        key = item["key"]
        if key not in report["modules"]:
            continue
        manifest = manifest_for(output, report, key)
        base = output / item["name"]
        for name in (item["test"], *item.get("additional_tests", ())):
            folder = base / ("native" if name.endswith("_io.py") else "state")
            result[name] = [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native" / name),
                           "--native-manifest", str(manifest), "--output", str(folder)]
    return result


def compiler_identity(output, report, key):
    """Read the actual owner manifest after admitting its complete TOP chain."""
    manifest = manifest_for(output, report, key)
    script(kind_for(key), "build").read_evidence(manifest, source_root=ROOT)
    top = strict_json(manifest.read_bytes())
    owner = manifest.parent.parent / top["owner_manifest"]
    raw = owner.read_bytes()
    if hashlib.sha256(raw).hexdigest() != top["owner_manifest_sha256"]:
        raise ValueError("capture owner manifest changed after complete build admission")
    metadata = strict_json(raw)
    return {name: metadata[name] for name in ("compiler_commit", "compiler_sha256")}


def native_evidence(output, report, key):
    import qualify_hia_runtime_native as q
    kind = kind_for(key)
    item = MODULES[KINDS.index(kind)]
    manifest = manifest_for(output, report, key)
    base = output / item["name"]
    metadata = strict_json(manifest.read_bytes())
    built = script(kind, "build").read_evidence(manifest, source_root=ROOT)
    commands = test_commands(output, report)
    completed, readers = {}, {}
    for name in (item["test"], *item.get("additional_tests", ())):
        completed[name] = q.shell_completed_process(output, report, name, commands[name],
            phase="native_components", timeout=180)
        io = name.endswith("_io.py")
        folder = base / ("native" if io else "state")
        module = suite(name)
        result = module.read_evidence(folder, native_manifest=manifest, **({"require_full": True} if io else {}))
        if result.get("status") != "PASS" or result.get("recorded_directory") != str(folder):
            raise ValueError("capture reader result or retained directory differs")
        captured = strict_json((folder / "report.json").read_bytes())
        if io:
            field = native_progress_field(kind)
            progress = [{"name": row["name"], "status": "PASS", field: row[field]} for row in captured["cases"]]
            if result.get("complete_registered_corpus") is not True:
                raise ValueError("partial capture OS corpus")
        else:
            progress = []
            counts = module.EXPECTED_COUNTS if kind == "path" else module.expected_counts()
            exact(result.get("counts"), counts, "capture complete state corpus counts differ")
        bind_process_output(output, name, [*progress, result])
        readers["native" if io else "state"] = result
    folders = [manifest.parent, (manifest.parent.parent / metadata["owner_manifest"]).parent]
    if kind != "path":
        folders.append((manifest.parent.parent / metadata["packer_manifest"]).parent)
    return {"schema": "hepta.runtime.shell-capture-" + kind + "-required-native.v1", "status": "PASS",
            "build": built, **readers, "completed_processes": completed,
            "artifact_sha256": q.shell_retained_files(output, tuple(folders)),
            "corpus_sha256": q.shell_retained_files(output, (base,)),
            "original_rust_compared": False, **SCOPE}


def original_commands(output, report, key, rustc):
    kind = kind_for(key)
    name = "shell-capture-" + kind
    base = output / (name + "-original")
    manifest = manifest_for(output, report, key)
    corpus = output / name / ("state" if kind == "path" else "native")
    args = ["--runtime", str(ROOT), "--rustc", str(rustc), "--linker", "/usr/bin/cc"]
    prefix = [sys.executable, "-I", "-B"]
    return {
        name + "-rust-build": prefix + [str(ROOT / "scripts" / (script_name(kind, "reference") + ".py")),
                                      *args, "--output", str(base / "build")],
        name + "-rust-compare": prefix + [str(ROOT / "scripts" / (script_name(kind, "qualification") + ".py")),
            *args, "--reference-build", str(base / "build"), "--native-corpus", str(corpus),
            "--native-manifest", str(manifest), "--output", str(base / "cases"),
            *([] if kind == "path" else ["--tracer", "/usr/bin/strace"])],
    }


def original_evidence(output, report, key, rustc):
    import qualify_hia_runtime_native as q
    kind = kind_for(key)
    name = "shell-capture-" + kind
    base = output / (name + "-original")
    manifest = manifest_for(output, report, key)
    corpus = output / name / ("state" if kind == "path" else "native")
    commands = original_commands(output, report, key, rustc)
    completed = {process: q.shell_completed_process(output, report, process, command,
        phase="original_rust_comparison", timeout=300) for process, command in commands.items()}
    reference = script(kind, "reference")
    built = reference.read_evidence(ROOT, base / "build", rustc, Path("/usr/bin/cc"))
    build_report = strict_json((base / "build/result.json").read_bytes())
    build_summary = {"status": build_report["status"], "result": str(base / "build/result.json"),
                     "error": build_report["error"], "actual_processes": len(build_report["processes"]),
                     **reference.scope()}
    bind_process_output(output, name + "-rust-build", [build_summary])
    comparison = script(kind, "qualification").read_evidence(ROOT, base / "build", corpus, manifest,
        base / "cases", rustc, Path("/usr/bin/cc"), *([] if kind == "path" else [Path("/usr/bin/strace")]))
    captured = strict_json((base / "cases/result.json").read_bytes())
    if kind == "path":
        progress = []
        extra = {"actual_original_replay_processes": len(captured["processes"])}
        counts = captured["comparison"]["counts"]
    else:
        progress = [{"case": row["name"], "status": "ORIGINAL_PAIR_PASS",
                     "syscalls": row["trace_counts"]["syscalls"]} for row in captured["cases"]]
        extra, counts = {}, captured["counts"]
    summary = {"status": captured["status"], "error": captured["error"],
               "report": str(base / "cases/result.json"), "counts": counts,
               "whole_runtime_replaced": False, **extra}
    bind_process_output(output, name + "-rust-compare", [*progress, summary])
    if comparison.get("status") != "PASS":
        raise ValueError("capture original complete comparison is not qualified")
    return {"schema": "hepta.runtime.shell-capture-" + kind + "-required-original.v1", "status": "PASS",
            "compiled_by_qualification_recipe": True, "completed_processes": completed,
            "reference_build": built, "comparison": comparison, "original_rust_compared": True,
            "original_tests": 0, "retained_files_sha256": q.shell_retained_files(output, (base,)), **SCOPE}


def compare(output, report, key, rustc):
    import qualify_hia_runtime_native as q
    before = native_evidence(output, report, key)
    exact(before, report.get(key + "_evidence"), "capture native evidence changed before original comparison")
    for name, command in original_commands(output, report, key, rustc).items():
        q.record_check(output, report, name=name, command=command, timeout=300, env=q.qualification_env())
    result = original_evidence(output, report, key, rustc)
    exact(native_evidence(output, report, key), before, "capture native evidence changed during original comparison")
    return result

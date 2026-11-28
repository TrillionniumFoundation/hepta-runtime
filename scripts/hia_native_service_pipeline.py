"""Bind the directory/workdir profiles to actual aggregate processes.

This module schedules and inspects qualification. It never implements a tool,
interprets HIA, or substitutes retained observations for a fresh Rust recipe.
The frozen semantic owners and their stricter domain inspectors stay unchanged.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import hia_native_directory_qualification as directory
import hia_native_workdir_qualification as workdir
import hia_native_connection_qualification as connection
import hia_native_write_chain_pipeline as write_chain

DIRECTORY_TESTS = {
    "test_directory_service.py": "functional",
    "directory_service_faults.py": "faults",
    "test_directory_service_transport.py": "transport",
    "test_directory_service_build.py": "builder",
    "test_directory_service_regex.py": "regex",
}
WORKDIR_TESTS = {
    "test_workdir_params.py": "parameters",
    "test_workdir_caller_controls.py": "caller",
    "test_workdir_service_regex.py": "regex",
}
# The public-MCP shard owns its independent Workdir oracle at workdir-original.
# Keep the service oracle's complete build, streams and fixture custody in its
# own namespace; the aggregate must retain both without deduplication.
WORKDIR_ORIGINAL = "workdir-service-original"
WORKDIR_ORIGINAL_FIXTURES = tuple(WORKDIR_ORIGINAL + "/" + name for name in
                                  ("probe-v1/fixture", "public/fixture", "regex/fixture"))
KEYS = ("directory_service", "workdir_service", "sdk_connection", "write_chain")
SOURCES = {"directory_service": "native/directory_caller.hepta",
           "workdir_service": "native/workdir_caller.hepta"}
SDK_MANIFEST = "native/sdk_rmcp_source_manifest.json"
SDK_MANIFEST_SHA256 = "5ba12f2a865b7f336fe0d798bde8422821927a2b82dd71b72082866bdeeb7e23"
require = workdir.require
sha = lambda raw: hashlib.sha256(raw).hexdigest()
encoded = lambda value: (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sources(root=ROOT):
    root = Path(root)
    names = set(directory.source_inventory(root)) | set(workdir.source_inventory(root))
    names.update(directory.original_source(root, root)["original_inputs"])
    names.update(connection.source_pins(root))
    names.update(write_chain.q.pins(root))
    names.add("scripts/hia_native_service_pipeline.py")
    names.add(SDK_MANIFEST)
    return {name: sha(workdir.native.file(root, name).read_bytes()) for name in sorted(names)}


def sdk_sources(root):
    raw = workdir.native.file(root, SDK_MANIFEST).read_bytes()
    require(sha(raw) == SDK_MANIFEST_SHA256, "complete SDK source manifest differs")
    value = json.loads(raw)
    require(value["schema"] == "hepta.runtime.rmcp-source-manifest.v1" and value["crate"] == "rmcp"
            and value["version"] == "3.4.1" and len(value["files"]) == 175
            and value["crate_sha256"] == "5b6317cd8c13e3ec9033cf2aa5aa92cd743f0f4f8a93cddc42ea0ae6ce3b8898",
            "SDK source domain differs")
    return value["files"]


def bundle(output, report, key):
    item = report["modules"][key]
    require(item.get("builder") == key and item.get("source") == SOURCES[key],
            "service component registry differs: " + key)
    path = workdir.native.file(output, item["manifest"])
    require(sha(path.read_bytes()) == item["sha256"], "service manifest changed: " + key)
    return path


def completed_process(output, report, completed, name, command):
    check, summary = completed(output, report, name)
    elapsed = check.get("elapsed_seconds")
    phase = "original_rust_comparison" if name.endswith("-rust-compare") else "native_components"
    require(check.get("command") == command and check.get("exit_code") == 0
            and check.get("phase") == phase
            and check.get("timed_out") is False and not check.get("start_error")
            and check.get("timeout_seconds") == 180 and type(elapsed) in (float, int)
            and math.isfinite(elapsed) and 0 <= elapsed < 180,
            "service actual command or completion differs: " + name)
    for channel in ("stdout", "stderr"):
        raw = workdir.native.file(output, name + "." + channel).read_bytes()
        require(len(raw) == check[channel + "_bytes"] and sha(raw) == check[channel + "_sha256"],
                "service complete stream differs: " + name)
    require(workdir.native.file(output, name + ".stderr").read_bytes() == b""
            and json.loads(workdir.native.file(output, name + ".stdout").read_bytes()) == summary,
            "service completed stdout is not the retained summary")
    return {key: check[key] for key in ("command", "exit_code", "timed_out", "timeout_seconds",
        "elapsed_seconds", "stdout_bytes", "stderr_bytes", "stdout_sha256", "stderr_sha256")}, summary


def directory_child_command(root, output, manifest, hepta, build_root, script):
    name = DIRECTORY_TESTS[script]
    command = [sys.executable, "-I", "-B", str(Path(root) / "tests/hia_native" / script),
               "--manifest", str(manifest), "--output", str(Path(output) / name)]
    if name == "builder":
        command += ["--hepta", str(hepta), "--build-root", str(build_root)]
    return command


def test_commands(root, output, report):
    root, output = Path(root), Path(output)
    result = {}
    if "directory_service" in report["modules"]:
        manifest = bundle(output, report, "directory_service")
        for script in DIRECTORY_TESTS:
            result[script] = [sys.executable, "-I", "-B", str(root / "scripts/hia_native_service_pipeline.py"),
                "directory-suite", "--suite", script, "--manifest", str(manifest),
                "--hepta", report["compiler_checkout"], "--build-root", str(output / "build"),
                "--output", str(output / "directory-native")]
    if "workdir_service" in report["modules"]:
        manifest = bundle(output, report, "workdir_service")
        selected = workdir.obj(manifest)
        members = {row["name"]: manifest.parent / row["manifest"] for row in selected["members"]}
        arguments = {
            "test_workdir_params.py": ["--manifest", members["params"], "--value-manifest", members["value"],
                "--cases", root / "tests/hia_native/workdir_parameter_cases.json"],
            "test_workdir_caller_controls.py": ["--manifest", manifest],
            "test_workdir_service_regex.py": ["--manifest", manifest],
        }
        for script, folder in WORKDIR_TESTS.items():
            result[script] = [sys.executable, "-I", "-B", str(root / "tests/hia_native" / script),
                *map(str, arguments[script]), "--output", str(output / "workdir-native" / folder)]
    return result


def run_directory_suite(args):
    require(args.suite in DIRECTORY_TESTS, "undeclared directory suite")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.native.verify_bundle(args.manifest, args.hepta, args.build_root, source_root=ROOT)
    command = directory_child_command(ROOT, args.output, args.manifest,
                                     args.hepta, args.build_root, args.suite)
    env = {name: value for name, value in os.environ.items() if not name.startswith("HIA_")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    name = DIRECTORY_TESTS[args.suite]
    raw = directory.run_process(args.output, name, command, env, root=ROOT)
    directory.process_evidence(args.output, name, ROOT)
    directory.native.verify_bundle(args.manifest, args.hepta, args.build_root, source_root=ROOT)
    sys.stdout.buffer.write(raw)


def retained_files(output, folder, omitted=()):
    output, folder = Path(output), Path(folder)
    require(folder.resolve(strict=True) == folder and not folder.is_symlink(), "service artifact root differs")
    omitted = {output / name for name in omitted}
    values = {}
    for base, dirs, names in os.walk(folder, followlinks=False):
        for name in list(dirs):
            path = Path(base) / name
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                    and path.resolve() == path, "service retained directory is not owned")
            if path in omitted:
                dirs.remove(name)
        for name in names:
            if name == "retired-fixtures.json":
                continue
            path = Path(base) / name
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and path.resolve() == path, "service evidence contains an unowned or special file")
            with path.open("rb") as stream:
                values[path.relative_to(output).as_posix()] = hashlib.file_digest(stream, "sha256").hexdigest()
    return dict(sorted(values.items()))


def inspect_bundle(root, output, report, key):
    root, output = Path(root), Path(output)
    manifest = bundle(output, report, key)
    module = directory.native if key == "directory_service" else workdir.native
    selected = module.verify_bundle(manifest, Path(report["compiler_checkout"]), output / "build", source_root=root)
    return manifest, selected


def native_evidence(root, output, report, completed, key):
    root, output = Path(root), Path(output)
    pins = sources(root)
    require(all(report["source_sha256"].get(name) == value for name, value in pins.items()),
            "service source closure omitted from aggregate")
    manifest, selected = inspect_bundle(root, output, report, key)
    commands = test_commands(root, output, report)
    processes, results = {}, {}
    if key == "directory_service":
        folder = output / "directory-native"
        inspectors = dict(functional=directory.functional_evidence, faults=directory.faults_evidence,
            transport=directory.transport_evidence, builder=directory.builder_evidence, regex=directory.regex_evidence)
        for script, name in DIRECTORY_TESTS.items():
            process, summary = completed_process(output, report, completed, script, commands[script])
            inner = directory.process_evidence(folder, name, root)
            require(inner["argv"] == directory_child_command(root, folder, manifest,
                    Path(report["compiler_checkout"]), output / "build", script)
                    and workdir.native.file(folder, name + ".stdout").read_bytes()
                        == workdir.native.file(output, script + ".stdout").read_bytes(),
                    "directory wrapper and actual child invocation differ")
            processes[script] = process
            results[name] = inspectors[name](folder / name, root)
        fixtures = ()
        counts = dict(native_processes=74, native_suite_groups=18, completed_native_suites=5)
    else:
        require(key == "workdir_service", "unknown service profile")
        folder = output / "workdir-native"
        results = dict(parameters=workdir.inspect_parameters(folder / "parameters",
            root / "tests/hia_native/workdir_parameter_cases.json", selected),
            caller=workdir.inspect_caller(folder / "caller", selected),
            regex=workdir.inspect_regex(folder / "regex", root, selected, sha(manifest.read_bytes())))
        omitted = dict(parameters={"cases", "controls", "modules"}, caller={"controls", "modules"}, regex={"cases"})
        for script, name in WORKDIR_TESTS.items():
            process, summary = completed_process(output, report, completed, script, commands[script])
            require(summary == {k: v for k, v in results[name].items() if k not in omitted[name]},
                    "workdir complete suite summary differs")
            processes[script] = process
        fixtures = ("workdir-native/regex/fixture",)
        counts = dict(native_parameters=680, native_parameter_entries=1416, explicit_caller_controls=193,
            native_caller_entries=1995, native_regex_processes=18, native_regex_requests=36,
            completed_native_suites=3)
    artifacts = retained_files(output, manifest.parent)
    corpus = retained_files(output, folder, fixtures)
    for name in processes:
        for suffix in ("stdout", "stderr"):
            path = output / (name + "." + suffix)
            corpus[path.relative_to(output).as_posix()] = sha(path.read_bytes())
    require(sources(root) == pins, "service source changed during admission")
    return dict(schema="hepta.runtime.service-completed-evidence.v1", status="PASS", component=key,
        source_sha256=pins, manifest_sha256=sha(manifest.read_bytes()), results=results,
        completed_processes=processes, artifact_sha256=artifacts, corpus_sha256=corpus,
        transient_fixture_directories=list(fixtures), **counts,
        production_activated=False, whole_runtime_replaced=False, old_stack_removal_qualified=False)


def original_command(root, output, report, rustc, key):
    root, output, rustc = Path(root), Path(output), Path(rustc)
    if key == "sdk_connection":
        return [sys.executable, "-I", "-B", str(root / "tests/hia_native/compare_sdk_connection_original.py"),
            "--repo", str(root), "--native-results", str(output / "connection-native/result.json"),
            "--output", str(output / "connection-original"), "--cargo", str(rustc.with_name("cargo")), "--rustc", str(rustc)]
    manifest = bundle(output, report, key)
    if key == "directory_service":
        return [sys.executable, "-I", "-B", str(root / "scripts/hia_native_directory_qualification.py"), "original",
            "--manifest", str(manifest), "--hepta", report["compiler_checkout"], "--build-root", str(output / "build"),
            "--output", str(output / "directory-original"), "--runtime", str(root),
            "--rust-bin", str(rustc.parent), "--native-results", str(output / "directory-native")]
    require(key == "workdir_service", "unknown original service recipe")
    return [sys.executable, "-I", "-B", str(root / "tests/hia_native/compare_workdir_service_original.py"),
        "--repo", str(root), "--native-manifest", str(manifest), "--output", str(output / WORKDIR_ORIGINAL),
        "--cargo", str(rustc.with_name("cargo")), "--rustc", str(rustc), "--rustfmt", str(rustc.with_name("rustfmt"))]


def original_check(key):
    return {"directory_service": "directory-rust-compare", "workdir_service": "workdir-rust-compare",
            "sdk_connection": "connection-rust-compare"}[key]


def retained_original(root, output, report, rustc, completed, key):
    root, output, rustc = Path(root), Path(output), Path(rustc)
    command = original_command(root, output, report, rustc, key)
    check, summary = completed_process(output, report, completed, original_check(key), command)
    if key == "sdk_connection":
        value = connection.original_evidence(root, output, report, completed)
        result = workdir.obj(output / "connection-original/result.json")
        require(result["cargo"] == str(rustc.with_name("cargo")) and result["rustc"] == str(rustc),
                "connection original selected toolchain differs")
        return value
    manifest, selected = inspect_bundle(root, output, report, key)
    if key == "workdir_service":
        folder = output / WORKDIR_ORIGINAL
        result = workdir.inspect_original(folder, root, selected, sha(manifest.read_bytes()))
        require(summary == {k: v for k, v in result.items() if k not in
                {"checks", "sdk_files", "original_project_files"}}, "workdir original stdout differs")
        require(result["checks"][0]["command"] == [str(rustc), "-vV"], "workdir original selected rustc differs")
        require(result["sdk_files"] == sdk_sources(root), "workdir complete actual SDK source inventory differs")
        fixtures = WORKDIR_ORIGINAL_FIXTURES
        counts = dict(original_parameters=680, public_requests_per_side=1537,
            public_processes_per_side=74, regex_requests_per_side=36, regex_processes_per_side=18)
    else:
        folder = output / "directory-original"
        result = workdir.obj(folder / "phase.json")
        expected = dict(schema="hepta.directory.actual-original-phase.v1", status="PASS",
            expected_processes=8, completed_processes=8, current_original_replay=True, native_processes=40,
            original_processes=40, original_functional_requests=67, original_regex_requests=18,
            paired_kernel_cases=6, production_activated=False, whole_runtime_replaced=False)
        require(all(result.get(k) == v for k, v in expected.items())
                and result.get("source_inventory") == directory.source_inventory(root)
                and result.get("original_source") == directory.original_source(root, root)
                and result.get("rust_version", "").startswith("rustc 1.95.0 "),
                "directory complete original phase differs")
        require(summary == {k: result[k] for k in ("schema", "status", "completed_processes",
                "original_processes", "native_processes", "original_functional_requests", "paired_kernel_cases")},
                "directory complete original stdout differs")
        binary_sha = sha((folder / "original-reference.elf").read_bytes())
        require(result["original_binary"] == directory.record(folder / "original-reference.elf"),
                "directory original executable changed")
        expected_files = workdir.obj(root / directory.REFERENCE_MANIFEST)["files"]
        require({name: directory.record(workdir.native.file(folder / "project", name))
                for name in expected_files} == expected_files, "directory compiled source changed")
        sdk = result.get("sdk_installed_files", {})
        require(sdk == sdk_sources(root) and result.get("sdk_crate_sha256")
                == "5b6317cd8c13e3ec9033cf2aa5aa92cd743f0f4f8a93cddc42ea0ae6ce3b8898",
                "directory complete actual SDK inventory differs")
        processes = {name: directory.process_evidence(folder, name, root) for name in
            ("rust-version", "format-check", "metadata", "build", "functional", "kernel", "regex", "evidence-controls")}
        require(processes["rust-version"]["argv"] == [str(rustc.parent.resolve(strict=True) / "rustc"), "-vV"],
                "directory selected Rust invocation differs")
        tool, project = rustc.parent.resolve(strict=True), folder / "project"
        reference, tests = folder / "original-reference.elf", root / "tests/hia_native"
        exact_commands = {
            "format-check": [tool / "rustfmt", "--check", "--edition", "2021", "--config",
                "hard_tabs=true,skip_children=true", project / "owner/oracle_directory_service.rs"],
            "metadata": [tool / "cargo", "metadata", "--locked", "--format-version", "1",
                "--manifest-path", project / "Cargo.toml"],
            "build": [tool / "cargo", "build", "--release", "--locked", "--manifest-path",
                project / "Cargo.toml", "--bin", "hia-directory-service-reference"],
            "functional": [sys.executable, "-I", "-B", tests / "test_directory_service.py",
                "--manifest", manifest, "--output", folder / "functional", "--reference", reference,
                "--reference-sha256", binary_sha],
            "kernel": [sys.executable, "-I", "-B", tests / "directory_service_kernel.py",
                "--native", manifest.parent / selected["executable"], "--native-sha256", selected["elf_sha256"],
                "--original", reference, "--original-sha256", binary_sha, "--output", folder / "kernel"],
            "regex": [sys.executable, "-I", "-B", tests / "test_directory_service_regex.py",
                "--manifest", manifest, "--output", folder / "regex", "--reference", reference,
                "--reference-sha256", binary_sha],
            "evidence-controls": [sys.executable, "-I", "-B", tests / "test_directory_service_evidence.py",
                "--native-results", output / "directory-native", "--original-results", folder,
                "--output", folder / "evidence-controls"],
        }
        require(all(processes[name]["argv"] == list(map(str, argv)) for name, argv in exact_commands.items()),
                "directory actual original command domain differs")
        require((folder / "rust-version.stdout").read_text() == result["rust_version"],
                "directory retained actual compiler version differs")
        require(result["functional"] == directory.functional_evidence(folder / "functional", root, binary_sha)
                and result["kernel"] == directory.kernel_evidence(folder / "kernel", root, binary_sha)
                and result["regex"] == directory.regex_evidence(folder / "regex", root, binary_sha),
                "directory actual original/native complete domains differ")
        controls = workdir.obj(folder / "evidence-controls/report.json")
        directory.strict_summary(controls, 6)
        require(len(controls["accepted"]) == 10 and len(controls["refused"]) == 31
                and result["evidence_controls"] == dict(accepted=10, refused=31, groups=6, semantic_cases_added=0),
                "directory actual evidence controls differ")
        fixtures = ()
        counts = dict(original_processes=40, native_processes=40, functional_requests_per_side=67,
            regex_requests_per_side=18, paired_kernel_cases=6, evidence_refusals=31)
    omitted = fixtures + ((WORKDIR_ORIGINAL + "/target",) if key == "workdir_service" else ())
    corpus = retained_files(output, folder, omitted)
    if key == "workdir_service":
        path = folder / "target/release/hia-workdir-reference"
        corpus[path.relative_to(output).as_posix()] = sha(path.read_bytes())
    return dict(schema="hepta.runtime.service-original-evidence.v1", status="PASS", component=key,
        completed_process=check, retained=result, compiled_by_qualification_recipe=True,
        corpus_sha256=corpus, transient_fixture_directories=list(fixtures),
        **counts, production_activated=False, whole_runtime_replaced=False, old_stack_removal_qualified=False)


def compare_original(root, output, report, rustc, completed, record_check, env, key):
    before = (connection.native_evidence(root, output, report, completed) if key == "sdk_connection"
              else native_evidence(root, output, report, completed, key))
    require(before == report[key + "_evidence"], "service native evidence changed before original replay")
    record_check(output, report, name=original_check(key),
        command=original_command(root, output, report, rustc, key), timeout=180, env=env)
    result = retained_original(root, output, report, rustc, completed, key)
    after = (connection.native_evidence(root, output, report, completed) if key == "sdk_connection"
             else native_evidence(root, output, report, completed, key))
    require(before == after, "service native evidence changed during original replay")
    return result


def write_fixtures(output, prefix="write-chain"):
    require(prefix in ("write-chain", "write-chain-original"), "write-chain fixture owner differs")
    folder = Path(output) / prefix
    result = [prefix + "/files/fixture"]
    for name, digits, count in (("kernel", 3, 53), ("concurrency", 2, 4)):
        cases = json.loads((folder / name / "cases.json").read_bytes())
        require(len(cases) == count, "write-chain fixture domain differs")
        result += [prefix + "/" + name + "/" + str(i).zfill(digits) + "-" + row["name"] + "/fixture"
                   for i, row in enumerate(cases)]
    return tuple(result)


def retire_fixtures(output, fixtures, receipt, evidence, *, create=False):
    output, receipt = Path(output), Path(receipt)
    expected = dict(schema="hepta.runtime.service-fixture-retirement.v1", status="PASS",
        fixture_directories=list(fixtures), complete_evidence_sha256=sha(encoded(evidence)), semantic_invocations_added=0)
    if receipt.exists():
        require(not receipt.is_symlink() and workdir.obj(receipt) == expected,
                "service fixture retirement evidence differs")
    else:
        require(create and output.resolve(strict=True) == output and not output.is_symlink()
                and shutil.rmtree.avoids_symlink_attacks, "service fixture retirement is not admitted")
        paths = []
        for name in fixtures:
            p = Path(name)
            require(not p.is_absolute() and ".." not in p.parts and p.name == "fixture",
                    "service fixture retirement path escaped")
            path = output / p
            info = path.lstat()
            require(path.resolve() == path and stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(),
                    "service fixture retirement target is not an owned directory")
            paths.append(path)
        for path in paths:
            path.chmod(0o700)
            for base, dirs, _ in os.walk(path, followlinks=False):
                for name in dirs:
                    child = Path(base) / name
                    info = child.lstat()
                    if stat.S_ISDIR(info.st_mode):
                        require(info.st_uid == os.getuid(), "service fixture contains an unowned directory")
                        child.chmod(0o700, follow_symlinks=False)
            shutil.rmtree(path)
        with receipt.open("xb") as stream:
            stream.write(encoded(expected))
    require(not any((output / name).exists() or (output / name).is_symlink() for name in fixtures),
            "retired service fixture reappeared")
    return expected


def prepare_transport(root, output, report, completed):
    names = {row["name"] for row in report.get("checks", ())}
    if "test_workdir_service_regex.py" in names:
        evidence = native_evidence(root, output, report, completed, "workdir_service")
        retire_fixtures(output, evidence["transient_fixture_directories"],
                        Path(output) / "workdir-native/retired-fixtures.json", evidence, create=True)
    if "test_write_chain_evidence.py" in names:
        evidence = write_chain.qualification_evidence(root, output, report, completed)
        retire_fixtures(output, write_fixtures(output),
                        Path(output) / "write-chain/retired-fixtures.json", evidence, create=True)


def original_fixture_transport(root, output, report, rustc, completed, *, create=False):
    """Retire only closed, fully observed fixtures after original admission."""
    output = Path(output)
    receipts = {}
    for key, folder in (("workdir_service", WORKDIR_ORIGINAL), ("write_chain", "write-chain-original")):
        evidence = (write_chain.retained_original(root, output, report, rustc, completed)
                    if key == "write_chain" else retained_original(root, output, report, rustc, completed, key))
        require(evidence == report["original_rust_comparisons"][key],
                "service original evidence changed before fixture retirement")
        fixtures = write_fixtures(output, folder) if key == "write_chain" else WORKDIR_ORIGINAL_FIXTURES
        receipts[key] = retire_fixtures(output, fixtures, output / folder / "retired-fixtures.json", evidence, create=create)
        after = (write_chain.retained_original(root, output, report, rustc, completed)
                 if key == "write_chain" else retained_original(root, output, report, rustc, completed, key))
        require(after == evidence, "service fixture retirement changed retained process evidence")
    return receipts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("directory-suite",))
    parser.add_argument("--suite", choices=tuple(DIRECTORY_TESTS), required=True)
    for name in ("manifest", "hepta", "build-root", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    run_directory_suite(args)


if __name__ == "__main__":
    main()

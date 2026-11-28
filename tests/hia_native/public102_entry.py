"""Bind the installed candidate default entry to the same run's fresh public102 qualification."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
import traceback

sys.dont_write_bytecode = True
MANIFEST = "31cc74fa8f38e77e5c1f89b202fe4c8dcb1a786aa93417df01a0b2685a68c867"
BINDING = "41a42a6247d8b4bf0ccee11e743bad28285273637b9f824fcbf2f0bf9bad0726"
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def doc(path):
    return json.loads(path.read_bytes())


def pin(path):
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and path.resolve(strict=True) == path.absolute(), str(path)
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=SHA(raw), git_blob=hashlib.sha1(
        b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest())


def put(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def reap_owned(process, *, force):
    """Reap the admitted child independently of signal or receipt failures."""
    errors = []
    if process is None:
        return errors
    if force:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException:
            errors.append(dict(stage="kill-owned-group", traceback=traceback.format_exc()))
    try:
        process.wait()
    except BaseException:
        errors.append(dict(stage="reap-owned-child", traceback=traceback.format_exc()))
        # A second independent attempt still runs when the first wait was
        # interrupted. Only the session created by this entry can be signaled.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException:
            errors.append(dict(stage="final-kill-owned-group", traceback=traceback.format_exc()))
        try:
            process.wait()
        except BaseException:
            errors.append(dict(stage="final-reap-owned-child", traceback=traceback.format_exc()))
    return errors


def expected_files(package):
    assert SHA((package / "source-manifest.json").read_bytes()) == MANIFEST
    manifest = doc(package / "source-manifest.json")
    rows = manifest["files"]
    assert len(rows) == 872
    assert {p.relative_to(package).as_posix() for p in package.rglob("*") if p.is_file()} == set(rows) | {"source-manifest.json"}
    for name, identity in rows.items():
        assert pin(package / name) == identity, name
    graph = {name.removeprefix("source/"): identity for name, identity in rows.items() if name.startswith("source/")}
    assert len(graph) == 218
    assert graph["native/runtime_mcp_sources.json"]["sha256"] == BINDING
    installed = dict(graph)
    changed = []
    for path in sorted((package / "authority-retained").rglob("*")):
        if not path.is_file():
            continue
        name = path.relative_to(package / "authority-retained").as_posix()
        if path.read_bytes() == (package / "authority-historical" / name).read_bytes():
            continue
        changed.append(name)
        identity = pin(path)
        if name in installed:
            assert installed[name] == identity
        installed[name] = identity
    assert len(changed) == 7 and len(installed) == 224
    return graph, installed


def actual_files(source, expected):
    actual = {name: pin(source / name) for name in expected}
    assert actual == expected
    return actual


def reference_pins(run):
    names = ("RECIPE.json", "verification.json", "public/BUILD.json",
             "public/build/public-authority-batch/manifest.json")
    return {name: pin(run / name) for name in names}


def expected_command(receipt, recipe):
    identity = recipe["producer_identity"]
    origin = Path(identity["output"])
    expected_source = Path(identity["cwd"]) / "runtime"
    expected_output = origin / "installed-main-entry"
    assert receipt["source_root"] == str(expected_source)
    assert receipt["producer_root"] == str(expected_output)
    assert receipt["reference_run"] == str(origin)
    assert receipt["python"] == identity["python"]
    assert receipt["hepta_root"] == identity["hepta"]
    assert receipt["cwd"] == identity["cwd"]
    return [identity["python"], "-I", "-B", str(expected_source / "scripts/hia_native_runtime_mcp_build.py"),
        "--hepta", identity["hepta"], "--output", str(expected_output / "build"),
        "--bootstrap", str(origin / "retained-eight/build/bootstrap"),
        "--reuse-manifests", str(expected_output / "reuse.json")]


def verify(source, package, run, output):
    graph, expected = expected_files(package)
    actual_files(source, expected)
    actual_files(output / "installed-source", expected)
    recipe = doc(run / "RECIPE.json")
    gate = doc(run / "verification.json")
    assert recipe["status"] == "PASS"
    assert recipe["source_manifest_sha256"] == MANIFEST
    assert recipe["fresh_public_102"] is True
    assert recipe["fresh_current_owner_v4"] is True
    assert recipe["current_public_owner_replay"] is True
    assert recipe["current_owner_original_rows"] == 243
    assert recipe["current_public_owner_rows"] == 16
    assert gate["status"] == "READONLY_PUBLIC102_AUTHORITY259_HANDSHAKE324_PUBLIC90_TRANSPORT24_PASS"
    receipt = doc(output / "PROCESS.json")
    assert receipt["status"] == "ACTUAL_MAIN_DEFAULT_ENTRY_CAPTURED"
    assert receipt["command"] == expected_command(receipt, recipe)
    assert receipt["exit_code"] == 0 and receipt["outer_timeout_seconds"] is None
    assert receipt["installed_files"] == expected
    assert receipt["graph_files"] == graph
    assert receipt["source_after_build"] == expected
    assert receipt["rust_executed"] is False
    assert type(receipt["pid"]) is int and receipt["pid"] > 0
    assert type(receipt["pgid"]) is int and receipt["pgid"] == receipt["pid"]
    assert receipt["owned_process_group"] is True and receipt["cleanup_errors"] == receipt["failures"] == []
    assert receipt["reference_evidence_before"] == receipt["reference_evidence_after"] == reference_pins(run)
    for name in ("stdout", "stderr"):
        assert pin(output / (name + ".bin")) == receipt[name]
    assert not (output / "stderr.bin").read_bytes()
    assert (output / "producer.py").read_bytes() == Path(__file__).read_bytes()
    reference = doc(run / "public/BUILD.json")
    current = doc(output / "build/BUILD.json")
    assert current["status"] == "NATIVE_BUILD_PASS" and current["default_public_entrypoint"] is True
    assert current["physical_images"] == reference["physical_images"] == 102
    assert current["fresh_member_compiles"] == 0 and current["checked_reused_members"] == 102
    assert reference["fresh_member_compiles"] == 102 and reference["checked_reused_members"] == 0
    folder = output / "build/build/public-authority-batch"
    original_folder = run / "public/build/public-authority-batch"
    manifest = folder / "manifest.json"
    assert SHA(manifest.read_bytes()) == current["manifest_sha256"]
    actual = doc(manifest)
    qualified = doc(original_folder / "manifest.json")
    assert actual["source_binding"] == qualified["source_binding"]
    assert actual["extra_table"] == qualified["extra_table"]
    assert actual["implemented_tools"] == qualified["implemented_tools"]
    assert len(actual["members"]) == len(qualified["members"]) == 102
    origin_run = Path(reference["manifest"]).parents[3]
    expected_reuse = {}
    for member, original in zip(actual["members"], qualified["members"], strict=True):
        assert member["fresh_compile"] is False and original["fresh_compile"] is True
        for key in ("name", "source", "source_sha256", "image_sha256", "image_bytes", "buffer_profile"):
            assert member[key] == original[key], (member["name"], key)
        relative = Path(original["manifest"]).relative_to(origin_run)
        assert not relative.is_absolute() and ".." not in relative.parts
        expected_manifest = str(Path(receipt["reference_run"]) / relative)
        expected_reuse[member["name"]] = expected_manifest
        assert member["manifest"] == expected_manifest
        assert member["manifest_sha256"] == original["manifest_sha256"] == pin(run / relative)["sha256"]
    assert doc(output / "reuse.json") == expected_reuse
    assert doc(output / "stdout.bin") == current
    executable = folder / actual["elf"]
    original_executable = original_folder / qualified["elf"]
    assert executable.read_bytes() == original_executable.read_bytes()
    assert SHA(executable.read_bytes()) == current["elf_sha256"] == reference["elf_sha256"] == actual["elf_sha256"]
    assert executable.stat().st_size == current["elf_bytes"] == reference["elf_bytes"]
    assert current["elf_sha256"] == recipe["candidate_elf_sha256"]
    return dict(status="ACTUAL_MAIN_DEFAULT_ENTRY_EQUALS_QUALIFIED_PUBLIC102",
        graph_files=218, installed_files=224, authority_profile_rebindings=7,
        physical_images=102, reference_fresh_members=102, entry_checked_reused_members=102,
        same_complete_executable_bytes=True, elf_sha256=current["elf_sha256"],
        same_reference_recipe_and_compilation_manifests=True,
        source_binding_sha256=BINDING, current_owner_original_rows=243,
        current_public_owner_original_rows=16, native_or_rust_executed_by_reader=False,
        production_activated=False, old_path_removed=False, full_sdk_qualified=False,
        full_async_qualified=False, target_original_public_handler_comparison=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "reference-package"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("run", "output"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--hepta", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--check-source-only", action="store_true")
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    package = args.reference_package.resolve(strict=True)
    graph, expected = expected_files(package)
    if args.check_source_only:
        assert not args.verify_only
        actual_files(source, expected)
        print(json.dumps(dict(status="INSTALLED_PUBLIC102_SOURCE_IDENTITIES_PASS",
            graph_files=218, installed_files=224, authority_profile_rebindings=7,
            source_binding_sha256=BINDING, native_or_rust_executed=False), sort_keys=True))
        return
    assert args.run is not None and args.output is not None
    run = args.run.resolve(strict=True)
    output = args.output.absolute()
    if args.verify_only:
        reference_root = package.parent
        assert SHA((reference_root / "joint-source.json").read_bytes()) == "5ff90d433a604920d689f56ffd38e3c95e622f0ab5b72bc143d500d4c9e6404d"
        source_path = reference_root / "check_package.py"
        assert pin(source_path)["sha256"] == "22bebc4b6bd28b0c7ce4d39ce60eeefd29746a4c0a0ab73ae38c8649d437dd4e"
        source_spec = importlib.util.spec_from_file_location("_public102_entry_source", source_path)
        source_reader = importlib.util.module_from_spec(source_spec)
        source_spec.loader.exec_module(source_reader)
        source_reader.check(reference_root)
        guard_file = package / "owner-reference/tests/hia_native/caller_owner_export/verify_readonly.py"
        spec = importlib.util.spec_from_file_location("_public102_entry_guard", guard_file)
        guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard)
        # The immutable complete reference package is admitted first. The
        # installed source roots also admit this exact entry file under tests.
        roots = [reference_root, run, output]
        roots.extend(source / name for name in sorted({Path(name).parts[0] for name in expected}))
        assert Path(__file__).resolve(strict=True).is_relative_to(source / "tests")
        result = guard.guarded(lambda: verify(source, package, run, output),
            roots=roots, foreign_path=Path("/dev/null"))
        assert len(result["probes"]) == 11 and result["before"] == result["after"]
        print(json.dumps(result, sort_keys=True))
        return
    assert args.hepta is not None and not output.exists()
    assert not output.is_relative_to(source) and not output.is_relative_to(package)
    assert doc(run / "RECIPE.json")["status"] == "PASS"
    assert doc(run / "public/BUILD.json")["fresh_member_compiles"] == 102
    actual_files(source, expected)
    output.mkdir(parents=True)
    for name in expected:
        target = output / "installed-source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
    original = doc(run / "public/BUILD.json")
    reference_before = reference_pins(run)
    origin_run = Path(original["manifest"]).parents[3]
    manifest = doc(run / "public/build/public-authority-batch/manifest.json")
    reuse = {}
    for row in manifest["members"]:
        relative = Path(row["manifest"]).relative_to(origin_run)
        assert not relative.is_absolute() and ".." not in relative.parts
        reuse[row["name"]] = str(run / relative)
    assert len(reuse) == 102
    put(output / "reuse.json", reuse)
    command = [sys.executable, "-I", "-B", str(source / "scripts/hia_native_runtime_mcp_build.py"),
        "--hepta", str(args.hepta.resolve(strict=True)), "--output", str(output / "build"),
        "--bootstrap", str(run / "retained-eight/build/bootstrap"),
        "--reuse-manifests", str(output / "reuse.json")]
    started = time.monotonic()
    process = None
    code = None
    raised = None
    failures = []
    try:
        with (output / "stdout.bin").open("xb") as stdout, (output / "stderr.bin").open("xb") as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
            code = process.wait()
    except BaseException as error:
        raised = error
        failures.append(dict(stage="execute-entry", traceback=traceback.format_exc()))
    finally:
        cleanup = reap_owned(process, force=code != 0 or raised is not None)
        if process is not None:
            code = process.returncode
        def observe(label, action):
            try:
                return action()
            except BaseException:
                failures.append(dict(stage=label, traceback=traceback.format_exc()))
                return None
        receipt = dict(command=command, exit_code=code,
            elapsed_seconds=time.monotonic() - started, outer_timeout_seconds=None,
            graph_files=graph, installed_files=expected,
            source_after_build=observe("source-after", lambda: actual_files(source, expected)),
            pid=process.pid if process is not None else None,
            pgid=process.pid if process is not None else None,
            owned_process_group=process is not None, cleanup_errors=cleanup, reference_run=str(run),
            reference_evidence_before=reference_before,
            reference_evidence_after=observe("reference-after", lambda: reference_pins(run)),
            stdout=observe("complete-stdout", lambda: pin(output / "stdout.bin")),
            stderr=observe("complete-stderr", lambda: pin(output / "stderr.bin")), rust_executed=False,
            python=sys.executable, source_root=str(source), producer_root=str(output),
            hepta_root=str(args.hepta.resolve(strict=True)), cwd=os.getcwd())
        observe("producer-source", lambda: shutil.copyfile(Path(__file__), output / "producer.py"))
        receipt["failures"] = failures
        receipt["status"] = ("ACTUAL_MAIN_DEFAULT_ENTRY_CAPTURED" if code == 0 and not failures and not cleanup
            else "ACTUAL_MAIN_DEFAULT_ENTRY_FAILED")
        put(output / "PROCESS.json", receipt)
    if raised is not None:
        raise raised
    assert receipt["status"] == "ACTUAL_MAIN_DEFAULT_ENTRY_CAPTURED", receipt["status"]
    print(json.dumps(verify(source, package, run, output), sort_keys=True))


if __name__ == "__main__":
    main()

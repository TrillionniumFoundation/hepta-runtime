"""Pure Python controls for the exact historical pre-CDLL admission prefix."""
from __future__ import annotations
import copy
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types

from static_code_admission import LOADER_SHA256, StaticCodeAdmission, need, sha


def _run(loader_source):
    original_bytes = Path(loader_source).read_bytes()
    need(sha(original_bytes) == LOADER_SHA256, "control historical loader identity")
    refusals = []
    saved = {key: sys.modules.get(key) for key in ("hia_native_loader", "_history_static_alias", "_history_static_late")}
    with tempfile.TemporaryDirectory(prefix="hia-history-static-controls-") as temporary:
        home = Path(temporary)
        source = home / "source"
        output = home / "capture"
        (source / "scripts").mkdir(parents=True)
        output.mkdir()
        loader_path = source / "scripts/hia_native_loader.py"
        loader_path.write_bytes(original_bytes)
        spec = importlib.util.spec_from_file_location("hia_native_loader", loader_path)
        loader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loader)
        sys.modules["hia_native_loader"] = loader
        original_class = loader.NativeModule
        source_bytes, image_bytes = b"retained source bytes\n", b"retained image bytes\0"
        source_path, image_path = output / "sample.hepta", output / "sample.image.bin"
        source_path.write_bytes(source_bytes)
        image_path.write_bytes(image_bytes)
        metadata = {"schema": "hepta.runtime.native-module.v1", "abi": loader.ABI,
                    "target": "linux-x86_64", "compiler_commit": loader.COMPILER_COMMIT,
                    "source": source_path.name, "image": image_path.name,
                    "source_sha256": sha(source_bytes), "image_sha256": sha(image_bytes),
                    "compiler_sha256": "4" * 64, "buffer_profile": "standard",
                    "input_capacity": 128, "output_capacity": 128, "workspace_capacity": 128}

        def encoded(value):
            return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

        raw = encoded(metadata)
        manifest = output / "manifest.json"
        manifest.write_bytes(raw)
        report = {"modules": {"sample": {"manifest": manifest.name, "sha256": sha(raw)}}}
        alias = types.ModuleType("_history_static_alias")
        alias.__file__ = str(source / "scripts/alias.py")
        Path(alias.__file__).write_text("# fixture-owned alias\n")
        alias.NativeModule = original_class
        sys.modules[alias.__name__] = alias
        adapter = None

        def reject(name, operation):
            try:
                operation()
            except (ValueError, PermissionError, OSError) as error:
                refusals.append({"name": name, "exception": type(error).__name__, "message": str(error)})
            else:
                raise AssertionError("static admission accepted " + name)

        try:
            adapter = StaticCodeAdmission(source, output, report, expected_module_count=1)
            adapter.install()
            need(loader.NativeModule is adapter.replacement and alias.NativeModule is adapter.replacement,
                 "all owned preloaded aliases replaced")
            with loader.NativeModule(manifest, manifest_sha256=sha(raw)) as admitted:
                need(admitted.metadata == metadata and admitted._address is None and admitted._entry is None,
                     "complete actual metadata and absence of executable mapping")
                for method, args in (("invoke", (b"",)), ("invoke_raw", (b"",)),
                                     ("session", ()), ("_invoke_buffers", ())):
                    reject("execution-" + method, lambda method=method, args=args: getattr(admitted, method)(*args))
            changed = output / "changed.json"

            def changed_manifest(value=None, *, data=None, digest=None):
                data = encoded(value) if data is None else data
                changed.write_bytes(data)
                return loader.NativeModule(changed, manifest_sha256=sha(data) if digest is None else digest)

            for field, value, name in (
                ("schema", "wrong", "schema"), ("abi", "wrong", "abi"),
                ("compiler_commit", "0" * 40, "compiler-commit"),
                ("source", "../sample.hepta", "source-basename"),
                ("image", "/image.bin", "image-basename"),
                ("image_sha256", "A" * 64, "member-hash-shape"),
                ("buffer_profile", "unregistered", "profile"),
                ("input_capacity", True, "boolean-capacity"),
                ("output_capacity", 0, "zero-capacity"),
                ("workspace_capacity", (32 << 20) + 1, "maximum-capacity"),
                ("source_sha256", "0" * 64, "complete-source-digest"),
                ("image_sha256", "0" * 64, "complete-image-digest")):
                value_metadata = copy.deepcopy(metadata)
                value_metadata[field] = value
                reject(name, lambda value_metadata=value_metadata: changed_manifest(value_metadata))
            reject("manifest-digest", lambda: changed_manifest(metadata, digest="0" * 64))
            duplicate = raw.rstrip()[:-1] + b',"schema":"hepta.runtime.native-module.v1"}\n'
            reject("duplicate-manifest-field", lambda: changed_manifest(data=duplicate))
            foreign = home / "foreign.json"
            foreign.write_bytes(raw)
            reject("foreign-manifest", lambda: loader.NativeModule(foreign, manifest_sha256=sha(raw)))
            reject("registered-manifest-pin", lambda: loader.NativeModule(manifest, manifest_sha256="0" * 64))
            reject("registered-table-count", lambda: StaticCodeAdmission(source, output, report))
            bad_report = copy.deepcopy(report)
            bad_report["modules"]["sample"]["sha256"] = "0" * 64
            reject("registered-table-pin", lambda: StaticCodeAdmission(source, output, bad_report, expected_module_count=1))
            source_path.write_bytes(b"")
            try:
                reject("empty-source", lambda: changed_manifest(metadata))
            finally:
                source_path.write_bytes(source_bytes)
            image_path.write_bytes(image_bytes + b"extra")
            try:
                reject("changed-image-bytes", lambda: changed_manifest(metadata))
            finally:
                image_path.write_bytes(image_bytes)
            loader_path.write_bytes(original_bytes + b"\n")
            try:
                reject("changed-loader-source", lambda: StaticCodeAdmission(source, output, report, expected_module_count=1))
            finally:
                loader_path.write_bytes(original_bytes)
            late = types.ModuleType("_history_static_late")
            late.__file__ = str(source / "scripts/late.py")
            Path(late.__file__).write_text("# fixture-owned late alias\n")
            late.NativeModule = loader.NativeModule
            sys.modules[late.__name__] = late
            evidence = adapter.evidence()
            need(len(evidence["admissions"]) == 1 and evidence["new_executable_mappings"] == 0,
                 "one complete static admission with no mapping")
            need(evidence["execution_attempts"] == ["invoke", "invoke_raw", "session", "_invoke_buffers"],
                 "all invocation paths explicitly refused")
            adapter.restore()
            need(all(module.NativeModule is original_class for module in (loader, alias, late)),
                 "all owned early and late aliases restored")
        finally:
            if adapter is not None:
                adapter.restore()
            for name, old in saved.items():
                if old is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = old
    need(len(refusals) == 25, "complete static-admission refusal set")
    return {"schema": "hepta.history.static-code-controls.v1", "status": "PASS",
            "complete_static_admissions": 1, "refusals": refusals,
            "prefix": evidence["prefix"], "early_and_late_alias_restoration": True,
            "native_or_rust_executions": 0, "new_executable_mappings": 0,
            "kernel_mapping_and_seals_retested": False}


def run(loader_source):
    active = [True]
    forbidden = []

    def audit(event, args):
        if active[0] and (event in {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn",
                                   "os.fork", "os.forkpty", "mmap.__new__"} or event.startswith("ctypes.")):
            forbidden.append(event)
            raise PermissionError("static code controls cannot execute or map native code: " + event)

    sys.addaudithook(audit)
    try:
        result = _run(loader_source)
        need(forbidden == [], "static admission attempted executable mapping or a process")
        result["forbidden_execution_attempts"] = forbidden
        return result
    finally:
        active[0] = False

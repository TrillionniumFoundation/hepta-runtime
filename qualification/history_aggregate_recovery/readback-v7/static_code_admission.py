"""Exact historical loader input admission without new executable mappings.

The original capture already retains its actual native process evidence.  This
reader runs every historical constructor statement before CDLL unchanged, and
refuses all entry/session operations.  It does not re-test current kernel RX
mapping, memfd creation or seals, and does not claim to do so.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import importlib
import json
from pathlib import Path
import sys

LOADER_SHA256 = "58e2fe0492379340d7471a7857e1aa5de1a9a5d1e37a118852278b131bb1fe06"


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def original_prefix(loader):
    path = Path(loader.__file__).resolve(strict=True)
    raw = path.read_bytes()
    need(sha(raw) == LOADER_SHA256, "exact historical loader source")
    tree = ast.parse(raw, filename=str(path))
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "NativeModule"]
    need(len(classes) == 1, "one historical native module class")
    functions = [node for node in classes[0].body if isinstance(node, ast.FunctionDef) and node.name == "__init__"]
    need(len(functions) == 1, "one historical native module constructor")
    original = functions[0]
    boundaries = [number for number, node in enumerate(original.body)
                  if isinstance(node, ast.Assign) and len(node.targets) == 1
                  and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "libc"
                  and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute)
                  and isinstance(node.value.func.value, ast.Name) and node.value.func.value.id == "ctypes"
                  and node.value.func.attr == "CDLL"]
    need(len(boundaries) == 1 and boundaries[0] > 0, "one exact pre-CDLL boundary")
    stop = boundaries[0]
    prefix = copy.deepcopy(original)
    prefix.name = "_historical_static_init"
    prefix.body = prefix.body[:stop]
    unchanged = ast.dump(ast.Module(body=prefix.body, type_ignores=[]), include_attributes=False)
    need(unchanged == ast.dump(ast.Module(body=original.body[:stop], type_ignores=[]),
                              include_attributes=False), "all pre-CDLL statements remain identical")
    # Return the exact bytes the unchanged statements actually read, solely
    # for a complete admission receipt.  No HIA output is synthesized.
    prefix.body.append(ast.Return(value=ast.Tuple(elts=[ast.Name(id=name, ctx=ast.Load())
                                                      for name in ("raw", "source", "image")], ctx=ast.Load())))
    module = ast.Module(body=[prefix], type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = dict(loader.__dict__)
    exec(compile(module, str(path), "exec"), namespace)
    lines = raw.splitlines(keepends=True)
    prefix_raw = b"".join(lines[original.lineno - 1:original.body[stop - 1].end_lineno])
    return namespace[prefix.name], {
        "loader_sha256": LOADER_SHA256,
        "constructor_statements": len(original.body),
        "unchanged_pre_cdll_statements": stop,
        "pre_cdll_ast_sha256": sha(unchanged.encode()),
        "pre_cdll_source_sha256": sha(prefix_raw),
        "kernel_mapping_and_seals_retested": False,
    }


class StaticCodeAdmission:
    def __init__(self, source, output, report, *, expected_module_count=87):
        self.source = Path(source).resolve(strict=True)
        self.output = Path(output).resolve(strict=True)
        self.loader = importlib.import_module("hia_native_loader")
        need(Path(self.loader.__file__).resolve(strict=True) == self.source / "scripts/hia_native_loader.py",
             "historical loader must come from the exact materialized source")
        self.original = self.loader.NativeModule
        self.prefix, self.prefix_proof = original_prefix(self.loader)
        need(type(expected_module_count) is int and expected_module_count > 0,
             "exact expected module table count")
        table = report["modules"]
        need(type(table) is dict and len(table) == expected_module_count, "complete registered module table")
        self.registered = {}
        self.module_table = []
        for key, row in sorted(table.items()):
            need(type(key) is str and type(row) is dict, "registered module row")
            relative = Path(row["manifest"])
            need(not relative.is_absolute() and ".." not in relative.parts, "registered manifest relative path")
            path = self.output / relative
            need(path.resolve(strict=True) == path and path.is_file(), "registered ordinary manifest")
            raw = path.read_bytes()
            need(sha(raw) == row["sha256"], "registered complete manifest bytes")
            prior = self.registered.get(str(path))
            need(prior is None or prior == row["sha256"], "registered manifest aliases disagree")
            self.registered[str(path)] = row["sha256"]
            self.module_table.append({"key": key, "manifest": relative.as_posix(),
                                      "bytes": len(raw), "sha256": sha(raw)})
        self.admissions = []
        self.execution_attempts = []
        self.bindings = []
        self.installed = False
        owner = self

        class ReadOnlyModule:
            def __init__(self, manifest_path, *, manifest_sha256):
                path = Path(manifest_path).absolute()
                need(path.resolve(strict=True) == path and path.is_relative_to(owner.output),
                     "static module admission remains within the retained capture")
                registered = owner.registered.get(str(path))
                need(registered is None or registered == manifest_sha256,
                     "constructor pin differs from the registered module table")
                raw, source_raw, image = owner.prefix(self, path, manifest_sha256=manifest_sha256)
                owner.admissions.append({
                    "manifest": path.relative_to(owner.output).as_posix(),
                    "manifest_bytes": len(raw), "manifest_sha256": sha(raw),
                    "source": self.source_path.relative_to(owner.output).as_posix(),
                    "source_bytes": len(source_raw), "source_sha256": sha(source_raw),
                    "image": (path.parent / self.metadata["image"]).relative_to(owner.output).as_posix(),
                    "image_bytes": len(image), "image_sha256": sha(image),
                    "metadata": copy.deepcopy(self.metadata),
                    "registered_top_level_manifest": registered is not None,
                    "new_executable_mapping": False,
                })

            def denied(self, method, *args, **kwargs):
                owner.execution_attempts.append(method)
                raise PermissionError("retained aggregate static admission refuses native " + method)

            def invoke(self, *args, **kwargs):
                return self.denied("invoke", *args, **kwargs)

            def invoke_raw(self, *args, **kwargs):
                return self.denied("invoke_raw", *args, **kwargs)

            def session(self, *args, **kwargs):
                return self.denied("session", *args, **kwargs)

            def _invoke_buffers(self, *args, **kwargs):
                return self.denied("_invoke_buffers", *args, **kwargs)

            def close(self):
                need(self._address is None and self._entry is None,
                     "static admitted module unexpectedly owns executable code")

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.close()

        self.replacement = ReadOnlyModule

    def source_modules(self):
        for name, module in list(sys.modules.items()):
            path = getattr(module, "__file__", None)
            if type(path) is str and Path(path).absolute().is_relative_to(self.source):
                yield name, module

    def install(self):
        need(not self.installed and self.loader.NativeModule is self.original, "static adapter installation state")
        self.installed = True
        for name, module in self.source_modules():
            for key, value in list(vars(module).items()):
                if value is self.original:
                    setattr(module, key, self.replacement)
                    self.bindings.append({"module": name, "attribute": key,
                                          "source": str(Path(module.__file__).absolute().relative_to(self.source))})
        need(self.loader.NativeModule is self.replacement, "historical loader binding installed")

    def restore(self):
        if self.installed:
            # Late imports also bind the same replacement class.  Restore all
            # such aliases without changing any source or retained evidence.
            for _, module in self.source_modules():
                for key, value in list(vars(module).items()):
                    if value is self.replacement:
                        setattr(module, key, self.original)
            need(self.loader.NativeModule is self.original, "historical loader binding restored")
            self.installed = False

    def evidence(self):
        return {"schema": "hepta.history.static-code-admission.v1",
                "source": str(self.source), "output": str(self.output),
                "prefix": self.prefix_proof, "registered_modules": self.module_table,
                "bindings": self.bindings, "admissions": self.admissions,
                "execution_attempts": self.execution_attempts,
                "new_executable_mappings": 0, "native_or_rust_executions": 0,
                "kernel_mapping_and_seals_retested": False,
                "original_native_process_evidence_required_by_unchanged_readers": True}

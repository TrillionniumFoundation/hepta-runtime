"""Admit and preload the exact already qualified original capture in an isolated namespace."""
from contextlib import contextmanager
from pathlib import Path
import hashlib
import importlib.util
import sys
from common import loads, pin, read, require

BASE_SHA = "35b5d7c107e0583ac3a25cdcabf5ec9f547fbb31840079c49b5486230b8281e6"
ADAPTER_SHA = "b15f253b6fd6a0ae306c1844cef269df1c5477f9fcaac09b8f9cec6581129e8d"
NAMES = ("common", "protocol", "fixture", "abi_controls", "read_build", "read_native",
         "read_original", "read_capture", "read_only_guard", "reader_controls", "reader_cli",
         "commands", "read_adapter")


def frozen(root, filename, expected):
    raw = read(root / filename)
    require(pin(raw)["sha256"] == expected, "unchanged qualified source manifest")
    manifest = loads(raw)
    for name, row in manifest["files"].items():
        relative = Path(name)
        require(not relative.is_absolute() and ".." not in relative.parts, "frozen source path")
        body = read(root / relative)
        require(pin(body) == {key: row[key] for key in ("bytes", "sha256")} and
                hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest() == row["git_blob"],
                "every source byte admitted before Python compilation")
    return manifest


@contextmanager
def namespace(modules, paths):
    saved = {name: sys.modules.get(name) for name in NAMES}
    old_path = list(sys.path)
    try:
        for name in NAMES:
            if name in modules:
                sys.modules[name] = modules[name]
            else:
                sys.modules.pop(name, None)
        sys.path[:0] = [str(p) for p in paths]
        yield
    finally:
        sys.path[:] = old_path
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


def prepare(root):
    base = root / "retained/source"
    adapter_root = root / "recovery-source"
    frozen(base, "SOURCE.json", BASE_SHA)
    frozen(adapter_root, "RECOVERY_SOURCE.json", ADAPTER_SHA)
    with namespace({}, [adapter_root, base]):
        spec = importlib.util.spec_from_file_location("read_adapter", adapter_root / "read_adapter.py")
        adapter = importlib.util.module_from_spec(spec)
        sys.modules["read_adapter"] = adapter
        spec.loader.exec_module(adapter)
        reader, controls, guard = adapter.install(base)
        import reader_cli
        reader_cli.prepare()
        modules = {name: sys.modules[name] for name in NAMES if name in sys.modules}
        require(modules["common"].source() == BASE_SHA, "unchanged original source after complete preload")
    return dict(root=root, base=base, adapter=adapter_root, modules=modules, reader=reader)


def compare(prepared, native):
    root, base, adapter = prepared["root"], prepared["base"], prepared["adapter"]
    frozen(base, "SOURCE.json", BASE_SHA)
    frozen(adapter, "RECOVERY_SOURCE.json", ADAPTER_SHA)
    with namespace(prepared["modules"], [adapter, base]):
        import common
        import read_original
        capture = root / "retained/run/semantic"
        metadata = common.loads(common.read(capture / "CAPTURE.json"))
        baseline = prepared["reader"].semantic(capture)
        require(baseline["status"] == "PASS" and baseline["native"]["calls"] == 5764 and
                baseline["native"]["refusals"] == 658 and baseline["original"]["operations"] == 459,
                "complete already qualified original and direct-owner domain retained")
        result = read_original.verify(capture, metadata, native)
        require(result["cases"] == 219 and result["operations"] == 459 and
                result["original_errors"] == 96 and result["durable_syscalls"] == 608 and
                native["fixture"] == metadata["owned_fixture"] and
                native["uid"] == metadata["uid"] and native["gid"] == metadata["gid"],
                "new native callable compares every existing original outcome/file/durable effect")
        return dict(status="COMPLETE_RETAINED_ORIGINAL_COMPARISON_PASS",
                    original_source_manifest_sha256=BASE_SHA, reader_adapter_source_sha256=ADAPTER_SHA,
                    original=result, retained_native=baseline["native"], original_rust_replay=0)

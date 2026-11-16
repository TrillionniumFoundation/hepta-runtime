"""Owned test transport for the fixed nine native authorities.

This adapter routes existing HIA capabilities and records complete buffers. It
does not select or calculate a session owner, authenticate headers, or bind it.
"""
from __future__ import annotations
import ctypes
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests/hia_native"))
from hia_native_loader import NativeModule
from authority_native_harness import Harness, frame, response

PROFILE_SHA = "1bc46dd775110425c5350efa66cc1ccef3d393cd190a335e6717e013b369e367"
FIXTURE_SOURCE = "cf33465aa3e26fde3e7c28d092f566000d2e0e01eb824cfbc4bf8f9325b23675"
FIXTURE_IMAGE = "e7fd77ba95a5f8ad13de09e1e06455437002b8305b5533b4f9ba9d7a97ed632d"

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

def regular(path):
    path = Path(path).absolute()
    if not path.is_file() or path.is_symlink() or path.resolve() != path:
        raise ValueError("native module source must be a regular owned file")
    return path.read_bytes()

class Modules:
    def __init__(self, manifest, fixture, *, source_root=ROOT, trace=None):
        self.modules = {}
        raw = regular(source_root / "native/caller_owner_export_profile.json")
        if sha(raw) != PROFILE_SHA:
            raise ValueError("new authority profile changed")
        profile = json.loads(raw)
        manifest = Path(manifest)
        graph_raw = regular(manifest)
        graph = json.loads(graph_raw)
        self.profile = [dict(row) for row in profile["members"]]
        if len(graph["members"]) != 9:
            raise ValueError("authority graph member inventory")
        self.profile[7] = dict(id=7, name="scope-entropy-fixture", flags=0, call_mask=0,
            input_capacity=48, output_capacity=128, workspace_capacity=128,
            source="tests/hia_native/scope_entropy_fixture.hepta", source_sha256=FIXTURE_SOURCE,
            image_sha256=FIXTURE_IMAGE, image_bytes=0)
        loaded = []
        try:
            for index, member in enumerate(self.profile):
                path = Path(fixture) if index == 7 else manifest.parent / graph["members"][index]["manifest"]
                metadata_raw = regular(path)
                metadata = json.loads(metadata_raw)
                if index != 7 and sha(metadata_raw) != graph["members"][index]["manifest_sha256"]:
                    raise ValueError("actual graph member manifest differs")
                for field in ("source", "image"):
                    if Path(metadata[field]).name != metadata[field]:
                        raise ValueError("child source/image path escapes")
                source = regular(path.parent / metadata["source"])
                image = regular(path.parent / metadata["image"])
                if source != regular(source_root / member["source"]) or sha(source) != member["source_sha256"] or sha(image) != member["image_sha256"]:
                    raise ValueError("actual child source/image differs")
                if metadata["source_sha256"] != sha(source) or metadata["image_sha256"] != sha(image):
                    raise ValueError("actual child metadata content differs")
                self.modules[index] = NativeModule(path, manifest_sha256=sha(metadata_raw))
                if trace is not None:
                    self.modules[index]._entry = trace.wrap(index, self.modules[index]._entry)
                loaded.append({"id": index, "manifest_sha256": sha(metadata_raw), "source_sha256": sha(source),
                    "image_sha256": sha(image), "image_bytes": len(image)})
        except BaseException:
            self.close()
            raise
        self.loaded_artifacts = {"schema": "hepta.runtime.owner-export.loaded-fixture.v2",
            "profile_sha256": sha(raw), "graph_manifest_sha256": sha(graph_raw),
            "fixture_entropy": True, "members": loaded}

    def close(self):
        for module in self.modules.values():
            module.close()

class Trace:
    def __init__(self, output):
        self.output = Path(output)
        (self.output / "buffers").mkdir(parents=True)
        self.stream = (self.output / "calls.jsonl").open("xb")
        self.index = {}
        self.calls = 0
        self.row = 0
        self.context = 0
        self.buffer_bytes = 0

    def blob(self, raw):
        key = sha(raw)
        row = {"bytes": len(raw), "sha256": key}
        if key not in self.index:
            packed = gzip.compress(raw, compresslevel=1, mtime=0)
            (self.output / "buffers" / (key + ".gz")).write_bytes(packed)
            self.index[key] = {**row, "compressed_bytes": len(packed), "compressed_sha256": sha(packed)}
        self.buffer_bytes += len(raw)
        return row

    def wrap(self, module, actual):
        def invoke(source, size, output, capacity, workspace, count):
            self.calls += 1
            label = self.calls
            source_at = ctypes.cast(source, ctypes.c_void_p).value
            output_at = ctypes.cast(output, ctypes.c_void_p).value
            work_at = ctypes.cast(workspace, ctypes.c_void_p).value
            before = {"input": self.blob(ctypes.string_at(source_at, size)),
                "output": self.blob(ctypes.string_at(output_at, capacity + 16)),
                "workspace": self.blob(ctypes.string_at(work_at, count + 16))}
            result = actual(source, size, output, capacity, workspace, count)
            after = {"input": self.blob(ctypes.string_at(source_at, size)),
                "output": self.blob(ctypes.string_at(output_at, capacity + 16)),
                "workspace": self.blob(ctypes.string_at(work_at, count + 16))}
            if before["input"] != after["input"]:
                raise ValueError("actual native input mutation")
            self.stream.write(encoded({"id": label, "row": self.row, "context": self.context,
                "module": module, "code": result, "input_bytes": size,
                "output_capacity": capacity, "workspace_capacity": count,
                "before": before, "after": after}))
            self.stream.flush()
            return result
        return invoke

    def close(self):
        self.stream.close()
        (self.output / "buffers.json").write_bytes(encoded(self.index))

def bound(harness):
    if harness.get(0, 80) == 0:
        return None
    if harness.get(0, 80) != 1 or harness.get(0, 88) not in (0, 1):
        raise ValueError("noncanonical actual private binding")
    return {"owner": harness.bytes(0, 352, 32).hex(), "authenticated": bool(harness.get(0, 88))}

def projection(state):
    if state is None:
        raise ValueError("projection requires actual bound state")
    return b"HROWR001" + struct.pack("<Q", state["authenticated"]) + state["owner"].encode()

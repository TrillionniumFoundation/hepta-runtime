# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Portable test-only custody and comparison helpers for SDK connection owners."""
from pathlib import Path
import gzip
import hashlib
import json
import os
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_loader import NativeModule

sha = lambda raw: hashlib.sha256(raw).hexdigest()
encoded = lambda value: (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
U = lambda raw, at: struct.unpack_from("<Q", raw, at)[0]
VARIANTS = ["PingRequest", "InitializeRequest", "DiscoverRequest", "CompleteRequest", "SetLevelRequest",
            "GetPromptRequest", "ListPromptsRequest", "ListResourcesRequest", "ListResourceTemplatesRequest",
            "ReadResourceRequest", "SubscriptionsListenRequest", "SubscribeRequest", "UnsubscribeRequest",
            "CallToolRequest", "ListToolsRequest", "GetTaskRequest", "UpdateTaskRequest", "CancelTaskRequest", "CustomRequest"]
VARIANTS = {value: i + 1 for i, value in enumerate(VARIANTS)} | {
    value: i + 101 for i, value in enumerate(["CancelledNotification", "ProgressNotification", "InitializedNotification",
                                            "RootsListChangedNotification", "CustomNotification"])}


def pair(raw, at):
    offset, size = struct.unpack_from("<QQ", raw, at)
    assert (offset == 0 and size == 0) or 256 <= offset <= offset + size <= len(raw)
    return None if offset == 0 else raw[offset:offset + size]


def projection_parts(raw):
    assert raw[:8] == b"HRCJR001" and len(raw) >= 256
    return [pair(raw, 64 + i * 16) for i in range(10)]


def message_frame(raw):
    return b"HRCJQ001" + struct.pack("<QQ", 1, len(raw)) + raw


def connection_frame(raw):
    return b"HRCNQ001" + struct.pack("<QQ", 1, len(raw)) + raw


def compare_projection(raw, projection, direct, transport):
    parts = projection_parts(projection)
    expected = 5 if transport["response_raw"] else 0
    if transport["messages"]:
        assert len(transport["messages"]) == 1
        expected = {"request": 1, "notification": 2, "response": 3, "error": 4}[transport["messages"][0]["kind"]]
    assert U(projection, 8) == expected, ("disposition", U(projection, 8), expected)
    if direct["accepted"] and direct["kind"] in ("request", "notification"):
        assert U(projection, 16) == VARIANTS[direct["variant"]]
        assert parts[0].decode() == direct["message"]["method"]
        assert json.loads(parts[2]) == direct["meta"]
        if direct["kind"] == "request":
            assert json.loads(parts[1]) == direct["id"]
            missing = int("io.modelcontextprotocol/protocolVersion" in direct["missing"])
            missing |= int("io.modelcontextprotocol/clientCapabilities" in direct["missing"]) << 1
            assert U(projection, 24) == missing
        if "params" in direct["message"]:
            assert parts[7] is not None and json.loads(parts[7]) == direct["message"]["params"]
            if direct["variant"] not in {"CustomRequest", "CustomNotification"}:
                assert parts[7] == direct["wire"].split(',"params":', 1)[1][:-1].encode()
    if direct["accepted"] and direct["kind"] in ("response", "error"):
        # Response ClientResult normalization belongs to the eventual peer-response
        # owner. Complete raw wire is retained; it is never replaced with null.
        assert parts[9] == raw
        if direct["kind"] == "error":
            assert parts[7] == direct["wire"].split(',"error":', 1)[1][:-1].encode()


class Context:
    def __init__(self):
        self.manifest = Path(os.environ["HIA_CONNECTION_BUILD"]).resolve(strict=True)
        self.metadata = json.loads(self.manifest.read_bytes())
        assert self.metadata["schema"] == "hepta.sdk-connection.build.v1"
        self.digest = sha(self.manifest.read_bytes())
        self.output = Path(os.environ["HIA_CONNECTION_OUTPUT_DIR"]).resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        self.data = Path(self.metadata["reference_data"])
        self.recheck()

    def recheck(self):
        assert sha(self.manifest.read_bytes()) == self.digest
        for path, digest in self.metadata["sources"].items():
            source = ROOT / path
            assert source.is_file() and not source.is_symlink() and sha(source.read_bytes()) == digest, path
        for key, row in self.metadata["modules"].items():
            manifest = Path(row["path"])
            assert sha(manifest.read_bytes()) == row["sha256"], key
            data = json.loads(manifest.read_bytes())
            assert sha((manifest.parent / data["source"]).read_bytes()) == data["source_sha256"]
            assert sha((manifest.parent / data["image"]).read_bytes()) == data["image_sha256"]
        for path, record in self.metadata["reference_files"].items():
            raw = (self.data / path).read_bytes()
            assert (len(raw), sha(raw)) == (record["bytes"], record["sha256"])

    def module(self, key):
        reference = self.metadata["modules"][key]
        return NativeModule(Path(reference["path"]), manifest_sha256=reference["sha256"])

    def rows(self, domain, file):
        return list(map(json.loads, (self.data / domain / file).read_bytes().splitlines()))

    def fixture(self):
        reference = self.metadata["fixture"]
        manifest = Path(reference["path"])
        assert sha(manifest.read_bytes()) == reference["sha256"]
        meta = json.loads(manifest.read_bytes())
        binary = manifest.parent / meta["executable"]
        raw = binary.read_bytes()
        assert sha(raw) == meta["elf_sha256"] and len(raw) == meta["elf_bytes"]
        at = meta["prefix_bytes"]
        for member in meta["members"]:
            child = self.metadata["modules"][member["name"]]
            assert member["manifest"] == child["path"] and member["manifest_sha256"] == child["sha256"]
            metadata = json.loads(Path(child["path"]).read_bytes())
            image = (Path(child["path"]).parent / metadata["image"]).read_bytes()
            assert member["offset"] == at and raw[at:at + len(image)] == image
            hole = member["call_displacement_offset"]
            assert raw[hole - 1] == 0xe8 and hole + 4 + struct.unpack_from("<i", raw, hole)[0] == at
            at += len(image)
        assert at == len(raw) and meta["test_fixture_only"] and not meta["production_runtime_handlers"]
        return binary, meta


class Suite:
    def __init__(self, name):
        self.context = Context()
        self.directory = self.context.output / name
        self.directory.mkdir(exist_ok=False)
        self.artifacts = {}
        self.started = time.monotonic()
        self.summary = {"status": "RUNNING", "suite": name, "build_sha256": self.context.digest,
                        "sources": self.context.metadata["sources"], "counts": {},
                        "production_tool_dispatch_closed": False, "client_result_typed_normalization_closed": False}

    def save(self, name, raw):
        path = self.directory / name
        path.write_bytes(raw)
        self.artifacts[name] = {"bytes": len(raw), "sha256": sha(raw)}

    def rows(self, name, rows):
        raw = b"".join(json.dumps(row, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode() + b"\n" for row in rows)
        self.save(name + ".gz", gzip.compress(raw, mtime=0))
        return {"file": name + ".gz", "raw_bytes": len(raw), "raw_sha256": sha(raw), "rows": len(rows)}

    def __enter__(self):
        return self

    def __exit__(self, kind, error, traceback):
        custody_error = None
        if kind is not None:
            self.summary.update(status="FAIL", error=kind.__name__ + ": " + str(error))
        else:
            try:
                self.context.recheck()
                self.summary["status"] = "PASS"
            except BaseException as caught:
                custody_error = caught
                self.summary.update(status="FAIL", error=type(caught).__name__ + ": " + str(caught))
        self.summary.update(elapsed_seconds=time.monotonic() - self.started, artifacts=self.artifacts)
        (self.directory / "result.json").write_bytes(encoded(self.summary))
        print(json.dumps(self.summary, sort_keys=True), flush=True)
        if custody_error is not None:
            raise custody_error
        return False

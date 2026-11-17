#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Complete buffers stored as verified content-addressed blocks, never summaries."""
from pathlib import Path
import gzip
import hashlib
from common import canonical, decode, owned, require, sha

CHUNK = 65536

class Writer:
    def __init__(self, root):
        self.root = Path(root); self.root.mkdir()
        self.known = set()
        self.images = 0
        self.logical_bytes = 0
        self.recent = []
        self.index = (self.root.parent/"buffer-index.jsonl").open("xb")

    def record(self, row):
        self.index.write(canonical(row)); self.index.flush(); return row

    def put(self, raw):
        require(type(raw) is bytes, "buffer is not complete immutable bytes")
        # Exact full-byte comparison can reuse a previously retained immutable image.
        # This observes the current buffer; it never assumes an unchanged workspace.
        for old, descriptor in self.recent:
            if raw == old:
                self.images += 1; self.logical_bytes += len(raw)
                return self.record(dict(descriptor, blocks=list(descriptor["blocks"])))
        rows = []
        for at in range(0, len(raw), CHUNK):
            block = raw[at:at+CHUNK]
            key = sha(block)
            if key not in self.known:
                with (self.root/(key+".gz")).open("xb") as file:
                    with gzip.GzipFile(filename="", mode="wb", fileobj=file, mtime=0, compresslevel=1) as out:
                        out.write(block)
                self.known.add(key)
            rows.append(key)
        self.images += 1
        self.logical_bytes += len(raw)
        descriptor = dict(bytes=len(raw), sha256=sha(raw), blocks=rows)
        self.recent = [(raw, descriptor), *self.recent[:7]]
        return self.record(descriptor)

class Reader:
    def __init__(self, root):
        self.root = Path(root)
        self.cache = {}
        self.used = set()
        self.images = 0
        self.logical_bytes = 0
        self.recent = []

    def get(self, row):
        require(set(row) == {"bytes", "sha256", "blocks"} and type(row["bytes"]) is int
            and row["bytes"] >= 0 and type(row["blocks"]) is list,
            "invalid complete buffer descriptor")
        require(len(row["blocks"]) == (row["bytes"]+CHUNK-1)//CHUNK, "buffer block count differs")
        for old, value in self.recent:
            if row == old:
                self.images += 1; self.logical_bytes += len(value)
                return value
        result = bytearray()
        for position, key in enumerate(row["blocks"]):
            require(type(key) is str and len(key) == 64 and all(c in "0123456789abcdef" for c in key),
                "invalid block identity")
            if key not in self.cache:
                path = owned(self.root, key+".gz")
                with gzip.open(path, "rb") as file:
                    value = file.read(CHUNK+1)
                    require(len(value) <= CHUNK and not file.read(1), "oversized or trailing block")
                require(sha(value) == key, "complete block bytes changed")
                self.cache[key] = value
            block = self.cache[key]
            require(len(block) == min(CHUNK, row["bytes"]-position*CHUNK), "block extent differs")
            result.extend(block); self.used.add(key)
        value = bytes(result)
        require(len(value) == row["bytes"] and sha(value) == row["sha256"], "complete buffer digest differs")
        self.images += 1; self.logical_bytes += len(value)
        self.recent = [(row, value), *self.recent[:7]]
        return value

    def finish(self):
        actual = {p.name for p in self.root.iterdir() if p.is_file()}
        require(actual == {x+".gz" for x in self.used}, "unread or missing stored block")
        return dict(blocks=len(self.used), complete_images=self.images,
            logical_buffer_bytes=self.logical_bytes)

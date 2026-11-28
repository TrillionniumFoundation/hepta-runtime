"""Small deterministic I/O and source admission shared by the private recipe."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import tomllib

BASE = "tests/hia_native/context_protocol_policy"
COMPILER_COMMIT = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
COMPILER_TREE = "8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49"
TARGET_COMMIT = "d3d75c30719db966b004756f610007a7c723729e"
SOURCE_SHA = "8a8e922b2d4e9bec6b1bf7f0184f9ea2cd42c8ab44c6b94d80f94f87fd3e0751"
SERVER_SHA = "0957f7d7d56ad76540a42ba82b33fc29a625bb186cece2a207a764ea8c5beb6f"
SDK_MODEL_SHA = "ac438543401b6b9d60021fc044dcf27b446df9539e837c6fecdf16a670091b9a"
LOCK_SHA = "0e1c54671034eb3e208dee2ec8a8723fbf5cfafd8c26107ad82ed452fa1174a2"
MANIFEST_SHA = "ca7ed1ec01228686835420e17da5bf812d66c263725f4bdd52333dd5f959b2ca"
TARGET_LOCK_SHA = "1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631"
FUNCTIONS = {
    "supports_cache_hints": (172, "5061167ddd0d7bf787ff0ad12a0243dddab451901576e2fa732c16d55afda85b"),
    "allows_unsolicited_notifications": (185, "a5b600838ccd6eb4690d7a9ce69cdd989c938adcaf0e436bdbd406d9a9cab757"),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def pairs(items):
    value = {}
    for key, member in items:
        require(key not in value, "duplicate JSON key")
        value[key] = member
    return value


def read(path):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and path.resolve() == path.absolute(), "nonregular or linked file: " + str(path))
    return path.read_bytes()


def document(path):
    return json.loads(read(path), object_pairs_hook=pairs)


def put(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = value if isinstance(value, bytes) else encoded(value)
    with path.open("xb") as handle:
        handle.write(raw)


def safe_relative(value):
    require(type(value) is str and value and not value.startswith("/") and
            all(part not in ("", ".", "..") for part in value.split("/")), "unsafe relative member")
    return value


def tree_files(root):
    root = Path(root).absolute()
    require(root.resolve() == root and root.is_dir(), "tree root is not an owned directory")
    result = {}
    for folder, directories, names in os.walk(root, followlinks=False):
        for name in directories:
            path = Path(folder) / name
            require(stat.S_ISDIR(path.lstat().st_mode) and path.resolve() == path, "linked tree directory")
        for name in names:
            path = Path(folder) / name
            raw = read(path)
            relative = path.relative_to(root).as_posix()
            result[relative] = {"bytes": len(raw), "sha256": sha(raw), "mode": stat.S_IMODE(path.stat().st_mode)}
    return dict(sorted(result.items()))


def source_evidence(source_root, expected_pins_sha=None):
    root = Path(source_root).absolute()
    pins_raw = read(root / BASE / "source-pins.json")
    if expected_pins_sha is not None:
        require(sha(pins_raw) == expected_pins_sha, "source pin manifest changed")
    pins = json.loads(pins_raw, object_pairs_hook=pairs)
    require(pins["schema"] == "hepta.runtime.context-protocol-source.v1", "source schema")
    require(pins["owner_checkpoint"] == "011e04554660a66b1fbd9e104672106ea4746008", "owner checkpoint")
    require(pins["target_commit"] == TARGET_COMMIT and pins["compiler_commit"] == COMPILER_COMMIT, "pinned dependency identity")
    for name, expected in pins["files"].items():
        raw = read(root / safe_relative(name))
        require(expected == {"bytes": len(raw), "sha256": sha(raw)}, "source changed: " + name)
    verify_original(root)
    return {"pins_sha256": sha(pins_raw), "files": pins["files"]}


def verify_original(root):
    base = Path(root) / BASE
    server = read(base / "reference/server.rs")
    require(sha(server) == SERVER_SHA, "target server source changed")
    extracted = []
    for name, (size, digest) in FUNCTIONS.items():
        start = server.index(b"fn " + name.encode() + b"(")
        end = server.index(b"\n}", start) + 3
        raw = server[start:end]
        require(len(raw) == size and sha(raw) == digest, "target function source changed: " + name)
        extracted.append(raw)
    header = server[:server.index(b"//!")]
    require(read(base / "oracle/original_policy.rs") == header +
            b"// Exact original target helper definitions follow without edits.\n" + b"\n".join(extracted),
            "included original function bodies or license header differ")
    require(sha(read(base / "oracle/Cargo.toml")) == MANIFEST_SHA, "original fixture manifest changed")
    lock_raw = read(base / "oracle/Cargo.lock")
    require(sha(lock_raw) == LOCK_SHA, "original fixture lock changed")
    target_raw = read(base / "reference/target-Cargo.lock")
    require(sha(target_raw) == TARGET_LOCK_SHA, "target lock changed")
    target = {(p["name"], p["version"]): p for p in tomllib.loads(target_raw.decode())["package"]}
    packages = tomllib.loads(lock_raw.decode())["package"]
    for package in packages:
        if "source" in package:
            key = (package["name"], package["version"])
            require(key in target and all(package.get(field) == target[key].get(field)
                                         for field in ("source", "checksum")), "fixture registry drift: " + repr(key))
    model = read(base / "reference/sdk-model.rs")
    require(sha(model) == SDK_MODEL_SHA, "SDK model source changed")
    start = model.index(b"impl ProtocolVersion {")
    end = model.index(b"impl", start + 5)
    constants = re.findall(rb'pub const V_[0-9_]+: Self = Self\(Cow::Borrowed\("([^\"]+)"\)\);', model[start:end])
    from cases import KNOWN
    require(tuple(sorted(value.decode() for value in constants)) == KNOWN, "known SDK protocol constant coverage changed")
    require(sha(read(Path(root) / "native/context_protocol_policy.hepta")) == SOURCE_SHA, "HIA source changed")


def packets(path):
    with Path(path).open("rb") as handle:
        while True:
            header = handle.read(8)
            if not header:
                return
            require(len(header) == 8, "packet length truncated")
            size = struct.unpack("<Q", header)[0]
            require(size <= (16 << 20), "packet oversized")
            raw = handle.read(size)
            require(len(raw) == size, "packet truncated")
            yield raw


def packet(raw):
    return struct.pack("<Q", len(raw)) + raw

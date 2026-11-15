"""Materialize exact original workdir bodies into a declared test carrier."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import tomllib

ROOT = Path(__file__).resolve().parent
SOURCE_FILES = (
    "Cargo.toml", "Cargo.lock", "src/mcp/mod.rs", "src/mcp/server.rs",
    "src/mcp/fs/workdir.rs", "src/mcp/fs/remote.rs", "src/mcp/runtime/config.rs",
)
HARNESS_FILES = ("Cargo.toml", "Cargo.lock", "cases.py", "run.py",
                 "verify_sources.py", "source_manifest.json", "src/driver.rs")


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":")).encode() + b"\n"


def block(text, start):
    opening = text.index("{", start)
    depth = 0
    # These frozen bodies contain balanced format-string braces. The complete
    # extracted bytes are independently pinned below; ambiguity is rejected.
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    raise AssertionError("unterminated original source block")


def function(text, name):
    matches = list(re.finditer(r"(?m)^[ \t]*(?:pub(?:\([^\n]*\))? )?(?:async )?fn "
                              + re.escape(name) + r"\(", text))
    if len(matches) != 1:
        raise AssertionError("original function must be unique: " + name)
    return block(text, matches[0].start())


def parts(runtime_root):
    runtime_root = Path(runtime_root)
    server = (runtime_root / "src/mcp/server.rs").read_text()
    config = (runtime_root / "src/mcp/runtime/config.rs").read_text()
    remote = (runtime_root / "src/mcp/fs/remote.rs").read_text()
    module = (runtime_root / "src/mcp/mod.rs").read_text()
    result = {
        "mcp_tool_call": block(module, module.index("#[derive(Debug, Clone, Serialize, Deserialize)]\npub struct McpToolCall")),
        "session_workdir": server[server.index("#[derive(Debug)]\npub struct SessionWorkdir"):
                                  server.index("/// Active `subscriptions/listen`")].rstrip(),
        "workdir_params": block(server, server.index("#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]\npub struct WorkdirParams")),
        "ensure_session_workdir": function(server, "ensure_session_workdir"),
        "workdir_handler": function(server, "workdir"),
        "enforce_runtime_path_spec": function(server, "enforce_runtime_path_spec"),
        "workdir_file": (runtime_root / "src/mcp/fs/workdir.rs").read_text(),
        "path_source": remote[remote.index("#[derive(Debug, Clone)]\npub enum PathSource"):
                              remote.index("// ── SFTP connection pool")].rstrip(),
        "io_canonicalize": function(remote, "io_canonicalize"),
        "io_is_dir": function(remote, "io_is_dir"),
        "config_definitions": config[config.index("#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]"):
                                     config.index("// The installed value")].rstrip(),
        "installed_runtime_config": block(config, config.index("struct InstalledRuntimeConfig {")),
        "installed_runtime_new": function(config[config.index("impl InstalledRuntimeConfig {"):
                                                 config.index("fn default_state_dir")], "new"),
    }
    for name in ("default_state_dir", "runtime_config", "maybe_runtime_config", "host_by_alias",
                 "normalize_absolute", "canonical_policy_path", "path_under", "check_local_path",
                 "remote_path_allowed", "check_remote_path"):
        result[name] = function(config, name)
    return result


def source(runtime_root):
    extracted = parts(runtime_root)
    raw = (ROOT / "src/driver.rs").read_text()
    for name, original in extracted.items():
        token = "@@" + name.upper() + "@@"
        if raw.count(token) != 1:
            raise AssertionError("exactly one original carrier slot required: " + name)
        raw = raw.replace(token, original)
    if "@@" in raw:
        raise AssertionError("unfilled carrier source slot")
    for name, original in extracted.items():
        if raw.count(original) != 1:
            raise AssertionError("original bytes must occur unchanged once: " + name)
    return raw.encode(), extracted


def dependency_subset(runtime_root):
    expected = {(p["name"], p["version"], p.get("source")): p.get("checksum")
                for p in tomllib.loads((Path(runtime_root) / "Cargo.lock").read_text())["package"]}
    count = 0
    for item in tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]:
        if "source" not in item:
            if (item["name"], item["version"]) != ("hepta-workdir-original-oracle", "0.1.0"):
                raise AssertionError("unexpected local oracle dependency")
        else:
            key = item["name"], item["version"], item["source"]
            if key not in expected or expected[key] != item.get("checksum"):
                raise AssertionError("dependency differs from original Cargo.lock: " + repr(key))
            count += 1
    return count


def check_sources(runtime_root):
    manifest = json.loads((ROOT / "source_manifest.json").read_bytes())
    if set(manifest["files"]) != set(SOURCE_FILES):
        raise AssertionError("original file inventory differs")
    for name, expected in manifest["files"].items():
        if pin((Path(runtime_root) / name).read_bytes()) != expected:
            raise AssertionError("original source differs: " + name)
    raw, extracted = source(runtime_root)
    if {name: pin(value.encode()) for name, value in extracted.items()} != manifest["extractions"]:
        raise AssertionError("original extraction differs")
    return raw, manifest


def materialize(runtime_root, destination):
    raw, manifest = check_sources(runtime_root)
    count = dependency_subset(runtime_root)
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "src").mkdir()
    for name in ("Cargo.toml", "Cargo.lock"):
        shutil.copyfile(ROOT / name, destination / name)
    (destination / "src/main.rs").write_bytes(raw)
    return {"source_commit": manifest["commit"], "source": pin(raw),
            "original_file_count": len(SOURCE_FILES), "original_body_count": len(manifest["extractions"]),
            "registry_dependencies": count, "original_bodies_unchanged": True,
            "actual_sdk_parameters_extractor": True, "actual_sdk_method_adapter": True,
            "original_workdir_body_executed": True, "original_full_router_executed": False,
            "configuration_installation_fixture": True, "original_config_loader_executed": False,
            "remote_io_executed": False, "unsupported_remote_branch_aborts": True}

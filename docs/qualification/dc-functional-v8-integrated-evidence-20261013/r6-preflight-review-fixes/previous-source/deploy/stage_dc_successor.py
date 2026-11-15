#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create a private immutable successor bundle; never activate or refresh it.

All source, artifact, baseline and receipt checks precede the first mkdir.
The only writes are create-only files under the explicitly absent destination.
Token/config/profile paths are references, not files this helper may inspect.
No binary, service command, tunnel, SSH client or administrator action is run.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import shlex
import stat
import subprocess
import sys
import urllib.parse

from mcp_tool_contract import ToolContract, canonical

ROOT = pathlib.Path(__file__).resolve().parents[1]
ORIGINAL_V4 = ROOT / "deploy/contracts/hepta-runtime-full-operator-v4.json"
ORIGINAL_V4_SHA256 = "d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1"
HASH = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}")
MAX_NATIVE_BYTES = 512 * 1024 * 1024
MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_RECEIPT_BYTES = 32 * 1024 * 1024
LIVE_ROLES = {"profile", "installed_manifest", "runtime_config", "unit_dropin"}
BASELINE_KEYS = {"schema", "native", "facade", "helper", "contract", "live_files",
                 "state_directory", "auth_token_file"}
SOURCE_ALGORITHM = "sha256(canonical sorted relative path -> byte-count and sha256 map)"


def absolute_path(value):
    path = pathlib.Path(value)
    if not path.is_absolute() or ".." in path.parts or any(ord(c) < 32 for c in str(path)):
        raise ValueError("explicit absolute path without traversal/control characters required")
    return path


def open_parent(path):
    """Walk by descriptor so symlinked ancestors cannot redirect a snapshot."""
    path = absolute_path(path)
    if not path.name:
        raise ValueError("a named file or directory is required")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor, path.name
    except BaseException:
        os.close(descriptor)
        raise


def validate_inode(info, label):
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError(label + ": single-link ordinary file required")
    if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
        raise PermissionError(label + ": trusted owner and no group/other writes required")


def snapshot(path, label, max_bytes=MAX_TEXT_BYTES):
    parent, name = open_parent(path)
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                             dir_fd=parent)
    finally:
        os.close(parent)
    try:
        before = os.fstat(descriptor)
        validate_inode(before, label)
        if before.st_size > max_bytes:
            raise ValueError(label + ": input size exceeds bounded snapshot")
        with os.fdopen(descriptor, "rb", closefd=False) as reader:
            raw = reader.read(max_bytes + 1)
        after = os.fstat(descriptor)
        validate_inode(after, label)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise ValueError(label + ": input changed during descriptor read")
        if len(raw) != before.st_size or len(raw) > max_bytes:
            raise ValueError(label + ": incomplete or oversized snapshot")
        return raw, {"path": str(absolute_path(path)), "bytes": len(raw),
                     "sha256": hashlib.sha256(raw).hexdigest(),
                     "source_mode": format(stat.S_IMODE(before.st_mode), "04o")}
    finally:
        os.close(descriptor)


def read_pinned(path, expected, label, max_bytes=MAX_TEXT_BYTES):
    if not isinstance(expected, str) or not HASH.fullmatch(expected):
        raise ValueError(label + ": explicit SHA256 pin required")
    raw, metadata = snapshot(path, label, max_bytes)
    if metadata["sha256"] != expected:
        raise ValueError(label + ": SHA256 differs from the supplied pin")
    return raw, metadata


def git(root, *arguments):
    result = subprocess.run(["git", "-C", str(root), *arguments], capture_output=True,
                            text=True, timeout=30)
    if result.returncode:
        raise ValueError("source Git identity unavailable")
    return result.stdout


def source_identity(root):
    root = absolute_path(root)
    parent, name = open_parent(root)
    try:
        directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
    finally:
        os.close(parent)
    os.close(directory)
    paths = set(root.glob("src/**/*.rs")) | set(root.glob("src/**/*.py"))
    paths.update([root / "Cargo.toml", root / "Cargo.lock"])
    entries = {}
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        raw, metadata = snapshot(path, "compile input", 16 * 1024 * 1024)
        entries[path.relative_to(root).as_posix()] = {
            "bytes": len(raw), "sha256": metadata["sha256"]}
    head = git(root, "rev-parse", "HEAD").strip()
    scope = ["src", "Cargo.toml", "Cargo.lock"]
    changed = git(root, "diff", "--name-only", "--no-renames", "-z", "HEAD", "--", *scope).split("\0")
    tracked = set(git(root, "ls-files", "--cached", "-z", "--", *scope).split("\0"))
    def compile_input(path):
        return path in ("Cargo.toml", "Cargo.lock") or (path.startswith("src/") and pathlib.PurePosixPath(path).suffix in (".rs", ".py"))
    # A deleted/renamed tracked source is absent from the glob map. Compare the
    # full Git scope as well, and refuse untracked or ignored compile inputs.
    dirty = any(compile_input(path) for path in changed) or not set(entries) <= tracked
    return {"base_HEAD": head, "dirty_source": dirty,
            "source_fingerprint_algorithm": SOURCE_ALGORITHM,
            "source_code_fingerprint": hashlib.sha256(canonical(entries)).hexdigest(),
            "source_files": entries}


def contract_from(raw):
    return ToolContract(json.loads(raw))


def require_original(current, original):
    for name, definition in original.by_name.items():
        if current.by_name.get(name) != definition:
            raise ValueError("original v4 definition drift: " + name)


def delta(previous, current):
    changed = []
    for name in sorted(set(previous.by_name) & set(current.by_name)):
        old = previous.by_name[name]
        new = current.by_name[name]
        if old.get("annotations") != new.get("annotations"):
            raise ValueError("retained tool annotations changed: " + name)
        fields = [key for key in sorted(set(old) | set(new)) if old.get(key) != new.get(key)]
        if fields:
            changed.append({"name": name, "changed_fields": fields})
    return {"added": sorted(set(current.by_name) - set(previous.by_name)),
            "removed": sorted(set(previous.by_name) - set(current.by_name)),
            "changed": changed}


def pin_reference(value, role):
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise ValueError(role + ": only a path and SHA256 reference are accepted")
    path = absolute_path(value["path"])
    if not isinstance(value["sha256"], str) or not HASH.fullmatch(value["sha256"]):
        raise ValueError(role + ": invalid digest reference")
    return {"path": str(path), "sha256": value["sha256"]}


def baseline_snapshot(args, original):
    raw, receipt = read_pinned(args.baseline_pins, args.baseline_pins_sha256,
                              "baseline pins", MAX_TEXT_BYTES)
    value = json.loads(raw)
    if (not isinstance(value, dict) or set(value) != BASELINE_KEYS
            or value["schema"] != "hepta-installed-baseline-pins-v1"):
        raise ValueError("explicit credential-free installed baseline pins required")
    if not isinstance(value["live_files"], dict) or set(value["live_files"]) != LIVE_ROLES:
        raise ValueError("baseline must reference each exact live file without copying it")
    live = {role: pin_reference(value["live_files"][role], role) for role in sorted(LIVE_ROLES)}
    state = str(absolute_path(value["state_directory"]))
    token = str(absolute_path(value["auth_token_file"]))
    if token != str(absolute_path(args.token_file)):
        raise ValueError("stage must preserve the existing token-file reference")
    if live["runtime_config"]["path"] != str(absolute_path(args.runtime_config)):
        raise ValueError("stage must preserve the existing runtime-config reference")
    files = {}
    artifacts = {}
    names = {"native": "rollback-native", "facade": "rollback-facade.py",
             "helper": "rollback-helper.py", "contract": "rollback-contract.json"}
    for role, name in names.items():
        reference = pin_reference(value[role], "baseline " + role)
        data, metadata = read_pinned(reference["path"], reference["sha256"],
                                     "baseline " + role,
                                     MAX_NATIVE_BYTES if role == "native" else MAX_TEXT_BYTES)
        if role == "native" and not int(metadata["source_mode"], 8) & 0o111:
            raise ValueError("baseline native must already be executable")
        files[name] = (data, 0o700 if role == "native" else 0o600)
        artifacts[role] = metadata
    require_original(contract_from(files["rollback-contract.json"][0]), original)
    return files, {"pins": receipt, "artifacts": artifacts, "live_files": live,
                   "state_directory": state, "auth_token_file": token}


def validate_upstream(value):
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.path != "/mcp"
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("planned upstream must be explicit IPv4 loopback HTTP /mcp")
    port = parsed.port or 80
    if not 1 <= port <= 65535:
        raise ValueError("invalid planned upstream port")
    return f"http://127.0.0.1:{port}/mcp", f"127.0.0.1:{port}"


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def prepare_stage(args):
    """Validate and hold immutable bytes; this function performs no writes."""
    destination = absolute_path(args.destination)
    token = str(absolute_path(args.token_file))
    config = str(absolute_path(args.runtime_config))
    workspace = str(absolute_path(args.controller_workspace))
    upstream, bind = validate_upstream(args.upstream)
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_head):
        raise ValueError("full committed source HEAD required")
    if not HASH.fullmatch(args.compiled_source_fingerprint):
        raise ValueError("explicit compiled-source fingerprint required")
    identity = source_identity(args.source_root)
    if identity["base_HEAD"] != args.source_head or identity["dirty_source"]:
        raise ValueError("source must equal the supplied committed HEAD")
    if identity["source_code_fingerprint"] != args.compiled_source_fingerprint:
        raise ValueError("source differs from the supplied compiled-source fingerprint")
    original_raw, _ = read_pinned(ORIGINAL_V4, ORIGINAL_V4_SHA256, "frozen original v4")
    original = contract_from(original_raw)
    if len(original.tools) != 50:
        raise ValueError("frozen original v4 tool count differs")
    files = {}
    inputs = {}
    for role, path, expected, filename in [
        ("native", args.native, args.native_sha256, "candidate-native"),
        ("facade", args.facade, args.facade_sha256, "chatgpt_full_operator.py"),
        ("helper", args.helper, args.helper_sha256, "mcp_tool_contract.py"),
        ("contract", args.contract, args.contract_sha256, "contract.json"),
        ("previous_contract", args.previous_contract, args.previous_contract_sha256,
         "previous-contract.json"),
    ]:
        data, metadata = read_pinned(path, expected, role,
                                     MAX_NATIVE_BYTES if role == "native" else MAX_TEXT_BYTES)
        if role == "native" and not int(metadata["source_mode"], 8) & 0o111:
            raise ValueError("candidate native must already be executable")
        files[filename] = (data, 0o700 if role == "native" else 0o600)
        inputs[role] = metadata
    current = contract_from(files["contract.json"][0])
    previous = contract_from(files["previous-contract.json"][0])
    require_original(previous, original)
    require_original(current, original)
    from_previous = delta(previous, current)
    from_v4 = delta(original, current)
    rollback_files, baseline = baseline_snapshot(args, original)
    files.update(rollback_files)
    if not args.receipt:
        raise ValueError("at least one genuinely pinned receipt reference is required")
    receipts = []
    seen = set()
    for name, path, expected in args.receipt:
        if not NAME.fullmatch(name) or name in seen:
            raise ValueError("receipt names must be bounded and unique")
        seen.add(name)
        _, metadata = read_pinned(path, expected, "qualification receipt", MAX_RECEIPT_BYTES)
        receipts.append({"name": name, **metadata})
    # Reobserve source before publication. No argument or late receipt failure
    # can leave a stage directory or overwrite an existing destination.
    after = source_identity(args.source_root)
    if after != identity:
        raise ValueError("source changed during staging validation")
    parent, name = open_parent(destination)
    try:
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError("stage destination must be entirely absent")
    finally:
        os.close(parent)
    native_command = [str(destination / "candidate-native"), "mcp", "--path", workspace,
                      "--bind", bind, "--runtime-config", config, "--auth-token-file", token]
    facade_command = ["/usr/bin/python3", str(destination / "chatgpt_full_operator.py"),
                      "--stdio", "--upstream", upstream, "--token-file", token,
                      "--contract", str(destination / "contract.json"),
                      "--contract-sha256", args.contract_sha256, "--acknowledge-full-operator"]
    native_line = shlex.join(native_command).replace("%", "%%").replace("$", "$$")
    dropin = ("[Service]\nExecStart=\nExecStart=" + native_line + "\n").encode()
    files["native-dropin.conf"] = (dropin, 0o600)
    commands = {"schema": "hepta-successor-planned-commands-v1", "status": "HOLD",
                "commands_executed": False, "native_argv": native_command,
                "facade_argv": facade_command, "facade_shell_command": shlex.join(facade_command),
                "shared_state_concurrent_controllers_allowed": False}
    files["candidate-commands.json"] = (json_bytes(commands), 0o600)
    template = {"schema": "hepta-successor-profile-template-v1", "status": "HOLD",
                "is_runnable_tunnel_profile": False, "candidate_profile_started": False,
                "mcp": {"commands": [{"channel": "main", "command": shlex.join(facade_command)}]},
                "merge_from_live_profile": baseline["live_files"]["profile"],
                "preserve_existing_health_tunnel_identity_authentication_and_other_fields": True,
                "credentials_in_template": False, "live_profile_not_read": True}
    files["candidate-profile-template.json"] = (json_bytes(template), 0o600)
    inventory = {
        "scope": "fresh complete six-host jobs, persistent and nonpersistent PTYs, streams, active dispatch and queue",
        "fixed_historical_counts_used": False,
        "required_bindings": ["host logical authority", "job/session ID", "backend", "unit nonce",
                              "supervisor/PID start identity", "output archive identity and cursors"],
        "unknown_is_terminal": False, "old_missing_nonce_auto_cancel_allowed": False,
        "old_job_archive_read_does_not_grant_cancel_authority": True,
        "nonpersistent_active_pty_restart_preservation_claimed": False}
    activation = {
        "schema": "hepta-successor-activation-plan-v1", "status": "HOLD", "performed": False,
        "native_unit": "hepta-runtime-operator.service",
        "facade_unit": "hepta-openai-full-operator.service",
        "protected_rescue_unit": "desktop-commander-remote.service",
        "new_dropin_content": str(destination / "native-dropin.conf"),
        "new_dropin_path": str(pathlib.Path(baseline["live_files"]["unit_dropin"]["path"]).parent / "70-parity-successor.conf"),
        "profile_merge_template": str(destination / "candidate-profile-template.json"),
        "installed_manifest_field_updates": {
            "release": str(destination), "facade_sha256": inputs["facade"]["sha256"],
            "contract_sha256": args.contract_sha256,
            "tool_contract_catalog_sha256": current.catalog_sha256, "tools": len(current.tools)},
        "preserve_other_installed_manifest_fields": True,
        "baseline_live_files": baseline["live_files"], "inventory": inventory,
        "state_directory_preserved": baseline["state_directory"],
        "token_and_runtime_config_references_preserved": True,
        "required_before_any_service_change": [
            "reverify this manifest and the exact current baseline pointers",
            "freeze admission and drain current requests without replaying unknown effects",
            "obtain fresh complete dynamic inventories after admission is frozen",
            "qualify old/new jobs and PTYs through forward, restart, rollback and recovery",
            "hold if a live job lacks trusted binding or a nonpersistent PTY cannot be preserved",
            "create private exact-byte backups of current profile/installed manifest/drop-ins; verify all pins",
            "switch native/facade/pinned contract as one consistent reviewed pair; preserve DC",
        ],
        "after_server_change": [
            "verify exact native/facade catalog, health and same job/PTY/archive identities",
            "authorized workspace administrator Refresh of the existing private MCP connection",
            "new-conversation genuine model-origin calls with actual reviewed definitions",
        ],
        "app_refresh_performed": False, "approval_inferred_from_stage": False,
        "merge_release_publication_authorized": False, "dc_off_authorized": False}
    files["activation-plan.json"] = (json_bytes(activation), 0o600)
    rollback = {
        "schema": "hepta-successor-rollback-plan-v1", "status": "HOLD", "performed": False,
        "baseline_artifacts": {role: {"path": str(destination / filename),
                                     "sha256": inputs_metadata["sha256"]}
                               for role, filename, inputs_metadata in [
                                   ("native", "rollback-native", baseline["artifacts"]["native"]),
                                   ("facade", "rollback-facade.py", baseline["artifacts"]["facade"]),
                                   ("helper", "rollback-helper.py", baseline["artifacts"]["helper"]),
                                   ("contract", "rollback-contract.json", baseline["artifacts"]["contract"])]},
        "restore_exact_private_backups_of": {role: baseline["live_files"][role]
                                             for role in ("profile", "installed_manifest")},
        "existing_dropin_preserved": baseline["live_files"]["unit_dropin"],
        "remove_only_activation_owned_successor_dropin": activation["new_dropin_path"],
        "runtime_config_reference_unchanged": baseline["live_files"]["runtime_config"],
        "restore_scope": "only native/facade/profile/installed-manifest/successor-drop-in pointers changed by the reviewed activation",
        "restore_or_delete_state_directory": False, "state_directory": baseline["state_directory"],
        "change_tokens_ssh_permissions_or_dc": False, "inventory": inventory,
        "required_before_execution": [
            "reinventory new successor jobs and PTYs; do not use historical counts",
            "prove rollback compatibility or reconcile the same identities without relaunch",
            "verify exact current pointer hashes and the activation-owned drop-in identity",
            "hold on unknown effects, missing bindings, active nonpersistent PTYs or incompatible records",
            "restore the actual installed baseline, never borrow the historical 46-tool rollback",
            "verify baseline catalog/readiness and retained identities; recover DC remains online",
        ], "rollback_qualified_by_staging": False}
    files["rollback-plan.json"] = (json_bytes(rollback), 0o600)
    manifest = {
        "schema": "hepta-dc-successor-stage-v1",
        "recorded_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "staged": True, "activated": False, "source": identity, "inputs": inputs,
        "compiled_source_fingerprint_supplied": args.compiled_source_fingerprint,
        "build_execution_performed": False,
        "source_to_native_compilation_proof": "pinned external receipts; this helper does not rebuild or execute the candidate",
        "catalog": {"tool_count": len(current.tools), "catalog_sha256": current.catalog_sha256,
                    "original_v4_definitions_exact": True, "delta_from_previous": from_previous,
                    "delta_from_v4": from_v4},
        "baseline": baseline, "receipts": receipts,
        "receipts_execution_or_success_inferred": False, "artifacts": {},
        "live_files_accessed": False, "credentials_copied": False, "plan_status": "HOLD",
        "app_refreshed": False, "service_changed": False, "candidate_profile_started": False,
        "full_dc_replacement_qualified": False}
    for filename, (contents, mode) in files.items():
        manifest["artifacts"][filename] = {"bytes": len(contents),
            "sha256": hashlib.sha256(contents).hexdigest(), "mode": format(mode, "04o")}
    files["manifest.json"] = (json_bytes(manifest), 0o600)
    return {"destination": destination, "files": files, "manifest": manifest}


def stage(args):
    bundle = prepare_stage(args)
    destination = bundle["destination"]
    parent, name = open_parent(destination)
    directory = None
    created = []
    made = False
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent)
        made = True
        directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
        os.fchmod(directory, 0o700)
        identity = os.fstat(directory)
        if identity.st_uid != os.getuid():
            raise PermissionError("new stage directory has an unexpected owner")
        for filename, (contents, mode) in bundle["files"].items():
            fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         mode, dir_fd=directory)
            created.append(filename)
            with os.fdopen(fd, "wb") as writer:
                writer.write(contents)
                writer.flush()
                os.fchmod(writer.fileno(), mode)
                os.fsync(writer.fileno())
            fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            with os.fdopen(fd, "rb") as reader:
                info = os.fstat(reader.fileno())
                validate_inode(info, "staged artifact")
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != mode or reader.read() != contents:
                    raise ValueError("staged artifact differs from the validated snapshot")
        os.fsync(directory)
        if (os.stat(name, dir_fd=parent, follow_symlinks=False).st_ino != identity.st_ino
                or os.stat(name, dir_fd=parent, follow_symlinks=False).st_dev != identity.st_dev):
            raise ValueError("stage pathname changed during publication")
        os.fsync(parent)
        return {"staged": True, "activated": False, "destination": str(destination),
                "manifest_path": str(destination / "manifest.json"),
                "manifest_sha256": hashlib.sha256(bundle["files"]["manifest.json"][0]).hexdigest()}
    except BaseException:
        if directory is not None:
            for filename in reversed(created):
                try:
                    os.unlink(filename, dir_fd=directory)
                except FileNotFoundError:
                    pass
        if made:
            try:
                os.rmdir(name, dir_fd=parent)
            except OSError:
                pass
        raise
    finally:
        if directory is not None:
            os.close(directory)
        os.close(parent)


def parser():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source-root", required=True, type=pathlib.Path)
    ap.add_argument("--source-head", required=True)
    ap.add_argument("--compiled-source-fingerprint", required=True)
    for role in ("native", "facade", "helper", "contract", "previous-contract"):
        ap.add_argument("--" + role, required=True, type=pathlib.Path)
        ap.add_argument("--" + role + "-sha256", required=True)
    ap.add_argument("--baseline-pins", required=True, type=pathlib.Path)
    ap.add_argument("--baseline-pins-sha256", required=True)
    ap.add_argument("--receipt", action="append", nargs=3, metavar=("NAME", "PATH", "SHA256"),
                    required=True)
    ap.add_argument("--destination", required=True, type=pathlib.Path)
    ap.add_argument("--token-file", required=True, type=pathlib.Path)
    ap.add_argument("--runtime-config", required=True, type=pathlib.Path)
    ap.add_argument("--controller-workspace", required=True, type=pathlib.Path)
    ap.add_argument("--upstream", default="http://127.0.0.1:8790/mcp")
    return ap


def main():
    try:
        result = stage(parser().parse_args())
    except (OSError, ValueError, PermissionError, json.JSONDecodeError) as error:
        # Only the type is output: filenames, receipts and credentials never
        # enter a failure diagnostic. Original inputs remain untouched.
        print(json.dumps({"staged": False, "activated": False,
                          "error_type": type(error).__name__}), file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

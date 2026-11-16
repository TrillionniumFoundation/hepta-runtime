"""Complete inputs lifted through the current Batch SDK parameter boundary.

The 417 typed-object rows and 926 filesystem rows preserve their original input
producers. No tool response, diagnostic or expected wire is an author input.
The eight private non-object Value rows remain in their separate original gate.
"""
from pathlib import Path
from collections import Counter
import copy
import importlib.util
import json
import os
import sys

ROOT = Path(__file__).resolve().parent
REFERENCE = ROOT / "corpus/reference"
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "runtime_support/scripts"))
sys.path.insert(0, str(REFERENCE / "tests/hia_native"))
os.environ["HIA_REFERENCE_RUNTIME"] = str(REFERENCE)
os.environ["HIA_RUNTIME_REPO"] = str(REFERENCE)
from test_batch_write_controller import load, cases
import batch_render_reference as render

BODY_DOMAINS = {"all_fifty": 1, "early_admission": 16, "existing_mode": 7,
    "full_five_mib_content": 1, "full_five_mib_file": 1, "missing_path": 3,
    "ordered_validation": 260, "original_endings": 232, "read_directory": 1,
    "resolved_conflict_apply": 400, "strict_invalid_utf8": 1,
    "symlink_replaced_after_followed_read": 1, "temporary_is_directory": 1,
    "temporary_name_too_long": 1}


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def inline_meta(capabilities=None):
    return {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "batch-public-corpus", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": capabilities or {}}


def initialize(identifier=1, capabilities=None):
    return {"jsonrpc": "2.0", "id": identifier, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": capabilities or {},
        "clientInfo": {"name": "batch-public-corpus", "version": "1"}}}


def tool_wire(identifier, raw_arguments, *, name="batch_edit", modern=False, metadata=None):
    assert type(raw_arguments) is bytes
    params = b'{"name":' + encode(name) + b',"arguments":' + raw_arguments
    if modern or metadata is not None:
        params += b',"_meta":' + encode(inline_meta() if metadata is None else metadata)
    return b'{"jsonrpc":"2.0","id":' + encode(identifier) + b',"method":"tools/call","params":' + params + b'}}\n'


def typed_rows():
    spec = importlib.util.spec_from_file_location("public_batch_typed_inputs", ROOT / "corpus/batch_params_cases.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    original = list(module.iter_cases()) + list(module.extra_cases())
    assert len(original) == 425
    rows = [row for row in original if row["domain"] == "typed-object"]
    assert len(rows) == 417 and sum(row["domain"] == "private-raw-value" for row in original) == 8
    for row in rows:
        raw = row["raw_json"].encode() if "raw_json" in row else encode(row["value"])
        yield {"name": row["name"], "domain": "typed-object", "original_case_id": row["case_id"],
            "raw_arguments": raw, "actions": [], "after_actions": [],
            "response": row["name"] != "deep-unknown-125"}


def body_rows(fixture):
    fixture = Path(fixture).absolute()
    plan = load("_public_batch_plan_inputs", REFERENCE / "tests/hia_native/test_batch_plan.py")
    apply = render.load_apply(REFERENCE)
    target = fixture / "target"
    rows = []
    def action(kind, path, **fields):
        return {"kind": kind, "path_hex": os.fsencode(path).hex(), **fields}
    def write(path, data):
        return action("write", path, data_hex=data.hex())
    def add(domain, operations, path, actions, after_actions=(), *, include_path=True):
        args = {"operations": operations}
        if include_path:
            args["path"] = str(path)
        rows.append({"name": domain + "-" + str(len(rows)), "domain": domain,
            "raw_arguments": encode(args), "actions": list(actions),
            "after_actions": list(after_actions), "response": True})
    for display in (None, "", str(target), "target"):
        for count in (0, 1, 50, 51):
            add("early_admission", [None] * count, display, [write(target, b"before")], include_path=display is not None)
    for domain, raw, operations, _ in cases(plan, apply):
        if domain != "early_admission":
            add(domain, operations, target, [write(target, raw)])
    inserts = [{"operation": "insert", "start": 0, "content": "new"}]
    for mode in (0o000, 0o600, 0o640, 0o755, 0o4755, 0o6750, 0o7777):
        add("existing_mode", inserts, target, [write(target, b"old\r\n"), action("chmod", target, mode=mode)],
            [action("chmod", target, mode=0o600)])
    for index, name in enumerate(("missing", "missing/child", "bad\0name")):
        add("missing_path", inserts, fixture / name, [action("remove_file", target)] if index == 0 else [])
    directory = fixture / "directory"
    add("read_directory", inserts, directory, [action("mkdir", directory)], [action("remove_dir", directory)])
    add("strict_invalid_utf8", inserts, target, [write(target, b"\xff\xfe")])
    alias = fixture / "alias"
    add("symlink_replaced_after_followed_read", inserts, alias,
        [write(target, b"a\r\nb\r\n"), action("symlink", alias, target_hex=b"target".hex())],
        [action("remove_file", alias), action("remove_file", target)])
    long = fixture / ("x" * 255)
    add("temporary_name_too_long", inserts, long, [write(long, b"old")], [action("remove_file", long)])
    temporary = fixture / ".octofs_tmp_target.tmp"
    add("temporary_is_directory", inserts, target, [write(target, b"old"), action("mkdir", temporary)],
        [action("remove_dir", temporary)])
    raw = b"old\r\n" + b"x" * ((5 << 20) - 5)
    add("full_five_mib_file", [{"operation": "replace", "start": render.line_id(1, b"old").decode(), "content": "new"}],
        target, [write(target, raw)])
    add("full_five_mib_content", [{"operation": "replace", "start": render.line_id(2, b"b").decode(), "content": "x" * (5 << 20)}],
        target, [write(target, b"a\nb\nc\n")])
    assert len(rows) == 926 and dict(Counter(row["domain"] for row in rows)) == BODY_DOMAINS
    yield from rows


def session_rows(fixture):
    """Persistent actual two-session scope/cache/history and typed recovery inputs."""
    fixture = Path(fixture).absolute()
    target = fixture / "target"
    rows = []
    def add(name, arguments, *, session=0, tool="batch_edit", actions=(), seed=None, metadata=None):
        rows.append({"name": name, "domain": "session-chain", "session": session, "tool": tool,
            "raw_arguments": encode(arguments), "actions": list(actions), "after_actions": [],
            "response": True, "seed": seed, "metadata": metadata})
    def batch(operations, path="target"):
        return {"path": path, "operations": operations}
    insert = {"operation": "insert", "start": 0, "content": "hello"}
    write = {"kind": "write", "path_hex": os.fsencode(target).hex(), "data_hex": b"alpha\nbeta\n".hex()}
    add("typed-error-before-session-admission", {"path": [], "operations": []}, actions=[write])
    add("matching-cache-get-set", batch([insert]), seed=[{"session": 0, "path": str(target), "content": "alpha\nbeta\n"}])
    add("other-session-stale-cache-forget", batch([{**insert, "start": -1, "content": "tail"}]), session=1,
        seed=[{"session": 1, "path": str(target), "content": "stale"}])
    add("other-session-undo-shared-history", {"command": "undo_edit", "path": "target"}, session=1, tool="text_editor")
    add("first-session-undo-shared-history", {"command": "undo_edit", "path": "target"}, tool="text_editor")
    add("stale-hash-rejects-without-effect", batch([{"operation": "replace", "start": "1:00", "content": "bad"}]))
    add("fifty-one-admission-before-body", batch([insert] * 51))
    add("empty-operations-admission", batch([]))
    add("same-session-after-rejections", batch([insert]))
    add("delete-then-undo-shared", {"command": "delete", "path": "target"}, session=1, tool="text_editor")
    add("restore-from-other-session", {"command": "undo_edit", "path": "target"}, tool="text_editor")
    add("replace-current-composite-id", batch([{"operation": "replace", "start": "1:57", "content": ["one", "two"]}]))
    add("unknown-field-is-ignored", {**batch([{**insert, "start": -1}]), "unknown": {"value": [1, None, False]}})
    add("per-operation-path-hoist", {"operations": [{**insert, "path": "target"}]}, session=1)
    add("conflicting-paths-before-effects", {"operations": [{**insert, "path": "target"}, {**insert, "path": "other"}]})
    add("null-content-type-error", batch([{**insert, "content": None}]))
    add("final-ordinary-call", batch([{**insert, "start": -1, "content": "final"}]), session=1)
    assert len(rows) == 17
    yield from rows

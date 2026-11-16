"""Inputs only for workdir helper, real SDK extraction, session and path policy.

No function in this file computes an expected response or an expected state.
Absolute paths are materialized once and kept in the complete input stream.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path

CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
PROTOCOL = "io.modelcontextprotocol/protocolVersion"
SCHEMA = "hepta.runtime.workdir-original-input.v1"
OUTPUT_MAGIC = b"HWDRO001"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode() + b"\n"


def encoded_path(path):
    return os.fsencode(path).hex()


def materialized(fixture_root):
    root = Path(fixture_root).absolute()
    allowed, outside = root / "allowed", root / "outside"
    host = {"ssh_target": "uncontacted-workdir-reference", "remote_state_dir": "/unused-state",
            "allowed_read_path_prefixes": ["/read"], "protected_path_prefixes": ["/read/protected"]}
    def policy(roots, hosts=None):
        return {"state_dir": str(root / "unused-controller-state"),
                "controller_workspace_roots": list(map(str, roots)),
                "hosts": {"configured": copy.deepcopy(host)} if hosts is None else hosts}
    policies = {
        "disabled": None,
        "allowed": policy([allowed]),
        "denied": policy([]),
        "missing-root": policy([root / "missing-policy-root"]),
        "missing-first": policy([root / "missing-policy-root", allowed]),
        "allowed-first": policy([allowed, root / "missing-policy-root"]),
        "remote-policy": policy([allowed], {"configured": host}),
    }
    scenarios = []
    next_id = 30000

    def add(name, policy_id="disabled", era="modern", capabilities=None, raw_root=False):
        index = len(scenarios)
        base, exterior = allowed / ("s-%03d" % index), outside / ("s-%03d" % index)
        state_root = base / ("root-\udcff" if raw_root else "root")
        def action(kind, path, **extra):
            return {"kind": kind, "path_hex": encoded_path(path), **extra}
        setup = [action("mkdir", value) for value in (
            state_root, state_root / "a", state_root / "b", state_root / "a/nested",
            state_root / "left", state_root / "right", state_root / "left|right",
            state_root / "left||right", state_root / " spaced ", state_root / "中🙂",
            state_root / "raw-\udcff", exterior / "outside-directory")]
        setup += [action("write", state_root / "plain", data_hex=b"regular file\n".hex()),
                  action("hardlink", state_root / "hard-plain", target_hex=encoded_path(state_root / "plain")),
                  action("symlink", state_root / "link-a", target_hex=encoded_path("a")),
                  action("symlink", state_root / "link-plain", target_hex=encoded_path("plain")),
                  action("symlink", state_root / "dangling", target_hex=encoded_path("missing")),
                  action("symlink", state_root / "loop-a", target_hex=encoded_path("loop-b")),
                  action("symlink", state_root / "loop-b", target_hex=encoded_path("loop-a")),
                  action("symlink", state_root / "raw-link", target_hex=encoded_path("raw-\udcff")),
                  action("symlink", state_root / "escape", target_hex=encoded_path(exterior / "outside-directory")),
                  action("fifo", state_root / "named-pipe")]
        row = {"schema": SCHEMA, "scenario_id": index, "name": name, "policy_id": policy_id,
               "setup": setup, "sessions": [], "steps": []}
        scenarios.append(row)
        def session(identifier="a", current_root=None, caps=capabilities):
            current_root = state_root if current_root is None else current_root
            initial = []
            if era == "legacy":
                initial = [{"jsonrpc": "2.0", "id": 100000 + index * 10 + len(row["sessions"]),
                            "method": "initialize", "params": {"protocolVersion": "2025-11-25",
                            "capabilities": caps or {}, "clientInfo": {"name": "workdir-original-oracle", "version": "1"}}},
                           {"jsonrpc": "2.0", "method": "notifications/initialized"}]
            row["sessions"].append({"id": identifier, "root_hex": encoded_path(current_root), "initial_messages": initial})
        session()
        def step(label, kind, *, identifier="a", domain=None, **fields):
            nonlocal next_id
            identifier_value = next_id; next_id += 1
            row["steps"].append({"case_id": identifier_value, "name": label, "session": identifier,
                "domain": domain or ("public-sdk" if kind == "public" else "helper" if kind == "helper" else "private-control"),
                "action": {"kind": kind, **fields}})
            return row["steps"][-1]
        def public(label, arguments, *, caps=capabilities, metadata=None, identifier="a", omit_arguments=False):
            entry = step(label, "public", identifier=identifier)
            params = {"name": "workdir"}
            if not omit_arguments: params["arguments"] = copy.deepcopy(arguments)
            if metadata is not None:
                params["_meta"] = copy.deepcopy(metadata)
            elif era == "modern":
                params["_meta"] = {PROTOCOL: "2026-07-28", CAPABILITIES: copy.deepcopy(caps or {})}
            entry["action"]["message"] = {"jsonrpc": "2.0", "id": entry["case_id"], "method": "tools/call", "params": params}
            return entry
        return row, state_root, exterior, step, public, session

    # Direct helper semantics: missing is distinct from null; reset is read as
    # bool and checked before every other field. These calls do not apply state.
    _, path, _, step, _, _ = add("direct-helper-value-domain")
    for label, parameters in (
        ("missing-path", {}), ("scalar-null-parameters", None), ("scalar-number-parameters", 4),
        ("scalar-bool-parameters", False), ("array-parameters", []),
        ("null-path", {"path": None}), ("empty-path", {"path": ""}),
        ("ascii-blank", {"path": " \t\r\n"}), ("unicode-blank", {"path": "\u0085\u00a0\u1680\u2000\u200a\u2028\u2029\u202f\u205f\u3000"}),
        ("bool-path", {"path": False}), ("number-path", {"path": 3}), ("array-path", {"path": []}),
        ("object-path", {"path": {}}), ("reset-true-number-path", {"reset": True, "path": 4}),
        ("reset-null-missing-path", {"reset": None}), ("reset-string-missing-path", {"reset": "true"}),
        ("reset-number-null-path", {"reset": 1, "path": None}), ("unknown-fields", {"unused": [True, 7]}),
        ("dot", {"path": "."}), ("trim-unicode", {"path": "\u3000\u00a0a\u0085\t"}),
        ("zero-width-not-trimmed", {"path": "\u200ba\u200b"}), ("bom-not-trimmed", {"path": "\ufeffa"}),
        ("embedded-newline", {"path": "a\nb"}), ("embedded-nul", {"path": "a\0b"}),
    ):
        step(label, "helper", parameters=parameters)

    for era in ("legacy", "modern"):
        _, path, _, _, public, _ = add(era + "-public-optional-values", era=era)
        for label, parameters in (
            ("missing-path", {}), ("null-path", {"path": None}),
            ("both-null", {"path": None, "reset": None}), ("reset-false-missing", {"reset": False}),
            ("reset-true-missing", {"reset": True}), ("reset-true-null", {"reset": True, "path": None}),
            ("dot-not-prohibited-by-doc", {"path": "."}), ("unknown-ignored", {"path": "a", "arbitrary": {"x": 1}}),
            ("reset-to-root", {"reset": True}), ("empty-path", {"path": ""}),
            ("unicode-blank", {"path": "\u00a0\u3000"}),
        ):
            public(label, parameters)
        public("arguments-omitted", {}, omit_arguments=True)

    wrong = [0, -1, 1.5, 1e-7, 1e16, 1.234e30, False, [], {}, ["x"], {"x": 1}]
    for field in ("path", "reset"):
        _, path, _, _, public, _ = add("typed-" + field)
        values = ([value for value in wrong if type(value) is not bool] + ["true", "\n\0'\"\\中🙂"]
                  if field == "reset" else wrong)
        for index, value in enumerate(values):
            public("typed-%s-%02d" % (field, index), {field: value, **({"reset": True} if field == "path" else {})})
        if field == "reset":
            for scalar in (0x115F, 0x1160, 0x3164, 0xFFA0, 0xFF9E, 0xFF9F):
                public("typed-reset-unicode-%04x" % scalar, {"reset": chr(scalar)})
        public("typed-both-fields-path-first", {"reset": "true", "path": 7})
        public("first-valid-after-typed-errors", {"path": "."}, caps={"experimental": {"session": {"workdir": str(path / "b")}}})

    for era in ("legacy", "modern"):
        for label, value in (("number", 2), ("array", []), ("string", "arguments"), ("null", None)):
            _, _, _, _, public, _ = add(era + "-arguments-" + label, era=era)
            public("arguments-" + label, value)

    _, path, exterior, _, public, _ = add("canonical-and-errno")
    paths = ["a/../b", "link-a", "plain", "hard-plain", "link-plain", "named-pipe", "dangling", "loop-a",
             "missing", "plain/child", "a\0b", "中🙂", "raw-link", "x" * 4097]
    for index, value in enumerate(paths):
        public("path-%02d" % index, {"path": str(path / value)})
        public("reset-after-path-%02d" % index, {"reset": True})

    _, path, _, step, public, _ = add("actual-permission-denied")
    step("create-unsearchable-directory", "filesystem", actions=[
        {"kind": "mkdir", "path_hex": encoded_path(path / "blocked/sub")},
        {"kind": "chmod", "path_hex": encoded_path(path / "blocked"), "mode": 0}])
    public("eacces-canonicalize", {"path": "blocked/sub"})
    step("restore-private-permissions", "filesystem", actions=[
        {"kind": "chmod", "path_hex": encoded_path(path / "blocked"), "mode": 0o700}])

    _, path, _, step, public, _ = add("raw-root-and-lossy-json", raw_root=True)
    step("direct-get-raw-root", "helper", parameters={})
    public("set-from-raw-root", {"path": "a"})
    public("reset-raw-root", {"reset": True})

    for policy_id in ("disabled", "allowed", "denied", "missing-root", "missing-first", "allowed-first"):
        _, path, exterior, _, public, _ = add("policy-" + policy_id, policy_id=policy_id)
        for label, value in (
            ("valid-local", "a"), ("dot", "."), ("whitespace", " \u3000"),
            ("trimmed-local", "\u3000a\u0085"), ("missing", "missing"), ("embedded-nul", "a\0b"),
            ("symlink-outside", "escape"), ("absolute-outside", str(exterior / "outside-directory")),
            ("pipe-existing-whole", "left|right"), ("empty-pipe-root", "left||right"),
            ("pipe-outside-second", "left|" + str(exterior / "outside-directory")),
            ("background-prefix", "octofs://resource"), ("background-leading-space", " octofs://resource"),
        ):
            public(label, {"path": value})
            public(label + "-reset", {"reset": True})

    # Capability application is first-call state, including calls that fail
    # later. The following cases retain full original method observations.
    for era in ("legacy", "modern"):
        for label in ("missing-first", "valid-first", "relative-first", "file-first", "missing-directory-first", "symlink-first", "space-name-first", "nul-first", "untrimmed-first"):
            row, path, _, _, public, _ = add(era + "-caps-" + label, era=era)
            choices = {"missing-first": {}, "valid-first": {"experimental": {"session": {"workdir": str(path / "a")}}},
                "relative-first": {"experimental": {"session": {"workdir": "a"}}},
                "file-first": {"experimental": {"session": {"workdir": str(path / "plain")}}},
                "missing-directory-first": {"experimental": {"session": {"workdir": str(path / "missing")}}},
                "symlink-first": {"experimental": {"session": {"workdir": str(path / "link-a")}}},
                "space-name-first": {"experimental": {"session": {"workdir": str(path / " spaced ")}}},
                "nul-first": {"experimental": {"session": {"workdir": str(path / "a\0b")}}},
                "untrimmed-first": {"experimental": {"session": {"workdir": "\u3000" + str(path / "a") + "\u3000"}}}}
            first = choices[label]
            if era == "legacy": row["sessions"][0]["initial_messages"][0]["params"]["capabilities"] = first
            public("first-error-still-latches", {}, caps=first)
            public("later-capabilities-do-not-reapply", {}, caps={"experimental": {"session": {"workdir": str(path / "b")}}})
            public("reset-preserves-latch", {"reset": True}, caps=first)
            public("after-reset-still-no-reapply", {}, caps=first)

    for era in ("legacy", "modern"):
        for label, replacement in (("empty", {}), ("null", None), ("string", "bad"),
                                   ("bad-experimental", {"experimental": []}),
                                   ("bad-roots", {"experimental": {}, "roots": True})):
            row, path, _, _, public, _ = add(era + "-capability-resolution-" + label, era=era)
            original = {"experimental": {"session": {"workdir": str(path / "a")}}}
            if era == "legacy": row["sessions"][0]["initial_messages"][0]["params"]["capabilities"] = original
            metadata = {CAPABILITIES: replacement}
            if era == "modern": metadata[PROTOCOL] = "2026-07-28"
            public("actual-sdk-caps-resolution", {"path": 7}, metadata=metadata)

    for policy_id in ("allowed", "denied", "missing-root"):
        for label in ("allowed", "outside", "relative"):
            _, path, exterior, _, public, _ = add("caps-policy-" + policy_id + "-" + label, policy_id=policy_id)
            cap_path = str(path / "a") if label == "allowed" else str(exterior / "outside-directory") if label == "outside" else "a"
            caps = {"experimental": {"session": {"workdir": cap_path}}}
            public("caps-before-path-policy-error", {"path": str(exterior / "outside-directory")}, caps=caps)
            public("reset-after-failed-policy", {"reset": True}, caps=caps)

    _, path, _, step, public, _ = add("actual-poisoned-session")
    step("private-set-before-poison", "state_set", path_hex=encoded_path(path / "a"))
    step("actual-rwlock-poison", "poison")
    public("public-set-success-with-poisoned-state", {"path": "b"}, caps={"experimental": {"session": {"workdir": str(path / "a")}}})
    public("public-reset-with-poisoned-state", {"reset": True})
    step("private-set-after-poison", "state_set", path_hex=encoded_path(path / "b"))
    step("private-reset-after-poison", "state_reset")
    step("private-get-after-poison", "state_get")

    _, path, _, step, public, session = add("two-live-session-isolation")
    session("b")
    public("session-a-set", {"path": "a"}, identifier="a")
    public("session-b-set", {"path": "b"}, identifier="b")
    public("session-a-unchanged-helper-error", {}, identifier="a")
    public("session-b-reset", {"reset": True}, identifier="b")
    step("session-a-actual-get", "state_get", identifier="a")
    step("session-b-actual-get", "state_get", identifier="b")

    _, path, _, step, public, _ = add("changed-filesystem-does-not-rewrite-state")
    public("set-a", {"path": "a"})
    step("rename-a-after-set", "filesystem", actions=[{"kind": "rename", "path_hex": encoded_path(path / "a"), "target_hex": encoded_path(path / "moved-a")}])
    public("dot-at-removed-current", {"path": "."})
    public("reset-after-rename", {"reset": True})
    public("absolute-recover", {"path": str(path / "b")})

    _, path, _, _, public, _ = add("remote-policy-rejections", policy_id="remote-policy")
    for label, value in (
        ("unknown-host", "ssh://unregistered/read"), ("user-override", "ssh://user@configured/read"),
        ("port-override", "ssh://configured:22/read"), ("home", "ssh://configured"),
        ("home-child", "sftp://configured/~/x"), ("traversal", "ssh://configured/read/../x"),
        ("outside-read-roots", "ssh://configured/outside"), ("protected", "ssh://configured/read/protected/x"),
    ):
        public(label, {"path": value})
    public("reset-skips-remote-io", {"reset": True, "path": "ssh://configured/read"})
    public("typed-error-before-remote-reset", {"reset": True, "path": 3})

    # Existing 8 MiB private carriers cannot define the original domain.
    # The real OS rejects the name; the original helper retains the full path
    # in its error, while reset ignores it after actual typed extraction.
    _, _, _, step, public, _ = add("wide-original-input")
    wide = "x" * ((8 << 20) + 17)
    step("wide-helper-error-full-body", "helper", parameters={"path": wide})
    public("wide-public-reset-ignores-path", {"path": wide, "reset": True})

    # This result-only domain does not claim the raw paths passed public I/O.
    # Only the unchanged original WorkdirResult impl produces the JSON body.
    _, _, _, step, _, _ = add("original-result-rendering")
    render_inputs = [b"", b"plain/path", b"\0\b\f\n\r\t\"\\'", bytes(range(256)),
        "中🙂\u0085\u2028\u2029\U0010ffff".encode(),
        b"\xf0\x80\x80A\xe0\x80B\xed\xa0\x80C\xf4\x90\x80\x80D\xc2",
        b"\xe2\x82\xac\xe2\x82\xe2\x82\xac",
        b"".join(bytes((a, b)) for a in range(256) for b in range(256)),
        b"q" * ((8 << 20) + 3)]
    for index, raw in enumerate(render_inputs):
        step("original-render-get-%02d" % index, "render", domain="private-render", variant="get", current_hex=raw.hex())
        if index != len(render_inputs) - 1:
            step("original-render-set-%02d" % index, "render", domain="private-render", variant="set",
                 previous_hex=raw.hex(), current_hex=(b"next/" + raw[::-1]).hex())
    step("original-render-reset", "render", domain="private-render", variant="reset")

    return {"fixture_root": str(root), "policies": policies, "scenarios": scenarios}


def iter_scenarios(fixture_root):
    yield from materialized(fixture_root)["scenarios"]


def read_records(stream):
    import struct
    if stream.read(8) != OUTPUT_MAGIC:
        raise ValueError("invalid original workdir output magic")
    while header := stream.read(16):
        if len(header) != 16: raise ValueError("truncated original record header")
        length, count = struct.unpack("<QQ", header)
        raw = stream.read(length)
        if len(raw) != length: raise ValueError("truncated original metadata")
        metadata = json.loads(raw)
        blobs = []
        for _ in range(count):
            size_raw = stream.read(8)
            if len(size_raw) != 8: raise ValueError("truncated original blob header")
            size, = struct.unpack("<Q", size_raw)
            value = stream.read(size)
            if len(value) != size: raise ValueError("truncated original blob")
            blobs.append(value)
        yield metadata, blobs

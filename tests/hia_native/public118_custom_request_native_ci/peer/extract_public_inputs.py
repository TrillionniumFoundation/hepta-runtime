"""Input-only current SDK extract_lines domains; no expected response or tool implementation.

The response Boolean in the legacy adapter is an input framing declaration only.
Protocol-shape scenarios use a following known request as a collection barrier and
must not assume a response to the preceding uncertain model input. EOF scenarios
belong to the real stdio transport, never private public-selector 34.
"""
# Copyright 2026 Muvon Un Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from pathlib import Path
import copy
import itertools
import json
import os

ABSENT = object()
TARGET = "d3d75c30719db966b004756f610007a7c723729e"
GRAPH = "a521066dfa07db38e6a22bd2f03d1dae3c203cc2"
PROCESS_SECONDS = 180
EXCHANGE_SECONDS = 60

def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def inline_meta(capabilities=None):
    return {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "extract-public-corpus", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": capabilities or {}}


def initialize(identifier=1, capabilities=None):
    return {"jsonrpc": "2.0", "id": identifier, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": capabilities or {},
        "clientInfo": {"name": "extract-public-corpus", "version": "1"}}}


def tool_wire(identifier, raw_arguments, *, name="extract_lines", modern=False, metadata=None):
    assert type(raw_arguments) is bytes
    params = b'{"name":' + encode(name) + b',"arguments":' + raw_arguments
    if modern or metadata is not None:
        params += b',"_meta":' + encode(inline_meta() if metadata is None else metadata)
    return b'{"jsonrpc":"2.0","id":' + encode(identifier) + b',"method":"tools/call","params":' + params + b'}}\n'


def line_hash(text):
    value = 2166136261
    for byte in text.encode():
        value = ((value ^ byte) * 16777619) & 0xffffffff
    return '%02x' % ((value ^ (value >> 8) ^ (value >> 16) ^ (value >> 24)) & 255)


def arguments(*, from_path="source", from_start=1, from_end=ABSENT,
              append_path="target", append_line=-1):
    value = {"from_path": from_path, "from_start": from_start,
             "append_path": append_path, "append_line": append_line}
    if from_end is not ABSENT:
        value["from_end"] = from_end
    return value


def owned_fixture(fixture):
    root = Path(fixture)
    if not root.is_absolute() or ".." in root.parts:
        raise ValueError("an explicit absolute owned fixture root is required")
    return root


def action(kind, path, **fields):
    return {"kind": kind, "path_hex": os.fsencode(path).hex(), **fields}


def write_input(path, raw):
    if type(raw) is not bytes:
        raise TypeError("fixture input bytes are explicit")
    return action("write", path, data_hex=raw.hex())


def fixture_actions(fixture, *, session=False):
    root = owned_fixture(fixture)
    rows = [write_input(root / "source", b"a\nb\nc\n"),
            write_input(root / "target", b"head\ntail\n")]
    if session:
        rows.append(write_input(root / "other", b"other\n"))
    return rows


def json_object_pairs(pairs):
    """Preserve supplied order and duplicate keys as input bytes."""
    return b"{" + b",".join(encode(key) + b":" + raw for key, raw in pairs) + b"}"


def typed_rows(fixture):
    """Ordinary typed-object inputs; the actual SDK decides every result."""
    setup = fixture_actions(fixture)
    rows = []
    def add(name, value=ABSENT, *, raw=None, group="typed-object"):
        if (value is ABSENT) == (raw is None):
            raise ValueError("exactly one raw/value input is required")
        data = encode(value) if raw is None else raw
        rows.append({"name": name, "domain": group, "tool": "extract_lines",
            "raw_arguments": data, "actions": copy.deepcopy(setup),
            "after_actions": [], "response": True, "response_declaration": "request framing only",
            "session": 0})
    base = arguments()
    add("ordinary-minimal", base)
    add("ordinary-explicit-end", arguments(from_end=2))
    add("ordinary-null-end", arguments(from_end=None))
    add("ordinary-source-last", arguments(from_start=-1))
    add("ordinary-target-start", arguments(append_line=0))
    add("ordinary-target-after-one", arguments(append_line=1))
    required = ("from_path", "from_start", "append_path", "append_line")
    for count in range(1, len(required) + 1):
        for absent in itertools.combinations(required, count):
            add("missing-" + "-".join(absent), {k: v for k, v in base.items() if k not in absent})
    path_values = [("null", None), ("false", False), ("true", True), ("integer", 7),
        ("fraction", 1.5), ("array", []), ("object", {}), ("empty", ""),
        ("spaces", " \t\u3000"), ("dot-local", "./source"),
        ("unicode-local", "source-λ"), ("escaped-local", "name\"with\\escapes")]
    for field in ("from_path", "append_path"):
        for label, value in path_values:
            if label == "dot-local" and field == "append_path":
                value = "./target"
            data = copy.deepcopy(base); data[field] = value
            add(field + "-" + label, data)
    endpoint_values = [("null", None), ("false", False), ("true", True),
        ("empty-array", []), ("number-array", [1]), ("empty-object", {}),
        ("number-object", {"line": 1}), ("zero", 0), ("one", 1), ("negative", -1),
        ("out-of-range", 4), ("negative-out-of-range", -4),
        ("integer-min", -(1 << 63)), ("integer-max", (1 << 63) - 1),
        ("unsigned-max", (1 << 64) - 1), ("integer-float", 1.0),
        ("fraction", 1.5), ("negative-zero-float", -0.0),
        ("empty-string", ""), ("spaces-string", " \t\u3000"),
        ("numeric-string", "1"), ("numeric-negative-string", "-1"),
        ("numeric-plus-string", "+1"), ("numeric-leading-zero", "001"),
        ("numeric-ascii-trim", " \t+1\r\n"), ("numeric-unicode-trim", "\u00a0+1\u3000"),
        ("fraction-string", "1.5"), ("exponent-string", "1e0"),
        ("non-number-string", "line"), ("i64-min-string", str(-(1 << 63))),
        ("i64-max-string", str((1 << 63) - 1)),
        ("u64-max-string", str((1 << 64) - 1)),
        ("u64-next-string", str(1 << 64)), ("plain-line-id", "1:" + line_hash("a")),
        ("uppercase-line-id", "2:" + line_hash("b").upper()),
        ("target-line-id", "1:" + line_hash("head")),
        ("different-line-id", "2:" + line_hash("a")), ("zero-line-id", "0:00"),
        ("empty-line-id", "1:"), ("plain-nonhex-id", "1:zz")]
    for field in ("from_start", "from_end", "append_line"):
        for label, value in endpoint_values:
            data = copy.deepcopy(base); data[field] = value
            add(field + "-" + label, data)
    for label, raw in [("one-decimal", b"1.0"), ("one-exponent", b"1e0"),
                       ("unsigned-next", b"18446744073709551616"),
                       ("signed-below", b"-9223372036854775809")]:
        for field in ("from_start", "from_end", "append_line"):
            pairs = [(k, encode(v)) for k, v in base.items() if k != field]
            pairs.append((field, raw))
            add(field + "-raw-" + label, raw=json_object_pairs(pairs))
    for label, unknown in [("null", None), ("number", 42), ("array", [1, False, None]),
                           ("object", {"nested": {"value": "λ"}})]:
        add("extra-field-" + label, {**base, "extra": unknown})
    for field in ("from_path", "from_start", "from_end", "append_path", "append_line"):
        value = "source" if field == "from_path" else "target" if field == "append_path" else 1
        pairs = [(k, encode(v)) for k, v in base.items()]
        if field == "from_end":
            pairs.append((field, b"null"))
        add("duplicate-" + field, raw=json_object_pairs(pairs + [(field, encode(value))]))
    add("escaped-field-names", raw=b'{"from_\\u0070ath":"source","from_start":1,"append_path":"target","append_\\u006cine":-1}')
    add("escaped-path-values", raw=b'{"from_path":"sou\\u0072ce","from_start":1,"append_path":"tar\\u0067et","append_line":-1}')
    add("ordinary-after-types", base)
    if len({r["name"] for r in rows}) != len(rows):
        raise ValueError("duplicate typed input name")
    return rows


def initialized_wire():
    return b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'


def workdir_capabilities(path):
    return {"experimental": {"session": {"workdir": str(path)}}}


def initialization_inputs(*, modern, sessions=(0, 1), capabilities=None):
    """Declare real session startup inputs, independently of tool rows."""
    if type(modern) is not bool or tuple(sessions) not in ((0,), (1,), (0, 1)):
        raise ValueError("explicit era and one/two session topology required")
    caps = {} if capabilities is None else capabilities
    result = []
    if not modern:
        for sid in sessions:
            result.extend([
                {"name": "initialize-" + str(sid), "session": sid,
                 "wire": encode(initialize(10 + sid, caps.get(sid))) + b"\n", "response": True},
                {"name": "initialized-" + str(sid), "session": sid,
                 "wire": initialized_wire(), "response": False}])
    return result


def session_rows(fixture, *, modern=False):
    """Two actual sessions, serial calls, separate caches, shared file history.

    Every row uses the existing full cache/session/history/lock observation
    before and after the call. These inputs do not claim concurrent lock WAIT.
    """
    if type(modern) is not bool:
        raise TypeError("modern is an explicit Boolean")
    root = owned_fixture(fixture)
    rows = []
    def add(name, value, *, session=0, tool="extract_lines", actions=(), seed=None):
        rows.append({"name": name, "domain": "session-chain", "session": session,
            "tool": tool, "raw_arguments": encode(value), "actions": list(actions),
            "after_actions": [], "response": True,
            "response_declaration": "request framing only", "seed": copy.deepcopy(seed),
            "metadata": inline_meta() if modern else None})
    def edit(command, path="target", **fields):
        return {"command": command, "path": path, **fields}
    add("typed-before-first-tool-admission", arguments(from_path=[]),
        actions=fixture_actions(root, session=True))
    add("session-zero-extract-with-own-cache-input", arguments(), seed=[
        {"session": 0, "path": str(root / "target"), "content": "head\ntail\n"},
        {"session": 0, "path": str(root / "source"), "content": "a\nb\nc\n"},
        {"session": 0, "path": str(root / "other"), "content": "other\n"}])
    add("session-one-extract-with-distinct-cache-input", arguments(from_start=2, from_end=3, append_line=0),
        session=1, seed=[
            {"session": 1, "path": str(root / "target"), "content": "older cached target\n"},
            {"session": 1, "path": str(root / "source"), "content": "a\nb\nc\n"},
            {"session": 1, "path": str(root / "other"), "content": "session one other cache\n"}])
    add("session-zero-undo-after-session-one-extract", edit("undo_edit"), tool="text_editor")
    add("session-one-undo-after-session-zero-extract", edit("undo_edit"), session=1, tool="text_editor")
    add("text-replace-before-extract", edit("str_replace", old_text="head", new_text="HEAD"),
        session=1, tool="text_editor")
    add("extract-after-text-replace", arguments(append_line=0))
    add("other-session-undo-extract-after-text", edit("undo_edit"), session=1, tool="text_editor")
    add("first-session-undo-prior-text-replace", edit("undo_edit"), tool="text_editor")
    add("dot-spelling-of-shared-target", arguments(from_start=-1, append_path="./target"))
    add("absolute-spelling-undo-from-other-session", edit("undo_edit", str(root / "target")),
        session=1, tool="text_editor")
    add("source-cache-input-differs-from-file", arguments(from_start=2, append_line=1), session=1,
        seed=[{"session": 1, "path": str(root / "source"), "content": "different cached source\n"}])
    add("same-file-extract-on-shared-target", arguments(from_path="target", from_start=1))
    add("other-session-undo-same-file", edit("undo_edit"), session=1, tool="text_editor")
    add("create-new-source-through-text", edit("create", "created", content="first\nsecond\n"), tool="text_editor")
    add("extract-from-created-source", arguments(from_path="created", from_start=2), session=1)
    add("undo-extract-from-created-source", edit("undo_edit"), tool="text_editor")
    add("extract-into-created-target", arguments(append_path="created", append_line=0), session=1)
    add("undo-created-target-from-other-session", edit("undo_edit", "created"), tool="text_editor")
    add("delete-created-target-through-text", edit("delete", "created"), session=1, tool="text_editor")
    add("undo-delete-created-target-from-other-session", edit("undo_edit", "created"), tool="text_editor")
    add("replace-created-source-through-text", edit("str_replace", "created", old_text="first", new_text="FIRST"),
        tool="text_editor")
    add("extract-created-source-to-second-key", arguments(from_path="created", append_path="other"), session=1)
    add("undo-second-key-from-other-session", edit("undo_edit", "other"), tool="text_editor")
    add("undo-created-source-replace-from-other-session", edit("undo_edit", "created"), session=1, tool="text_editor")
    add("missing-local-source-input", arguments(from_path="missing-local-source"))
    add("zero-source-line-input", arguments(from_start=0), session=1)
    add("different-source-line-id-input", arguments(from_start="2:" + line_hash("a")))
    add("typed-target-path-input", arguments(append_path=[]), session=1)
    add("ordinary-second-key-after-errors", arguments(append_path="other"))
    add("other-session-undo-second-key-after-errors", edit("undo_edit", "other"), session=1, tool="text_editor")
    add("trimmed-number-and-null-end", arguments(from_start=" +1 ", from_end=None, append_line="0"), session=1)
    add("other-session-undo-trimmed-number-call", edit("undo_edit"), tool="text_editor")
    add("final-extract-on-original-shared-key", arguments(from_start=3, from_end=3))
    add("final-other-session-undo", edit("undo_edit"), session=1, tool="text_editor")
    return rows


def context_plan(fixture, *, modern=False):
    """Fresh two-session workdir inputs; the SDK owns capability precedence."""
    if type(modern) is not bool:
        raise TypeError("modern is an explicit Boolean")
    root = owned_fixture(fixture)
    red, blue = root / "red", root / "blue"
    caps = {0: workdir_capabilities(red), 1: workdir_capabilities(blue)}
    setup = fixture_actions(root) + [action("mkdir", red), action("mkdir", blue),
        write_input(red / "source", b"red first\nred second\n"),
        write_input(red / "target", b"red target\n"),
        write_input(blue / "source", b"blue first\nblue second\n"),
        write_input(blue / "target", b"blue target\n")]
    rows = []
    def add(name, value, *, session=0, tool="extract_lines", capabilities=ABSENT):
        meta = inline_meta(caps[session]) if modern else None
        if capabilities is not ABSENT:
            meta = inline_meta(capabilities)
        rows.append({"name": name, "domain": "session-context", "session": session,
            "tool": tool, "raw_arguments": encode(value), "actions": [], "after_actions": [],
            "response": True, "response_declaration": "request framing only", "metadata": meta})
    add("typed-first-input-with-other-capability", arguments(from_path=[]), capabilities=caps[1])
    add("first-valid-session-zero-tool", arguments())
    add("first-valid-session-one-tool", arguments(), session=1)
    add("session-one-undo-red-absolute-key", {"command": "undo_edit", "path": str(red / "target")},
        session=1, tool="text_editor")
    add("session-zero-undo-blue-absolute-key", {"command": "undo_edit", "path": str(blue / "target")},
        tool="text_editor")
    add("later-session-zero-capability-blue", arguments(from_start=2), capabilities=caps[1])
    add("later-session-one-capability-red", arguments(from_start=2), session=1, capabilities=caps[0])
    add("explicit-cross-workdir-source-target", arguments(from_path=str(blue / "source"),
        append_path=str(red / "target")), session=1)
    add("other-session-undo-cross-workdir-target", {"command": "undo_edit", "path": str(red / "target")},
        tool="text_editor")
    add("later-relative-workdir-capability", arguments(), capabilities=workdir_capabilities("blue"))
    add("later-null-workdir-capability", arguments(), session=1,
        capabilities={"experimental": {"session": {"workdir": None}}})
    add("ordinary-session-zero-final", arguments(from_end=None))
    add("ordinary-session-one-final", arguments(from_end=None), session=1)
    return {"name": "context-" + ("modern" if modern else "legacy"),
        "session_count": 2, "actions": setup,
        "initial": initialization_inputs(modern=modern, capabilities=caps), "rows": rows}


def ordinary_stdio_rows(*, modern=False):
    """Actual JSON-lines inputs with an extract/text/undo chain in one session."""
    if type(modern) is not bool:
        raise TypeError("modern is an explicit Boolean")
    data = [
        ("typed-path-input", "extract_lines", arguments(from_path=[])),
        ("first-extract", "extract_lines", arguments()),
        ("second-extract", "extract_lines", arguments(from_start=2, from_end=3, append_line=0)),
        ("undo-second-extract", "text_editor", {"command": "undo_edit", "path": "target"}),
        ("undo-first-extract", "text_editor", {"command": "undo_edit", "path": "target"}),
        ("replace-before-extract", "text_editor", {"command": "str_replace", "path": "target", "old_text": "head", "new_text": "HEAD"}),
        ("extract-after-replace", "extract_lines", arguments(append_line=1)),
        ("undo-extract-after-replace", "text_editor", {"command": "undo_edit", "path": "target"}),
        ("undo-prior-replace", "text_editor", {"command": "undo_edit", "path": "target"}),
        ("nullable-end", "extract_lines", arguments(from_start=2, from_end=None)),
        ("undo-nullable-end", "text_editor", {"command": "undo_edit", "path": "target"}),
        ("numeric-string-endpoints", "extract_lines", arguments(from_start=" +1 ", from_end="2", append_line="-1")),
        ("undo-numeric-strings", "text_editor", {"command": "undo_edit", "path": "target"}),
        ("different-line-id", "extract_lines", arguments(from_start="2:" + line_hash("a"))),
        ("missing-local-file", "extract_lines", arguments(from_path="missing-local-file")),
        ("missing-required-field", "extract_lines", {"from_path": "source", "append_path": "target", "append_line": -1}),
        ("create-source", "text_editor", {"command": "create", "path": "created", "content": "created first\ncreated second\n"}),
        ("extract-created-source", "extract_lines", arguments(from_path="created", from_start=2)),
        ("undo-created-source-extract", "text_editor", {"command": "undo_edit", "path": "target"}),
        ("final-ordinary-extract", "extract_lines", arguments(from_start=3)),
    ]
    result = initialization_inputs(modern=modern, sessions=(0,))
    for index, (name, tool, value) in enumerate(data):
        result.append({"name": name, "session": 0,
            "wire": tool_wire(100 + index, encode(value), name=tool, modern=modern), "response": True})
    return result


def requests(modern):
    """Drop-in input provider for qualify_stdio.requests; setup has two files."""
    return [(row["name"], row["wire"], row["response"]) for row in ordinary_stdio_rows(modern=modern)]


def wire_for_row(row, index, *, modern=False):
    """The existing typed/session driver framing, with extract as the tool."""
    if type(index) is not int or index < 0 or type(modern) is not bool:
        raise ValueError("explicit nonnegative case index and protocol era")
    return tool_wire(1000 + index, row["raw_arguments"], name=row["tool"],
        modern=modern, metadata=row.get("metadata"))


def raw_request(identifier, method, params=ABSENT):
    """Bytes in, bytes out: retain JSON number spelling and unknown model shapes."""
    if type(identifier) is not bytes or type(method) is not bytes:
        raise TypeError("raw ID and method tokens are explicit bytes")
    raw = b'{"jsonrpc":"2.0","id":' + identifier + b',"method":' + method
    if params is not ABSENT:
        if type(params) is not bytes:
            raise TypeError("raw params token is explicit bytes")
        raw += b',"params":' + params
    return raw + b'}\n'


def raw_tool_request(identifier, raw_arguments=ABSENT, *, metadata=ABSENT, name=b'"extract_lines"'):
    pairs = [("name", name)]
    if raw_arguments is not ABSENT:
        if type(raw_arguments) is not bytes:
            raise TypeError("raw arguments are explicit bytes")
        pairs.append(("arguments", raw_arguments))
    if metadata is not ABSENT:
        if type(metadata) is not bytes:
            raise TypeError("raw metadata is explicit bytes")
        pairs.append(("_meta", metadata))
    return raw_request(identifier, b'"tools/call"', json_object_pairs(pairs))


def ping_wire(identifier, *, modern=False):
    params = encode({"_meta": inline_meta()}) if modern else ABSENT
    return raw_request(encode(identifier), b'"ping"', params)


def protocol_scenarios(fixture, *, modern=False):
    """Complete wire inputs whose SDK response cardinality is not assumed.

    Use real stdio with a collector that retains all lines until the actual
    barrier ID or observed EOF. A barrier is only input correlation; neither
    its result nor any preceding reply is authored here. Never pass a trial
    to the old Boolean response_count driver or discard an extra response.
    Each scenario owns a fresh process and the same 180/60 second bounds.
    """
    if type(modern) is not bool:
        raise TypeError("modern is an explicit Boolean")
    setup = fixture_actions(fixture)
    current = encode(inline_meta()) if modern else ABSENT
    ordinary = encode(arguments())
    typed_input = encode(arguments(from_path=[]))
    trials = []
    def add(name, wire, category):
        if type(wire) is not bytes or not wire.endswith(b"\n"):
            raise ValueError("a complete ordinary JSON-line trial is required")
        trials.append((name, wire, category))
    meta_values = [("absent", ABSENT), ("null", b"null"), ("empty-object", b"{}"),
        ("false", b"false"), ("array", b"[]"), ("string", b'"plain"'),
        ("current-complete", encode(inline_meta())),
        ("protocol-only", encode({"io.modelcontextprotocol/protocolVersion": "2026-07-28"})),
        ("capabilities-only", encode({"io.modelcontextprotocol/clientCapabilities": {}})),
        ("current-capabilities-null", encode({**inline_meta(), "io.modelcontextprotocol/clientCapabilities": None})),
        ("current-client-info-null", encode({**inline_meta(), "io.modelcontextprotocol/clientInfo": None})),
        ("current-with-extra", encode({**inline_meta(), "fixture-note": [1, None, "λ"]})),
        ("legacy-complete", encode({**inline_meta(), "io.modelcontextprotocol/protocolVersion": "2025-11-25"})),
        ("empty-version", encode({**inline_meta(), "io.modelcontextprotocol/protocolVersion": ""})),
        ("unknown-version", encode({**inline_meta(), "io.modelcontextprotocol/protocolVersion": "2099-01-01"})),
        ("number-version", encode({**inline_meta(), "io.modelcontextprotocol/protocolVersion": 2026}))]
    for name, meta in meta_values:
        add("metadata-" + name, raw_tool_request(b"20001", typed_input, metadata=meta), "request-metadata")
    arguments_values = [("absent", ABSENT), ("null", b"null"), ("false", b"false"),
        ("number", b"7"), ("string", b'"plain"'), ("empty-array", b"[]"),
        ("object-array", b"[{}]"), ("empty-object", b"{}")]
    for name, raw in arguments_values:
        add("sdk-arguments-" + name, raw_tool_request(b"20002", raw, metadata=current), "sdk-arguments-map")
    for name, params in [("absent", ABSENT), ("null", b"null"), ("false", b"false"),
                         ("array", b"[]"), ("string", b'"plain"')]:
        add("sdk-params-" + name, raw_request(b"20003", b'"tools/call"', params), "sdk-tool-params")
    for name, tool in [("null", b"null"), ("number", b"7")]:
        add("sdk-tool-name-" + name, raw_tool_request(b"20004", typed_input, metadata=current, name=tool), "sdk-tool-name")
    for name, raw_id in [("integer", b"17"), ("integral-float", b"17.0"),
            ("negative-integer", b"-17"), ("empty-string", b'""'),
            ("escaped-string", encode('extract"\\\t\n\0λ')),
            ("long-string", encode("extract-" + "id" * 1024)),
            ("completed-id-reuse", b"10000")]:
        add("request-id-" + name, raw_tool_request(raw_id, typed_input, metadata=current), "sdk-request-id")
    cancel_params = {"requestId": 10000, "reason": "completed ordinary request"}
    if modern:
        cancel_params["_meta"] = inline_meta()
    add("cancel-completed-request", encode({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": cancel_params}) + b"\n",
        "notifications")
    other_cancel = copy.deepcopy(cancel_params); other_cancel["requestId"] = "not-issued-in-this-session"
    add("cancel-unissued-request", encode({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": other_cancel}) + b"\n",
        "notifications")
    add("initialized-notification", initialized_wire(), "notifications")
    notification_params = [("name", b'"extract_lines"'), ("arguments", typed_input)]
    if modern:
        notification_params.append(("_meta", current))
    add("tool-name-without-request-id", b'{"jsonrpc":"2.0","method":"tools/call","params":' +
        json_object_pairs(notification_params) + b'}\n', "notifications")
    for name, raw in [("null", b"null\n"), ("array", b"[]\n"), ("string", b'"plain"\n'),
                      ("empty-object", b"{}\n")]:
        add("json-top-level-" + name, raw, "sdk-message-shape")
    add("request-without-method", b'{"jsonrpc":"2.0","id":20005}\n', "sdk-message-shape")
    add("request-without-jsonrpc", b'{"id":20006,"method":"ping"}\n', "sdk-message-shape")
    result = []
    for index, (name, wire, category) in enumerate(trials):
        barrier_id = "extract-barrier-" + str(index)
        anchor = tool_wire(10000, ordinary, modern=modern)
        recovery = tool_wire(30000 + index, ordinary, modern=modern)
        result.append({"name": ("modern-" if modern else "legacy-") + name,
            "category": category, "session_count": 1, "requires_real_stdio": True,
            "actions": copy.deepcopy(setup),
            "initial": initialization_inputs(modern=modern, sessions=(0,)),
            "anchor": {"wire": anchor, "input_id": 10000, "collect": "through-input-id-or-eof"},
            "trial": {"wire": wire, "collect": "defer-to-barrier"},
            "recovery": {"wire": recovery, "input_id": 30000 + index,
                "collect": "all-actual-lines-through-input-id-or-eof"},
            "barrier": {"wire": ping_wire(barrier_id, modern=modern), "input_id": barrier_id,
                "collect": "all-actual-lines-through-input-id-or-eof"},
            "finish": {"action": "close-stdin-after-barrier-or-observed-eof", "collect": "all-remaining-lines-and-process-exit"},
            "per_exchange_deadline_seconds": EXCHANGE_SECONDS, "outer_lane_deadline_seconds": PROCESS_SECONDS,
            "response_count": None})
    return result


def eof_scenarios(fixture, *, modern=False):
    """Actual stdin half-close inputs; no private-frame transport substitute."""
    if type(modern) is not bool:
        raise TypeError("modern is an explicit Boolean")
    complete = tool_wire(41002, encode(arguments(from_start=2)), modern=modern)
    partial = b'{"jsonrpc":"2.0","id":41003,"method":"tools/call","params":'
    tails = [
        ("after-observed-complete-request", b""),
        ("complete-json-without-newline", complete[:-1]),
        ("partial-json-without-newline", partial),
        ("complete-line-then-partial-tail", complete + partial),
        ("complete-line-immediate-half-close", complete),
    ]
    return [{"name": ("modern-" if modern else "legacy-") + "eof-" + name,
        "session_count": 1, "requires_real_stdio": True,
        "actions": fixture_actions(fixture),
        "initial": initialization_inputs(modern=modern, sessions=(0,)),
        "anchor": {"wire": tool_wire(41001, encode(arguments()), modern=modern),
            "input_id": 41001, "collect": "through-input-id-or-eof"},
        "tail": {"wire": tail, "action": "write-all-then-close-stdin", "collect": "until-eof"},
        "finish": {"collect": "all-actual-lines-filesystem-and-process-exit"},
        "per_exchange_deadline_seconds": EXCHANGE_SECONDS, "outer_lane_deadline_seconds": PROCESS_SECONDS,
        "response_count": None} for name, tail in tails]


def all_inputs(fixture):
    """One complete portable input object; byte fields remain bytes in memory."""
    root = owned_fixture(fixture)
    typed = typed_rows(root)
    result = {"schema": "hepta.extract-public-inputs.v1", "target": TARGET, "graph": GRAPH,
        "fixture": str(root), "budgets": {"per_exchange_seconds": EXCHANGE_SECONDS,
            "per_process_seconds": PROCESS_SECONDS, "ci_job_minutes": 15}, "domains": {}}
    for modern in (False, True):
        era = "modern" if modern else "legacy"
        result["domains"]["typed-" + era] = {"session_count": 2,
            "initial": initialization_inputs(modern=False, sessions=(1,)) if modern else initialization_inputs(modern=False),
            "modern": modern,
            "rows": copy.deepcopy(typed)}
        result["domains"]["session-" + era] = {"session_count": 2,
            "initial": initialization_inputs(modern=modern),
            "rows": session_rows(root, modern=modern)}
        result["domains"]["context-" + era] = context_plan(root, modern=modern)
        result["domains"]["stdio-" + era] = {"session_count": 1, "actions": fixture_actions(root),
            "requires_real_stdio": True, "rows": ordinary_stdio_rows(modern=modern)}
        result["domains"]["protocol-" + era] = {"scenarios": protocol_scenarios(root, modern=modern)}
        result["domains"]["eof-" + era] = {"scenarios": eof_scenarios(root, modern=modern)}
    return result


def serial_inputs(value):
    """Lossless JSON representation for authored input bytes, never responses."""
    if type(value) is bytes:
        return {"input_hex": value.hex()}
    if type(value) is dict:
        return {key: serial_inputs(item) for key, item in value.items()}
    if type(value) in (list, tuple):
        return [serial_inputs(item) for item in value]
    if value is None or type(value) in (str, bool, int, float):
        return value
    raise TypeError("unsupported authored input type: " + type(value).__name__)


def main():
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, help="owned absolute fixture root; no filesystem action is performed")
    parser.add_argument("--domain", help="optional one declared domain")
    args = parser.parse_args()
    value = all_inputs(args.fixture)
    if args.domain:
        if args.domain not in value["domains"]:
            parser.error("unknown input domain")
        value["domains"] = {args.domain: value["domains"][args.domain]}
    sys.stdout.buffer.write(encode(serial_inputs(value)) + b"\n")


if __name__ == "__main__":
    main()

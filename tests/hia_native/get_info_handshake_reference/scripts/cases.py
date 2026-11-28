"""Ordinary initialize versions and sequential metadata observations, without expected wire."""
import json

LEGACY = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
VERSIONS = (*LEGACY, "2026-07-28", "2099-01-01", "", "版本-普通", "2025-11-25\0ordinary")
ID_LEXEMES = (
    ("integer", "17"),
    ("negative", "-17"),
    ("integral-float", "17.0"),
    ("escaped", '"normal\\u002fescaped\\u0000id"'),
    ("unicode", json.dumps("编号-α", ensure_ascii=False)),
    ("long", json.dumps("ordinary-id-" + "x" * 4096)),
)
META_PREFIX = "io.modelcontextprotocol/"


def wire(method, identity, params=None, *, id_lexeme=None):
    obj = {"jsonrpc": "2.0", "id": identity, "method": method}
    if params is not None:
        obj["params"] = params
    text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    if id_lexeme is not None:
        old = '"id":' + json.dumps(identity, ensure_ascii=False, separators=(",", ":"))
        assert text.count(old) == 1
        text = text.replace(old, '"id":' + id_lexeme, 1)
    assert "\n" not in text and json.loads(text)["jsonrpc"] == "2.0"
    return text


def metadata(version, label):
    return {
        META_PREFIX + "protocolVersion": version,
        META_PREFIX + "clientInfo": {"name": "request-" + label, "version": "1"},
        META_PREFIX + "clientCapabilities": {"experimental": {"observation": {"scope": label}}},
    }


def cases():
    result = []
    for version_index, version in enumerate(VERSIONS):
        for id_name, id_lexeme in ID_LEXEMES:
            label = f"version-{version_index:02d}-id-{id_name}"
            initial_id = json.loads(id_lexeme)
            params = {
                "protocolVersion": version,
                "clientInfo": {"name": "session-" + label, "version": "1"},
                "capabilities": {"experimental": {"observation": {"scope": "session"}}},
            }
            events = [{"wire": wire("initialize", initial_id, params, id_lexeme=id_lexeme), "response": True}]
            events.append({"wire": wire("ping", label + "-before-initialized"), "response": True})
            events.append({"wire": '{"jsonrpc":"2.0","method":"notifications/initialized"}', "response": False})
            events.append({"wire": wire("ping", label + "-legacy-meta", {"_meta": metadata(LEGACY[0], "legacy")}), "response": True})
            events.append({"wire": wire("ping", label + "-after-legacy"), "response": True})
            events.append({"wire": wire("ping", label + "-modern-meta", {"_meta": metadata("2026-07-28", "modern")}), "response": True})
            events.append({"wire": wire("ping", label + "-after-modern"), "response": True})
            result.append({"label": label, "requested_version": version, "id_profile": id_name,
                           "id_lexeme": id_lexeme, "events": events})
    assert len(result) == 54
    return result

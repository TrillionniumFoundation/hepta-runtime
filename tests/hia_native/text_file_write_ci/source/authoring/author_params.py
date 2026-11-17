#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Derive the current target TextFileWriteParams projection from exact HIA helpers.

This script only authors HIA source. It never compiles or invokes native code.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from authoring_support import compile_delta, substitute

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CANON = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
BASELINE = "310368785b761a4c1dbde449f3ebba2cb20df9d0f91cc9264ec8b2afbc20a262"
LITERALS = {
    1: b"missing field `path`",
    2: b"missing field `mode`",
    3: b"invalid type: ",
    4: b", expected ",
    5: b"a string",
    6: b"a boolean",
    7: b"string or map",
    8: b"invalid value: map, expected map with a single key",
    9: b"unit",
    10: b"unknown variant `",
    11: b"`, expected one of `create`, `replace`, `append`",
    12: b"missing field `content`",
    13: b"missing field `expected_sha256`",
    14: b"unknown field `",
    15: b"`, expected one of `path`, `mode`, `content`, `expected_sha256`",
}


def literal_source():
    text = "\ndef literal(w:mutbuf,o:mutbuf,code:u64) -> u64:\n"
    for code, raw in LITERALS.items():
        text += f"    if code=={code}:\n"
        for byte in raw:
            text += f"        emit(w,o,{byte})\n"
        text += "        return 0\n"
    return text + "    return 0\n"


def field_source():
    text = "\ndef field_key(s:readbuf,start:u64,end:u64) -> u64:\n"
    for index, field in enumerate((b'"path"', b'"mode"', b'"content"', b'"expected_sha256"'), 1):
        text += f"    if end-start=={len(field)}:\n        same=1\n"
        for i, byte in enumerate(field):
            text += f"        if byte(s,start+{i})!={byte}:\n            same=0\n"
        text += f"        if same!=0:\n            return {index}\n"
    return text + "    return 0\n"


def enum_source():
    text = "\ndef enum_byte(kind:u64,index:u64) -> u64:\n"
    for kind, raw in enumerate((b"create", b"replace", b"append"), 1):
        text += f"    if kind=={kind}:\n"
        for i, byte in enumerate(raw):
            text += f"        if index=={i}:\n            return {byte}\n"
    return text + "    return 256\n"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hepta", required=True, type=Path)
    p.add_argument("--source", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    source = a.source.resolve(strict=True)
    output = a.output.absolute()
    if output.exists():
        raise ValueError("Author output must be a fresh directory")
    raw = (source / "baseline/text_editor_params.hepta").read_bytes()
    if SHA(raw) != BASELINE:
        raise ValueError("Text Editor helper source changed")
    composition = json.loads((source / "baseline/text_editor_params_composition.json").read_bytes())
    aliases = dict(composition["functions"])
    aliases.update(emit_scalar="f22", retained_error="f43")
    constants = dict(INVALID=0xffffffff, CAPACITY=0xfffffffe, MAXIMUM=(1 << 64) - 1,
        REQUEST=int.from_bytes(b"HTPPRQ01", "little"), RESPONSE=int.from_bytes(b"HTPPRR01", "little"), META=65536)
    pseudo = (source / "authoring/params.pseudo").read_text()
    pseudo += literal_source() + field_source() + enum_source()
    pseudo = substitute(pseudo, constants)
    replacements = dict(entry="f0", project="f1", enum_kind="f3", error="f4", header="f5",
                        field_key="f6", enum_byte="f7", literal="f8")
    authored, after, retained = compile_delta(a.hepta.resolve(strict=True), raw, aliases, pseudo,
        replacements, {}, (("f4", "f43"),))
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    document = assemble_program(authored).as_dict()
    document["module"] = "text_file_write_typed_params"
    authored = render_assembly(document).encode()
    original = assemble_program(raw).as_dict()
    final = assemble_program(authored).as_dict()
    before = {f["name"]: f for f in original["functions"]}
    actual = {f["name"]: f for f in final["functions"]}
    for name in retained:
        assert actual[name] == before[name]
    restored = dict(actual["f43"]); restored["name"] = "f4"
    assert restored == before["f4"]
    output.mkdir(parents=True)
    (output / "text_file_write_params.hepta").write_bytes(authored)
    (output / "authored.pseudo").write_text(pseudo)
    receipt = dict(schema="hepta.runtime.text-file-write-params.source.v1",
        target_commit="d3d75c30719db966b004756f610007a7c723729e",
        baseline_source_sha256=BASELINE, source_bytes=len(authored), source_sha256=SHA(authored),
        functions=len(actual), changed_functions=sorted(replacements.values()),
        retained_exact_functions=retained, relocated_exact_functions={"f4": "f43"},
        aliases={**aliases, **replacements}, constants=constants,
        function_sha256={name: SHA(CANON(body)) for name, body in actual.items()},
        canonical_typed_map_required=True, generic_value_reentry=False,
        body_validation_in_typed_owner=False, syscall_capability=False,
        native_compiled=False, native_executed=False, original_compared=False,
        public_route_integrated=False, whole_runtime_qualified=False)
    (output / "text_file_write_params_composition.json").write_text(json.dumps(receipt, sort_keys=True, indent=2)+"\n")
    print(json.dumps({key: receipt[key] for key in ("source_bytes", "source_sha256", "functions")}, sort_keys=True))


if __name__ == "__main__":
    main()

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the HIA classic-ZIP parser; Python is a development author only."""
from pathlib import Path
import argparse
import ast
import copy
import hashlib
import json
import re
import sys

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CANONICAL = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
CONSTANTS = {
    "H": 4096, "INIT": 5120, "P": 8192, "STAT": 9000,
    "TAIL": 16384, "SMALL": 98304, "CFIX": 98432, "LFIX": 98560,
    "CVAR": 131072, "LVAR": 393216, "NUMBER": 2048,
    "VERSION_TEXT": 700000, "VERSION_VALUE": 701024,
    "DIR_DIGEST": 701200, "EOCD_DIGEST": 701264,
    "ENTRIES": 2097152, "TABLE": 9437184, "RANGES": 11534336,
    "ARENA": 12582912, "JSON_BASE": 50331648, "JSON_END": 51380224,
    "WORKSPACE": 67108864,
    "INVALID": 0xffffffff, "CAPACITY": 0xfffffffe, "PENDING": 0xfffffff0,
    "REQUEST": int.from_bytes(b"HZIPRQ01", "little"),
    "FIELD_REQUEST": int.from_bytes(b"HZIPAT01", "little"),
    "RESPONSE": int.from_bytes(b"HZIPRS01", "little"),
    "PRIVATE": int.from_bytes(b"HZIPST01", "little"),
    "EFFECT": int.from_bytes(b"HZIPFX01", "little"),
}
NAMES = {
    "N_ANDROID": b"AndroidManifest.xml", "N_JAR": b"META-INF/MANIFEST.MF",
    "N_CLASSES": b"classes", "N_DEX": b".dex", "N_SO": b".so",
    "N_DLL": b".dll", "N_DYLIB": b".dylib", "N_META": b"META-INF/",
    "N_RSA": b".RSA", "N_DSA": b".DSA", "N_EC": b".EC", "N_SF": b".SF",
    "N_RESOURCE": b"resources.arsc", "N_RES": b"res/", "N_ASSETS": b"assets/",
    "N_CLASS": b".class",
}
LITERALS = {
    "L_VERSION_PREFIX": b"hepta-archive-observation-v1:",
    "L_VERSION_TOKEN": b"afv1_",
    "L_ALL": b'"all"', "L_MANIFEST": b'"manifest"', "L_DEX": b'"dex"',
    "L_NATIVE": b'"native_library"', "L_RESOURCE": b'"resource"',
    "L_CLASS": b'"java_class"', "L_SIGNATURE": b'"signature_marker"',
    "L_DIRECTORY": b'"directory"', "L_OTHER": b'"other"',
    "L_UTF8": b'"utf8"', "L_ASCII": b'"ascii"',
    "L_TRUE": b"true", "L_FALSE": b"false", "L_NULL": b"null",
    "L_NAME_KEY": b'{"name":', "L_ENCODING_KEY": b',"name_encoding":',
    "L_ROLE_KEY": b',"role":', "L_CENTRAL_KEY": b',"central_header_offset":',
    "L_LOCAL_KEY": b',"local_header_offset":', "L_PAYLOAD_KEY": b',"payload_offset":',
    "L_COMPRESSED_KEY": b',"compressed_bytes":', "L_UNCOMPRESSED_KEY": b',"uncompressed_bytes":',
    "L_METHOD_KEY": b',"compression_method":', "L_FLAGS_KEY": b',"flags":',
    "L_ENCRYPTED_KEY": b',"encrypted":', "L_CRC_KEY": b',"declared_crc32":"',
    "L_DESCRIPTOR_KEY": b'","data_descriptor_bytes":',
    "L_EXTRAS_KEY": b',"central_extra_field_ids":[',
    "L_ENTRY_END": b'],"content_verified":false}',
    "L_REPORT_HEAD": b'{"record_format":"hepta.rea-archive-index.v1","rea_evidence_compatible":false,"operation":"inspect_archive","format":"zip","application_kind_candidates":[',
    "L_APK_HINT": b'"apk_candidate"', "L_JAR_HINT": b'"jar_candidate"',
    "L_SOURCE_HEAD": b'],"source":{"observed_version":',
    "L_SIZE_KEY": b',"size_bytes":', "L_DIRECTORY_OFFSET_KEY": b',"central_directory_offset":',
    "L_DIRECTORY_BYTES_KEY": b',"central_directory_bytes":',
    "L_DIRECTORY_HASH_KEY": b',"central_directory_sha256":',
    "L_EOCD_OFFSET_KEY": b',"eocd_offset":', "L_EOCD_BYTES_KEY": b',"eocd_bytes":',
    "L_EOCD_HASH_KEY": b',"eocd_sha256":', "L_COUNT_KEY": b'},"entry_count":',
    "L_ENCRYPTED_COUNT_KEY": b',"encrypted_entry_count":',
    "L_RESULT_FILTER_KEY": b',"result":{"filter":',
    "L_OFFSET_KEY": b',"offset":', "L_LIMIT_KEY": b',"limit":',
    "L_TOTAL_KEY": b',"total":', "L_NEXT_KEY": b',"next_offset":',
    "L_ROWS_KEY": b',"rows":[',
    "L_REPORT_END": b']},"coverage":{"central_directory":"complete_within_supported_classic_zip","local_header_declarations":"checked","entry_payloads":"not_interpreted_or_decompressed","payload_crc32":"not_verified","signatures":"not_verified"},"limitations":["APK/JAR, manifest, DEX, class and native-library labels are filename observations only; content and application identity are unverified.","CRC values and data descriptors are checked for declaration consistency only, not against decompressed payloads.","ZIP64, multi-volume, prefixed/overlaid archives, legacy non-ASCII names and Unicode-path override fields are unsupported.","Bytes between local records and the central directory, including any APK signing block, are not interpreted. No archive member is extracted or executed."]}',
}
ERRORS = {
    1: "archive page limit must be between 1 and 256",
    2: "archive must be a regular file with an exact, nontruncated extent",
    3: "archive structure extends beyond admitted file size",
    5: "archive structure exceeds 64 MiB I/O budget",
    6: "truncated archive structure",
    7: "ZIP EOCD missing or trailing overlay unsupported",
    8: "multi-volume ZIP or inconsistent volume counts are unsupported",
    9: "ZIP64 sentinel or locator requires a separately qualified reader",
    10: "archive exceeds native directory count or byte budget",
    11: "ZIP central-directory extent does not terminate at EOCD",
    12: "ZIP central entry exceeds directory extent",
    13: "invalid ZIP central-directory signature",
    14: "ZIP64 or multi-volume member is unsupported",
    15: "ZIP central variable fields exceed directory extent",
    16: "ambiguous or traversing ZIP member name is refused",
    17: "legacy non-ASCII ZIP filename encoding is unknown",
    18: "invalid ZIP UTF-8 filename",
    19: "truncated ZIP u16",
    20: "ZIP extra field extends beyond its declared region",
    21: "ZIP64 extra fields are explicitly unsupported by this reader",
    22: "ZIP Unicode-path override fields are not qualified; no filename is guessed",
    23: "ZIP local header overlaps central directory",
    24: "ZIP local header signature missing",
    25: "ZIP local and central flags or compression disagree",
    26: "ZIP local payload crosses central-directory boundary",
    27: "ZIP local and central member names disagree",
    28: "ZIP local and central CRC/size declarations disagree",
    29: "unencrypted stored ZIP member has inconsistent size declarations",
    30: "truncated ZIP data descriptor",
    31: "ZIP data descriptor is ambiguous or disagrees with central declarations",
    32: "archive index exceeds 32 MiB retained representation budget",
    33: "duplicate ZIP member name is ambiguous",
    34: "ZIP central-directory count or trailing structure differs from declaration",
    35: "ZIP local ranges overlap or a prefixed/self-extracting archive is unsupported",
    36: "archive page offset exceeds selected collection size",
    37: "REA inspection denied: admitted artifact changed during read",
    47: "archive parser response exceeds 1 MiB; reduce page size",
    48: "invalid archive parser continuation state",
}


def literal_function(name, values):
    source = f"\ndef {name}(w:mutbuf, at:u64, code:u64) -> u64:\n"
    for code, raw in values.items():
        source += f"    if code == {code}:\n"
        full = len(raw) // 8 * 8
        for offset in range(0, full, 8):
            value = int.from_bytes(raw[offset:offset + 8], "little")
            source += f"        at = word(w, at, {value})\n"
        for value in raw[full:]:
            source += f"        at = emit(w, at, {value})\n"
        source += "        return at\n"
    return source + "    return at\n"


def generated_source(root):
    constants = dict(CONSTANTS)
    literals, names = {}, {}
    for index, (name, raw) in enumerate(LITERALS.items(), 1):
        constants[name] = index
        literals[index] = raw
    for index, (name, raw) in enumerate(NAMES.items(), 1):
        constants[name] = index
        names[index] = raw
    source = (root / "scripts/rea_zip_parser_source.py.txt").read_text()
    source = re.sub(r"\b(" + "|".join(constants) + r")\b", lambda m: str(constants[m[0]]), source)
    source += literal_function("literal", literals)
    source += literal_function("error_text", {code: text.encode() for code, text in ERRORS.items()})
    source += "\ndef matches(w:mutbuf, at:u64, n:u64, code:u64) -> u64:\n"
    for code, raw in names.items():
        source += f"    if code == {code}:\n        if n != {len(raw)}:\n            return 0\n"
        full = len(raw) // 8 * 8
        for offset in range(0, full, 8):
            value = int.from_bytes(raw[offset:offset + 8], "little")
            source += f"        if get(w, at + {offset}) != {value}:\n            return 0\n"
        for offset in range(full, len(raw)):
            source += f"        if byte(w, at + {offset}) != {raw[offset]}:\n            return 0\n"
        source += "        return 1\n"
    source += "    return 0\n"
    return source


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    options = parser.parse_args()
    root = options.runtime.resolve(strict=True)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(options.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly

    class Bulk(Builder):
        def expr(self, node):
            if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.FloorDiv, ast.Mod)):
                args = [self.expr(node.left), self.expr(node.right)]
                return self.op("int.div.checked" if isinstance(node.op, ast.FloorDiv) else "int.rem.checked", args, args[0][1])
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "copy_range":
                args = [self.expr(item) for item in node.args]
                if args[0] == args[1]:
                    return self.op("buffer.move_within", [args[0], *(self.cast(x, "usize") for x in args[2:])])
                source = args[1]
                if source[1] == "mutbuf":
                    source = self.op("borrow.read", [source], "readbuf")
                result = self.op("buffer.copy_range", [args[0], source, *(self.cast(x, "usize") for x in args[2:])])
                if args[1][1] == "mutbuf":
                    self.op("loan.end", [source])
                return result
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in self.signatures:
                values = [self.expr(item) for item in node.args]
                signature = self.signatures[node.func.id]
                assert len(values) == len(signature[0])
                args, loans = [], []
                for value, kind in zip(values, signature[0]):
                    if value[1] == "mutbuf" and kind == "readbuf":
                        value = self.op("borrow.read", [value], "readbuf")
                        loans.append(value)
                    args.append(self.cast(value, kind) if value[1] != kind else value)
                result = self.op("call", args, signature[1], function=self.names[node.func.id])
                for value in loans:
                    self.op("loan.end", [value])
                return result
            return super().expr(node)

    source = generated_source(root)
    nodes = ast.parse(source).body
    assert all(isinstance(node, ast.FunctionDef) for node in nodes)
    names = {node.name: "f" + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    specs = [
        ("native/binary_codec.hepta", {"sha_init": "f17", "sha_compress": "f19", "sha_final": "f10", "get": "f21", "put": "f22"},
         "f58ab824ecb47545f19cd1d0daded9e41fca5457110693677d84e393e3098f23"),
        ("native/text_budget.hepta", {"utf8": "f2"},
         "89df7b4320fdbd3525450e9446267ae3d54a5b62660d8904fe8f09be36a7fbf9"),
    ]
    imports, proof = [], []
    for relative, aliases, expected in specs:
        raw = (root / relative).read_bytes()
        assert SHA(raw) == expected
        original = {f["name"]: f for f in assemble_program(raw).as_dict()["functions"]}
        selected, pending = set(aliases.values()), list(aliases.values())
        while pending:
            for block in original[pending.pop()]["blocks"]:
                for op in block["ops"]:
                    if op["op"] == "call" and op["attrs"]["function"] not in selected:
                        selected.add(op["attrs"]["function"])
                        pending.append(op["attrs"]["function"])
        relocation = {old: "f" + str(len(nodes) + len(imports) + index)
                      for index, old in enumerate(sorted(selected, key=lambda n: int(n[1:])))}
        for alias, old in aliases.items():
            names[alias] = relocation[old]
            signatures[alias] = ([p["type"] for p in original[old]["params"]], original[old]["returns"][0])
        for old, new in relocation.items():
            item = copy.deepcopy(original[old])
            item["name"] = new
            for block in item["blocks"]:
                for op in block["ops"]:
                    if op["op"] == "call":
                        op["attrs"]["function"] = relocation[op["attrs"]["function"]]
            imports.append(item)
        proof.append({"source": relative, "sha256": expected, "relocation": relocation,
                      "functions": {old: SHA(CANONICAL(original[old])) for old in relocation},
                      "changes": "function and direct-call target names only"})
    functions = []
    total = total_scalar_functions(nodes)
    for node in nodes:
        builder = Bulk(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({"name": names[node.name], "params": [builder.param(p) for p in builder.params],
                          "returns": [builder.returns], "effects": ["read", "write", "trap"],
                          "entry": "b0", "blocks": builder.blocks})
    document = compact_authoring_cfg({"schema": "hepta.hia.program.v8", "module": "hepta_runtime_rea_classic_zip", "functions": functions + imports})
    document["functions"] = document["functions"][:len(functions)] + imports
    raw = render_assembly(document).encode()
    actual = {f["name"]: f for f in assemble_program(raw).as_dict()["functions"]}
    assert all(actual[f["name"]] == f for f in imports)
    target = root / "native/rea_zip_parser.hepta"
    target.write_bytes(raw)
    metadata = {
        "schema": "hepta.runtime.rea-classic-zip-composition.v1",
        "source_sha256": SHA(raw), "source_bytes": len(raw), "imports": proof,
        "functions": names, "original_parser": "src/mcp/rea_artifact_zip_parser.rs",
        "original_parser_sha256": SHA((root / "src/mcp/rea_artifact_zip_parser.rs").read_bytes()),
        "original_parent_sha256": SHA((root / "src/mcp/rea_artifact_zip.rs").read_bytes()),
        "workspace_bytes": CONSTANTS["WORKSPACE"], "maximum_result_bytes": 1048576,
        "constants": CONSTANTS, "errors": ERRORS,
        "qualified": False, "public_route_qualified": False, "whole_runtime_qualified": False,
        "scope": "HIA seek parser and exact JSON result on one caller-admitted read-only descriptor; host configuration, MCP parameters, file admission and optional full hash are separate owners",
    }
    (root / "native/rea_zip_parser_composition.json").write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"source_bytes": len(raw), "sha256": SHA(raw), "functions": len(actual),
                      "instructions": sum(len(b["ops"]) for f in actual.values() for b in f["blocks"]),
                      "fits_existing_1MiB_compiler_input": len(raw) <= 1048576}, sort_keys=True))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Author the Local extract_lines controller from frozen source and child ABIs."""
from pathlib import Path
import argparse
import ast
import copy
import hashlib
import json
import sys

TEXT_PIN = "89df7b4320fdbd3525450e9446267ae3d54a5b62660d8904fe8f09be36a7fbf9"
BODY_PIN = "ac7c2feece9de07129b14434aa2399c3767fa1ef2211eeca11feaead3b34ce49"
LITERALS = (
    "Parameter 'from_path' cannot be empty",
    "Missing required parameter 'from_start' (line number or line id)",
    "Invalid 'from_start': ", "Invalid 'from_end': ",
    "Parameter 'append_path' cannot be empty",
    "Missing required parameter 'append_line' (0 = start, -1 = end, N, or a line id)",
    "Invalid 'append_line': ", "Source file does not exist: ",
    "Failed to read source file '", "': ", "Invalid from_start: ", "Invalid from_end: ",
    "from_start (line ", ") is after from_end (line ", ") — the range must go forward",
    "Failed to create parent directories for '", "': Failed to create dirs for '",
    "file name contained an unexpected NUL byte", "Failed to read target file '",
    "Invalid append_line ", ": use 0 (beginning), -1 (end), N (after line N), or a line id",
    "Cannot use a line id for append_line on an empty or non-existent target file",
    "Invalid append_line: ", "Insert position ", " exceeds target file length (",
    " lines) in '", "'", "Failed to acquire lock on file history",
    "Failed to write to target file '",
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def magic(value):
    assert len(value) == 8
    return int.from_bytes(value.encode(), "little")


def literal_source():
    rows = ["def message_literal(w: mutbuf, ident: u64) -> u64:", "    at = get(w, 400)"]
    for index, value in enumerate(LITERALS):
        raw = value.encode()
        rows.append(f"    if ident == {index}:")
        offset = 0
        while offset + 8 <= len(raw):
            rows.append(f"        put(w, at + {offset}, {int.from_bytes(raw[offset:offset + 8], 'little')})")
            offset += 8
        while offset < len(raw):
            rows.append(f"        store(w, at + {offset}, {raw[offset]})")
            offset += 1
        rows.extend([f"        put(w, 400, at + {len(raw)})", "        return 1"])
    rows.append("    return 0")
    return "\n".join(rows) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--text-owner", type=Path, required=True)
    parser.add_argument("--body-owner", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    text_raw, body_raw = args.text_owner.read_bytes(), args.body_owner.read_bytes()
    assert sha(text_raw) == TEXT_PIN and sha(body_raw) == BODY_PIN
    text, body = assemble_program(text_raw).as_dict(), assemble_program(body_raw).as_dict()
    originals = {"utf8": (text, "f2"), "load": (text, "f14"), "get": (text, "f15"),
                 "put": (text, "f16"), "decode_scalar": (body, "f37")}
    constants = {"INVALID": 0xffffffff, "CAPACITY": 0xfffffffe, "RESOURCE": 0xfffffffc,
        "WORK_GROW": 0xffffffef, "OUT_GROW": 0xffffffee, "CALL": 0xffffffe0,
        "WAIT": 0xffffffdf, "FIRST_ERROR": 0xffff0000, "MAXIMUM": (1 << 64) - 1,
        "STATE": magic("HEXTRS01"), "REQUEST": magic("HEXTRQ01"), "RESULT": magic("HEXTRP01"),
        "CHILD_CALL": magic("HLTBCAL1"), "CALLBACK": magic("HLTBCQ01"), "WAKE": magic("HLTBWK01"),
        "WAIT_RESULT": magic("HLTBWT01"), "ENDPOINT": magic("HIAEP002"), "ENDPOINT_RESULT": magic("HIAEPR02"),
        "READ": magic("HFLRIO01"), "READ_RESULT": magic("HFLRO001"),
        "KEY": magic("HRLKKEY1"), "KEY_RESULT": magic("HRLKY001"),
        "LOCK": magic("HRFLOCK1"), "LOCK_RESULT": magic("HRFLKR01"),
        "DATA": magic("HEXDATA1"), "SELECT": magic("HEXSEL01"), "VERIFY_REQUEST": magic("HLINE002"), "VERIFY_RESULT": magic("HLINER01"),
        "EDIT_RESULT": magic("HEDRES01"), "PARENT": magic("HSHCPQ01"), "PARENT_RESULT": magic("HSHCPR01"),
        "MKDIR": magic("HSHMKQ01"), "MKDIR_RESULT": magic("HSHMKR01"),
        "HISTORY": magic("HHISTQ01"), "HISTORY_RESULT": magic("HHISTR01"),
        "ATOMIC": magic("HRAWI001"), "ATOMIC_RESULT": magic("HRAWR001"),
        "CACHE": magic("HVCACH01"), "CACHE_RESULT": magic("HVCAR001"), "ERROR": magic("HVERQ001")}

    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load) and node.id in constants:
                return ast.copy_location(ast.Constant(constants[node.id]), node)
            return node

    class BodyBuilder(Builder):
        def expr(self, node):
            if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.FloorDiv)):
                left, right = self.expr(node.left), self.expr(node.right)
                assert left[1] == right[1]
                return self.op("int.rem.checked" if isinstance(node.op, ast.Mod) else "int.div.checked", [left, right], left[1])
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "copy_range":
                    destination, source, at, start, size = [self.expr(a) for a in node.args]
                    positions = [self.cast(v, "usize") for v in (at, start, size)]
                    if destination == source:
                        self.op("buffer.move_within", [destination, *positions])
                    elif source[1] == "mutbuf":
                        loan = self.op("borrow.read", [source], "readbuf")
                        self.op("buffer.copy_range", [destination, loan, *positions])
                        self.op("loan.end", [loan])
                    else:
                        self.op("buffer.copy_range", [destination, source, *positions])
                    return None
                if node.func.id in self.signatures:
                    signature = self.signatures[node.func.id]
                    values = [self.expr(a) for a in node.args]
                    converted, loans = [], []
                    for value, typ in zip(values, signature[0], strict=True):
                        if value[1] == "mutbuf" and typ == "readbuf":
                            value = self.op("borrow.read", [value], "readbuf")
                            loans.append(value)
                        else:
                            value = self.cast(value, typ)
                        converted.append(value)
                    returned = self.op("call", converted, signature[1], function=self.names[node.func.id])
                    for loan in reversed(loans):
                        self.op("loan.end", [loan])
                    return returned
            return super().expr(node)

    pseudo = Path(__file__).with_name("extract_body.pseudo").read_bytes()
    literal = literal_source().encode()
    nodes = [Constants().visit(n) for n in ast.parse(pseudo + b"\n" + literal).body]
    assert all(isinstance(node, ast.FunctionDef) for node in nodes)
    names = {node.name: "f" + str(i) for i, node in enumerate(nodes)}
    names.update({name: "f" + str(len(nodes) + i) for i, name in enumerate(originals)})
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    imported, retained = {}, []
    for alias, (doc, ident) in originals.items():
        old = next(f for f in doc["functions"] if f["name"] == ident)
        assert not any(op["op"] == "call" for block in old["blocks"] for op in block["ops"])
        signatures[alias] = ([p["type"] for p in old["params"]], old["returns"][0])
        actual = copy.deepcopy(old)
        actual["name"] = names[alias]
        retained.append(actual)
        imported[alias] = {"source_sha256": TEXT_PIN if doc is text else BODY_PIN,
            "from": ident, "to": names[alias], "full_graph_sha256": sha(canonical(old))}
    total = total_scalar_functions(nodes)
    new = []
    for node in nodes:
        builder = BodyBuilder(node, names, signatures, total)
        builder.statements(node.body)
        new.append({"name": names[node.name], "params": [builder.param(v) for v in builder.params],
            "returns": [builder.returns], "effects": ["read", "write", "trap"], "entry": "b0", "blocks": builder.blocks})
    temp = {"schema": text["schema"], "module": "extract_body_new", "functions": new + retained}
    new_names = {f["name"] for f in new}
    functions = [f for f in compact_authoring_cfg(temp)["functions"] if f["name"] in new_names] + retained
    document = {"schema": text["schema"], "module": "runtime_local_extract_lines", "functions": functions}
    encoded = render_assembly(document).encode()
    assert assemble_program(encoded).as_dict() == document
    stats = {"functions": len(functions), "blocks": sum(len(f["blocks"]) for f in functions),
             "operations": sum(len(b["ops"]) for f in functions for b in f["blocks"])}
    assert stats["functions"] <= 128 and stats["blocks"] <= 1536 and stats["operations"] <= 8192, stats
    result = {"schema": "hepta.runtime.extract-body-author.v1", "source_bytes": len(encoded),
        "source_sha256": sha(encoded), "author_sha256": sha(Path(__file__).read_bytes()),
        "pseudo_sha256": sha(pseudo), "literal_source_sha256": sha(literal), "aliases": names,
        "imports": imported, "observed_result_inputs": False, "native_executed": False,
        "fresh_target_original_compared": False, "public_handler_qualified": False,
        "full_async_cancellation_qualified": False, "remote_qualified": False, "whole_runtime_replaced": False, **stats}
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "extract_body.hepta").write_bytes(encoded)
    (args.output / "extract_body.proof.json").write_bytes(canonical(result))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

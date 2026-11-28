"""Build the HIA foreground composition; reread proof without executing code.

The HIA packer produces the relocatable bundle. Python records compilation and
fixed assembler/linker invocations, then checks original image bytes, relocation
targets and the complete linked text. It makes no shell lifecycle or IO choice.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import hia_native_build as nb
import hia_native_loader as nl
import hia_native_shell_process_build as process
import hia_native_shell_output_build as output
import hia_native_shell_outcome_build as outcome

DRIVER = "scripts/hia_native_shell_foreground_build.py"
DRIVER_BYTES = Path(__file__).read_bytes()
COMPILER = nb.HEPTA_COMMIT
SCHEMA = "hepta.runtime.shell-foreground.v1"
INPUTS = (
    "native/shell_foreground_controller.hepta", "native/shell_foreground_controller_abi.md",
    "native/shell_foreground_packer.hepta", "native/shell_foreground_layout.json",
    "scripts/shell_foreground_adapter.S", "native/shell_foreground_fixture.md", DRIVER,
    "scripts/hia_native_build.py", "scripts/hia_native_loader.py",
    "scripts/hia_native_shell_process_build.py", "scripts/hia_native_shell_output_build.py",
    "scripts/hia_native_shell_outcome_build.py",
)
SYMBOLS = ("shell_process_entry", "shell_io_entry", "shell_controller_entry")
SCOPE = {"production_activated": False, "production_shell_execution_qualified": False,
         "whole_runtime_replaced": False, "old_stack_removal_qualified": False,
         "matching_source_full_cold_qualified": False,
         "actual_native_process_wait_qualified_by_build": False}
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
ordinary, strict_json, sha, pin, member = (
    process.ordinary, process.strict_json, process.sha, process.pin, process.member)


def need(value, message):
    if not value:
        raise ValueError(message)


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def align(value, boundary=16):
    return (value + boundary - 1) & -boundary


def sources(root):
    values = {name: ordinary(root / name) for name in INPUTS}
    need(values[DRIVER] == DRIVER_BYTES, "executing foreground builder source changed")
    for module, name in ((nb, "hia_native_build"), (nl, "hia_native_loader"),
                         (process, "hia_native_shell_process_build"),
                         (output, "hia_native_shell_output_build"),
                         (outcome, "hia_native_shell_outcome_build")):
        need(ordinary(Path(module.__file__).absolute()) == values["scripts/" + name + ".py"],
             "imported foreground build dependency differs: " + name)
    return values


def elf(raw, kind):
    need(len(raw) >= 64 and raw[:16] == b"\x7fELF\x02\x01\x01" + bytes(9), "ELF64 LE identity")
    h = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
    need(h[0:3] == (kind, 62, 1) and h[6] == 0 and h[7] == 64 and h[10] == 64
         and 0 < h[11] <= 4096 and h[5] <= len(raw) - 64 * h[11]
         and 0 <= h[12] < h[11], "ELF target and section headers")
    sections = [struct.unpack_from("<IIQQQQIIQQ", raw, h[5] + i * 64) for i in range(h[11])]
    need(sections[0] == (0,) * 10, "ELF null section")
    for s in sections:
        need(s[1] == 8 or s[4] <= len(raw) and s[5] <= len(raw) - s[4], "ELF section extent")
    names_section = sections[h[12]]
    need(names_section[1] == 3, "ELF section strings")
    names = raw[names_section[4]:names_section[4] + names_section[5]]

    def string(table, offset):
        need(0 <= offset < len(table), "ELF string offset")
        end = table.find(b"\0", offset)
        need(end >= 0, "ELF terminated string")
        return table[offset:end].decode("ascii")

    labels = [string(names, s[0]) for s in sections]
    need(len(set(labels)) == len(labels), "ELF duplicate section name")
    tables = {}
    for i, s in enumerate(sections):
        if s[1] not in (2, 11):
            continue
        need(s[9] == 24 and s[5] % 24 == 0 and 0 <= s[6] < len(sections), "ELF symbol layout")
        st = sections[s[6]]
        need(st[1] == 3, "ELF symbol strings")
        strings = raw[st[4]:st[4] + st[5]]
        rows = []
        for offset in range(s[4], s[4] + s[5], 24):
            row = struct.unpack_from("<IBBHQQ", raw, offset)
            rows.append({"name": string(strings, row[0]), "info": row[1], "other": row[2],
                         "index": row[3], "value": row[4], "size": row[5]})
        tables[i] = rows
    programs = []
    if kind == 1:
        need(h[3] == h[4] == h[9] == 0 and h[8] == 0, "relocatable program header shape")
    else:
        need(h[8] == 56 and 0 < h[9] <= 128 and h[4] <= len(raw) - h[9] * 56,
             "ELF program headers")
        programs = [struct.unpack_from("<IIQQQQQQ", raw, h[4] + i * 56) for i in range(h[9])]
    return {"header": h, "sections": sections, "names": labels, "symbols": tables,
            "programs": programs, "string": string}


def section(view, name):
    need(name in view["names"], "missing ELF section: " + name)
    index = view["names"].index(name)
    return index, view["sections"][index]


def contents(raw, value):
    need(value[1] != 8, "NOBITS has no file bytes")
    return raw[value[4]:value[4] + value[5]]


def relocation_signature(raw):
    view = elf(raw, 1)
    text_index, _ = section(view, ".text")
    rows = []
    for table in view["sections"]:
        if table[1] not in (4, 9):
            continue
        need(table[1] == 4 and table[7] == text_index and table[9] == 24 and
             table[5] % 24 == 0 and table[6] in view["symbols"], "source-owned adapter relocation layout")
        symbols = view["symbols"][table[6]]
        for offset in range(table[4], table[4] + table[5], 24):
            at, info, addend = struct.unpack_from("<QQq", raw, offset)
            index = info >> 32
            need(index < len(symbols), "source-owned adapter relocation symbol")
            rows.append({"offset": at, "kind": info & 0xffffffff,
                         "symbol": symbols[index]["name"], "addend": addend})
    return rows


def adapter_entry(raw):
    view = elf(raw, 1)
    text_index, text = section(view, ".text")
    tables = [i for i, s in enumerate(view["sections"]) if s[1] == 2]
    need(len(tables) == 1, "source-owned adapter static symbol table")
    entries = [s for s in view["symbols"][tables[0]] if s["name"] == "_start"]
    need(len(entries) == 1 and entries[0]["info"] >> 4 == 1 and
         entries[0]["info"] & 15 in (0, 2) and entries[0]["other"] == 0 and
         entries[0]["index"] == text_index and entries[0]["value"] < text[5],
         "source-owned adapter unique executable entry")
    return entries[0]["value"]


def bundle_geometry(images):
    a = 0
    b = align(len(images[0]))
    c = align(b + len(images[1]))
    size = align(c + len(images[2]))
    symoff = align(64 + size, 8)
    stroff = symoff + 96
    nameoff = stroff + 59
    shoff = align(nameoff + 33, 8)
    return (a, b, c), size, symoff, stroff, nameoff, shoff, shoff + 320


def verify_bundle(raw, images):
    positions, size, symoff, stroff, nameoff, shoff, total = bundle_geometry(images)
    view = elf(raw, 1)
    need(len(raw) == total and view["header"] ==
         (1, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 5, 4), "bundle complete header geometry")
    expected_sections = [
        (0,) * 10,
        (1, 1, 6, 0, 64, size, 0, 0, 16, 0),
        (7, 2, 0, 0, symoff, 96, 3, 1, 8, 24),
        (15, 3, 0, 0, stroff, 59, 0, 0, 1, 0),
        (23, 3, 0, 0, nameoff, 33, 0, 0, 1, 0),
    ]
    need(view["sections"] == expected_sections, "bundle full section table")
    text = bytearray(size)
    for at, image in zip(positions, images):
        text[at:at + len(image)] = image
    need(raw[64:64 + size] == text, "bundle three complete images and zero alignment")
    names = b"\0" + b"\0".join(x.encode() for x in SYMBOLS) + b"\0"
    need(len(names) == 59 and raw[stroff:stroff + 59] == names and
         raw[nameoff:nameoff + 33] == b"\0.text\0.symtab\0.strtab\0.shstrtab\0", "bundle symbol strings")
    expected = bytes(24) + b"".join(struct.pack("<IBBHQQ", name, 0x12, 0, 1, at, len(image))
                                   for name, at, image in zip((1, 21, 36), positions, images))
    need(raw[symoff:symoff + 96] == expected and
         raw[64 + size:symoff] == bytes(symoff - 64 - size) and
         raw[nameoff + 33:shoff] == bytes(shoff - nameoff - 33), "bundle complete symbols/padding")
    return {"bytes": len(raw), "sha256": sha(raw), "text_bytes": size,
            "symbols": [{"name": name, "offset": at, "bytes": len(image), "sha256": sha(image)}
                        for name, at, image in zip(SYMBOLS, positions, images)]}


def packer_cases(images):
    wire = b"HSHFGPK1" + struct.pack("<4Q", 3, *(len(x) for x in images)) + b"".join(images)
    total = bundle_geometry(images)[-1]
    cases = [("success", wire, total + 37, total),
             ("short-header", wire[:39], total + 37, 0xffffffff),
             ("bad-magic", b"X" + wire[1:], total + 37, 0xffffffff),
             ("bad-count", wire[:8] + struct.pack("<Q", 2) + wire[16:], total + 37, 0xffffffff),
             ("length-mismatch", wire[:16] + struct.pack("<Q", len(images[0]) + 1) + wire[24:],
              total + 37, 0xffffffff),
             ("trailing-byte", wire + b"x", total + 37, 0xffffffff),
             ("short-output", wire, total - 1, 0xfffffffe)]
    for i in range(3):
        start = 16 + 8 * i
        cases.append(("zero-image-" + str(i), wire[:start] + bytes(8) + wire[start + 8:],
                      total + 37, 0xffffffff))
    cases.append(("oversized-image", wire[:16] + struct.pack("<Q", 0xffffffffffffffff) + wire[24:],
                  total + 37, 0xfffffffe))
    return cases


def native_component(path, source, compiler_sha):
    raw = ordinary(path)
    value = strict_json(raw)
    need(value.get("schema") == "hepta.runtime.native-module.v1" and
         value.get("abi") == nb.ABI and value.get("target") == "linux-x86_64" and
         value.get("compiler_commit") == COMPILER and value.get("compiler_sha256") == compiler_sha and
         value.get("standalone") is None and value.get("qualification") == "development_fixed_point",
         "foreground native component identity")
    need(ordinary(member(path.parent, value["source"])) == source and value["source_sha256"] == sha(source),
         "foreground native component source")
    image = ordinary(member(path.parent, value["image"]))
    need(image and not image.startswith(b"\x7fELF") and value["image_sha256"] == sha(image),
         "foreground native component image")
    need(all(integer(value.get(k), 1) for k in ("input_capacity", "output_capacity", "workspace_capacity")),
         "foreground native component capacities")
    built = strict_json(ordinary(path.parent / "build.json"))
    receipt = strict_json(ordinary(path.parent / "module.receipt.json"))
    need(receipt == built["compile_receipt"], "foreground compiler receipt copies differ")
    actual_input = ordinary(path.parent / "module.input.bin")
    actual_output = ordinary(path.parent / "module.output.bin")
    need(actual_input == source and receipt.get("status") == "returned" and
         type(receipt.get("abi_status")) is int and receipt["abi_status"] == 0 and
         type(receipt.get("core_u32")) is int and receipt["core_u32"] == len(image) and
         type(receipt.get("result_u64")) is int and receipt["result_u64"] == len(image) and
         receipt.get("source_unchanged") is True and receipt.get("forbidden_compiler_modules_loaded") == [] and
         receipt.get("input_bytes") == len(source) and receipt.get("input_sha256") == sha(source) and
         receipt.get("artifact_sha256") == compiler_sha and receipt.get("image_sha256") == compiler_sha and
         receipt.get("format") == "flat-x86-64" and receipt.get("produced_bytes") == len(image) and
         receipt.get("produced_sha256") == sha(image) and receipt.get("output_sha256") == sha(actual_output) and
         actual_output[:len(image)] == image, "foreground actual compiler invocation")
    boot = path.parent.parent.parent / "bootstrap"
    bootstrap = strict_json(ordinary(boot / "bootstrap.json"))
    need(bootstrap.get("schema") == "hepta.runtime.native-bootstrap.v1" and
         bootstrap.get("qualification") == "development_fixed_point" and
         bootstrap.get("matching_source_cold_qualified") is False and
         bootstrap.get("dependency") == built.get("compiler_dependency") and
         bootstrap["dependency"].get("commit") == COMPILER and
         bootstrap["dependency"].get("tree") == nb.HEPTA_TREE and
         bootstrap.get("generation_sha256") == compiler_sha,
         "foreground matching compiler fixed point")
    for label in ("B1", "B2", "B3"):
        need(sha(ordinary(boot / (label + ".image.bin"))) == compiler_sha, "foreground compiler generation bytes")
    return value, image


def component_binding(label, path, root):
    path = Path(path).absolute()
    raw = ordinary(path)
    value = strict_json(raw)
    if label == "process":
        evidence = process.read_evidence(path)
        sealed = path.parent / "source-snapshots"
        for name in process.INPUTS + process.PRODUCERS:
            need(ordinary(root / name) == ordinary(sealed / name), "current process component source changed")
        proof = strict_json(ordinary(path.parent / value["build_evidence"]))
        need(proof["producer_folder"] == str(path.parent), "process component relocated")
    elif label == "output":
        evidence = output.read_evidence(path, source_root=root)
    else:
        evidence = outcome.read_evidence(path, source_root=root)
        need(value["recorded_directory"] == str(path.parent) and value["recorded_source_root"] == str(root),
             "outcome component relocated")
    need(evidence.get("status") == "PASS" and value.get("compiler_commit") == COMPILER,
         "foreground component strong evidence")
    return {"path": str(path), **pin(path), "evidence": evidence}, value


def run_tool(folder, label, tool_name, arguments, inputs, outputs):
    selected = shutil.which(tool_name, path=ENVIRONMENT["PATH"])
    need(selected is not None, "missing build tool " + tool_name)
    tool = Path(selected).resolve(strict=True)
    binary = ordinary(tool)
    write = nb.write_new
    write(folder / ("tools/" + label + ".tool.bin"), binary)
    before = {name: pin(member(folder, name)) for name in inputs}
    command = [str(tool), *arguments]
    started = time.time_ns()
    clock = time.monotonic_ns()
    child = None
    stdout = stderr = b""
    timed_out = False
    error = None
    try:
        child = subprocess.Popen(command, cwd=folder, env=ENVIRONMENT, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = child.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            timed_out = True
            child.kill()
            stdout, stderr = child.communicate(timeout=5)
    except Exception as exc:
        error = type(exc).__name__ + ": " + str(exc)
    row = {"schema": "hepta.runtime.shell-foreground-tool.v1", "label": label,
           "tool": str(tool), "argv": command, "cwd": str(folder), "environment": ENVIRONMENT,
           "pid": child.pid if child else None, "started_unix_ns": started,
           "finished_unix_ns": time.time_ns(), "elapsed_ns": time.monotonic_ns() - clock,
           "timeout_seconds": 30, "timed_out": timed_out, "error": error,
           "exit_code": child.returncode if child else None, "tool_before": pin(folder / ("tools/" + label + ".tool.bin")),
           "tool_after": pin(tool), "inputs_before": before,
           "inputs_after": {name: pin(member(folder, name)) for name in inputs},
           "outputs": {name: pin(member(folder, name)) for name in outputs if member(folder, name).exists()}}
    for name, raw in (("stdout", stdout), ("stderr", stderr)):
        write(folder / ("tools/" + label + "." + name), raw)
        row[name] = pin(folder / ("tools/" + label + "." + name))
    write(folder / ("tools/" + label + ".json"), nb.json_bytes(row))
    need(row["exit_code"] == 0 and not timed_out and error is None and row["tool_before"] == row["tool_after"]
         and before == row["inputs_after"] and set(row["outputs"]) == set(outputs),
         "foreground build tool failed; complete receipt retained: " + label)


def tool_specs(folder, interpreter):
    return (
        ("assemble", "as", ["--64", "-o", str(folder / "adapter.o"),
                            str(folder / "source-snapshots/scripts/shell_foreground_adapter.S")],
         ["source-snapshots/scripts/shell_foreground_adapter.S"], ["adapter.o"]),
        ("adapter-text", "objcopy", ["-O", "binary", "-j", ".text", str(folder / "adapter.o"),
                                      str(folder / "adapter.text.bin")], ["adapter.o"], ["adapter.text.bin"]),
        ("link", "ld", ["-m", "elf_x86_64", "-e", "_start", "-z", "noexecstack", "-z", "relro",
                         "-z", "now", "--no-undefined", "--dynamic-linker", interpreter,
                         str(folder / "adapter.o"), str(folder / "bundle.o"), str(folder / "outcome.o"),
                         str(folder / "allocator-libc.so.6"), "-o", str(folder / "shell-foreground.elf")],
         ["adapter.o", "bundle.o", "outcome.o", "allocator-libc.so.6"], ["shell-foreground.elf"]),
        ("linked-text", "objcopy", ["-O", "binary", "-j", ".text", str(folder / "shell-foreground.elf"),
                                     str(folder / "linked.text.bin")], ["shell-foreground.elf"], ["linked.text.bin"]),
    )


def read_tool(folder, spec):
    label, name, arguments, inputs, outputs = spec
    row = strict_json(ordinary(folder / ("tools/" + label + ".json")))
    tool = Path(row["tool"])
    expected_tool = Path("/usr/bin") / name
    need(tool.is_absolute() and tool == expected_tool.resolve(strict=True) and
         row.get("schema") == "hepta.runtime.shell-foreground-tool.v1" and
         row.get("label") == label and row.get("argv") == [str(tool), *arguments] and
         row.get("cwd") == str(folder) and row.get("environment") == ENVIRONMENT and
         integer(row.get("pid"), 1) and type(row.get("exit_code")) is int and row["exit_code"] == 0 and
         row.get("timed_out") is False and row.get("error") is None and
         row.get("timeout_seconds") == 30 and integer(row.get("elapsed_ns")) and
         row["elapsed_ns"] <= 35_000_000_000 and integer(row.get("started_unix_ns"), 1) and
         integer(row.get("finished_unix_ns"), row["started_unix_ns"]), "foreground exact tool process: " + label)
    need(row["tool_before"] == row["tool_after"] == pin(tool) == pin(folder / ("tools/" + label + ".tool.bin")) and
         row["inputs_before"] == row["inputs_after"] == {n: pin(member(folder, n)) for n in inputs} and
         row["outputs"] == {n: pin(member(folder, n)) for n in outputs}, "foreground tool/file bytes: " + label)
    for stream in ("stdout", "stderr"):
        need(row[stream] == pin(folder / ("tools/" + label + "." + stream)), "complete foreground tool stream")
    return row


def dynamic_view(raw, view, interpreter):
    ss, ps = view["sections"], view["programs"]
    loads = [p for p in ps if p[0] == 1]
    need(loads, "linked load segments")
    for p in ps:
        need(p[2] <= len(raw) and p[5] <= len(raw) - p[2] and p[5] <= p[6] and
             p[3] <= (1 << 64) - 1 - p[6], "linked segment extent")
    ranges = sorted((p[3], p[3] + p[6]) for p in loads if p[6])
    need(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), "overlapping linked load byte extents")
    for p in loads:
        need(p[1] & ~7 == 0 and p[1] & 4 and p[1] & 3 != 3 and
             p[5] == p[6] and
             (p[3] - p[2]) % 4096 == 0 and
             (p[7] in (0, 1) or p[7] & (p[7] - 1) == 0 and (p[3] - p[2]) % p[7] == 0),
             "linked load permission/alignment")
    # This composition has no allocated BSS: every input object's only allocated
    # bytes are its text. Linux maps PT_LOAD at base-page granularity, so disjoint
    # byte extents alone do not prevent a later mapping from replacing code.
    for axis, label in ((3, "virtual"), (2, "file")):
        pages = sorted((p[axis] & -4096, align(p[axis] + p[5], 4096))
                       for p in loads if p[5])
        need(all(a[1] <= b[0] for a, b in zip(pages, pages[1:])),
             "linked overlapping or aliased PT_LOAD " + label + " pages")
    def mapped(s, executable=False):
        hits = [p for p in loads if p[3] <= s[3] and s[3] - p[3] + s[5] <= p[5]
                and s[3] - p[3] + s[5] <= p[6]]
        need(s[2] & 2 and len(hits) == 1 and hits[0][2] + s[3] - hits[0][3] == s[4],
             "linked section actual load mapping")
        need(not executable or hits[0][1] == 5, "linked code must map uniquely into a read/execute load")
        return s
    interpreters = [p for p in ps if p[0] == 3]
    need(len(interpreters) == 1 and raw[interpreters[0][2]:interpreters[0][2] + interpreters[0][5]] ==
         os.fsencode(interpreter) + b"\0", "actual pinned ELF interpreter")
    stacks = [p for p in ps if p[0] == 0x6474e551]
    need(len(stacks) == 1 and stacks[0][1] == 6, "non-executable linked stack")
    need(all(p[0] in (1, 2, 3, 4, 6, 0x6474e550, 0x6474e551, 0x6474e552) for p in ps),
         "linked program capability inventory")
    _, code = section(view, ".text"); mapped(code, True)
    _, trampoline = section(view, ".plt"); mapped(trampoline, True)
    entry = view["header"][3]
    entries = [p for p in loads if p[3] <= entry < p[3] + p[5] and entry < p[3] + p[6]]
    need(code[3] <= entry < code[3] + code[5] and len(entries) == 1 and entries[0][1] == 5 and
         entries[0][2] + entry - entries[0][3] == code[4] + entry - code[3],
         "linked actual entry must map to admitted executable text")
    _, ds = section(view, ".dynamic"); mapped(ds)
    dp = [p for p in ps if p[0] == 2]
    need(len(dp) == 1 and (dp[0][2], dp[0][3], dp[0][5], dp[0][6]) ==
         (ds[4], ds[3], ds[5], ds[5]) and ds[9] == 16 and ds[5] % 16 == 0,
         "linked PT_DYNAMIC/section identity")
    tags = {}; ended = False
    allowed = {1, 2, 3, 4, 5, 6, 10, 11, 20, 21, 23, 24, 30,
               0x6ffffef5, 0x6ffffff0, 0x6ffffffb, 0x6ffffffe, 0x6fffffff}
    for at in range(ds[4], ds[4] + ds[5], 16):
        tag, value = struct.unpack_from("<qQ", raw, at)
        if ended or not tag:
            need(tag == value == 0, "linked dynamic null padding"); ended = True; continue
        need(tag in allowed and tag not in tags, "linked extra dynamic capability")
        tags[tag] = value
    need(ended and tags.get(30, 0) & ~8 == 0 and tags.get(0x6ffffffb, 0) & ~1 == 0 and
         tags.get(21, 0) == 0 and tags.get(24, 0) == 0 and
         (24 in tags or tags.get(30, 0) & 8 or tags.get(0x6ffffffb, 0) & 1), "linked eager dynamic binding")
    dyn_indices = [i for i, s in enumerate(ss) if s[1] == 11]
    need(len(dyn_indices) == 1, "linked unique dynamic symbols")
    di = dyn_indices[0]; syms = view["symbols"][di]; sym = mapped(ss[di]); strings = mapped(ss[sym[6]])
    need(len(syms) == 3 and sorted(x["name"] for x in syms) == ["", "calloc", "free"] and
         syms[0] == {"name": "", "info": 0, "other": 0, "index": 0, "value": 0, "size": 0} and
         all(x["index"] == x["other"] == x["value"] == x["size"] == 0 and
             x["info"] >> 4 == 1 and x["info"] & 15 in (0, 2) for x in syms[1:]),
         "linked allocator-only dynamic imports")
    need(tags.get(6) == sym[3] and tags.get(11) == sym[9] == 24 and
         tags.get(5) == strings[3] and tags.get(10) == strings[5] and ds[6] == sym[6],
         "linked actual dynamic symbol/string pointers")
    strraw = contents(raw, strings)
    need(1 in tags and view["string"](strraw, tags[1]) == "libc.so.6", "linked exact libc dependency")
    hashes = []
    for tag, typ in ((4, 5), (0x6ffffef5, 0x6ffffff6)):
        hits = [s for s in ss if s[1] == typ and s[2] & 2]
        need(len(hits) == (1 if tag in tags else 0), "linked hash inventory")
        if not hits: continue
        hs = mapped(hits[0]); need(tags[tag] == hs[3] and hs[6] == di, "linked hash actual pointer")
        b = contents(raw, hs)
        if tag == 4:
            need(len(b) >= 8, "SYSV hash header"); count, chains = struct.unpack_from("<II", b)
            need(count > 0 and chains == len(syms) and len(b) == 8 + 4 * (count + chains), "SYSV hash extent")
            numbers = struct.unpack_from("<" + "I" * (count + chains), b, 8)
            need(all(n < chains for n in numbers), "SYSV hash bounds")
            for at in numbers[:count]:
                seen = set()
                while at:
                    need(at not in seen, "SYSV hash cycle"); seen.add(at); at = numbers[count + at]
        else:
            need(len(b) >= 16, "GNU hash header"); buckets, first, blooms, shift = struct.unpack_from("<IIII", b)
            need(buckets > 0 and blooms > 0 and blooms & (blooms - 1) == 0 and
                 0 < first <= len(syms) and shift < 64 and
                 len(b) == 16 + 8 * blooms + 4 * buckets and not any(b[16:]),
                 "GNU hash must be empty for this import-only dynamic symbol table")
        hashes.append(tag)
    need(hashes, "linked symbol hash inventory")
    for tag, typ in ((0x6ffffff0, 0x6fffffff), (0x6ffffffe, 0x6ffffffe)):
        hits = [s for s in ss if s[1] == typ]
        need(len(hits) == 1 and tags.get(tag) == mapped(hits[0])[3], "linked actual version pointer")
    vs = next(s for s in ss if s[1] == 0x6fffffff)
    vn = next(s for s in ss if s[1] == 0x6ffffffe)
    need(vs[6] == di and vs[5] == 2 * len(syms) and vn[6] == sym[6] and
         tags.get(0x6fffffff) == vn[7] == 1 and vn[5] >= 16, "linked version table layout")
    ver, count, filename, aux, following = struct.unpack_from("<HHIII", raw, vn[4])
    need(ver == 1 and 0 < count <= 2 and following == 0 and aux >= 16 and
         view["string"](strraw, filename) == "libc.so.6", "linked version dependency")
    ordinals = set(); visited = set()
    for i in range(count):
        need(16 <= aux <= vn[5] - 16 and not visited.intersection(range(aux, aux + 16)), "linked version extent")
        visited.update(range(aux, aux + 16))
        vh, flags, ordinal, name, nxt = struct.unpack_from("<IHHII", raw, vn[4] + aux)
        need(flags == 0 and 1 < ordinal < 0x8000 and ordinal not in ordinals and
             re.fullmatch(r"GLIBC_[0-9]+(?:\.[0-9]+)+", view["string"](strraw, name)), "linked allocator version")
        ordinals.add(ordinal)
        need((i == count - 1 and nxt == 0) or (i < count - 1 and nxt >= 16), "linked version chain")
        aux += nxt
    versions = struct.unpack_from("<3H", raw, vs[4])
    need(versions[0] == 0 and set(versions[1:]) == ordinals, "linked symbol version indices")
    _, rela = section(view, ".rela.plt"); mapped(rela)
    need(rela[1] == 4 and rela[6] == di and rela[9] == 24 and rela[5] == 48 and
         tags.get(23) == rela[3] and tags.get(2) == 48 and tags.get(20) == 7,
         "linked complete JMPREL table")
    got = mapped(ss[rela[7]])
    need(got[1] == 1 and got[2] & 1 and got[3] == tags.get(3) and got[5] == 40,
         "linked actual allocator GOT")
    _, plt = section(view, ".plt"); mapped(plt, True)
    need(plt[5] == 48 and plt[2] == 6, "linked fixed x86 PLT shape")
    expected = bytearray(b"\xff\x35" + struct.pack("<i", got[3] + 8 - plt[3] - 6) +
                         b"\xff\x25" + struct.pack("<i", got[3] + 16 - plt[3] - 12) + b"\x0f\x1f\x40\x00")
    addresses = {}; targets = []
    for i in range(2):
        target, info, addend = struct.unpack_from("<QQq", raw, rela[4] + 24 * i)
        ordinal, typ = info >> 32, info & 0xffffffff
        need(typ == 7 and 0 < ordinal < len(syms) and addend == 0 and
             target == got[3] + 24 + 8 * i and syms[ordinal]["name"] not in addresses,
             "linked allocator-only JUMP_SLOT")
        pos = plt[3] + 16 * (i + 1)
        expected.extend(b"\xff\x25" + struct.pack("<i", target - pos - 6) +
                        b"\x68" + struct.pack("<I", i) + b"\xe9" + struct.pack("<i", plt[3] - pos - 16))
        addresses[syms[ordinal]["name"]] = pos; targets.append(target)
    need(contents(raw, plt) == expected and set(addresses) == {"calloc", "free"}, "complete allocator PLT bytes")
    need([s for s in ss if s[1] in (4, 9, 19) and s[2] & 2 and s[5]] == [rela],
         "linked additional runtime relocations")
    return addresses, {"needed": ["libc.so.6"], "imports": sorted(addresses), "dynamic_tags": sorted(tags),
                       "interpreter": interpreter, "hash_tables": hashes, "plt_bytes": len(expected)}


def linked_text(raw, objects, interpreter):
    final = elf(raw, 2)
    plt, dynamic = dynamic_view(raw, final, interpreter)
    ti, ts = section(final, ".text")
    need(ts[1] == 1 and ts[2] == 6 and ts[8] == 16, "linked text layout")
    static_indices = [i for i, s in enumerate(final["sections"]) if s[1] == 2]
    need(len(static_indices) == 1, "linked complete static symbol table")
    final_symbols = final["symbols"][static_indices[0]]
    globals_final = {s["name"]: s for s in final_symbols if s["info"] >> 4 == 1 and s["index"] != 0}
    need("_start" in globals_final and final["header"][3] == globals_final["_start"]["value"], "linked actual entry")
    blocks = []; definitions = {}
    for label, original in objects:
        view = elf(original, 1); index, text = section(view, ".text")
        need(text[1] == 1 and text[2] == 6 and text[8] <= 16 and text[8] > 0 and
             all(not s[2] & 2 or i == index or s[5] == 0 for i, s in enumerate(view["sections"])),
             "input object has an unexpected allocated section")
        symbol_indices = [i for i, s in enumerate(view["sections"]) if s[1] == 2]
        need(len(symbol_indices) == 1, "input object symbol table")
        si = symbol_indices[0]; symbols = view["symbols"][si]
        anchor = {"adapter": "_start", "bundle": SYMBOLS[0], "outcome": "f0"}[label]
        own = [s for s in symbols if s["name"] == anchor and s["index"] == index]
        need(len(own) == 1 and anchor in globals_final, "linked object anchor: " + label)
        base = globals_final[anchor]["value"] - own[0]["value"]
        for s in symbols:
            if s["info"] >> 4 == 1 and s["index"] != 0:
                need(s["index"] == index and s["name"] not in definitions, "input global definition inventory")
                definitions[s["name"]] = base + s["value"]
                need(s["name"] in globals_final and globals_final[s["name"]]["value"] == base + s["value"] and
                     globals_final[s["name"]]["size"] == s["size"], "linked global definition differs")
        blocks.append((label, original, view, index, text, si, symbols, base))
    need(set(definitions) == {"_start", *SYMBOLS, "f0"}, "foreground code entry inventory")
    expected = bytearray(); relocation_rows = []
    for label, original, view, index, text, si, symbols, base in blocks:
        need(base == ts[3] + len(expected), "foreground whole text has an unbound gap or reorder")
        body = bytearray(contents(original, text)); occupied = set()
        for rel in view["sections"]:
            if rel[1] not in (4, 9): continue
            need(rel[1] == 4 and rel[6] == si and rel[7] == index and rel[9] == 24 and rel[5] % 24 == 0,
                 "foreground input relocation table")
            for at in range(rel[4], rel[4] + rel[5], 24):
                offset, info, addend = struct.unpack_from("<QQq", original, at)
                ordinal, typ = info >> 32, info & 0xffffffff
                need(typ == 4 and ordinal < len(symbols) and offset <= len(body) - 4 and
                     not occupied.intersection(range(offset, offset + 4)), "foreground PLT32 relocation")
                occupied.update(range(offset, offset + 4)); symbol = symbols[ordinal]
                if symbol["index"] == 0:
                    name = symbol["name"]
                    need(name in definitions or name in plt, "foreground unresolved capability")
                    target = definitions[name] if name in definitions else plt[name]
                else:
                    need(symbol["index"] == index, "foreground relocated non-text symbol")
                    target = base + symbol["value"]
                value = target + addend - base - offset
                need(-(1 << 31) <= value < (1 << 31), "foreground rel32 range")
                struct.pack_into("<i", body, offset, value)
                relocation_rows.append({"object": label, "offset": offset, "symbol": symbol["name"],
                                        "addend": addend, "target": target, "value": value})
        if label != "outcome":
            need(len(body) % 16 == 0, "explicit input text alignment is missing")
        expected.extend(body)
    need(contents(raw, ts) == expected, "entire linked text differs from sealed input objects and relocations")
    need({name for name, s in zip(final["names"], final["sections"]) if s[2] & 4 and s[5]} == {".plt", ".text"},
         "extra executable ELF section")
    _, ps = section(final, ".plt")
    for program in final["programs"]:
        if program[0] != 1 or not program[1] & 1: continue
        verified = bytearray(program[5])
        covered = bytearray(program[5])
        for s in (ps, ts):
            if program[3] <= s[3] and s[3] + s[5] <= program[3] + program[5]:
                at = s[3] - program[3]; verified[at:at + s[5]] = contents(raw, s); covered[at:at + s[5]] = b"\1" * s[5]
        need(raw[program[2]:program[2] + program[5]] == verified, "unbound executable load bytes")
    return {"text_sha256": sha(bytes(expected)), "text_bytes": len(expected), "entry": final["header"][3],
            "object_order": [x[0] for x in objects], "relocations": relocation_rows, "dynamic": dynamic}


def interpreter_path():
    raw = ordinary(Path(sys.executable).resolve(strict=True))
    kind = struct.unpack_from("<H", raw, 16)[0]
    view = elf(raw, kind)
    rows = [p for p in view["programs"] if p[0] == 3]
    need(len(rows) == 1, "actual host interpreter declaration")
    p = rows[0]; value = raw[p[2]:p[2] + p[5]]
    need(value.endswith(b"\0") and b"\0" not in value[:-1], "actual host interpreter path")
    return Path(os.fsdecode(value[:-1])).resolve(strict=True)


def read_packer(folder, metadata, packer, images, bundle):
    cases = packer_cases(images)
    for name, wire, capacity, returned in cases:
        case = folder / "packer" / name
        row = strict_json(ordinary(case / "invocation.json"))
        files = {label + "." + when + ".bin" for label in ("input", "output", "workspace", "guards")
                 for when in ("before", "after")}
        need(row.get("schema") == "hepta.runtime.shell-process-packer-invocation.v1" and row.get("status") == "PASS"
             and row.get("name") == name and row.get("manifest_sha256") == metadata["packer_manifest_sha256"] and
             row.get("source_sha256") == packer["source_sha256"] and row.get("image_sha256") == packer["image_sha256"] and
             type(row.get("returned")) is int and row["returned"] == returned and row.get("expected_return") == returned and
             row.get("input_capacity") == len(wire) and row.get("output_capacity") == capacity and
             row.get("workspace_capacity") == 4096 and row.get("exception") is None and
             integer(row.get("started_ns")) and integer(row.get("finished_ns"), row["started_ns"]) and
             row.get("duration_ns") == row["finished_ns"] - row["started_ns"] and set(row.get("files", {})) == files and
             all(row.get(k) is True for k in ("input_and_workspace_unchanged", "guards_unchanged", "output_tail_or_refusal_unchanged")),
             "actual foreground HIA packer invocation differs: " + name)
        for filename, expected in row["files"].items():
            need(pin(case / filename) == expected, "foreground packer full buffer pin")
        expected_output = bundle + b"\xa7" * 37 if name == "success" else b"\xa7" * capacity
        need(ordinary(case / "input.before.bin") == ordinary(case / "input.after.bin") == wire and
             ordinary(case / "output.before.bin") == b"\xa7" * capacity and
             ordinary(case / "output.after.bin") == expected_output and
             ordinary(case / "workspace.before.bin") == ordinary(case / "workspace.after.bin") == b"\x5c" * 4096 and
             ordinary(case / "guards.before.bin") == ordinary(case / "guards.after.bin") == process.GUARDS,
             "foreground packer complete arrays/refusal differ: " + name)
    return len(cases)


def read_evidence(manifest, *, source_root=ROOT):
    manifest = Path(manifest).absolute(); raw = ordinary(manifest); metadata = strict_json(raw)
    folder = manifest.parent; root = Path(source_root).absolute(); sealed = sources(root)
    need(metadata.get("schema") == SCHEMA and metadata.get("target") == "linux-x86_64" and
         metadata.get("compiler_commit") == COMPILER and metadata.get("elf") == "shell-foreground.elf" and
         metadata.get("recorded_directory") == str(folder) and metadata.get("recorded_source_root") == str(root) and
         metadata.get("runtime_python_required") is False and metadata.get("runtime_libc_required") is True and
         all(metadata.get(k) is v for k, v in SCOPE.items()), "foreground build identity/scope")
    evidence = strict_json(ordinary(folder / "build-evidence.json"))
    need(evidence.get("schema") == SCHEMA + ".build" and evidence.get("status") == "PASS" and
         evidence.get("error") is None and
         metadata.get("build_evidence_sha256") == sha(ordinary(folder / "build-evidence.json")) and
         evidence.get("sources") == {n: {"size": len(b), "sha256": sha(b)} for n, b in sealed.items()},
         "foreground complete source evidence")
    for name, data in sealed.items():
        need(ordinary(member(folder / "source-snapshots", name)) == data, "sealed foreground source bytes")
    bindings = {}; components = {}
    for name in ("process", "output", "outcome"):
        selected = Path(metadata[name + "_manifest"])
        need(selected.is_absolute(), "foreground component manifest must be explicitly absolute")
        binding, value = component_binding(name, selected, root)
        need(metadata[name + "_manifest_sha256"] == binding["sha256"] and
             value["compiler_sha256"] == metadata["compiler_sha256"], "foreground same-compiler component binding")
        bindings[name] = binding; components[name] = value
    need(evidence.get("components") == bindings, "foreground component evidence changed")
    generated = {}
    for name, source in (("controller", "native/shell_foreground_controller.hepta"),
                         ("packer", "native/shell_foreground_packer.hepta")):
        path = member(folder.parent, metadata[name + "_manifest"])
        need(sha(ordinary(path)) == metadata[name + "_manifest_sha256"], "foreground generated manifest changed")
        generated[name] = native_component(path, sealed[source], metadata["compiler_sha256"])
        need(metadata.get(name + "_source_sha256") == generated[name][0]["source_sha256"] and
             metadata.get(name + "_image_sha256") == sha(generated[name][1]),
             "foreground generated source/image scalar binding")
    images = []
    for name, source in (("process", "native/shell_process.hepta"), ("output", "native/shell_output_io.hepta")):
        parent = Path(metadata[name + "_manifest"]).parent
        cp = member(parent.parent, components[name]["owner_manifest"])
        _, image = native_component(cp, ordinary(root / source), metadata["compiler_sha256"])
        images.append(image)
    images.append(generated["controller"][1])
    bundle = ordinary(folder / "bundle.o")
    need(verify_bundle(bundle, images) == metadata["bundle"], "foreground bundle table/complete bytes changed")
    layout = strict_json(sealed["native/shell_foreground_layout.json"])
    need(layout.get("schema") == "hepta.runtime.shell-foreground-layout.v1" and
         layout.get("ordered_symbols") == list(SYMBOLS) and layout.get("module_alignment") == 16 and
         layout.get("code_unchanged") is True and layout.get("runtime_module_table_mutable") is False,
         "foreground source-owned bundle layout")
    om = components["outcome"]; op = Path(metadata["outcome_manifest"]).parent
    need(ordinary(folder / "outcome.o") == ordinary(member(op, om["object"])), "foreground unchanged outcome object")
    allocator = metadata["allocator"]; loader = metadata["interpreter"]
    need(allocator["path"] == om["allocator"]["path"] and allocator["pin"] == om["allocator"]["before"] and
         type(allocator["path"]) is str and Path(allocator["path"]).is_absolute() and
         allocator["pin"] == pin(folder / "allocator-libc.so.6") and
         type(loader["path"]) is str and Path(loader["path"]).is_absolute() and
         loader["pin"] == pin(folder / "interpreter.bin"), "foreground retained loader/allocator bytes")
    for spec in tool_specs(folder, loader["path"]): read_tool(folder, spec)
    adapter = ordinary(folder / "adapter.o"); av = elf(adapter, 1); _, at = section(av, ".text")
    need(ordinary(folder / "adapter.text.bin") == contents(adapter, at), "actual objcopy complete adapter text")
    need(layout.get("text_tail_alignment") == 16 and layout.get("text_padding_byte") == 0 and
         layout.get("adapter_source_sha256") == sha(sealed["scripts/shell_foreground_adapter.S"]) and
         layout.get("adapter_text_sha256") == sha(contents(adapter, at)) and
         integer(layout.get("adapter_entry_offset")) and
         layout["adapter_entry_offset"] == adapter_entry(adapter) and
         layout.get("adapter_relocations") == relocation_signature(adapter),
         "source-owned complete adapter text and relocation pins")
    executable = ordinary(folder / "shell-foreground.elf")
    inspection = linked_text(executable, [("adapter", adapter), ("bundle", bundle),
                                         ("outcome", ordinary(folder / "outcome.o"))], loader["path"])
    need(inspection == metadata["inspection"] and sha(executable) == metadata["elf_sha256"], "foreground complete ELF bytes")
    final = elf(executable, 2); _, text = section(final, ".text")
    need(ordinary(folder / "linked.text.bin") == contents(executable, text), "actual objcopy complete linked text")
    count = read_packer(folder, metadata, generated["packer"][0], images, bundle)
    expected = {"bundle.o", "adapter.o", "adapter.text.bin", "outcome.o", "allocator-libc.so.6",
                "interpreter.bin", "shell-foreground.elf", "linked.text.bin"}
    expected |= {"source-snapshots/" + n for n in INPUTS}
    for label, *_ in tool_specs(folder, loader["path"]):
        expected |= {"tools/" + label + suffix for suffix in (".json", ".tool.bin", ".stdout", ".stderr")}
    for name, *_ in packer_cases(images):
        expected.add("packer/" + name + "/invocation.json")
        expected |= {"packer/" + name + "/" + label + "." + when + ".bin"
                     for label in ("input", "output", "workspace", "guards") for when in ("before", "after")}
    need(set(evidence.get("files", {})) == expected and
         evidence["files"] == {n: pin(member(folder, n)) for n in expected}, "foreground exhaustive evidence inventory")
    return {"schema": SCHEMA + ".readback", "status": "PASS", "manifest_sha256": sha(raw),
            "elf_sha256": sha(executable), "compiler_sha256": metadata["compiler_sha256"],
            "sealed_sources": len(INPUTS), "component_manifests": 3, "tool_processes": 4,
            "packer_invocations": count, "whole_text_bytes_reconstructed": inspection["text_bytes"],
            "current_source_bytes_verified": True, "runtime_python_required": False,
            "runtime_libc_required": True, **SCOPE}


def admit_execution(manifest, *, source_root=ROOT):
    """Require this host's exact loader and allocator before native execution.

    A collector only reconstructs retained bytes and must not substitute its
    own runner image for the recorded consumer. Actual execution still rejects
    any loader/allocator drift, including equal-version libraries with different
    bytes. The outcome owner's independent loaded-allocator check is unchanged.
    """
    reviewed = read_evidence(manifest, source_root=source_root)
    metadata = strict_json(ordinary(Path(manifest)))
    allocator, loader = metadata["allocator"], metadata["interpreter"]
    current, current_pin, current_version = outcome.loaded_allocator()
    outcome_metadata = strict_json(ordinary(Path(metadata["outcome_manifest"])))
    need(str(current) == allocator["path"] and current_pin == allocator["pin"] and
         current_version == outcome_metadata["allocator"]["runtime_version"] and
         pin(Path(allocator["path"])) == allocator["pin"] and
         loader["path"] == str(interpreter_path()) and
         pin(Path(loader["path"])) == loader["pin"], "foreground actual loader/allocator bytes")
    return reviewed


def build_shell_foreground(hepta, build_root, *, source_root=ROOT,
                           process_manifest=None, output_manifest=None, outcome_manifest=None):
    root = Path(source_root).resolve(strict=True); build_root = Path(build_root).resolve()
    folder = build_root / "shell-foreground"; folder.mkdir(parents=True, exist_ok=False)
    state = {"schema": SCHEMA + ".build", "status": "RUNNING", "error": None}
    def save(): (folder / "build-evidence.json").write_bytes(nb.json_bytes(state))
    save()
    try:
        sealed = sources(root)
        state["sources"] = {n: {"size": len(b), "sha256": sha(b)} for n, b in sealed.items()}
        for name, raw in sealed.items():
            p = member(folder / "source-snapshots", name); p.parent.mkdir(parents=True, exist_ok=True); nb.write_new(p, raw)
        (folder / "tools").mkdir()
        supplied = {"process": process_manifest, "output": output_manifest, "outcome": outcome_manifest}
        bindings = {}; components = {}; paths = {}
        for name, value in supplied.items():
            selected = Path(value).absolute() if value is not None else build_root / ("shell-" + name) / "manifest.json"
            bindings[name], components[name] = component_binding(name, selected, root); paths[name] = selected
        state["components"] = bindings
        builder = nb.NativeBuild(hepta, build_root); compiler_sha = sha(ordinary(builder.bootstrap()))
        need(all(v["compiler_sha256"] == compiler_sha for v in components.values()), "foreground components use another compiler")
        generated = {}
        for name in ("controller", "packer"):
            generated[name] = builder.compile("shell-foreground-" + name,
                folder / "source-snapshots/native" / ("shell_foreground_" + name + ".hepta"), standalone=None)
        images = []
        for name, source in (("process", "native/shell_process.hepta"), ("output", "native/shell_output_io.hepta")):
            p = member(paths[name].parent.parent, components[name]["owner_manifest"])
            images.append(native_component(p, ordinary(root / source), compiler_sha)[1])
        images.append(native_component(generated["controller"], sealed["native/shell_foreground_controller.hepta"], compiler_sha)[1])
        native_component(generated["packer"], sealed["native/shell_foreground_packer.hepta"], compiler_sha)
        bundle = None
        with nl.NativeModule(generated["packer"], manifest_sha256=sha(ordinary(generated["packer"]))) as module:
            for name, wire, capacity, expected in packer_cases(images):
                raw = process.invoke_recorded(module, folder, name, wire, capacity, expected)
                if name == "success": bundle = raw
        need(bundle is not None, "actual HIA bundle is missing")
        bundle_info = verify_bundle(bundle, images); nb.write_new(folder / "bundle.o", bundle)
        om = components["outcome"]
        nb.write_new(folder / "outcome.o", ordinary(member(paths["outcome"].parent, om["object"])))
        allocator = Path(om["allocator"]["path"]); need(pin(allocator) == om["allocator"]["before"], "actual allocator changed")
        nb.write_new(folder / "allocator-libc.so.6", ordinary(allocator))
        interpreter = interpreter_path(); nb.write_new(folder / "interpreter.bin", ordinary(interpreter))
        for label, tool, arguments, inputs, outputs in tool_specs(folder, str(interpreter)):
            run_tool(folder, label, tool, arguments, inputs, outputs)
        executable = ordinary(folder / "shell-foreground.elf")
        inspection = linked_text(executable, [("adapter", ordinary(folder / "adapter.o")), ("bundle", bundle),
                                             ("outcome", ordinary(folder / "outcome.o"))], str(interpreter))
        metadata = {"schema": SCHEMA, "target": "linux-x86_64", "compiler_commit": COMPILER,
                    "compiler_sha256": compiler_sha, "recorded_directory": str(folder), "recorded_source_root": str(root),
                    "elf": "shell-foreground.elf", "elf_sha256": sha(executable), "bundle": bundle_info,
                    "inspection": inspection, "runtime_python_required": False, "runtime_libc_required": True,
                    "allocator": {"path": str(allocator), "pin": pin(allocator)},
                    "interpreter": {"path": str(interpreter), "pin": pin(interpreter)}, **SCOPE}
        for name in ("controller", "packer"):
            metadata[name + "_manifest"] = str(generated[name].relative_to(build_root))
            metadata[name + "_manifest_sha256"] = sha(ordinary(generated[name]))
            compiled = strict_json(ordinary(generated[name]))
            metadata[name + "_source_sha256"] = compiled["source_sha256"]
            metadata[name + "_image_sha256"] = compiled["image_sha256"]
        for name in paths:
            metadata[name + "_manifest"] = str(paths[name]); metadata[name + "_manifest_sha256"] = bindings[name]["sha256"]
        need(sources(root) == sealed, "foreground sources changed during build")
        builder._recheck()
        state["status"] = "PASS"
        names = {"bundle.o", "adapter.o", "adapter.text.bin", "outcome.o", "allocator-libc.so.6", "interpreter.bin",
                 "shell-foreground.elf", "linked.text.bin", *["source-snapshots/" + n for n in INPUTS]}
        for label, *_ in tool_specs(folder, str(interpreter)):
            names |= {"tools/" + label + s for s in (".json", ".tool.bin", ".stdout", ".stderr")}
        for name, *_ in packer_cases(images):
            names.add("packer/" + name + "/invocation.json")
            names |= {"packer/" + name + "/" + label + "." + when + ".bin"
                      for label in ("input", "output", "workspace", "guards") for when in ("before", "after")}
        state["files"] = {n: pin(member(folder, n)) for n in sorted(names)}; save()
        metadata["build_evidence_sha256"] = sha(ordinary(folder / "build-evidence.json"))
        manifest = folder / "manifest.json"; nb.write_new(manifest, nb.json_bytes(metadata))
        admit_execution(manifest, source_root=root)
        return manifest
    except Exception as error:
        state["status"] = "FAIL"; state["error"] = type(error).__name__ + ": " + str(error); save(); raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--process-manifest", type=Path)
    parser.add_argument("--output-manifest", type=Path)
    parser.add_argument("--outcome-manifest", type=Path)
    parser.add_argument("--read-only", type=Path)
    args = parser.parse_args()
    if args.read_only is not None:
        print(json.dumps(read_evidence(args.read_only, source_root=args.source_root), sort_keys=True)); return
    for name in ("hepta", "build", "process_manifest", "output_manifest", "outcome_manifest"):
        if getattr(args, name) is None: parser.error("--" + name.replace("_", "-") + " is required for a build")
    path = build_shell_foreground(args.hepta, args.build, source_root=args.source_root,
        process_manifest=args.process_manifest, output_manifest=args.output_manifest, outcome_manifest=args.outcome_manifest)
    print(json.dumps({"status": "PASS", "manifest": str(path), **SCOPE}, sort_keys=True))


if __name__ == "__main__":
    main()

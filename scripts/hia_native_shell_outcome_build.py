"""Compile the HIA outcome owner with the pinned owned-buffer ELF profile.

The only external runtime imports are calloc/free. Python owns compiler/tool
invocation, byte admission and borrowed-buffer transport, never Shell policy.
The pure evidence reader does not execute a tool, inspect a process, or load code.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
COMPILER = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
ABI = "hepta.runtime.shell-outcome-owned-elf.linux-x86_64.v1"
INPUTS = (
    "native/shell_outcome.hepta", "native/shell_outcome_abi.md",
    "native/shell_outcome_reuse.json", "native/terminal_clean.hepta",
    "native/text_budget.hepta", "native/shell_gate.hepta", "native/policy.hepta",
    "src/mcp/fs/shell.rs", "src/mcp/fs/background.rs",
    "scripts/hia_native_shell_outcome_build.py",
)
SCOPE = {"whole_runtime_replaced": False, "production_activated": False,
         "production_shell_execution_qualified": False, "old_stack_removal_qualified": False,
         "matching_source_full_cold_qualified": False, "filesystem_reads_qualified": False}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def obj(raw):
    return json.loads(raw, object_pairs_hook=pairs)


def raw_file(path):
    path = Path(path)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and not path.is_symlink(), "ordinary file required")
    raw = path.read_bytes()
    after = path.stat()
    identity = lambda p: (p.st_dev, p.st_ino, p.st_mode, p.st_size, p.st_mtime_ns, p.st_ctime_ns)
    need(identity(info) == identity(after) and len(raw) == info.st_size, "file changed during read")
    return raw


def pin(path):
    raw = raw_file(path)
    return {"size": len(raw), "sha256": digest(raw)}


def write(path, raw, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)


def write_json(path, value):
    write(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def member(folder, name):
    need(type(name) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name),
         "artifact member is not a basename")
    return Path(folder) / name


def loader_view(raw, sections, programs):
    """Pure ELF64 loader-view checks, in addition to elf_info's symbol checks.

    Inputs are unmodified <IIQQQQIIQQ Shdr and <IIQQQQQQ Phdr tuples.
    Uses only the caller's need() and struct module; no process or ELF loading.
    This is the restricted allocator fixture ABI, not a general ELF validator.
    """
    limit = 1 << 64
    loads = [p for p in programs if p[0] == 1]
    need(bool(loads), "loader PT_LOAD inventory")
    for p in loads:
        _, flags, off, addr, _, files, memory, align = p
        need(0 <= off <= len(raw) and files <= len(raw) - off and
             files <= memory and addr < limit and memory <= limit - addr,
             "loader load extent")
        need(flags & ~7 == 0 and flags & 4 and flags & 3 != 3,
             "loader load permissions")
        need(align in (0, 1) or
             (align & (align - 1) == 0 and (addr - off) % align == 0),
             "loader load alignment")
    ordered = sorted((p[3], p[3] + p[6]) for p in loads if p[6])
    need(all(a[1] <= b[0] for a, b in zip(ordered, ordered[1:])),
         "loader overlapping load byte intervals")

    def mapped(addr, size, *, writable=False, executable=False):
        need(0 <= addr < limit and 0 < size <= limit - addr,
             "loader mapped address extent")
        matches = [p for p in loads if p[3] <= addr and
                   addr - p[3] + size <= p[5]]
        need(len(matches) == 1, "loader unique file-backed mapping")
        p = matches[0]
        need(not writable or p[1] & 2, "loader writable mapping")
        need(not executable or p[1] & 1, "loader executable mapping")
        return p[2] + addr - p[3]

    def table(index, *, writable=False):
        need(0 <= index < len(sections), "loader section index")
        s = sections[index]
        need(s[1] != 8 and s[2] & 2 and s[5] > 0 and
             s[4] <= len(raw) and s[5] <= len(raw) - s[4],
             "loader allocated table extent")
        need(mapped(s[3], s[5], writable=writable) == s[4],
             "loader section/load byte identity")
        return s

    def one_type(kind):
        hits = [i for i, s in enumerate(sections) if s[1] == kind]
        need(len(hits) == 1, "loader unique section type " + hex(kind))
        return hits[0], table(hits[0])

    dynamic_index, dynamic = one_type(6)
    dynprogram = [p for p in programs if p[0] == 2]
    need(len(dynprogram) == 1, "loader unique PT_DYNAMIC")
    dp = dynprogram[0]
    need((dp[2], dp[3], dp[5], dp[6]) ==
         (dynamic[4], dynamic[3], dynamic[5], dynamic[5]),
         "loader PT_DYNAMIC/SHT_DYNAMIC identity")
    need(dynamic[9] == 16 and dynamic[5] % 16 == 0,
         "loader dynamic entry layout")
    permitted = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 20, 23, 24, 30,
                 0x6ffffef5, 0x6ffffff0, 0x6ffffff9, 0x6ffffffb,
                 0x6ffffffe, 0x6fffffff}
    tags = {}
    ended = False
    padding = 0
    for off in range(dynamic[4], dynamic[4] + dynamic[5], 16):
        tag, value = struct.unpack_from("<qQ", raw, off)
        if ended or tag == 0:
            need(tag == 0 and value == 0, "loader dynamic null padding")
            ended = True
            padding += 1
            continue
        need(tag in permitted and tag not in tags,
             "loader dynamic capability/duplicate tag " + hex(tag))
        tags[tag] = value
    need(ended, "loader terminated dynamic table")
    need(tags.get(30, 0) & ~8 == 0 and tags.get(0x6ffffffb, 0) & ~1 == 0,
         "loader dynamic flags capabilities")
    need(24 not in tags or tags[24] == 0, "loader BIND_NOW value")
    need(24 in tags or tags.get(30, 0) & 8 or tags.get(0x6ffffffb, 0) & 1,
         "loader eager symbol binding")
    sym_index, sym = one_type(11)
    strings = table(sym[6])
    need(strings[1] == 3 and dynamic[6] == sym[6],
         "loader dynamic string section identity")
    need(tags.get(5) == strings[3] and tags.get(10) == strings[5] and
         tags.get(6) == sym[3] and tags.get(11) == 24 and sym[9] == 24 and
         sym[5] % 24 == 0, "loader actual symbol/string table pointers")
    string_bytes = raw[strings[4]:strings[4] + strings[5]]
    def string(at):
        need(0 <= at < len(string_bytes), "loader string offset")
        end = string_bytes.find(b"\0", at)
        need(end >= 0, "loader terminated string")
        return string_bytes[at:end]
    need(1 in tags and string(tags[1]) == b"libc.so.6",
         "loader exact dynamic dependency")
    symbols = [struct.unpack_from("<IBBHQQ", raw, sym[4] + off)
               for off in range(0, sym[5], 24)]
    need(symbols and symbols[0] == (0, 0, 0, 0, 0, 0), "loader null symbol")
    labels = [string(s[0]) for s in symbols]
    need(len(symbols) == 4 and sorted(labels) == [b"", b"calloc", b"f0", b"free"],
         "loader exact dynamic symbol inventory")
    imports = {}
    for i, (name, info, other, index, addr, size) in enumerate(symbols[1:], 1):
        label = labels[i]
        need(info >> 4 in (1, 2) and other == 0, "loader symbol binding/visibility")
        if label in (b"calloc", b"free"):
            need(index == 0 and addr == 0 and size == 0 and info & 15 in (0, 2),
                 "loader allocator symbol shape")
            imports[i] = label.decode("ascii")
        else:
            need(0 < index < len(sections) and info & 15 == 2,
                 "loader entry symbol shape")
            mapped(addr, max(size, 1), executable=True)

    hashes = []
    for tag, kind, name in ((4, 5, "sysv"), (0x6ffffef5, 0x6ffffff6, "gnu")):
        hits = [i for i, s in enumerate(sections) if s[1] == kind and s[2] & 2]
        need(bool(hits) == (tag in tags) and len(hits) <= 1,
             "loader hash tag/table inventory")
        if not hits:
            continue
        h = table(hits[0])
        need(tags[tag] == h[3] and h[6] == sym_index,
             "loader actual hash table pointer/link")
        b = raw[h[4]:h[4] + h[5]]
        if name == "sysv":
            need(len(b) >= 8, "loader SYSV hash header")
            buckets, chains = struct.unpack_from("<II", b)
            need(buckets > 0 and chains == len(symbols) and
                 len(b) == 8 + 4 * (buckets + chains), "loader SYSV hash extent")
            values = struct.unpack_from("<" + "I" * (buckets + chains), b, 8)
            need(all(v < chains for v in values), "loader SYSV hash symbol bounds")
            for start in values[:buckets]:
                seen = set()
                while start:
                    need(start not in seen, "loader SYSV hash acyclic chain")
                    seen.add(start)
                    start = values[buckets + start]
        else:
            need(len(b) >= 16, "loader GNU hash header")
            buckets, first, bloom_count, shift = struct.unpack_from("<IIII", b)
            need(buckets > 0 and bloom_count > 0 and bloom_count & (bloom_count - 1) == 0
                 and 0 < first <= len(symbols) and shift < 64 and
                 len(b) == 16 + 8 * bloom_count + 4 * buckets +
                 4 * (len(symbols) - first), "loader GNU hash exact extent")
            at = 16 + 8 * bloom_count
            starts = struct.unpack_from("<" + "I" * buckets, b, at)
            chain = struct.unpack_from("<" + "I" * (len(symbols) - first), b,
                                       at + 4 * buckets)
            for start in starts:
                if not start:
                    continue
                need(first <= start < len(symbols), "loader GNU hash symbol bounds")
                while not chain[start - first] & 1:
                    start += 1
                    need(start < len(symbols), "loader GNU hash terminated chain")
        hashes.append(name)
    need(bool(hashes), "loader symbol hash table")

    version_tags = (0x6ffffff0, 0x6ffffffe, 0x6fffffff)
    version_sections = [s for s in sections if s[1] in (0x6fffffff, 0x6ffffffe)
                        and s[2] & 2]
    if any(t in tags for t in version_tags):
        need(all(t in tags for t in version_tags), "loader complete version tags")
        _, vs = one_type(0x6fffffff)
        _, vn = one_type(0x6ffffffe)
        need(tags[0x6ffffff0] == vs[3] and vs[6] == sym_index and
             vs[5] == len(symbols) * 2 and tags[0x6ffffffe] == vn[3] and
             vn[6] == sym[6] and tags[0x6fffffff] == vn[7] == 1,
             "loader actual version table pointers/count")
        need(vn[5] >= 16, "loader version need header")
        version, count, file_name, aux, following = struct.unpack_from("<HHIII", raw, vn[4])
        need(version == 1 and count > 0 and string(file_name) == b"libc.so.6" and
             following == 0 and aux >= 16, "loader version dependency")
        accepted = set()
        used = set(range(16))
        for i in range(count):
            need(aux <= vn[5] - 16 and not used.intersection(range(aux, aux + 16)),
                 "loader version auxiliary extent")
            used.update(range(aux, aux + 16))
            hash_value, flags, ordinal, name, nxt = struct.unpack_from("<IHHII", raw, vn[4] + aux)
            label = string(name)
            need(flags == 0 and 1 < ordinal < 0x8000 and ordinal not in accepted and
                 label.startswith(b"GLIBC_") and len(label) > 6 and
                 all(part.isdigit() for part in label[6:].split(b".")) and
                 len(label[6:].split(b".")) >= 2, "loader allocator version identity")
            accepted.add(ordinal)
            need((i + 1 == count and nxt == 0) or (i + 1 < count and nxt >= 16),
                 "loader version auxiliary chain")
            aux += nxt
        versions = struct.unpack_from("<" + "H" * len(symbols), raw, vs[4])
        need(versions[0] == 0 and
             all(versions[i] in accepted if i in imports else versions[i] == 1
                 for i in range(1, len(symbols))), "loader symbol version binding")
        need(accepted == {versions[i] for i in imports}, "loader used version inventory")
    else:
        need(not version_sections, "loader undeclared version section")

    need(all(t in tags for t in (2, 3, 20, 23)) and tags[20] == 7,
         "loader complete RELA PLT tags")
    relocs = [i for i, s in enumerate(sections) if s[1] == 4 and s[2] & 2
              and s[3] == tags[23]]
    need(len(relocs) == 1, "loader unique JMPREL section")
    rela = table(relocs[0])
    need(rela[6] == sym_index and rela[9] == 24 and
         rela[5] == tags[2] == 48, "loader JMPREL pointer/size/link")
    got = table(rela[7], writable=True)
    need(got[1] == 1 and got[2] & 1 and got[3] == tags[3] and got[5] >= 40,
         "loader actual PLTGOT section")
    relocation_symbols = set()
    relocation_slots = set()
    for off in range(rela[4], rela[4] + rela[5], 24):
        target, info, addend = struct.unpack_from("<QQq", raw, off)
        ordinal, kind = info >> 32, info & 0xffffffff
        need(kind == 7 and ordinal in imports and ordinal not in relocation_symbols and
             target not in relocation_slots and addend == 0 and target % 8 == 0 and
             got[3] + 24 <= target <= got[3] + got[5] - 8,
             "loader allocator-only JUMP_SLOT relocation")
        mapped(target, 8, writable=True)
        relocation_symbols.add(ordinal)
        relocation_slots.add(target)
    need(relocation_symbols == set(imports), "loader allocator relocation inventory")
    need(not any(t in tags for t in (7, 8, 9, 0x6ffffff9)),
         "loader unexpected non-PLT relocation capability")
    need([i for i, s in enumerate(sections) if s[1] in (4, 9, 19) and s[2] & 2
          and s[5]] == relocs, "loader extra allocated relocation table")
    return {"load_segments": len(loads), "dynamic_section": dynamic_index,
            "dynamic_address": dynamic[3], "dynamic_size": dynamic[5],
            "dynamic_null_entries": padding, "dynamic_tags": sorted(tags),
            "hash_styles": hashes, "dynamic_symbols": [s.decode("ascii") for s in labels],
            "plt_relocations": len(relocation_slots)}


def elf_info(raw, expected_type):
    """Read ELF64 metadata directly; no readelf output or stored PASS is trusted."""
    need(len(raw) >= 64 and raw[:7] == b"\x7fELF\x02\x01\x01", "ELF64 LE header")
    kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, names = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
    need(kind == expected_type and machine == 62 and version == 1 and ehsize == 64,
         "ELF object target/type")
    need(shsize == 64 and 0 < shnum <= 4096 and shoff <= len(raw) - shnum * 64,
         "ELF section table")
    sections = [struct.unpack_from("<IIQQQQIIQQ", raw, shoff + i * 64) for i in range(shnum)]
    for section in sections:
        if section[1] != 8:
            need(section[4] <= len(raw) and section[5] <= len(raw) - section[4],
                 "ELF section extent")
    def contents(index):
        need(0 <= index < shnum and sections[index][1] != 8, "ELF linked section")
        section = sections[index]
        return raw[section[4]:section[4] + section[5]]
    def string(table, at):
        need(0 <= at < len(table), "ELF string offset")
        end = table.find(b"\0", at)
        need(end >= 0, "ELF terminated string")
        return table[at:end].decode("ascii")
    undefined = set()
    undefined_records = set()
    dynamic_undefined = set()
    exports = set()
    for section in sections:
        if section[1] not in (2, 11):
            continue
        need(section[9] == 24 and section[5] % 24 == 0, "ELF symbol record")
        strings = contents(section[6])
        for offset in range(section[4], section[4] + section[5], 24):
            name, info, other, index, address, size = struct.unpack_from("<IBBHQQ", raw, offset)
            label = string(strings, name)
            if not label:
                continue
            if index == 0:
                base, separator, symbol_version = label.partition("@")
                need(base in ("calloc", "free") and
                     (not separator or (expected_type == 3 and
                      re.fullmatch(r"GLIBC_[0-9]+(?:\.[0-9]+)+", symbol_version))),
                     "ELF external symbol name/version allowlist")
                undefined.add(base)
                undefined_records.add(label)
                if section[1] == 11:
                    need(not separator, "ELF dynamic allocator symbol")
                    dynamic_undefined.add(base)
            elif info >> 4 in (1, 2) and info & 15 == 2:
                exports.add(label)
    need(undefined == {"calloc", "free"}, "ELF external symbol allowlist")
    need(exports == {"f0"}, "ELF callable export inventory")
    needed = []
    if expected_type == 3:
        need(dynamic_undefined == {"calloc", "free"}, "ELF dynamic allocator imports")
        need(phsize == 56 and 0 < phnum <= 128 and phoff <= len(raw) - phnum * 56,
             "ELF program table")
        programs = [struct.unpack_from("<IIQQQQQQ", raw, phoff + i * 56)
                    for i in range(phnum)]
        stack = False
        for tag, access, offset, address, physical, files, memory, alignment in programs:
            need(files <= memory and offset <= len(raw) and files <= len(raw) - offset,
                 "ELF segment extent")
            need(tag != 3 and not (tag == 1 and access & 3 == 3), "ELF interpreter/WX")
            if tag == 0x6474e551:
                need(access & 1 == 0, "ELF executable stack")
                stack = True
        need(stack, "ELF stack declaration")
        for section in sections:
            if section[1] != 6:
                continue
            need(section[9] == 16 and section[5] % 16 == 0, "ELF dynamic table")
            strings = contents(section[6])
            for offset in range(section[4], section[4] + section[5], 16):
                tag, value = struct.unpack_from("<qQ", raw, offset)
                need(tag not in (12, 13, 15, 22, 25, 26, 29, 32),
                     "ELF init/fini/RPATH/text-relocation capability")
                if tag == 1:
                    needed.append(string(strings, value))
        need(needed == ["libc.so.6"], "ELF allocator dependency")
    result = {"type": kind, "machine": machine, "entry": entry,
            "undefined_symbols": sorted(undefined), "undefined_records": sorted(undefined_records),
            "exports": sorted(exports),
            "needed": needed}
    if expected_type == 3:
        result["loader_view"] = loader_view(raw, sections, programs)
    return result


def function_bodies(raw):
    text = raw.decode("utf-8")
    result = {}
    for match in re.finditer(r"(?ms)^fn (f\d+)\(.*?^end\n", text):
        need(match.group(1) not in result, "duplicate HIA function")
        result[match.group(1)] = match.group(0)
    need(result, "empty HIA function inventory")
    return result


def read_reuse(root):
    root = Path(root)
    source = raw_file(root / "native/shell_outcome.hepta")
    reuse = obj(raw_file(root / "native/shell_outcome_reuse.json"))
    need(reuse.get("schema") == "hepta.runtime.shell-outcome-reuse.v1" and
         reuse.get("source_sha256") == digest(source) and reuse.get("compiler_commit") == COMPILER,
         "outcome HIA composition source")
    roots = {"native/terminal_clean.hepta": ["f0"],
             "native/text_budget.hepta": ["f0"],
             "native/shell_gate.hepta": ["f13", "f62", "f63", "f64", "f65"],
             "native/policy.hepta": ["f18"]}
    need(set(reuse["source_pins"]) == set(roots), "HIA original leaf source inventory")
    destination = function_bodies(source)
    rows = reuse["imports"]
    need(type(rows) is list and len(rows) == 65, "complete imported HIA functions")
    names = set()
    for path, entry in roots.items():
        raw = raw_file(root / path)
        need(digest(raw) == reuse["source_pins"][path], "current original HIA leaf bytes")
        bodies = function_bodies(raw)
        pending, closure = list(entry), set()
        while pending:
            name = pending.pop()
            if name in closure:
                continue
            need(name in bodies, "HIA call closure member")
            closure.add(name)
            pending.extend(re.findall(r'"function":"(f\d+)"', bodies[name]))
        selected = [row for row in rows if row.get("source") == path]
        need({row["original_function"] for row in selected} == closure and
             len(selected) == len(closure), "HIA transitive call coverage")
        rename = {row["original_function"]: row["destination_function"] for row in selected}
        for row in selected:
            need(row["allowed_transform"] == "function-name-and-call-target-rename-only" and
                 row["rename"] == rename and row["source_sha256"] == digest(raw),
                 "HIA allowed transformation")
            original = bodies[row["original_function"]]
            expected = re.sub(r"\bf\d+\b", lambda match: rename[match.group(0)], original)
            target = row["destination_function"]
            need(target not in names and target in destination, "HIA imported destination")
            names.add(target)
            need(destination[target] == expected and
                 row["original_body_sha256"] == digest(original.encode()) and
                 row["relocated_body_sha256"] == digest(expected.encode()),
                 "original HIA function body changed beyond IDs")
    wrapper = reuse["terminal_u64_wrapper"]
    original_clean = function_bodies(raw_file(root / "native/terminal_clean.hepta"))["f0"]
    need(wrapper["source"] == "native/terminal_clean.hepta" and wrapper["original_entry"] == "f0" and
         wrapper["original_body_sha256"] == digest(original_clean.encode()) and
         wrapper["wrapper_function"] in destination and wrapper["wrapper_function"] not in names and
         wrapper["wrapper_body_sha256"] == digest(destination[wrapper["wrapper_function"]].encode()) and
         wrapper["private_invalid_u64"] == (1 << 64) - 2 and
         wrapper["private_capacity_u64"] == (1 << 64) - 1 and
         wrapper["physical_over_4gib_test_in_ordinary_corpus"] is False,
         "u64 cleaner wrapper source boundary")
    steps = [
        ("f1", "validate complete UTF-8", True),
        ("f0", "empty input returns zero before scratch check", True),
        ("f0", "workspace extent at least input extent", True),
        ("f7", "ANSI removal", True),
        ("f10", "line cleanup", True),
        ("f14", "repeated-line join and checked scratch extent", True),
        ("f0", "skip leading LF bytes", True),
        ("f5", "trim final Unicode whitespace", True),
        ("f0", "compare complete count against output extent", True),
        ("f0", "omit private u32 count restriction", False),
        ("f0", "copy complete published prefix", True),
        ("f0", "return u64 count without u32 cast", False),
    ]
    need(wrapper["steps"] == [{"order": index + 1, "original": old,
                               "action": action, "preserved": preserved}
                              for index, (old, action, preserved) in enumerate(steps)],
         "u64 wrapper step inventory")
    rename = {row["original_function"]: row["destination_function"]
              for row in rows if row["source"] == "native/terminal_clean.hepta"}
    calls = re.findall(r'"function":"(f\d+)"', destination[wrapper["wrapper_function"]])
    need(calls == [rename[name] for name in ("f1", "f7", "f10", "f14", "f5")],
         "u64 wrapper retained helper order")
    shell = raw_file(root / "src/mcp/fs/shell.rs")
    need(digest(shell) == reuse["original_shell_sha256"], "original Shell body")
    for key, begin, end in (("foreground_span", 28553, 30328), ("promotion_span", 27497, 28278)):
        need(reuse[key] == {"start": begin, "end": end, "sha256": digest(shell[begin:end])},
             "original Shell exact span")
    fixed = {
        "glibc-2.43/sysdeps/gnu/errlist.h": "7811bfd3c3f9ddd2405e29954c74c8532057197afe67f564310ff503744dbb6b",
        "glibc-2.43/string/_strerror.c": "69bf60445a3c8a867ba1f4f2f75297954d031cd9e5e58d4d8009f106bc76790e",
        "glibc-2.43/string/strerror_l.c": "9e658bf117d6bc203fad967f9b38f6f9dd1560e39322a36ec40b5e1e1937d6a8",
    }
    linux = {
        "linux-v6.12/include/uapi/asm-generic/errno-base.h": "9653140bff92dd2ee5a261a66dfe6c5687c3e956",
        "linux-v6.12/include/uapi/asm-generic/errno.h": "cf9c51ac49f97efd8d5aed07cf4fca2d9a368515",
    }
    need(set(reuse["errno_sources"]) == set(fixed) | set(linux), "errno original source inventory")
    defines = {}
    for key, record in reuse["errno_sources"].items():
        raw = record["text"].encode()
        need(record["size"] == len(raw) and record["sha256"] == digest(raw), "errno original source bytes")
        if key in fixed:
            need(digest(raw) == fixed[key], "fixed glibc original body")
        else:
            git = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            need(git == linux[key], "fixed Linux original errno numbers")
            defines.update(re.findall(r"^#define\s+(\w+)\s+(\w+)", record["text"], re.M))
    def number(name):
        value = defines[name]
        return int(value) if value.isdigit() else number(value)
    table = []
    text = reuse["errno_sources"]["glibc-2.43/sysdeps/gnu/errlist.h"]["text"]
    for name, message in re.findall(r'_S\s*\(\s*(\w+)\s*,\s*N_\s*\(\s*"([^"]*)"\s*\)\s*\)', text):
        if name != "0" and name not in defines:
            continue
        aliases = {"EDEADLOCK": "EDEADLK", "EWOULDBLOCK": "EAGAIN", "ENOTSUP": "EOPNOTSUPP"}
        if name in aliases and number(name) == number(aliases[name]):
            continue
        # The retained fixed table consists entirely of plain ASCII strings.
        need("\\" not in message, "unexpected errno string escape")
        table.append({"number": 0 if name == "0" else number(name),
                      "symbol": name, "description_hex": message.encode().hex()})
    table.sort(key=lambda row: row["number"])
    need(reuse["errno_table"] == table and
         [row["number"] for row in table] == [i for i in range(134) if i not in (41, 58)],
         "complete GNU/Linux errno table derivation")
    return {"imported_functions": len(rows), "known_errno_messages": len(table),
            "source_sha256": digest(source), "reuse_sha256": digest(raw_file(root / "native/shell_outcome_reuse.json"))}


def loaded_allocator():
    """Build/execute admission only; never called by the pure evidence reader."""
    candidates = {}
    for line in Path("/proc/self/maps").read_text().splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6 or not fields[5].endswith("/libc.so.6"):
            continue
        path = Path(fields[5]).resolve(strict=True)
        info = path.stat()
        need(info.st_ino == int(fields[4]), "mapped allocator inode changed")
        candidates[str(path)] = path
    need(len(candidates) == 1, "one actual loaded GNU libc is required")
    path = next(iter(candidates.values()))
    return path, pin(path), os.confstr("CS_GNU_LIBC_VERSION")


def read_evidence(manifest, source_root=None):
    path = Path(manifest).resolve(strict=True)
    folder = path.parent
    raw = raw_file(path)
    data = obj(raw)
    need(data.get("schema") == "hepta.runtime.shell-outcome.v1" and data.get("abi") == ABI and
         data.get("target") == "linux-x86_64" and data.get("compiler_commit") == COMPILER and
         data.get("profile") == "selfhost_elf",
         "outcome build ABI/compiler")
    for key, value in SCOPE.items():
        need(data.get(key) is value, "outcome build scope")
    need(data.get("qualification") == "development_fixed_point_owned_elf", "outcome build qualification")
    root = Path(source_root or ROOT).resolve(strict=True)
    need(set(data["sources"]) == set(INPUTS), "outcome build source inventory")
    for name in INPUTS:
        expected = data["sources"][name]
        need(pin(root / name) == expected and pin(folder / "inputs" / name) == expected,
             "current/snapshotted outcome source differs")
    reuse = read_reuse(root)
    object_path = member(folder, data["object"])
    shared_path = member(folder, data["shared"])
    need(pin(object_path) == data["object_pin"] and pin(shared_path) == data["shared_pin"],
         "outcome ELF/object bytes")
    need(elf_info(raw_file(object_path), 1) == data["object_inspection"] and
         elf_info(raw_file(shared_path), 3) == data["shared_inspection"],
         "outcome ELF capability inspection")
    compile_record = obj(raw_file(folder / "owner.receipt.json"))
    compile_output = raw_file(folder / "owner.output.bin")
    source = raw_file(folder / "owner.input.bin")
    need(source == raw_file(root / "native/shell_outcome.hepta"), "actual compiler input")
    size = compile_record.get("core_u32")
    need(integer(size, 1) and size == len(raw_file(object_path)) and
         compile_record.get("result_u64") == size and compile_record.get("abi_status") == 0 and
         type(compile_record.get("abi_status")) is int and compile_record.get("status") == "returned" and
         compile_record.get("source_unchanged") is True and
         compile_record.get("forbidden_compiler_modules_loaded") == [] and
         compile_record.get("input_bytes") == len(source) and
         compile_record.get("input_sha256") == digest(source) and
         compile_record.get("source_sha256") == digest(source) and
         compile_record.get("artifact_sha256") == data["compiler_sha256"] and
         compile_record.get("image_sha256") == data["compiler_sha256"] and
         compile_record.get("format") == "flat-x86-64" and
         compile_record.get("produced_bytes") == size and
         compile_record.get("produced_sha256") == digest(raw_file(object_path)) and
         compile_record.get("output_sha256") == digest(compile_output) and
         compile_output[:size] == raw_file(object_path), "actual pinned native compiler result")
    boot = folder.parent / "bootstrap"
    boot_record = obj(raw_file(boot / "bootstrap.json"))
    need(boot_record.get("qualification") == "development_fixed_point" and
         boot_record.get("matching_source_cold_qualified") is False and
         boot_record.get("generation_sha256") == data["compiler_sha256"] and
         boot_record["dependency"]["commit"] == COMPILER, "actual compiler fixed point")
    for label in ("B1", "B2", "B3"):
        need(digest(raw_file(boot / (label + ".image.bin"))) == data["compiler_sha256"],
             "retained compiler generation")
    allocator = data["allocator"]
    need(allocator["symbols"] == ["calloc", "free"] and
         allocator["before"] == allocator["after"] == pin(folder / "allocator-libc.so.6") and
         type(allocator["runtime_version"]) is str and allocator["runtime_version"].startswith("glibc "),
         "actual allocator identity")
    tool = data["linker"]
    need(tool["before"] == tool["after"] == pin(folder / "linker.bin"), "actual linker identity")
    process = obj(raw_file(folder / "link.process.json"))
    original_folder = Path(data["recorded_directory"])
    expected_command = [tool["path"], "--shared", "-z", "noexecstack", "-z", "relro",
                        "-z", "now", "--no-undefined", str(original_folder / data["object"]),
                        allocator["path"], "-o", str(original_folder / data["shared"])]
    need(process.get("command") == expected_command and
         process.get("cwd") == data["recorded_source_root"] and
         integer(process.get("pid"), 1) and type(process.get("exit_code")) is int and
         process["exit_code"] == 0 and process.get("timed_out") is False and
         process.get("timeout_seconds") == 60 and integer(process.get("elapsed_ns")) and
         process.get("environment") == {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
         "actual fixed linker process")
    for stream in ("stdout", "stderr"):
        observed = raw_file(folder / ("link." + stream))
        need(process.get(stream + "_bytes") == len(observed) and
             process.get(stream + "_sha256") == digest(observed) and len(observed) == 0,
             "linker process complete streams")
    return {"status": "PASS", "schema": "hepta.runtime.shell-outcome-build-review.v1",
            "manifest_sha256": digest(raw), "source_sha256": reuse["source_sha256"],
            "shared_sha256": data["shared_pin"]["sha256"], "compiler_sha256": data["compiler_sha256"],
            "imported_functions": reuse["imported_functions"], "known_errno_messages": 132,
            "runtime_allocator": allocator["runtime_version"], "allocator_sha256": allocator["before"]["sha256"],
            "symbol_allowlist": ["calloc", "free"], "current_source_bytes_verified": True, **SCOPE}


def build_shell_outcome(hepta, build, source_root=ROOT):
    root = Path(source_root).resolve(strict=True)
    build = Path(build).resolve()
    folder = build / "shell-outcome"
    folder.mkdir(parents=True, exist_ok=False)
    before = {name: pin(root / name) for name in INPUTS}
    for name in INPUTS:
        write(folder / "inputs" / name, raw_file(root / name))
    reuse = read_reuse(root)
    sys.path.insert(0, str(root / "scripts"))
    from hia_native_build import NativeBuild
    builder = NativeBuild(hepta, build)
    compiler = builder.bootstrap()
    from tools.qualify_hia_selfhost import compile_stage
    object_path, compile_record = compile_stage(folder, "owner", compiler,
                                                raw_file(root / "native/shell_outcome.hepta"))
    object_inspection = elf_info(raw_file(object_path), 1)
    tool = Path("/usr/bin/ld").resolve(strict=True)
    libc, libc_before, libc_version = loaded_allocator()
    linker_before = pin(tool)
    write(folder / "linker.bin", raw_file(tool))
    write(folder / "allocator-libc.so.6", raw_file(libc))
    shared = folder / "shell-outcome.so"
    command = [str(tool), "--shared", "-z", "noexecstack", "-z", "relro",
               "-z", "now", "--no-undefined", str(object_path), str(libc), "-o", str(shared)]
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    started = time.time_ns()
    clock = time.monotonic_ns()
    child = subprocess.Popen(command, cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timed_out = False
    try:
        stdout, stderr = child.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        timed_out = True
        child.kill()
        stdout, stderr = child.communicate()
    record = {"command": command, "cwd": str(root), "environment": env,
              "pid": child.pid, "exit_code": child.returncode, "timed_out": timed_out,
              "timeout_seconds": 60, "started_unix_ns": started, "finished_unix_ns": time.time_ns(),
              "elapsed_ns": time.monotonic_ns() - clock,
              "stdout_bytes": len(stdout), "stdout_sha256": digest(stdout),
              "stderr_bytes": len(stderr), "stderr_sha256": digest(stderr)}
    write(folder / "link.stdout", stdout)
    write(folder / "link.stderr", stderr)
    write_json(folder / "link.process.json", record)
    need(not timed_out and child.returncode == 0 and stdout == stderr == b"", "outcome native link failed")
    shared_inspection = elf_info(raw_file(shared), 3)
    after = {name: pin(root / name) for name in INPUTS}
    need(before == after, "outcome source changed during build")
    need(linker_before == pin(tool) and libc_before == pin(libc), "linker/allocator changed")
    data = {"schema": "hepta.runtime.shell-outcome.v1", "abi": ABI, "target": "linux-x86_64",
            "profile": "selfhost_elf",
            "compiler_commit": COMPILER, "compiler_sha256": digest(raw_file(compiler)),
            "qualification": "development_fixed_point_owned_elf",
            "recorded_directory": str(folder), "recorded_source_root": str(root),
            "sources": before, "object": object_path.name, "object_pin": pin(object_path),
            "shared": shared.name, "shared_pin": pin(shared),
            "object_inspection": object_inspection, "shared_inspection": shared_inspection,
            "linker": {"path": str(tool), "before": linker_before, "after": pin(tool)},
            "allocator": {"path": str(libc), "before": libc_before, "after": pin(libc),
                          "runtime_version": libc_version, "symbols": ["calloc", "free"]},
            **SCOPE}
    manifest = folder / "manifest.json"
    write_json(manifest, data)
    read_evidence(manifest, source_root=root)
    return manifest



class NativeOutcome:
    """Admit one sealed ELF and call its fixed borrowed-buffer ABI.

    This transport reads no Shell policy and supplies no expected result.
    call() returns all six actual guarded buffer snapshots. call_borrowed()
    is the corresponding private pointer capability for a controller which
    already owns disjoint live loans; its caller owns all buffer observation.
    """
    GUARD = 16
    ARRAY_NAMES = ("input_before", "input_after", "output_before", "output_after",
                   "workspace_before", "workspace_after")

    def __init__(self, manifest, source_root=ROOT):
        import ctypes
        import fcntl
        self.review = read_evidence(manifest, source_root=source_root)
        self.manifest = Path(manifest).resolve(strict=True)
        self.metadata = obj(raw_file(self.manifest))
        current, current_pin, current_version = loaded_allocator()
        need(current_pin == self.metadata["allocator"]["before"] and
             current_version == self.metadata["allocator"]["runtime_version"],
             "loaded allocator differs from qualified native build")
        self.allocator_path = str(current)
        self.allocator_pin = current_pin
        self.image = raw_file(member(self.manifest.parent, self.metadata["shared"]))
        self.fd = os.memfd_create("hia-shell-outcome", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            position = 0
            while position < len(self.image):
                amount = os.write(self.fd, self.image[position:])
                need(amount > 0, "complete sealed native image write")
                position += amount
            seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL
            fcntl.fcntl(self.fd, fcntl.F_ADD_SEALS, seals)
            need(fcntl.fcntl(self.fd, fcntl.F_GET_SEALS) == seals, "sealed ELF admission")
            self.library = ctypes.CDLL("/proc/self/fd/" + str(self.fd),
                                      mode=os.RTLD_NOW | os.RTLD_LOCAL)
            self.function = self.library.f0
            self.function.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
            self.function.restype = ctypes.c_uint64
            self.ctypes = ctypes
            self.calls = 0
        except BaseException:
            os.close(self.fd)
            self.fd = -1
            raise

    def close(self):
        if self.fd < 0:
            return
        import _ctypes
        self.function = None
        _ctypes.dlclose(self.library._handle)
        self.library = None
        os.close(self.fd)
        self.fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *ignored):
        self.close()

    def call_borrowed(self, input_address, input_length, output_address,
                      output_length, workspace_address, workspace_length):
        need(self.fd >= 0, "closed native outcome")
        spans = []
        for address, size in ((input_address, input_length), (output_address, output_length),
                              (workspace_address, workspace_length)):
            need(integer(address, 1) and integer(size) and
                 address < 1 << 64 and size <= (1 << 64) - address,
                 "live native borrowed-buffer interval")
            spans.append((address, address + size))
        for index, (start, end) in enumerate(spans):
            for other_start, other_end in spans[:index]:
                need(end <= other_start or other_end <= start or start == end or other_start == other_end,
                     "native outcome borrows must be disjoint")
        self.calls += 1
        return int(self.function(input_address, input_length, output_address, output_length,
                                 workspace_address, workspace_length))

    def call(self, wire, output_capacity, workspace_capacity=128, output_fill=0xa7,
             workspace_fill=0xb8):
        need(type(wire) is bytes and integer(output_capacity) and integer(workspace_capacity) and
             max(len(wire), output_capacity, workspace_capacity) <= sys.maxsize - 32 and
             type(output_fill) is int and 0 <= output_fill <= 255 and
             type(workspace_fill) is int and 0 <= workspace_fill <= 255,
             "native outcome transport dimensions")
        c = self.ctypes
        def allocate(size, left, right, fill):
            buffer = c.create_string_buffer(size + 32)
            c.memset(buffer, left, 16)
            c.memset(c.addressof(buffer) + 16, fill, size)
            c.memset(c.addressof(buffer) + 16 + size, right, 16)
            return buffer
        input_buffer = allocate(len(wire), 0x31, 0x32, 0)
        if wire:
            c.memmove(c.addressof(input_buffer) + 16, wire, len(wire))
        output_buffer = allocate(output_capacity, 0x41, 0x42, output_fill)
        workspace_buffer = allocate(workspace_capacity, 0x51, 0x52, workspace_fill)
        arrays = {"input_before": bytes(input_buffer), "output_before": bytes(output_buffer),
                  "workspace_before": bytes(workspace_buffer)}
        started = time.time_ns()
        clock = time.monotonic_ns()
        returned = self.call_borrowed(c.addressof(input_buffer) + 16, len(wire),
                                     c.addressof(output_buffer) + 16, output_capacity,
                                     c.addressof(workspace_buffer) + 16, workspace_capacity)
        elapsed = time.monotonic_ns() - clock
        finished = time.time_ns()
        arrays.update(input_after=bytes(input_buffer), output_after=bytes(output_buffer),
                      workspace_after=bytes(workspace_buffer))
        body = None
        extent = 0
        if returned == 40:
            need(output_capacity >= 40, "native success without header capacity")
            head = arrays["output_after"][16:56]
            magic, kind, text_length, present, uri_length = struct.unpack("<8sQQQQ", head)
            need(magic == b"HSHOUR01" and kind in (0, 1, 2) and present in (0, 1) and
                 (present == 1 or uri_length == 0) and
                 text_length <= output_capacity - 40 and
                 uri_length <= output_capacity - 40 - text_length, "native complete response envelope")
            extent = 40 + text_length + uri_length
            body = arrays["output_after"][16:16 + extent]
        else:
            need(returned in (0xffffffff, 0xfffffffe, 0xfffffff9), "native outcome return domain")
        guards = {
            "input_unchanged": arrays["input_before"] == arrays["input_after"],
            "input_guards": arrays["input_after"][:16] == b"1" * 16 and
                            arrays["input_after"][-16:] == b"2" * 16,
            "output_guards": arrays["output_after"][:16] == b"A" * 16 and
                             arrays["output_after"][-16:] == b"B" * 16,
            "workspace_guards": arrays["workspace_after"][:16] == b"Q" * 16 and
                                arrays["workspace_after"][-16:] == b"R" * 16,
            "output_tail_unchanged": arrays["output_after"][16 + extent:] ==
                                     arrays["output_before"][16 + extent:],
            "output_unchanged": arrays["output_after"] == arrays["output_before"],
        }
        need(all(guards[key] for key in guards if key != "output_unchanged"),
             "native input/output/workspace boundary changed")
        entry = {"status": "returned", "pid": os.getpid(), "entry": self.calls,
                 "returned": returned, "extent": extent, "input_length": len(wire),
                 "output_capacity": output_capacity, "workspace_capacity": workspace_capacity,
                 "output_fill": output_fill, "workspace_fill": workspace_fill,
                 "started_unix_ns": started, "finished_unix_ns": finished, "elapsed_ns": elapsed,
                 "manifest_sha256": self.review["manifest_sha256"],
                 "shared_sha256": self.review["shared_sha256"],
                 "allocator_sha256": self.allocator_pin["sha256"], "guards": guards,
                 "arrays": {key: {"size": len(raw), "sha256": digest(raw)}
                            for key, raw in arrays.items()}}
        return {"body": body, "entry": entry, "arrays": arrays}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.verify:
        print(json.dumps(read_evidence(args.verify, args.source_root), sort_keys=True))
    else:
        parser.error("--hepta and --build required") if not args.hepta or not args.build else None
        manifest = build_shell_outcome(args.hepta, args.build, source_root=args.source_root)
        print(json.dumps({"status": "PASS", "manifest": str(manifest), **SCOPE}, sort_keys=True))


if __name__ == "__main__":
    main()

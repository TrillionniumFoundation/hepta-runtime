"""Pure admission of the complete libc image and the actually loaded capabilities."""
from pathlib import Path
import struct
from common import loads, pin, read, require
from callable_contract import FUNCTIONS


def span(raw, at, size):
    require(type(at) is int and type(size) is int and 0 <= at <= len(raw) and
            0 <= size <= len(raw) - at, "complete ELF span")
    return raw[at:at + size]


def symbols(raw):
    require(raw[:7] == b"\x7fELF\x02\x01\x01" and raw[7] in (0, 3) and
            raw[8:16] == bytes(8), "ELF64 little-endian libc identity")
    header = struct.unpack("<HHIQQQIHHHHHH", span(raw, 16, 48))
    kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, names = header
    require(kind == 3 and machine == 62 and version == 1 and ehsize == 64 and
            phsize == 56 and shsize == 64 and 0 < phnum < 1024 and 0 < shnum < 65535 and
            0 < names < shnum, "actual x86-64 shared-library structure")
    segments = []
    for i in range(phnum):
        row = struct.unpack("<II6Q", span(raw, phoff + phsize * i, phsize))
        typ, mask, offset, address, physical, size, memory, align = row
        if typ == 1:
            span(raw, offset, size)
            require(size <= memory and address + memory < 1 << 64, "whole loaded ELF segment")
            segments.append(dict(mask=mask, offset=offset, address=address, size=size, memory=memory))
    sections = [struct.unpack("<II4QII2Q", span(raw, shoff + shsize * i, shsize)) for i in range(shnum)]
    result = {}
    for section in sections:
        name, typ, mask, address, offset, size, link, info, alignment, step = section
        if typ != 11:
            continue
        require(step == 24 and size % step == 0 and link < shnum, "complete dynamic-symbol table")
        strings = sections[link]
        require(strings[1] == 3, "dynamic symbol string table")
        text = span(raw, strings[4], strings[5])
        for at in range(offset, offset + size, step):
            label, info, other, index, value, count = struct.unpack("<IBBHQQ", span(raw, at, step))
            require(label < len(text), "ELF symbol name extent")
            end = text.find(b"\0", label)
            require(end >= label, "ELF symbol name terminator")
            name = text[label:end].decode("utf-8")
            if index and info & 15 == 2:  # Actual STT_FUNC, not an inferred IFUNC target.
                result.setdefault(name, set()).add(value)
    require(segments and result, "actual complete exported ELF functions")
    return result, segments


def mappings(raw):
    rows = []
    for line in raw.decode("utf-8").splitlines():
        fields = line.split(None, 5)
        require(len(fields) in (5, 6), "complete process mapping line")
        pair, permissions, offset, device, inode = fields[:5]
        lo, hi = [int(x, 16) for x in pair.split("-")]
        require(0 <= lo < hi and len(permissions) == 4 and
                permissions[0] in "r-" and permissions[1] in "w-" and
                permissions[2] in "x-" and permissions[3] in "ps", "process mapping extent/permissions")
        rows.append(dict(lo=lo, hi=hi, permissions=permissions, offset=int(offset, 16),
                         device=device, inode=int(inode), path=fields[5] if len(fields) == 6 else ""))
    require(rows and all(a["hi"] <= b["lo"] for a, b in zip(rows, rows[1:])),
            "complete ordered non-overlapping process map")
    return rows


def verify(folder):
    raw = read(folder / "LIBC.bin")
    identity = pin(raw)
    rows = loads(read(folder / "LIBC-BINDINGS.json"))
    mapped = mappings(read(folder / "PROCESS-MAPS.txt"))
    exports, segments = symbols(raw)
    require(type(rows) is list and len(rows) == len(FUNCTIONS), "all fixed actual libc capabilities")
    table = []
    bases = set()
    paths = set()
    for name, row in zip(FUNCTIONS, rows):
        require(set(row) == {"name", "pointer", "loaded_base", "library_path", "library",
                             "observed_symbol", "observed_symbol_address"} and row["name"] == name and
                row["library"] == identity and type(row["pointer"]) is int and
                type(row["loaded_base"]) is int and 0 < row["loaded_base"] < row["pointer"] < 1 << 64 and
                type(row["library_path"]) is str and Path(row["library_path"]).is_absolute() and
                Path(row["library_path"]).name == "libc.so.6", "complete actual libc binding")
        relative = row["pointer"] - row["loaded_base"]
        require(relative in exports.get(name, set()), "requested actual symbol equals its complete ELF definition")
        require(type(row["observed_symbol"]) is str and
                type(row["observed_symbol_address"]) is int and
                row["observed_symbol_address"] == row["pointer"] and
                relative in exports.get(row["observed_symbol"], set()),
                "actual dladdr alias is the same exact exported function")
        require(any(s["mask"] & 1 and s["address"] <= relative < s["address"] + s["size"] for s in segments),
                "every actual libc address belongs to file-backed executable ELF bytes")
        require(any(m["path"] == row["library_path"] and m["offset"] == 0 and
                    m["lo"] == row["loaded_base"] for m in mapped), "actual library base mapping")
        owners = [m for m in mapped if m["lo"] <= row["pointer"] < m["hi"]]
        require(len(owners) == 1 and owners[0]["path"] == row["library_path"] and
                owners[0]["permissions"][2] == "x" and owners[0]["permissions"][1] != "w",
                "actual function is loaded from the retained read/execute library mapping")
        bases.add(row["loaded_base"])
        paths.add(row["library_path"])
        table.append(row["pointer"])
    require(len(bases) == len(paths) == 1 and len(set(table)) == len(FUNCTIONS), "one exact library and distinct fixed functions")
    return dict(library=identity, bindings=rows, table=struct.pack("<"+str(len(FUNCTIONS)+1)+"Q", *table, 0), maps=mapped)

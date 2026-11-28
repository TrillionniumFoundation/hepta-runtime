"""Author a HIA static ELF64/x86-64 linker; this helper never links objects.

The checked-in HIA program parses section/symbol/rela records, resolves exact
names and bindings, validates every relocation, lays out RX/RW segments, and
emits ET_EXEC. It has no filesystem/linker/host-parser calls. The caller chooses
a zero-argument scalar C-ABI entry. Limits are this application's separate
profile, not changes to the compiler's 1-MiB input or workspace ceilings.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

WIRE_LIMIT = 8 << 20
OUTPUT_LIMIT = 8 << 20
WORKSPACE_BYTES = 16 << 20
MAGIC = int.from_bytes(b'HIALNK01', 'little')
INVALID, NO_SPACE = 0xffffffff, 0xfffffffe
SOURCE = '''
def link(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 16777216:
        return 4294967294
    if length(s) < 32 or length(s) > 8388608:
        return 4294967295
    if uint(s, 0, 8) != MAGIC or uint(s, 24, 8) != 0:
        return 4294967295
    count = uint(s, 8, 8)
    name = uint(s, 16, 8)
    if count == 0 or count > 64 or name == 0 or name > 4096 or name > length(s) - 32:
        return 4294967295
    fill_range(w, 0, 256, 0)
    put(w, 0, count)
    put(w, 40, 256)
    put(w, 72, 32)
    put(w, 80, name)
    if objects(s, w) == 0:
        return 4294967295
    data = aligned(get(w, 40), 4096)
    if data > 8388608 or get(w, 48) > 8388608 - data:
        return 4294967294
    total = data + get(w, 48)
    if length(o) < total:
        return 4294967294
    put(w, 56, data)
    put(w, 64, total)
    i = 0
    while i < get(w, 8):
        sec = 16384 + i * 48
        if (get(w, sec + 16) & 3) == 3:
            put(w, sec + 24, get(w, sec + 24) + data)
        i = i + 1
    if symbols(s, w) == 0:
        return 4294967295
    found = global_find(s, w, 32, name)
    if found == 0:
        return 4294967295
    record = get(w, found + 16)
    flags = get(w, record + 24)
    if ((flags >> 8) & 255) != 2 or ((flags >> 16) & 255) != 1 or ((flags >> 24) & 4) == 0:
        return 4294967295
    put(w, 88, get(w, record + 16) - 4194304)
    fill_range(w, 3145728, 8388608, 0)
    if relocations(s, w) == 0:
        return 4294967295
    fill_range(o, 0, total, 0)
    headers(o, w)
    i = 0
    while i < get(w, 8):
        sec = 16384 + i * 48
        if (get(w, sec + 16) & 2) != 0 and get(w, sec + 32) == 1:
            copy_bytes(s, o, get(w, sec), get(w, sec + 24), get(w, sec + 8))
        i = i + 1
    i = 0
    while i < get(w, 32):
        patch = 1572864 + i * 24
        write(o, get(w, patch), get(w, patch + 16), get(w, patch + 8))
        i = i + 1
    return total

def objects(s:readbuf, w:mutbuf) -> u64:
    pos = 32 + get(w, 80)
    obj = 0
    while obj < get(w, 0):
        if within(length(s), pos, 8) == 0:
            return 0
        size = uint(s, pos, 8)
        pos = pos + 8
        if size < 64 or within(length(s), pos, size) == 0:
            return 0
        if uint(s, pos, 7) != 282584257676671 or (byte(s, pos + 7) != 0 and byte(s, pos + 7) != 3) or byte(s, pos + 8) != 0:
            return 0
        if uint(s, pos + 16, 8) != 4299030529 or uint(s, pos + 24, 8) != 0 or uint(s, pos + 32, 8) != 0:
            return 0
        if uint(s, pos + 48, 4) != 0 or uint(s, pos + 52, 2) != 64 or uint(s, pos + 56, 2) != 0 or uint(s, pos + 58, 2) != 64:
            return 0
        table = uint(s, pos + 40, 8)
        count = uint(s, pos + 60, 2)
        strings = uint(s, pos + 62, 2)
        if count == 0 or count > 4096 - get(w, 8) or strings >= count or table < 64 or within(size, table, count * 64) == 0:
            return 0
        record = 4096 + obj * 80
        fill_range(w, record, 80, 0)
        put(w, record, pos)
        put(w, record + 8, size)
        put(w, record + 16, get(w, 8))
        put(w, record + 24, count)
        put(w, record + 72, count)
        i = 0
        while i < count:
            h = pos + table + i * 64
            kind = uint(s, h + 4, 4)
            flags = uint(s, h + 8, 8)
            offset = uint(s, h + 24, 8)
            extent = uint(s, h + 32, 8)
            align = uint(s, h + 48, 8)
            if i == 0:
                j = 0
                while j < 64:
                    if byte(s, h + j) != 0:
                        return 0
                    j = j + 1
            if kind != 8 and within(size, offset, extent) == 0:
                return 0
            if align == 0:
                align = 1
            if align > 4096 or (align & (align - 1)) != 0:
                return 0
            # Our startup has neither CET feature. GNU FEATURE_1_AND therefore
            # intersects to zero, just as ld with this startup object. Admit
            # only that understood property; never discard a needed/unknown
            # property or arbitrary allocated note.
            if kind == 7 and (flags & 2) != 0:
                if flags != 2 or property_note(s, pos + offset, extent) == 0:
                    return 0
                flags = 0
            sec = 16384 + (get(w, 8) + i) * 48
            put(w, sec, pos + offset)
            put(w, sec + 8, extent)
            put(w, sec + 16, flags)
            put(w, sec + 24, 0)
            put(w, sec + 32, kind)
            put(w, sec + 40, align)
            if (flags & 2) != 0:
                if (kind != 1 and kind != 8) or (flags & 18446744073709551608) != 0 or (flags & 5) == 5 or (kind == 8 and (flags & 4) != 0):
                    return 0
                field = 40
                if (flags & 1) != 0:
                    field = 48
                out = aligned(get(w, field), align)
                if out > 8388608 or extent > 8388608 - out:
                    return 0
                put(w, sec + 24, out)
                put(w, field, out + extent)
            if kind == 2:
                if get(w, record + 72) != count or flags != 0 or uint(s, h + 56, 8) != 24 or extent == 0 or extent % 24 != 0:
                    return 0
                link = uint(s, h + 40, 4)
                if link >= count:
                    return 0
                sh = pos + table + link * 64
                str_at = uint(s, sh + 24, 8)
                str_size = uint(s, sh + 32, 8)
                if uint(s, sh + 4, 4) != 3 or uint(s, sh + 8, 8) != 0 or str_size == 0 or within(size, str_at, str_size) == 0 or byte(s, pos + str_at) != 0:
                    return 0
                if extent // 24 > 32768 - get(w, 16) or uint(s, h + 44, 4) > extent // 24:
                    return 0
                put(w, record + 32, h)
                put(w, record + 40, extent // 24)
                put(w, record + 48, pos + str_at)
                put(w, record + 56, str_size)
                put(w, record + 64, get(w, 16))
                put(w, record + 72, i)
                put(w, 16, get(w, 16) + extent // 24)
            if kind == 9 and extent != 0:
                return 0
            i = i + 1
        if get(w, record + 72) == count:
            return 0
        put(w, 8, get(w, 8) + count)
        pos = pos + size
        obj = obj + 1
    if pos != length(s):
        return 0
    return 1

def symbols(s:readbuf, w:mutbuf) -> u64:
    obj = 0
    while obj < get(w, 0):
        record = 4096 + obj * 80
        i = 0
        while i < get(w, record + 40):
            if read_symbol(s, w, record, i) == 0:
                return 0
            i = i + 1
        obj = obj + 1
    return 1

def read_symbol(s:readbuf, w:mutbuf, record:u64, i:u64) -> u64:
    h = get(w, record + 32)
    table = get(w, record) + uint(s, h + 24, 8)
    local = uint(s, h + 44, 4)
    at = table + i * 24
    sym = 262144 + (get(w, record + 64) + i) * 32
    name = uint(s, at, 4)
    binding = byte(s, at + 4) >> 4
    kind = byte(s, at + 4) & 15
    section = uint(s, at + 6, 2)
    value = uint(s, at + 8, 8)
    extent = uint(s, at + 16, 8)
    if (binding != 0 and binding != 1 and binding != 2) or kind > 4 or byte(s, at + 5) > 3:
        return 0
    if (i < local and binding != 0) or (i >= local and binding == 0):
        return 0
    n = string_size(s, get(w, record + 48), get(w, record + 56), name)
    if n == 4294967295 or (binding != 0 and n == 0):
        return 0
    put(w, sym, get(w, record + 48) + name)
    put(w, sym + 8, n)
    defined = 0
    flags = 0
    if i == 0:
        j = 0
        while j < 24:
            if byte(s, at + j) != 0:
                return 0
            j = j + 1
    if section == 0:
        if value != 0 or extent != 0:
            return 0
    else:
        if section == 65521:
            defined = 2
        else:
            if section >= get(w, record + 24):
                return 0
            sec = 16384 + (get(w, record + 16) + section) * 48
            flags = get(w, sec + 16)
            if (flags & 2) == 0:
                # File/debug-only symbols have no runtime address;
                # record them as undefined, refusing any actual use.
                defined = 0
            else:
                if value > get(w, sec + 8) or extent > get(w, sec + 8) - value:
                    return 0
                defined = 1
                value = 4194304 + get(w, sec + 24) + value
    put(w, sym + 16, value)
    put(w, sym + 24, binding | (kind << 8) | (defined << 16) | (flags << 24))
    if binding != 0 and defined != 0:
        old = global_find(s, w, get(w, sym), n)
        if old != 0:
            previous = get(w, old + 24)
            if previous == 1 and binding == 1:
                return 0
            if previous == 2 and binding == 1:
                put(w, old + 16, sym)
                put(w, old + 24, binding)
        else:
            if get(w, 24) >= 8192:
                return 0
            old = 1310720 + get(w, 24) * 32
            put(w, old, get(w, sym))
            put(w, old + 8, n)
            put(w, old + 16, sym)
            put(w, old + 24, binding)
            put(w, 24, get(w, 24) + 1)
    return 1

def relocations(s:readbuf, w:mutbuf) -> u64:
    obj = 0
    while obj < get(w, 0):
        record = 4096 + obj * 80
        table = get(w, record) + uint(s, get(w, record) + 40, 8)
        i = 0
        while i < get(w, record + 24):
            h = table + i * 64
            if uint(s, h + 4, 4) == 4:
                count = uint(s, h + 32, 8)
                target = uint(s, h + 44, 4)
                if uint(s, h + 56, 8) != 24 or count % 24 != 0 or uint(s, h + 40, 4) != get(w, record + 72) or target >= get(w, record + 24):
                    return 0
                sec = 16384 + (get(w, record + 16) + target) * 48
                if (get(w, sec + 16) & 2) == 0:
                    if count != 0:
                        return 0
                j = 0
                while j < count:
                    at = get(w, record) + uint(s, h + 24, 8) + j
                    if relocate_one(s, w, record, sec, at) == 0:
                        return 0
                    j = j + 24
            i = i + 1
        obj = obj + 1
    return 1

def relocate_one(s:readbuf, w:mutbuf, record:u64, sec:u64, at:u64) -> u64:
    offset = uint(s, at, 8)
    kind = uint(s, at + 8, 4)
    symbol = uint(s, at + 12, 4)
    addend = uint(s, at + 16, 8)
    if kind != 0:
        width = 4
        if kind == 1:
            width = 8
        else:
            if kind != 2 and kind != 4 and kind != 10 and kind != 11:
                return 0
        if within(get(w, sec + 8), offset, width) == 0 or symbol >= get(w, record + 40):
            return 0
        sym = 262144 + (get(w, record + 64) + symbol) * 32
        info = get(w, sym + 24)
        address = get(w, sym + 16)
        if (info & 255) != 0:
            found = global_find(s, w, get(w, sym), get(w, sym + 8))
            if found == 0:
                if (info & 255) != 2:
                    return 0
                address = 0
            else:
                address = get(w, get(w, found + 16) + 16)
        else:
            if ((info >> 16) & 255) == 0:
                if symbol != 0:
                    return 0
                address = 0
        patch = get(w, sec + 24) + offset
        value = address + addend
        if kind == 2 or kind == 4:
            value = value - (4194304 + patch)
        if kind == 10 and value > 4294967295:
            return 0
        if (kind == 2 or kind == 4 or kind == 11) and value > 2147483647 and value < 18446744071562067968:
            return 0
        if get(w, 32) >= 32768:
            return 0
        k = 0
        while k < width:
            if byte(w, 3145728 + patch + k) != 0:
                return 0
            store(w, 3145728 + patch + k, 1)
            k = k + 1
        p = 1572864 + get(w, 32) * 24
        put(w, p, patch)
        put(w, p + 8, width)
        put(w, p + 16, value)
        put(w, 32, get(w, 32) + 1)
    return 1

def headers(o:mutbuf, w:mutbuf) -> u64:
    write(o, 0, 282584257676671, 8)
    write(o, 16, 4299030530, 8)
    put(o, 24, 4194536)
    put(o, 32, 64)
    write(o, 52, 12888571968, 8)
    # Exactly RX text/rodata, RW data/zero initialized bss, and RW nonexec stack.
    put(o, 64, 21474836481)
    put(o, 80, 4194304)
    put(o, 88, 4194304)
    put(o, 96, get(w, 40))
    put(o, 104, get(w, 40))
    put(o, 112, 4096)
    put(o, 120, 25769803777)
    put(o, 128, get(w, 56))
    put(o, 136, 4194304 + get(w, 56))
    put(o, 144, 4194304 + get(w, 56))
    put(o, 152, get(w, 48))
    put(o, 160, get(w, 48))
    put(o, 168, 4096)
    put(o, 176, 27455186257)
    put(o, 224, 16)
    # SysV zero-argument entry, scalar result -> Linux exit status.
    write(o, 232, 264864245804337, 6)
    store(o, 238, 232)
    write(o, 239, get(w, 88) - 243, 4)
    write(o, 243, 260798122312, 8)
    write(o, 251, 185533711, 4)
    return 0

def property_note(s:readbuf, at:u64, size:u64) -> u64:
    if size < 16 or uint(s, at, 4) != 4 or uint(s, at + 8, 4) != 5 or uint(s, at + 12, 4) != 5590599:
        return 0
    desc = uint(s, at + 4, 4)
    if desc != size - 16 or (desc & 7) != 0:
        return 0
    i = 16
    while i < size:
        if size - i < 16 or uint(s, at + i, 4) != 3221225474 or uint(s, at + i + 4, 4) != 4 or uint(s, at + i + 8, 4) > 3:
            return 0
        i = i + 16
    return 1

def global_find(s:readbuf, w:mutbuf, at:u64, size:u64) -> u64:
    i = 0
    while i < get(w, 24):
        row = 1310720 + i * 32
        if get(w, row + 8) == size:
            j = 0
            while j < size and byte(s, at + j) == byte(s, get(w, row) + j):
                j = j + 1
            if j == size:
                return row
        i = i + 1
    return 0

def string_size(s:readbuf, at:u64, size:u64, offset:u64) -> u64:
    if offset >= size:
        return 4294967295
    i = 0
    while i < size - offset and i <= 4096:
        if byte(s, at + offset + i) == 0:
            return i
        i = i + 1
    return 4294967295

def within(size:u64, at:u64, count:u64) -> u64:
    if count > size:
        return 0
    if at > size - count:
        return 0
    return 1

def aligned(value:u64, align:u64) -> u64:
    return (value + align - 1) & (0 - align)

def uint(s:readbuf, at:u64, size:u64) -> u64:
    value = 0
    i = 0
    while i < size:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def write(o:mutbuf, at:u64, value:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0

def put(w:mutbuf, at:u64, value:u64) -> u64:
    return write(w, at, value, 8)

def copy_bytes(s:readbuf, o:mutbuf, source:u64, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, target + i, byte(s, source + i))
        i = i + 1
    return 0
'''


def source_program():
    return SOURCE.replace('MAGIC', str(MAGIC))


class LinkerBuilder(Builder):
    def expr(self, value):
        if isinstance(value, ast.BinOp) and isinstance(value.op, (ast.Mod, ast.FloorDiv)):
            left, right = self.expr(value.left), self.expr(value.right)
            return self.op('int.rem.checked' if isinstance(value.op, ast.Mod) else 'int.div.checked', [left, right], left[1])
        return super().expr(value)


def document():
    nodes = ast.parse(source_program()).body
    names = {n.name:'f'+str(i) for i,n in enumerate(nodes)}
    sigs = {n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    functions = []
    for n in nodes:
        b = LinkerBuilder(n,names,sigs,total_scalar_functions(nodes));b.statements(n.body)
        functions.append({'name':names[n.name],'params':[b.param(p) for p in b.params],
            'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'elf_static_linker','functions':functions})


def main():
    path = Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/elf_static_linker.hepta'
    path.write_text(render_assembly(document()))
    print(path.name,path.stat().st_size)


if __name__ == '__main__':main()

"""Author input for the HIA Bellman result serializer; never used at runtime."""

SOURCE = '''
def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 64:
        return 4294967295
    if get(s, 0) != INPUT_MAGIC or get(s, 8) != 1:
        return 4294967295
    if get(s, 40) != 0 or get(s, 48) != 0 or get(s, 56) != 0:
        return 4294967295
    core = get(s, 16)
    commitment = get(s, 24)
    if core < 200 or core > 295040 or commitment < 128 or commitment > 8388736:
        return 4294967295
    if length(s) != 64 + core + commitment:
        return 4294967295
    if finite(get(s, 32)) == 0 or (get(s, 32) >> 63) != 0:
        return 4294967295
    if valid_core(s, core) == 0 or valid_commitment(s, 64 + core, commitment) == 0:
        return 4294967295
    if length(o) < 64:
        return 4294967294
    count = get(s, 72)
    capacity = 20480 + count * 256
    if length(w) < capacity:
        return header(o, 2, 0, capacity)
    put(w, 12288, 0)
    put(w, 12296, 0)
    render(s, w, 64 + core)
    if w_get(w, 12296) != 0:
        return 4294967292
    size = w_get(w, 12288)
    if length(o) < 64 + size:
        return header(o, 3, 0, 64 + size)
    header(o, 0, size, 0)
    index = 0
    while index < size:
        store(o, 64 + index, byte(w, 16384 + index))
        index = index + 1
    return 64 + size

def valid_core(s:readbuf, extent:u64) -> u64:
    if get(s, 64) != CORE_MAGIC:
        return 0
    count = get(s, 72)
    if count == 0 or count > 4096 or extent != 128 + count * 72:
        return 0
    legal = get(s, 80)
    continuing = get(s, 88)
    branches = get(s, 96)
    if legal < count or legal > count * 6 or continuing > count * 2:
        return 0
    if branches > 24576 or branches > continuing * 3 or get(s, 104) > branches:
        return 0
    if get(s, 120) != count * 256 + legal * 64 + branches * 128:
        return 0
    if get(s, 128) > get(s, 136) or get(s, 136) > count or get(s, 144) > 1:
        return 0
    if get(s, 144) == 0 and get(s, 152) != 0:
        return 0
    if finite(get(s, 112)) == 0 or finite(get(s, 152)) == 0 or finite(get(s, 160)) == 0:
        return 0
    if get(s, 168) != 0 or get(s, 176) != 0 or get(s, 184) != 0:
        return 0
    index = 0
    actions = 0
    while index < count:
        at = 192 + index * 72
        mask = get(s, at)
        selected = get(s, at + 8)
        if mask == 0 or mask > 63 or selected > 5:
            return 0
        if ((mask >> selected) & 1) == 0:
            return 0
        if finite(get(s, at + 16)) == 0 or get(s, at + 16) != get(s, at + 24 + selected * 8):
            return 0
        action = 0
        while action < 6:
            bits = get(s, at + 24 + action * 8)
            if ((mask >> action) & 1) != 0:
                if finite(bits) == 0:
                    return 0
                actions = actions + 1
            else:
                if bits != 0:
                    return 0
            action = action + 1
        index = index + 1
    if actions != legal:
        return 0
    return 1

def valid_commitment(s:readbuf, at:u64, extent:u64) -> u64:
    if get(s, at) != COMMITMENT_MAGIC:
        return 0
    size = get(s, at + 8)
    if size > 8388608 or extent != 128 + size:
        return 0
    if get(s, at + 112) != 0 or get(s, at + 120) != 0:
        return 0
    return 1

def header(o:mutbuf, status:u64, size:u64, capacity:u64) -> u64:
    put(o, 0, OUTPUT_MAGIC)
    put(o, 8, status)
    put(o, 16, size)
    put(o, 24, capacity)
    put(o, 32, 0)
    put(o, 40, 0)
    put(o, 48, 0)
    put(o, 56, 0)
    return 64

def finite(bits:u64) -> u64:
    if ((bits >> 52) & 2047) == 2047:
        return 0
    return 1

def render_states(s:readbuf, w:mutbuf) -> u64:
    text_array_open(w)
    count = get(s, 72)
    index = 0
    while index < count:
        if index != 0:
            text_comma(w)
        at = 192 + index * 72
        mask = get(s, at)
        text_state_open(w)
        emit_integer(w, get(s, at + 8))
        text_q_open(w)
        action = 0
        while action < 6:
            if action != 0:
                text_comma(w)
            if ((mask >> action) & 1) != 0:
                emit_float(w, get(s, at + 24 + action * 8))
            else:
                text_null(w)
            action = action + 1
        text_value(w)
        emit_float(w, get(s, at + 16))
        text_object_close(w)
        index = index + 1
    return text_array_close(w)

def reserve(w:mutbuf, size:u64) -> u64:
    if w_get(w, 12296) != 0:
        return 0
    cursor = w_get(w, 12288)
    if size > 1052672 or cursor > 1052672 - size:
        put(w, 12296, 1)
        return 0
    if length(w) < 16384 + cursor + size:
        put(w, 12296, 1)
        return 0
    put(w, 12288, cursor + size)
    return 16384 + cursor

def emit_float(w:mutbuf, bits:u64) -> u64:
    size = format_bits(w, bits)
    if size == 0 or size > 32:
        put(w, 12296, 1)
        return 0
    at = reserve(w, size)
    if at == 0:
        return 0
    index = 0
    while index < size:
        store(w, at + index, byte(w, 6144 + index))
        index = index + 1
    return 0

def emit_integer(w:mutbuf, value:u64) -> u64:
    count = 0
    while value != 0 or count == 0:
        quotient = (value * 3435973837) >> 35
        store(w, 10000 + count, 48 + value - quotient * 10)
        value = quotient
        count = count + 1
    at = reserve(w, count)
    if at == 0:
        return 0
    index = 0
    while index < count:
        store(w, at + index, byte(w, 10000 + count - 1 - index))
        index = index + 1
    return 0

def emit_digest(s:readbuf, w:mutbuf, begin:u64) -> u64:
    at = reserve(w, 64)
    if at == 0:
        return 0
    index = 0
    while index < 32:
        value = byte(s, begin + index)
        store(w, at + index * 2, hex_digit(value >> 4))
        store(w, at + index * 2 + 1, hex_digit(value & 15))
        index = index + 1
    return 0

def hex_digit(value:u64) -> u64:
    if value < 10:
        return 48 + value
    return 87 + value

def get(s:readbuf, at:u64) -> u64:
    index = 0
    value = 0
    while index < 8:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def w_get(w:mutbuf, at:u64) -> u64:
    index = 0
    value = 0
    while index < 8:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, at + index, value >> (index * 8))
        index = index + 1
    return 0
'''

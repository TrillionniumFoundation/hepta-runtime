"""Authoring input for the private HIA Bellman typed commitment owner."""

SOURCE = r'''
def commitment(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 56:
        return 4294967295
    if get(s, 0) != INPUT_MAGIC or get(s, 40) != 3552298066436507976:
        return 4294967295
    count = get(s, 48)
    if count > 4096 or length(s) != 56 + count * 720:
        return 4294967295
    if length(w) < 16384 or length(o) < 128:
        return 4294967293
    if frame_valid(s, count) == False:
        return 4294967295
    put(w, 12288, 0)
    put(w, 12296, 0)
    text_request_open(w)
    index = 0
    while index < count:
        if index != 0:
            text_comma(w)
        text_state_open(w)
        action = 0
        while action < 6:
            if action != 0:
                text_comma(w)
            emit_action(s, w, 56 + index * 720 + action * 120)
            action = action + 1
        text_array_object_close(w)
        if w_get(w, 12296) != 0:
            return w_get(w, 12296)
        index = index + 1
    text_array_object_close(w)
    failure = w_get(w, 12296)
    if failure != 0:
        return failure
    size = w_get(w, 12288)
    if length(o) < 128 + size:
        return 4294967293
    sha_init(w)
    sha_update(w, 16384, size)
    finish_to(w, 12000)
    identity_prefix(w)
    identity_hashes(s, w)
    sha_init(w)
    sha_update(w, 8192, IDENTITY_LENGTH)
    finish_to(w, 12032)
    put(o, 0, OUTPUT_MAGIC)
    put(o, 8, size)
    index = 0
    while index < 32:
        store(o, 16 + index, byte(w, 12000 + index))
        store(o, 48 + index, byte(s, 8 + index))
        store(o, 80 + index, byte(w, 12032 + index))
        index = index + 1
    put(o, 112, 0)
    put(o, 120, 0)
    index = 0
    while index < size:
        store(o, 128 + index, byte(w, 16384 + index))
        index = index + 1
    return 128 + size

def frame_valid(s:readbuf, count:u64) -> bool:
    state = 0
    while state < count:
        action = 0
        while action < 6:
            at = 56 + state * 720 + action * 120
            kind = get(s, at)
            if kind > 2:
                return False
            if kind == 0:
                if zero_span(s, at + 8, 112) == False:
                    return False
            if kind == 1:
                if zero_span(s, at + 16, 104) == False or finite(get(s, at + 8)) == False:
                    return False
            if kind == 2:
                branches = get(s, at + 16)
                if get(s, at + 8) != 0 or branches > 3:
                    return False
                if zero_span(s, at + 24 + branches * 32, (3 - branches) * 32) == False:
                    return False
                branch = 0
                while branch < branches:
                    where = at + 24 + branch * 32
                    if finite(get(s, where)) == False or get(s, where + 8) > 4294967295:
                        return False
                    if finite(get(s, where + 16)) == False or finite(get(s, where + 24)) == False:
                        return False
                    branch = branch + 1
            action = action + 1
        state = state + 1
    return True

def emit_action(s:readbuf, w:mutbuf, at:u64) -> u64:
    kind = get(s, at)
    if kind == 0:
        return text_null(w)
    if kind == 1:
        text_terminal_open(w)
        emit_float(w, get(s, at + 8))
        return text_object_close(w)
    text_continue_open(w)
    count = get(s, at + 16)
    index = 0
    while index < count:
        if index != 0:
            text_comma(w)
        emit_branch(s, w, at + 24 + index * 32)
        index = index + 1
    return text_array_object_close(w)

def emit_branch(s:readbuf, w:mutbuf, at:u64) -> u64:
    text_probability(w)
    emit_float(w, get(s, at))
    text_successor(w)
    emit_integer(w, get(s, at + 8))
    text_reward(w)
    emit_float(w, get(s, at + 16))
    text_fee(w)
    emit_float(w, get(s, at + 24))
    return text_object_close(w)

def reserve(w:mutbuf, size:u64) -> u64:
    if w_get(w, 12296) != 0:
        return 0
    cursor = w_get(w, 12288)
    if size > 8388608 or cursor > 8388608 - size:
        put(w, 12296, 4294967040)
        return 0
    if length(w) < 16384 + cursor + size:
        put(w, 12296, 4294967293)
        return 0
    put(w, 12288, cursor + size)
    return 16384 + cursor

def emit_float(w:mutbuf, bits:u64) -> u64:
    if w_get(w, 12296) != 0:
        return 0
    size = format_bits(w, bits)
    if size >= 4294967292:
        put(w, 12296, 4294967292)
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

def identity_hashes(s:readbuf, w:mutbuf) -> u64:
    index = 0
    while index < 32:
        value = byte(s, 8 + index)
        store(w, 8192 + PREFIX_LENGTH + index * 2, hex_digit(value >> 4))
        store(w, 8193 + PREFIX_LENGTH + index * 2, hex_digit(value & 15))
        value = byte(w, 12000 + index)
        store(w, 8257 + PREFIX_LENGTH + index * 2, hex_digit(value >> 4))
        store(w, 8258 + PREFIX_LENGTH + index * 2, hex_digit(value & 15))
        index = index + 1
    store(w, 8256 + PREFIX_LENGTH, 0)
    return 0

def hex_digit(value:u64) -> u64:
    if value < 10:
        return 48 + value
    return 87 + value

def finish_to(w:mutbuf, at:u64) -> u64:
    sha_finish(w)
    index = 0
    while index < 8:
        value = sha_word(w, 1024 + index * 8)
        part = 0
        while part < 4:
            store(w, at + index * 4 + part, (value >> ((3 - part) * 8)) & 255)
            part = part + 1
        index = index + 1
    return 0

def get(s:readbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(s, at + index) << (index * 8))
        index = index + 1
    return value

def w_get(w:mutbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, at + index, value & 255)
        value = value >> 8
        index = index + 1
    return 0

def finite(value:u64) -> bool:
    return ((value >> 52) & 2047) != 2047

def zero_span(s:readbuf, at:u64, count:u64) -> bool:
    index = 0
    while index < count:
        if byte(s, at + index) != 0:
            return False
        index = index + 1
    return True
'''

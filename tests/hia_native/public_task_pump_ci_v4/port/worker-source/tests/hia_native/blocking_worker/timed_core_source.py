"""Continuation machinery for the existing numerical Bellman function graph.

These helpers never perform Bellman arithmetic. The author redirects five
original edges and preserves every old numerical instruction and helper.
Clock/commitment acknowledgements are private fixed-caller capabilities.
"""

SOURCE = r'''
def admit(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(w) < 640 or (length(w) & 7) != 0 or length(o) < 64:
        return 4294967293
    t = length(w) - 512
    if length(s) == 64 and read64(s, 0) == INIT_MAGIC:
        if get(w, t) != 0:
            return 4294967295
        job = read64(s, 8)
        now = read64(s, 16)
        if job == 0 or now > 18446744043709551615 or read64(s, 24) != 1:
            return 4294967295
        i = 32
        while i < 64:
            if read64(s, i) != 0:
                return 4294967295
            i = i + 8
        i = 0
        while i < 512:
            if get(w, t + i) != 0:
                return 4294967295
            i = i + 8
        put(w, t, STATE_MAGIC)
        put(w, t + 16, job)
        put(w, t + 24, now)
        put(w, t + 32, now + 30000000000)
        put(w, t + 40, now)
        put(w, t + 96, length(w))
        put(o, 0, INIT_RESULT_MAGIC)
        put(o, 8, 64)
        put(o, 16, job)
        put(o, 24, now)
        put(o, 32, now + 30000000000)
        put(o, 40, 0)
        put(o, 48, 0)
        put(o, 56, 0)
        return 64
    if get(w, t) != STATE_MAGIC or get(w, t + 16) == 0:
        return 4294967295
    start = get(w, t + 24)
    if start > 18446744043709551615 or get(w, t + 32) != start + 30000000000:
        return 4294967295
    if get(w, t + 40) < start or get(w, t + 96) != length(w):
        return 4294967295
    if get(w, t + 104) != 0 or get(w, t + 112) != 0 or get(w, t + 120) != 0:
        return 4294967295
    i = 152
    while i < 256:
        if get(w, t + i) != 0:
            return 4294967295
        i = i + 8
    i = 448
    while i < 512:
        if get(w, t + i) != 0:
            return 4294967295
        i = i + 8
    phase = get(w, t + 8)
    if phase > 1:
        return 4294967295
    if phase == 0:
        if get(w, t + 48) != 0 or get(w, t + 56) != 0 or get(w, t + 64) != 0 or get(w, t + 72) != 0 or get(w, t + 80) != 0 or get(w, t + 88) != 0:
            return 4294967295
        i = 128
        while i < 448:
            if get(w, t + i) != 0:
                return 4294967295
            i = i + 8
        if length(s) < 16 or read64(s, 0) != CORE_MAGIC:
            return 4294967295
        count = read64(s, 8)
        if count == 0 or count > 4096:
            return 4294966785
        if length(s) != 16 + count * 720:
            return 4294967295
        size = 128 + count * 72
        if t < size or length(o) < size:
            return 4294967293
        put(w, t + 8, 3)
        put(w, t + 64, length(s))
        put(w, t + 72, length(o))
        put(w, t + 80, count)
        return 0
    if length(s) != get(w, t + 64) or length(o) != get(w, t + 72):
        return 4294967295
    if length(s) < 16 or read64(s, 0) != CORE_MAGIC or read64(s, 8) != get(w, t + 80):
        return 4294967295
    pc = get(w, t + 56)
    if pc < 1 or pc > 5:
        return 4294967295
    count = get(w, t + 80)
    if count == 0 or count > 4096 or length(s) != 16 + count * 720:
        return 4294967295
    size = 128 + count * 72
    if t < size or length(o) < size or get(w, t + 128) != count or get(w, t + 136) != size:
        return 4294967295
    index = get(w, t + 144)
    if pc == 2 or pc == 5:
        if index != 0:
            return 4294967295
    else:
        if index >= count:
            return 4294967295
    sequence = get(w, t + 48)
    if sequence == 0 or get(w, t + 88) != 0:
        return 4294967295
    kind = 1
    if pc == 2:
        kind = 2
    if get(w, t + 256) != EFFECT_MAGIC or get(w, t + 264) != sequence or get(w, t + 272) != kind or get(w, t + 280) != get(w, t + 16):
        return 4294967295
    if get(w, t + 288) != pc or get(w, t + 296) != index or get(w, t + 304) != start or get(w, t + 312) != get(w, t + 32):
        return 4294967295
    if get(w, t + 320) != length(s) or get(w, t + 328) != length(o) or get(w, t + 336) != size:
        return 4294967295
    i = 344
    while i < 384:
        if get(w, t + i) != 0:
            return 4294967295
        i = i + 8
    if get(w, t + 384) != ACK_MAGIC or get(w, t + 392) != sequence or get(w, t + 400) != kind or get(w, t + 408) != get(w, t + 16):
        return 4294967295
    if get(w, t + 432) != 0 or get(w, t + 440) != 0:
        return 4294967295
    now = get(w, t + 416)
    result = get(w, t + 424)
    if kind == 1:
        if result != 0 or now < get(w, t + 40):
            return 4294967295
        put(w, t + 40, now)
        if now >= get(w, t + 32):
            return finish(w, 4294966768)
    else:
        if now != 0 or result > 4294967295:
            return 4294967295
        if result != 0:
            return finish(w, result)
    put(w, t + 8, 3)
    i = 384
    while i < 448:
        put(w, t + i, 0)
        i = i + 8
    return pc

def pause(s:readbuf, o:mutbuf, w:mutbuf, pc:u64, count:u64, size:u64, index:u64) -> u64:
    t = length(w) - 512
    sequence = get(w, t + 48)
    if sequence == 18446744073709551615:
        return finish(w, 4294967295)
    if get(w, t + 8) != 3 or get(w, t + 64) != length(s) or get(w, t + 72) != length(o):
        return finish(w, 4294967295)
    kind = 1
    if pc == 2:
        kind = 2
    sequence = sequence + 1
    put(w, t + 8, 1)
    put(w, t + 48, sequence)
    put(w, t + 56, pc)
    put(w, t + 128, count)
    put(w, t + 136, size)
    put(w, t + 144, index)
    put(w, t + 256, EFFECT_MAGIC)
    put(w, t + 264, sequence)
    put(w, t + 272, kind)
    put(w, t + 280, get(w, t + 16))
    put(w, t + 288, pc)
    put(w, t + 296, index)
    put(w, t + 304, get(w, t + 24))
    put(w, t + 312, get(w, t + 32))
    put(w, t + 320, length(s))
    put(w, t + 328, length(o))
    put(w, t + 336, size)
    return 4294967264

def saved(w:mutbuf, index:u64) -> u64:
    return get(w, length(w) - 384 + index * 8)

def finish(w:mutbuf, result:u64) -> u64:
    t = length(w) - 512
    put(w, t + 8, 2)
    put(w, t + 88, result)
    return result
'''

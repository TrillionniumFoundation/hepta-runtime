"""Resumable typed Serde writer, with one CLOCK edge per original Write call.

The private input borrow is immutable for the whole invocation. The only
caller-writable live region is the 64-byte acknowledgement at tail + 384.
Original formatting and SHA helpers are imported by the author unchanged.
"""

SOURCE = r'''
def timed_commitment(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 16896 or (length(w) & 7) != 0 or length(o) < 64:
        return 4294967293
    if length(s) == 64 and old_10(s, 0) == INIT_MAGIC:
        return initialize(s, o, w)
    admission = admit(s, o, w)
    if admission != 0:
        return admission
    t = length(w) - 512
    size = next_fragment(s, w)
    if size == 0:
        return publish(s, o, w)
    if size > 32:
        return finish(w, size)
    sequence = old_11(w, t + 48)
    if sequence == 18446744073709551615:
        return finish(w, 4294967295)
    sequence = sequence + 1
    old_12(w, t + 8, 1)
    old_12(w, t + 48, sequence)
    old_12(w, t + 136, size)
    old_12(w, t + 256, EFFECT_MAGIC)
    old_12(w, t + 264, sequence)
    old_12(w, t + 272, 1)
    old_12(w, t + 280, old_11(w, t + 16))
    old_12(w, t + 288, old_11(w, t + 56))
    old_12(w, t + 296, old_11(w, t + 64))
    old_12(w, t + 304, old_11(w, t + 24))
    old_12(w, t + 312, old_11(w, t + 32))
    old_12(w, t + 320, old_11(w, t + 128))
    old_12(w, t + 328, size)
    old_12(w, t + 336, old_11(w, t + 72))
    old_12(w, t + 344, old_11(w, t + 80))
    old_12(w, t + 352, old_11(w, t + 88))
    return 4294967264

def initialize(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    t = length(w) - 512
    job = old_10(s, 8)
    start = old_10(s, 16)
    if job == 0 or start > 18446744043709551615 or old_10(s, 24) != 1:
        return 4294967295
    i = 32
    while i < 64:
        if old_10(s, i) != 0:
            return 4294967295
        i = i + 8
    i = 0
    while i < 512:
        if old_11(w, t + i) != 0:
            return 4294967295
        i = i + 8
    old_12(w, t, STATE_MAGIC)
    old_12(w, t + 16, job)
    old_12(w, t + 24, start)
    old_12(w, t + 32, start + 30000000000)
    old_12(w, t + 40, start)
    old_12(w, t + 112, length(w))
    old_12(o, 0, INIT_RESULT_MAGIC)
    old_12(o, 8, 64)
    old_12(o, 16, job)
    old_12(o, 24, start)
    old_12(o, 32, start + 30000000000)
    old_12(o, 40, 0)
    old_12(o, 48, 0)
    old_12(o, 56, 0)
    return 64

def admit(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    t = length(w) - 512
    if length(s) < 56 or old_10(s, 0) != INPUT_MAGIC or old_10(s, 40) != CORE_MAGIC:
        return 4294967295
    count = old_10(s, 48)
    if count > 4096 or length(s) != 56 + count * 720:
        return 4294967295
    if length(o) < 128:
        return 4294967293
    if old_11(w, t) != STATE_MAGIC or old_11(w, t + 16) == 0 or old_11(w, t + 112) != length(w):
        return 4294967295
    start = old_11(w, t + 24)
    if start > 18446744043709551615 or old_11(w, t + 32) != start + 30000000000 or old_11(w, t + 40) < start:
        return 4294967295
    i = 144
    while i < 224:
        if old_11(w, t + i) != 0:
            return 4294967295
        i = i + 8
    i = 448
    while i < 512:
        if old_11(w, t + i) != 0:
            return 4294967295
        i = i + 8
    phase = old_11(w, t + 8)
    if phase == 0:
        i = 48
        while i < 112:
            if old_11(w, t + i) != 0:
                return 4294967295
            i = i + 8
        if old_11(w, t + 120) != 0 or old_11(w, t + 128) != 0 or old_11(w, t + 136) != 0:
            return 4294967295
        i = 224
        while i < 448:
            if old_11(w, t + i) != 0:
                return 4294967295
            i = i + 8
        if old_1(s, count) == False:
            return 4294967295
        i = 0
        while i < 32:
            old_12(w, 12360 + i * 64, 0)
            i = i + 1
        old_12(w, t + 56, 1)
        old_12(w, t + 96, length(s))
        old_12(w, t + 104, length(o))
        old_12(w, t + 120, count)
        return 0
    if phase != 1 or length(s) != old_11(w, t + 96) or length(o) != old_11(w, t + 104) or count != old_11(w, t + 120):
        return 4294967295
    if old_11(w, t + 56) < 1 or old_11(w, t + 56) > 15 or old_11(w, t + 64) > count or old_11(w, t + 72) > 6 or old_11(w, t + 80) > 3 or old_11(w, t + 88) > 25:
        return 4294967295
    sequence = old_11(w, t + 48)
    cursor = old_11(w, t + 128)
    size = old_11(w, t + 136)
    if sequence == 0 or cursor > 8388608 or t < 16384 + cursor or size == 0 or size > 32:
        return 4294967295
    if old_11(w, t + 256) != EFFECT_MAGIC or old_11(w, t + 264) != sequence or old_11(w, t + 272) != 1 or old_11(w, t + 280) != old_11(w, t + 16):
        return 4294967295
    if old_11(w, t + 288) != old_11(w, t + 56) or old_11(w, t + 296) != old_11(w, t + 64) or old_11(w, t + 304) != start or old_11(w, t + 312) != old_11(w, t + 32):
        return 4294967295
    if old_11(w, t + 320) != cursor or old_11(w, t + 328) != size or old_11(w, t + 336) != old_11(w, t + 72) or old_11(w, t + 344) != old_11(w, t + 80) or old_11(w, t + 352) != old_11(w, t + 88):
        return 4294967295
    if old_11(w, t + 360) != 0 or old_11(w, t + 368) != 0 or old_11(w, t + 376) != 0:
        return 4294967295
    if old_11(w, t + 384) != ACK_MAGIC or old_11(w, t + 392) != sequence or old_11(w, t + 400) != 1 or old_11(w, t + 408) != old_11(w, t + 16):
        return 4294967295
    if old_11(w, t + 424) != 0 or old_11(w, t + 432) != 0 or old_11(w, t + 440) != 0:
        return 4294967295
    now = old_11(w, t + 416)
    if now < old_11(w, t + 40):
        return 4294967295
    old_12(w, t + 40, now)
    if now >= old_11(w, t + 32):
        return finish(w, 4294966753)
    if cursor > 8388608 - size:
        return finish(w, 4294967040)
    if t < 16384 + cursor + size:
        return finish(w, 4294967293)
    i = 0
    while i < size:
        store(w, 16384 + cursor + i, byte(w, t + 224 + i))
        i = i + 1
    old_12(w, t + 128, cursor + size)
    old_12(w, t + 8, 3)
    i = 384
    while i < 448:
        old_12(w, t + i, 0)
        i = i + 8
    return 0

def next_fragment(s:readbuf, w:mutbuf) -> u64:
    t = length(w) - 512
    while True:
        pc = old_11(w, t + 56)
        index = old_11(w, t + 64)
        action = old_11(w, t + 72)
        branch = old_11(w, t + 80)
        token = old_11(w, t + 88)
        if pc == 1 or pc == 3 or pc == 6 or pc == 7 or pc == 9 or pc == 10 or pc == 12 or pc == 14:
            limit = group_size(pc)
            if token < limit:
                old_12(w, t + 88, token + 1)
                return group_fragment(s, w, pc, token, 56 + index * 720 + action * 120 + branch * 32)
            old_12(w, t + 88, 0)
            if pc == 1:
                old_12(w, t + 56, 2)
            if pc == 3:
                old_12(w, t + 56, 4)
            if pc == 6 or pc == 10:
                old_12(w, t + 56, 11)
            if pc == 7:
                old_12(w, t + 56, 8)
            if pc == 9:
                old_12(w, t + 80, branch + 1)
                old_12(w, t + 56, 8)
            if pc == 12:
                old_12(w, t + 56, 13)
            if pc == 14:
                old_12(w, t + 56, 15)
        else:
            if pc == 2:
                if index == old_11(w, t + 120):
                    old_12(w, t + 56, 14)
                else:
                    old_12(w, t + 56, 3)
                    if index != 0:
                        return literal(w, 9)
            if pc == 4:
                if action == 6:
                    old_12(w, t + 56, 12)
                else:
                    old_12(w, t + 56, 5)
                    if action != 0:
                        return literal(w, 9)
            if pc == 5:
                kind = old_10(s, 56 + index * 720 + action * 120)
                if kind == 0:
                    old_12(w, t + 56, 11)
                    return literal(w, 8)
                if kind == 1:
                    old_12(w, t + 56, 6)
                if kind == 2:
                    old_12(w, t + 56, 7)
            if pc == 8:
                if branch == old_10(s, 72 + index * 720 + action * 120):
                    old_12(w, t + 56, 10)
                else:
                    old_12(w, t + 56, 9)
                    if branch != 0:
                        return literal(w, 9)
            if pc == 11:
                old_12(w, t + 72, action + 1)
                old_12(w, t + 80, 0)
                old_12(w, t + 56, 4)
            if pc == 13:
                old_12(w, t + 64, index + 1)
                old_12(w, t + 72, 0)
                old_12(w, t + 56, 2)
            if pc == 15:
                return 0
    return 4294967295

def stage_float(w:mutbuf, bits:u64) -> u64:
    slot = 12352 + ((((bits ^ (bits >> 32)) * 11400714819323198485) >> 59) * 64)
    size = old_11(w, slot + 8)
    source = 6144
    if size != 0 and size <= 32 and old_11(w, slot) == bits:
        source = slot + 16
    else:
        size = old_37(w, bits)
        if size >= 4294967292 or size == 0 or size > 32:
            return 4294967292
        old_12(w, slot, bits)
        index = 0
        while index < size:
            store(w, slot + 16 + index, byte(w, 6144 + index))
            index = index + 1
        old_12(w, slot + 8, size)
    clear_fragment(w)
    t = length(w) - 512
    index = 0
    while index < size:
        store(w, t + 224 + index, byte(w, source + index))
        index = index + 1
    return size

def stage_integer(w:mutbuf, value:u64) -> u64:
    count = 0
    while value != 0 or count == 0:
        quotient = (value * 3435973837) >> 35
        store(w, 10000 + count, 48 + value - quotient * 10)
        value = quotient
        count = count + 1
    clear_fragment(w)
    t = length(w) - 512
    index = 0
    while index < count:
        store(w, t + 224 + index, byte(w, 10000 + count - 1 - index))
        index = index + 1
    return count

def clear_fragment(w:mutbuf) -> u64:
    t = length(w) - 512
    old_12(w, t + 224, 0)
    old_12(w, t + 232, 0)
    old_12(w, t + 240, 0)
    old_12(w, t + 248, 0)
    return 0

def publish(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    t = length(w) - 512
    size = old_11(w, t + 128)
    if length(o) < 128 + size:
        return finish(w, 4294967293)
    old_42(w)
    old_43(w, 16384, size)
    old_9(w, 12000)
    old_27(w)
    old_7(s, w)
    old_42(w)
    old_43(w, 8192, 184)
    old_9(w, 12032)
    old_12(o, 0, OUTPUT_MAGIC)
    old_12(o, 8, size)
    index = 0
    while index < 32:
        store(o, 16 + index, byte(w, 12000 + index))
        store(o, 48 + index, byte(s, 8 + index))
        store(o, 80 + index, byte(w, 12032 + index))
        index = index + 1
    old_12(o, 112, 0)
    old_12(o, 120, 0)
    index = 0
    while index < size:
        store(o, 128 + index, byte(w, 16384 + index))
        index = index + 1
    return finish(w, 128 + size)

def finish(w:mutbuf, result:u64) -> u64:
    old_12(w, length(w) - 504, 2)
    return result
'''

"""HIA policy for two permits owned by actual admitted blocking workers."""

SOURCE = r'''
def pool(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 64 or read64(s, 0) != REQUEST_MAGIC:
        return 4294967295
    if read64(s, 40) != 0 or read64(s, 48) != 0 or read64(s, 56) != 0:
        return 4294967295
    command = read64(s, 8)
    job = read64(s, 16)
    now = read64(s, 24)
    argument = read64(s, 32)
    if command > 12:
        return 4294967295
    if command != 3 and command != 5 and command != 12 and now != 0:
        return 4294967295
    if command != 5 and command != 11 and command != 12 and argument != 0:
        return 4294967295
    if command == 0 or command == 1 or command == 9 or command == 10:
        if job != 0:
            return 4294967295
    else:
        if job == 0:
            return 4294967295
    if argument > 4294967295:
        return 4294967295
    if length(o) < 128 or length(w) < 128:
        return 4294967294
    if command == 0:
        at = 0
        while at < 128:
            if get(w, at) != 0:
                return 4294967295
            at = at + 8
        put(w, 0, STATE_MAGIC)
        put(w, 72, 128)
        return response(o, w, command, 0, 0, 0)
    if valid_pool(w) == False:
        return 4294967295
    if command == 10:
        return response(o, w, command, 0, 0, 0)
    if command == 9:
        at = 128
        while at < get(w, 72):
            if get(w, at + 8) == 1:
                return 4294967295
            at = at + 128
        put(w, 16, 1)
        at = 128
        while at < get(w, 72):
            if get(w, at) != 0 and get(w, at + 16) == 0:
                put(w, at + 16, 1)
                put(w, 48, get(w, 48) + 1)
                retire_if_finished(w, at)
            at = at + 128
        return response(o, w, command, 0, 0, 0)
    if command == 1:
        if get(w, 16) != 0:
            return response(o, w, command, 0, 0, 2)
        if get(w, 24) == 2:
            return response(o, w, command, 0, 0, 1)
        if get(w, 8) == 18446744073709551615:
            return response(o, w, command, 0, 0, 5)
        at = 128
        while at < get(w, 72) and get(w, at) != 0:
            at = at + 128
        if at == get(w, 72) and length(w) - at < 128:
            put(o, 0, GROW_MAGIC)
            put(o, 8, 1)
            put(o, 16, at + 128)
            put(o, 24, 0)
            return 4294967248
        if at == get(w, 72):
            clear_record(w, at)
            put(w, 72, at + 128)
        job = get(w, 8) + 1
        put(w, 8, job)
        put(w, at, job)
        put(w, at + 8, 1)
        put(w, at + 24, 1)
        put(w, 24, get(w, 24) + 1)
        put(w, 64, get(w, 64) + 1)
        return response(o, w, command, job, at, 0)
    at = find(w, job)
    if at == 0:
        return 4294967295
    phase = get(w, at + 8)
    caller = get(w, at + 16)
    if command == 2:
        if phase != 1:
            return 4294967295
        put(w, at + 8, 2)
        put(w, 32, get(w, 32) + 1)
        return response(o, w, command, job, at, 0)
    if command == 3:
        if phase != 2 or now > 18446744043709551615:
            return 4294967295
        put(w, at + 8, 3)
        put(w, at + 32, now)
        put(w, at + 40, now + 30000000000)
        put(w, 88, get(w, 88) + 1)
        return response(o, w, command, job, at, 0)
    if command == 4:
        if caller != 0:
            return 4294967295
        if phase == 4:
            return response(o, w, command, job, at, 0)
        return response(o, w, command, job, at, 3)
    if command == 5:
        if phase != 3 or now < get(w, at + 32):
            return 4294967295
        put(w, at + 8, 4)
        put(w, at + 24, 0)
        put(w, at + 48, now)
        put(w, at + 64, argument)
        put(w, 24, get(w, 24) - 1)
        put(w, 40, get(w, 40) + 1)
        return response(o, w, command, job, at, 0)
    if command == 6:
        if phase == 1 or caller == 2:
            return 4294967295
        if caller == 0:
            put(w, at + 16, 1)
            put(w, 48, get(w, 48) + 1)
        code = response(o, w, command, job, at, 0)
        retire_then_update(o, w, at)
        return code
    if command == 7:
        if caller != 0:
            return 4294967295
        if phase != 4:
            return response(o, w, command, job, at, 3)
        put(w, at + 16, 2)
        put(w, 56, get(w, 56) + 1)
        code = response(o, w, command, job, at, 0)
        retire_then_update(o, w, at)
        return code
    if command == 8:
        if phase != 4 or get(w, at + 72) != 0:
            return 4294967295
        put(w, at + 72, 1)
        code = response(o, w, command, job, at, 0)
        retire_then_update(o, w, at)
        return code
    if command == 11:
        if phase != 1 or argument == 0 or argument > 4095:
            return 4294967295
        put(w, at + 8, 4)
        put(w, at + 24, 0)
        put(w, at + 64, argument)
        put(w, at + 72, 1)
        put(w, at + 80, 1)
        put(w, 24, get(w, 24) - 1)
        put(w, 40, get(w, 40) + 1)
        put(w, 96, get(w, 96) + 1)
        return response(o, w, command, job, at, 5)
    if command == 12:
        if phase != 2 and phase != 3:
            return 4294967295
        if argument == 0 or now < get(w, at + 32):
            return 4294967295
        put(w, at + 8, 4)
        put(w, at + 24, 0)
        put(w, at + 48, now)
        put(w, at + 64, argument)
        put(w, at + 72, 1)
        put(w, at + 80, 2)
        put(w, 24, get(w, 24) - 1)
        put(w, 40, get(w, 40) + 1)
        code = response(o, w, command, job, at, 0)
        retire_then_update(o, w, at)
        return code
    return 4294967295

def valid_pool(w:mutbuf) -> bool:
    if get(w, 0) != STATE_MAGIC or get(w, 16) > 1 or get(w, 24) > 2:
        return False
    used = get(w, 72)
    if used < 128 or used > length(w) or (used & 127) != 0:
        return False
    if get(w, 104) != 0 or get(w, 112) != 0 or get(w, 120) != 0:
        return False
    last = get(w, 8)
    if get(w, 32) > last or get(w, 40) > last or get(w, 48) > last or get(w, 56) > last or get(w, 80) > last or get(w, 96) > last:
        return False
    if get(w, 88) > get(w, 32) or get(w, 32) > last - get(w, 96):
        return False
    live = 0
    busy = 0
    prepared = 0
    consumed = 0
    at = 128
    while at < used:
        if valid_record(w, at, last) == False:
            return False
        job = get(w, at)
        if job != 0:
            if unique_before(w, at, job) == False:
                return False
            live = live + 1
            busy = busy + get(w, at + 24)
            if get(w, at + 8) == 1:
                if get(w, 16) != 0:
                    return False
                prepared = prepared + 1
            if get(w, at + 16) != 0:
                consumed = consumed + 1
        at = at + 128
    if live != get(w, 64) or busy != get(w, 24) or last - get(w, 80) != live:
        return False
    if get(w, 40) != last - busy or prepared > last - get(w, 96) or get(w, 32) != last - get(w, 96) - prepared:
        return False
    if get(w, 48) > last - get(w, 56) or get(w, 48) + get(w, 56) != get(w, 80) + consumed:
        return False
    return True

def valid_record(w:mutbuf, at:u64, last:u64) -> bool:
    job = get(w, at)
    if job == 0:
        i = 0
        while i < 128:
            if get(w, at + i) != 0:
                return False
            i = i + 8
        return True
    if job > last:
        return False
    phase = get(w, at + 8)
    caller = get(w, at + 16)
    permit = get(w, at + 24)
    if phase < 1 or phase > 4 or caller > 2 or permit > 1:
        return False
    if get(w, at + 56) != 0 or get(w, at + 88) != 0 or get(w, at + 96) != 0 or get(w, at + 104) != 0 or get(w, at + 112) != 0 or get(w, at + 120) != 0:
        return False
    if phase < 4:
        if permit != 1 or caller == 2 or get(w, at + 48) != 0 or get(w, at + 64) != 0 or get(w, at + 72) != 0 or get(w, at + 80) != 0:
            return False
        if phase == 1 and caller != 0:
            return False
        if phase < 3:
            if get(w, at + 32) != 0 or get(w, at + 40) != 0:
                return False
        else:
            start = get(w, at + 32)
            if start > 18446744043709551615 or get(w, at + 40) != start + 30000000000:
                return False
        return True
    if permit != 0 or get(w, at + 64) > 4294967295 or get(w, at + 72) > 1 or get(w, at + 80) > 2:
        return False
    reason = get(w, at + 80)
    if reason == 1:
        if get(w, at + 32) != 0 or get(w, at + 40) != 0 or get(w, at + 48) != 0 or get(w, at + 72) != 1:
            return False
        if get(w, at + 64) == 0 or get(w, at + 64) > 4095:
            return False
        return True
    if reason == 2:
        if get(w, at + 64) == 0 or get(w, at + 72) != 1:
            return False
        if get(w, at + 40) == 0:
            return get(w, at + 32) == 0
    start = get(w, at + 32)
    if start > 18446744043709551615 or get(w, at + 40) != start + 30000000000 or get(w, at + 48) < start:
        return False
    return True

def unique_before(w:mutbuf, stop:u64, job:u64) -> bool:
    at = 128
    while at < stop:
        if get(w, at) == job:
            return False
        at = at + 128
    return True

def find(w:mutbuf, job:u64) -> u64:
    at = 128
    while at < get(w, 72):
        if get(w, at) == job:
            return at
        at = at + 128
    return 0

def clear_record(w:mutbuf, at:u64) -> u64:
    i = 0
    while i < 128:
        put(w, at + i, 0)
        i = i + 8
    return 0

def retire_if_finished(w:mutbuf, at:u64) -> u64:
    if get(w, at + 8) == 4 and get(w, at + 16) != 0 and get(w, at + 72) == 1:
        clear_record(w, at)
        put(w, 64, get(w, 64) - 1)
        put(w, 80, get(w, 80) + 1)
    return 0

def retire_then_update(o:mutbuf, w:mutbuf, at:u64) -> u64:
    retire_if_finished(w, at)
    put(o, 104, get(w, 64))
    return 0

def response(o:mutbuf, w:mutbuf, command:u64, job:u64, at:u64, status:u64) -> u64:
    put(o, 0, RESULT_MAGIC)
    put(o, 8, 128)
    put(o, 16, status)
    put(o, 24, command)
    put(o, 32, job)
    i = 40
    while i < 96:
        put(o, i, 0)
        i = i + 8
    if at != 0:
        put(o, 40, get(w, at + 8))
        put(o, 48, get(w, at + 16))
        put(o, 56, get(w, at + 24))
        put(o, 64, get(w, at + 32))
        put(o, 72, get(w, at + 40))
        put(o, 80, get(w, at + 64))
        put(o, 88, get(w, at + 72) | (get(w, at + 80) << 8))
    put(o, 96, get(w, 24))
    put(o, 104, get(w, 64))
    put(o, 112, get(w, 32))
    put(o, 120, get(w, 40))
    return 128

def read64(s:readbuf, at:u64) -> u64:
    return 0

def get(w:mutbuf, at:u64) -> u64:
    return 0

def put(w:mutbuf, at:u64, value:u64) -> u64:
    return 0
'''

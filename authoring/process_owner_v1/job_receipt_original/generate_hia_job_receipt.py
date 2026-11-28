"""Author the HIA durable job receipt publisher and its ELF packer."""
from __future__ import annotations

import ast
from pathlib import Path
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from tools.build_hia_agent_batch_commit import adapter_layout
from tools.generate_hia_direct_load_plan import LinkerBuilder
from tools.generate_hia_native_filter import bind_adapter, document as packer_document, elf_header
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions


ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = 'examples/hia_bootstrap/job_receipt.hepta'
PACKER_PATH = 'examples/hia_bootstrap/job_receipt_packer.hepta'
ADAPTER_PATH = 'tools/hia_job_receipt_syscalls.S'
PACKER_MAGIC = int.from_bytes(b'HIAJPK01', 'little')
REQUEST_MAGIC = int.from_bytes(b'HIAJRQ01', 'little')
TERMINAL_MAGIC = int.from_bytes(b'HIAJRQ02', 'little')
OWNER_MAGIC = int.from_bytes(b'HIAJRO01', 'little')
CHILD_MAGIC = int.from_bytes(b'HIAJCH01', 'little')
CHILD_PROBE = int.from_bytes(b'{}\n', 'little')
CAPTURE_MAGIC = int.from_bytes(b'HIAJLG01', 'little')
LAUNCH_MAGIC = int.from_bytes(b'HIAJSP01', 'little')
PROCESS_IDENTITY_MAGIC = int.from_bytes(b'HIAJPI01', 'little')
CAPTURE_CHUNK_BYTES = 65536
ISOLATED_OUTPUT_BYTES = 16 * 1024 * 1024
CANCEL_MAGIC = int.from_bytes(b'HIAJRC01', 'little')
OWNER_CUSTODY_MAGIC = int.from_bytes(b'HIAJLH01', 'little')
OWNER_MARKERS_MAGIC = int.from_bytes(b'HIAJMK01', 'little')
OWNER_LOCK_MAGIC = int.from_bytes(b'HIAJLF01', 'little')
GROUP_SIGNAL_MAGIC = int.from_bytes(b'HIASGQ01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAJRW01', 'little')

SOURCE = f'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) >= 61 and uint(s, 0, 8) == {PROCESS_IDENTITY_MAGIC}:
        return supervisor_identity(s, o)
    if length(s) == 48 and uint(s, 0, 8) == {LAUNCH_MAGIC}:
        return workload_spawn_plan(s, o)
    if length(s) == 48 and uint(s, 0, 8) == {CAPTURE_MAGIC}:
        return capture_output_chunk(s, o)
    if length(s) == 48 and uint(s, 0, 8) == {OWNER_CUSTODY_MAGIC}:
        return acquire_owner_custody(s, o, w)
    if length(s) == 40 and uint(s, 0, 8) == {OWNER_MARKERS_MAGIC}:
        return observe_owner_markers(s, o, w)
    if length(s) == 40 and uint(s, 0, 8) == {OWNER_LOCK_MAGIC}:
        return advance_owner_lock(s, o, w)
    if length(s) == 40 and uint(s, 0, 8) == {GROUP_SIGNAL_MAGIC}:
        return advance_group_signal(s, o, w)
    if length(s) >= 35 and uint(s, 0, 8) == {OWNER_MAGIC}:
        return advance_owner(s, o, w)
    if length(s) >= 35 and uint(s, 0, 8) == {CANCEL_MAGIC}:
        return advance_cancel(s, o, w)
    phase = observed(w, 0)
    result = observed(w, 8)
    if phase == 0:
        if length(s) == 35 and uint(s, 0, 8) == {CHILD_MAGIC}:
            parent = uint(s, 16, 8)
            if 0 < parent and parent <= 2147483647 and parent == observed(w, 16) and uint(s, 8, 8) == 3 and uint(s, 24, 8) == 0:
                if uint(s, 32, 3) == {CHILD_PROBE}:
                    return acknowledge(o, 0, 0)
            return 0
        if prepare(s, o, observed(w, 16)) == 0:
            return 0
    elif result >> 63 != 0 or phase == 6:
        return acknowledge(o, phase, result)
    phase = phase + 1
    put(w, 0, phase, 8)
    return phase

def capture_output_chunk(s:readbuf, o:mutbuf) -> u64:
    mode = uint(s, 8, 8)
    stored = uint(s, 16, 8)
    received = uint(s, 24, 8)
    failed = uint(s, 32, 8)
    if length(o) != 16 or mode > 1 or received > {CAPTURE_CHUNK_BYTES} or failed > 1 or uint(s, 40, 8) != 0:
        return 0
    kept = received
    if mode == 1:
        if stored > {ISOLATED_OUTPUT_BYTES}:
            return 0
        remaining = {ISOLATED_OUTPUT_BYTES} - stored
        kept = choose(received <= remaining, received, remaining)
    put(o, 0, choose(failed == 0, kept, 0), 8)
    put(o, 8, choose(kept != received, 1, 0), 8)
    return 16

def workload_spawn_plan(s:readbuf, o:mutbuf) -> u64:
    if length(o) != 64 or uint(s, 40, 8) != 0:
        return 0
    current = 8
    while current < 40:
        descriptor = uint(s, current, 8)
        if descriptor < 3 or descriptor > 2147483647:
            return 0
        previous = 8
        while previous < current:
            if uint(s, previous, 8) == descriptor:
                return 0
            previous = previous + 8
        current = current + 8
    put(o, 0, uint(s, 16, 8), 8)
    put(o, 8, 0, 8)
    put(o, 16, uint(s, 24, 8), 8)
    put(o, 24, 1, 8)
    put(o, 32, uint(s, 32, 8), 8)
    put(o, 40, 2, 8)
    put(o, 48, 3, 8)
    # New session; restore the default SIGPIPE and SIGXFSZ actions.
    put(o, 56, 7, 8)
    return 64

def supervisor_identity(s:readbuf, o:mutbuf) -> u64:
    size = length(s)
    pid = uint(s, 8, 8)
    if size <= 61 or size >= 4157 or uint(s, 16, 8) != size - 61:
        return 0
    if length(o) != 57 or pid < 2 or pid > 2147483647 or byte(s, 60) != 10:
        return 0
    if valid_boot_id(s) == 0:
        return 0
    at = 61
    seen_pid = 0
    while at < size and byte(s, at) != 32:
        ch = byte(s, at)
        if ch < 48 or ch > 57 or at - 61 >= 10:
            return 0
        seen_pid = seen_pid * 10 + ch - 48
        at = at + 1
    if seen_pid != pid or at + 3 >= size or byte(s, at + 1) != 40:
        return 0
    return supervisor_stat_ticks(s, o, at + 2)

def valid_boot_id(s:readbuf) -> u64:
    index = 0
    while index < 36:
        ch = byte(s, 24 + index)
        hyphen = index == 8 or index == 13 or index == 18 or index == 23
        if hyphen:
            if ch != 45:
                return 0
        elif (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return 0
        index = index + 1
    return 1

def supervisor_stat_ticks(s:readbuf, o:mutbuf, floor:u64) -> u64:
    size = length(s)
    marker = size - 1
    while marker > floor and byte(s, marker) != 41:
        marker = marker - 1
    if byte(s, marker) != 41 or marker + 4 >= size or byte(s, marker + 1) != 32 or byte(s, marker + 3) != 32:
        return 0
    at = marker + 4
    field = 4
    while field < 22:
        base = at
        while at < size and byte(s, at) != 32:
            at = at + 1
        if at == base or at + 1 >= size:
            return 0
        at = at + 1
        field = field + 1
    return encode_supervisor_identity(s, o, at)

def encode_supervisor_identity(s:readbuf, o:mutbuf, start:u64) -> u64:
    size = length(s)
    at = start
    value = 0
    while at < size and byte(s, at) != 32:
        ch = byte(s, at)
        if ch < 48 or ch > 57 or at - start >= 20:
            return 0
        digit = ch - 48
        if value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
            return 0
        value = value * 10 + digit
        at = at + 1
    if at == start or at + 1 >= size or (at - start > 1 and byte(s, start) == 48):
        return 0
    index = 0
    while index < 36:
        put(o, index, byte(s, 24 + index), 1)
        index = index + 1
    put(o, 36, 58, 1)
    index = 0
    while index < at - start:
        put(o, 37 + index, byte(s, start + index), 1)
        index = index + 1
    return 37 + at - start

def acknowledge(o:mutbuf, phase:u64, result:u64) -> u64:
    put(o, 0, {RESULT_MAGIC}, 8)
    put(o, 8, phase, 8)
    put(o, 16, result, 8)
    return 7

def advance_owner(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    phase = observed(w, 0)
    result = observed(w, 8)
    if phase == 0:
        size = length(s)
        if size > 65568 or length(o) < 352 or uint(s, 8, 8) != size - 32:
            return 0
        pid = uint(s, 16, 8)
        if pid == 0 or pid > 2147483647 or pid != observed(w, 16) or uint(s, 24, 8) != 0:
            return 0
        if byte(s, 32) != 123 or byte(s, size - 1) != 125:
            return 0
        put(o, 24, 32, 8)
        put(o, 192, {int.from_bytes(b'owner-in', 'little')}, 8)
        put(o, 200, {int.from_bytes(b'tent.jso', 'little')}, 8)
        put(o, 208, 110, 2)
    elif phase > 9:
        return 0
    elif result >> 63 != 0:
        return acknowledge(o, phase, result)
    elif phase == 9:
        return acknowledge(o, 6, result)
    elif phase == 4:
        # O_EXCL on each original name. The one directory barrier follows
        # both independently synced and closed records.
        put(o, 192, {int.from_bytes(b'started.', 'little')}, 8)
        put(o, 200, {int.from_bytes(b'json', 'little')}, 5)
    put(w, 0, phase + 1, 8)
    if phase < 3:
        return phase + 1
    if phase == 3 or phase == 7:
        return 8
    if phase < 7:
        return phase - 3
    return 6

def advance_cancel(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    phase = observed(w, 0)
    result = observed(w, 8)
    if phase == 0:
        if prepare_cancellation(s, o, w) == 0:
            return 0
    elif phase > 7:
        return 0
    elif result >> 63 != 0 or phase == 7:
        return acknowledge(o, phase, result)
    put(w, 0, phase + 1, 8)
    if phase == 1:
        return 9
    if phase == 3:
        return 8
    if phase == 6:
        # Only the inherited pidfd, after durable publication. Never address
        # a recyclable PID or send a stronger signal from this operation.
        return 10
    return phase + 1

def advance_group_signal(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    phase = observed(w, 0)
    result = observed(w, 8)
    if phase == 0:
        parent = uint(s, 8, 8)
        leader = uint(s, 16, 8)
        action = uint(s, 24, 8)
        if parent < 2 or parent > 2147483647 or parent != observed(w, 16) or uint(s, 32, 8) != 0:
            return 0
        if leader == 0 and action == 0:
            return acknowledge(o, 0, 0)
        if leader <= 1 or leader > 2147483647 or leader == parent or (action != 1 and action != 2):
            return 0
        if length(o) < 4960:
            return 0
        put(w, 24, leader, 8)
        number = 9
        if action == 1:
            number = 15
        put(w, 32, number, 8)
        put(o, 32, {int.from_bytes(b'/proc/', 'little')}, 6)
        at = append_decimal(o, 38, leader)
        put(o, at, {int.from_bytes(b'/stat', 'little')}, 5)
        put(w, 0, 1, 8)
        return 11
    if result >> 63 != 0 or phase == 3:
        return acknowledge(o, phase, result)
    if phase == 1:
        put(w, 0, 2, 8)
        return 12
    if phase != 2:
        return 0
    if result == 0 or result >= 4096 or valid_group_snapshot(o, w, 864 + result) == 0:
        return acknowledge(o, phase, 18446744073709551542)
    put(w, 0, 3, 8)
    return 13

def valid_group_snapshot(o:mutbuf, w:mutbuf, end:u64) -> u64:
    first = stat_word(o, w, 864, end)
    if first == 0 or byte(o, first + 1) != 40 or observed(w, 40) != observed(w, 24):
        return 0
    # comm may contain spaces, parentheses and newlines. The last right
    # parenthesis is the actual kernel delimiter before the state byte.
    marker = last_stat_delimiter(o, first + 2, end)
    if marker <= first + 2 or marker + 4 >= end or byte(o, marker + 1) != 32 or byte(o, marker + 3) != 32:
        return 0
    next = stat_word(o, w, marker + 4, end)
    if next == 0 or observed(w, 40) != observed(w, 16):
        return 0
    group = stat_word(o, w, next + 1, end)
    if group == 0 or observed(w, 40) != observed(w, 24):
        return 0
    return 1

def last_stat_delimiter(o:mutbuf, floor:u64, end:u64) -> u64:
    marker = end
    while marker > floor:
        marker = marker - 1
        if byte(o, marker) == 41:
            return marker
    return 0

def stat_word(o:mutbuf, w:mutbuf, at:u64, end:u64) -> u64:
    if at >= end:
        return 0
    value = 0
    start = at
    while at < end:
        digit = byte(o, at)
        if digit == 32 and at > start:
            put(w, 40, value, 8)
            return at
        if digit < 48 or digit > 57 or at - start >= 10:
            return 0
        value = value * 10 + (digit - 48)
        at = at + 1
    return 0

def prepare_cancellation(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = length(s)
    if size < 81 or size > 208 or length(o) < 864:
        return 0
    parent = uint(s, 8, 8)
    target = uint(s, 16, 8)
    count = uint(s, 32, 8)
    if parent < 2 or parent > 2147483647 or parent != observed(w, 16):
        return 0
    if target < 3 or target > 2147483647 or count != size - 80 or uint(s, 40, 8) != 0:
        return 0
    at = 48
    while at < 80:
        value = byte(s, at)
        if (value < 48 or value > 57) and (value < 97 or value > 102):
            return 0
        at = at + 1
    at = 80
    while at < size:
        if allowed(byte(s, at)) == 0:
            return 0
        at = at + 1
    put(w, 24, target, 8)
    cancel_names(o, 32, False)
    cancel_names(o, 192, True)
    count = cancel_payload(s, o, size)
    put(o, 24, count, 8)
    return 1

def cancel_names(o:mutbuf, at:u64, staging:bool) -> u64:
    put(o, at, {int.from_bytes(b'cancel-r', 'little')}, 8)
    put(o, at + 8, {int.from_bytes(b'equest.j', 'little')}, 8)
    put(o, at + 16, {int.from_bytes(b'son', 'little')}, 3)
    if staging:
        put(o, at + 19, {int.from_bytes(b'.tmp', 'little')}, 4)
    return 0

def cancel_payload(s:readbuf, o:mutbuf, size:u64) -> u64:
    put(o, 352, {int.from_bytes(bytes((123,)) + b'"at_uni', 'little')}, 8)
    put(o, 360, {int.from_bytes(b'x_ms": ', 'little')}, 7)
    at = append_decimal(o, 367, uint(s, 24, 8))
    put(o, at, {int.from_bytes(b', "job_i', 'little')}, 8)
    put(o, at + 8, {int.from_bytes(b'd": "', 'little')}, 5)
    at = at + 13
    index = 80
    while index < size:
        store(o, at, byte(s, index))
        at = at + 1
        index = index + 1
    put(o, at, {int.from_bytes(b'", "laun', 'little')}, 8)
    put(o, at + 8, {int.from_bytes(b'ch_nonce', 'little')}, 8)
    put(o, at + 16, {int.from_bytes(b'": "', 'little')}, 4)
    at = at + 20
    index = 48
    while index < 80:
        store(o, at, byte(s, index))
        at = at + 1
        index = index + 1
    put(o, at, {int.from_bytes(bytes((34, 125, 10)), 'little')}, 3)
    return at + 3 - 352

def prepare(s:readbuf, o:mutbuf, parent:u64) -> u64:
    size = length(s)
    if size < 35 or size > 4194464 or length(o) < 352:
        return 0
    magic = uint(s, 0, 8)
    if magic != {REQUEST_MAGIC} and magic != {TERMINAL_MAGIC} and magic != {CHILD_MAGIC}:
        return 0
    extent = uint(s, 8, 8)
    pid = uint(s, 16, 8)
    name_bytes = uint(s, 24, 8)
    if pid == 0 or pid > 2147483647 or pid != parent:
        return 0
    if extent < 2 or extent > 4194304 or name_bytes == 0 or name_bytes > 128:
        return 0
    start = 32 + name_bytes
    if size != start + extent:
        return 0
    if byte(s, start) != 123:
        return 0
    if magic == {TERMINAL_MAGIC} or magic == {CHILD_MAGIC}:
        if extent < 3 or extent > 1048576 or byte(s, size - 2) != 125 or byte(s, size - 1) != 10:
            return 0
        if magic == {CHILD_MAGIC}:
            if extent > 65536 or name_bytes != 5 or uint(s, 32, 5) != {int.from_bytes(b'child', 'little')}:
                return 0
        else:
            if name_bytes != 4 and name_bytes != 12:
                return 0
            if uint(s, 32, 4) != {int.from_bytes(b'exit', 'little')}:
                return 0
            if name_bytes == 12 and uint(s, 36, 8) != {int.from_bytes(b'.witness', 'little')}:
                return 0
    elif byte(s, size - 1) != 125:
        return 0
    at = 0
    while at < name_bytes:
        value = byte(s, 32 + at)
        if allowed(value) == 0:
            return 0
        store(o, 32 + at, value)
        store(o, 192 + at, value)
        at = at + 1
    put(o, 32 + at, {int.from_bytes(b'.json', 'little')}, 5)
    put(o, 192 + at, {int.from_bytes(b'.json.tm', 'little')}, 8)
    store(o, 200 + at, 112)
    store(o, 201 + at, 46)
    append_decimal(o, 202 + at, pid)
    put(o, 24, start, 8)
    return 1

def allowed(byte:u64) -> u64:
    if byte >= 48 and byte <= 57:
        return 1
    if (byte >= 65 and byte <= 90) or (byte >= 97 and byte <= 122):
        return 1
    if byte == 45 or byte == 46 or byte == 64 or byte == 95:
        return 1
    return 0

def append_decimal(o:mutbuf, at:u64, value:u64) -> u64:
    divisor = 1
    while divisor <= value // 10:
        divisor = divisor * 10
    while divisor != 0:
        store(o, at, 48 + value // divisor)
        value = value % divisor
        divisor = divisor // 10
        at = at + 1
    store(o, at, 0)
    return at

def uint(s:readbuf, start:u64, size:u64) -> u64:
    index = 0
    value = 0
    while index < size:
        value = value | (byte(s, start + index) << (index * 8))
        index = index + 1
    return value

def observed(w:mutbuf, start:u64) -> u64:
    index = 0
    value = 0
    while index < 8:
        value = value | (byte(w, start + index) << (index * 8))
        index = index + 1
    return value

def put(o:mutbuf, start:u64, value:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(o, start + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0

def advance_owner_lock(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    phase = observed(w, 0)
    result = observed(w, 8)
    if phase == 0:
        parent = uint(s, 8, 8)
        if parent < 2 or parent > 2147483647 or parent != observed(w, 16) or uint(s, 32, 8) != 0:
            return 0
        put(w, 0, 1, 8)
        return 14
    if result >> 63 != 0 or phase == 2:
        return acknowledge(o, phase, result)
    if phase != 1:
        return 0
    if uint(s, 16, 8) != observed(w, 24) or uint(s, 24, 8) != observed(w, 32):
        return 0
    mode = observed(w, 40)
    if mode & 61440 != 32768 or mode & 63 != 0:
        return 0
    if observed(o, 0) != 1 or observed(o, 8) != observed(o, 16):
        return 0
    put(w, 0, 2, 8)
    return 15


def observe_owner_markers(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    phase = observed(w, 0)
    result = observed(w, 8)
    if phase == 0:
        parent = uint(s, 8, 8)
        if parent < 2 or parent > 2147483647 or parent != observed(w, 16) or uint(s, 32, 8) != 0:
            return 0
        put(w, 0, 1, 8)
        return 14
    if phase == 1:
        if result >> 63 != 0:
            return acknowledge(o, 1, result)
        if uint(s, 16, 8) != observed(w, 24) or uint(s, 24, 8) != observed(w, 32):
            return 0
        if observed(w, 40) & 61440 != 16384 or observed(w, 40) & 63 != 0:
            return 0
        if observed(o, 8) != observed(o, 16):
            return 0
        put(w, 24, 0, 8)
    elif phase >= 2 and phase <= 6:
        mask = observed(w, 24)
        if result == 0:
            mask = mask | (1 << (phase - 2))
        elif result != 18446744073709551614:
            return acknowledge(o, 2, result)
        if phase == 6:
            return acknowledge(o, 3, mask)
        put(w, 24, mask, 8)
    else:
        return 0
    owner_marker_name(o, phase)
    put(w, 0, phase + 1, 8)
    return 16

def owner_marker_name(o:mutbuf, phase:u64) -> u64:
    if phase == 1:
        put(o, 192, {int.from_bytes(b'owner-in', 'little')}, 8)
        put(o, 200, {int.from_bytes(b'tent.jso', 'little')}, 8)
        put(o, 208, {int.from_bytes(b'n', 'little')}, 2)
    elif phase == 2:
        put(o, 192, {int.from_bytes(b'started.', 'little')}, 8)
        put(o, 200, {int.from_bytes(b'json', 'little')}, 5)
    elif phase == 3:
        put(o, 192, {int.from_bytes(b'exit.jso', 'little')}, 8)
        put(o, 200, {int.from_bytes(b'n', 'little')}, 2)
    elif phase == 4:
        put(o, 192, {int.from_bytes(b'exit.wit', 'little')}, 8)
        put(o, 200, {int.from_bytes(b'ness.jso', 'little')}, 8)
        put(o, 208, {int.from_bytes(b'n', 'little')}, 2)
    elif phase == 5:
        put(o, 192, {int.from_bytes(b'exit.wit', 'little')}, 8)
        put(o, 200, {int.from_bytes(b'ness.jso', 'little')}, 8)
        put(o, 208, {int.from_bytes(b'n.tmp', 'little')}, 6)
    return 0


def acquire_owner_custody(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    phase = observed(w, 0)
    result = observed(w, 8)
    if phase == 0:
        parent = uint(s, 8, 8)
        peer = uint(s, 32, 8)
        if parent < 2 or parent > 2147483647 or parent != observed(w, 16):
            return 0
        if peer < 3 or peer > 2147483647 or uint(s, 40, 8) != 0:
            return 0
        put(w, 0, 1, 8)
        return 14
    if phase >= 7 and phase <= 11:
        return custody_marker(o, w, phase, result)
    if result >> 63 != 0:
        return acknowledge(o, phase, result)
    if phase == 1:
        if uint(s, 16, 8) != observed(w, 24) or uint(s, 24, 8) != observed(w, 32):
            return 0
        if observed(w, 40) & 61440 != 16384 or observed(w, 40) & 63 != 0:
            return 0
        if observed(o, 8) != observed(o, 16):
            return 0
        put(w, 0, 2, 8)
        return 17
    if phase == 2:
        if observed(o, 24) != observed(w, 16) or observed(o, 32) != observed(o, 16):
            return 0
        put(o, 192, {int.from_bytes(b'owner.lo', 'little')}, 8)
        put(o, 200, {int.from_bytes(b'ck', 'little')}, 3)
        put(w, 0, 3, 8)
        return 18
    if phase == 3 or phase == 5:
        put(w, 0, phase + 1, 8)
        return 19
    if phase == 4 or phase == 6:
        if custody_lock_valid(o, w) == False:
            return acknowledge(o, 20, 0)
        if phase == 4:
            put(w, 0, 5, 8)
            return 20
        put(w, 24, 0, 8)
        owner_marker_name(o, 1)
        put(w, 0, 7, 8)
        return 16
    if phase == 12 and result == 1:
        return acknowledge(o, 12, 0)
    return 0

def custody_lock_valid(o:mutbuf, w:mutbuf) -> bool:
    mode = observed(w, 40)
    return mode & 61440 == 32768 and mode & 63 == 0 and observed(o, 0) == 1 and observed(o, 8) == observed(o, 16)

def custody_marker(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u64:
    mask = observed(w, 24)
    if result == 0:
        mask = mask | (1 << (phase - 7))
    elif result != 18446744073709551614:
        return acknowledge(o, phase, result)
    if phase == 11:
        if mask != 0:
            return acknowledge(o, 21, mask)
        put(w, 0, 12, 8)
        return 21
    put(w, 24, mask, 8)
    owner_marker_name(o, phase - 5)
    put(w, 0, phase + 1, 8)
    return 16

'''


def document():
    nodes = ast.parse(SOURCE).body
    names = {node.name: f'f{index}' for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = LinkerBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(arg) for arg in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'job_receipt',
                                  'functions': functions})


def main():
    source = (ROOT / ADAPTER_PATH).read_bytes()
    with TemporaryDirectory(prefix='hia-job-receipt-adapter-') as directory:
        adapter, holes, _ = adapter_layout(Path(directory), ADAPTER_PATH, source, {'policy': 'policy_call_hole'})
    header = elf_header()
    hole = holes['policy']
    packer = packer_document(magic=PACKER_MAGIC, module='job_receipt_packer',
                             image_template=(header + adapter, (len(header) + hole,)))
    for path, item in ((SOURCE_PATH, document()), (PACKER_PATH, bind_adapter(packer, source, adapter, (hole,)))):
        (ROOT / path).write_text(render_assembly(item))


if __name__ == '__main__':
    main()

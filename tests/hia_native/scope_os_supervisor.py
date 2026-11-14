#!/usr/bin/env python3
"""Entropy controls and cleanup observation for one directly forked scope ELF.

No external PID is accepted. Synthetic bytes are written only to the owned
child's currently notified buffer, bounded by its 128-byte RNG request.
"""
import argparse, array, ctypes, errno, hashlib, json, os, select, socket, struct, sys
from pathlib import Path
ROOT = Path(os.environ.get("HIA_REFERENCE_RUNTIME", Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(ROOT / "tests/hia_native"))
from io_fault_supervisor import Filter, Program, Notification, Response
MODES = ["observe", "eintr", "eio", "enosys", "eagain", "zero", "oversized", "partial", "partial_error",
         "probe_enosys", "probe_eperm", "probe_eintr", "probe_eio", "probe_eagain", "fallback_eintr",
         "fallback_open_error", "fallback_poll_error", "fallback_urandom_open_error",
         "fallback_read_error", "fallback_partial", "fallback_partial_error", "constant", "fallback_constant",
         "stdio_fail_1", "stdio_fail_2", "stdio_fail_3", "stdio_fail_4", "fallback_oversized",
         "bad_errno", "fallback_bad_errno"]
class IoVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]
def device_for_fd(pid, fd):
    try:
        return os.readlink(f"/proc/{pid}/fd/{fd}")
    except FileNotFoundError:
        return None

def original_rng_callsite(pid, instruction, cache):
    """Classify syscall(318) versus libc getrandom without reading result bytes.

    The pinned original getrandom crate invokes libc syscall. Rust's standard
    library separately calls libc getrandom when constructing RandomState for
    the nonce HashSet. Both real calls are retained; only SystemEntropy's site
    is eligible for this test's controlled completions.
    """
    mappings = [line.split() for line in Path(f'/proc/{pid}/maps').read_text().splitlines()]
    selected = [row for row in mappings if len(row) >= 6 and
                int(row[0].split('-')[0],16) <= instruction < int(row[0].split('-')[1],16)]
    assert len(selected) == 1
    filename = selected[0][-1]
    assert Path(filename).name == 'libc.so.6' or filename == '[vdso]', ('unclassified original RNG module',filename)
    bias = min(int(row[0].split('-')[0],16)-int(row[2],16) for row in mappings if row[-1] == filename)
    if filename not in cache:
        if filename == '[vdso]':
            start,end = map(lambda x:int(x,16),selected[0][0].split('-'))
            size = end-start
            assert 0 < size <= 131072
            owned = ctypes.create_string_buffer(size)
            local,remote = IoVec(ctypes.addressof(owned),size),IoVec(start,size)
            reader = ctypes.CDLL(None,use_errno=True)
            reader.process_vm_readv.argtypes = [ctypes.c_int,ctypes.POINTER(IoVec),ctypes.c_ulong,
                                                ctypes.POINTER(IoVec),ctypes.c_ulong,ctypes.c_ulong]
            reader.process_vm_readv.restype = ctypes.c_ssize_t
            if reader.process_vm_readv(pid,ctypes.byref(local),1,ctypes.byref(remote),1,0) != size:
                raise OSError(ctypes.get_errno(),'owned public vDSO inspection failed')
            raw = owned.raw
        else:
            raw = Path(filename).read_bytes()
        assert raw[:7] == b'\x7fELF\x02\x01\x01'
        at = struct.unpack_from('<Q',raw,40)[0]
        width, count = struct.unpack_from('<HH',raw,58)
        sections = [struct.unpack_from('<II4QII2Q',raw,at+i*width) for i in range(count)]
        found = {}
        for section in sections:
            if section[1] != 11:
                continue
            strings = sections[section[6]]
            names = raw[strings[4]:strings[4]+strings[5]]
            assert section[9] == 24
            for cursor in range(section[4],section[4]+section[5],24):
                name,info,other,index,value,size = struct.unpack_from('<IBBHQQ',raw,cursor)
                end = names.find(b'\0',name)
                label = names[name:end]
                if label in (b'syscall',b'getrandom',b'__vdso_getrandom') and size:
                    found[label.decode()] = (value,size)
        if filename == '[vdso]':
            assert set(found) in ({'__vdso_getrandom'},{'__vdso_getrandom','getrandom'}), found
            if 'getrandom' in found:
                assert found.pop('getrandom') == found['__vdso_getrandom'], 'vDSO aliases differ'
        else:
            assert set(found) == {'syscall','getrandom'}, found
        cache[filename] = (hashlib.sha256(raw).hexdigest(),found)
    library_hash,symbols = cache[filename]
    relative = instruction-bias
    matches = [(name,start,size) for name,(start,size) in symbols.items() if start < relative < start+size]
    assert len(matches) == 1, ('original RNG site is outside admitted symbols', filename, relative, symbols)
    name,start,size = matches[0]
    return {'module_kind':'linux-vdso' if filename=='[vdso]' else 'libc','library_sha256':library_hash,'symbol':name,'symbol_value':start,'symbol_bytes':size,
            'instruction_offset':relative-start}
def main_literal_addresses(pid, executable, raw, literal):
    elf_type = struct.unpack_from("<H", raw, 16)[0]
    bias = 0
    if elf_type == 3:
        mappings = []
        for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
            fields = line.split()
            if len(fields) >= 6 and fields[-1] == str(executable):
                mappings.append(int(fields[0].split("-")[0], 16) - int(fields[2], 16))
        if not mappings:
            return set()
        bias = min(mappings)
    phoff = struct.unpack_from("<Q", raw, 32)[0]
    phsize, count = struct.unpack_from("<HH", raw, 54)
    addresses = set()
    at = raw.find(literal)
    while at >= 0:
        for index in range(count):
            kind, flags, offset, virtual, physical, size, memory, alignment = struct.unpack_from(
                "<IIQQQQQQ", raw, phoff + index * phsize)
            if kind == 1 and offset <= at and at + len(literal) <= offset + size:
                addresses.add(bias + virtual + at - offset)
        at = raw.find(literal, at + 1)
    return addresses
def apply_fault(libc, pid, mode, kind, call, address, size, response, event):
    error, count = None, None
    if kind == "probe":
        if mode.startswith("fallback_") or mode == "probe_enosys":
            error = errno.ENOSYS
        elif mode.startswith("probe_"):
            error = {"probe_eperm": errno.EPERM, "probe_eintr": errno.EINTR,
                     "probe_eio": errno.EIO, "probe_eagain": errno.EAGAIN}[mode]
    elif kind == "open_random":
        if call == 1 and mode == "fallback_eintr": error = errno.EINTR
        if call == 1 and mode == "fallback_open_error": error = errno.EACCES
    elif kind == "poll":
        if mode == "fallback_eintr" and call <= 2: error = errno.EINTR if call == 1 else errno.EAGAIN
        if mode == "fallback_poll_error" and call == 1: error = errno.EIO
    elif kind == "open_urandom":
        if mode == "fallback_eintr" and call == 1: error = errno.EINTR
        if mode == "fallback_urandom_open_error" and call == 1: error = errno.EACCES
    elif kind in ("getrandom", "read_urandom"):
        direct = kind == "getrandom"
        if mode in ("bad_errno", "fallback_bad_errno"):
            error = 5000  # Deliberately outside valid kernel errno; native control only.
        elif mode.startswith("stdio_fail_") and call == int(mode.rsplit('_', 1)[1]):
            error = errno.EIO
        elif mode in ("constant", "fallback_constant") or mode.startswith("stdio_fail_"):
            count = size
        elif direct and mode in ("eio", "enosys", "eagain"):
            error = {"eio": errno.EIO, "enosys": errno.ENOSYS, "eagain": errno.EAGAIN}[mode]
        elif call == 1 and mode in ("eintr", "fallback_eintr"):
            error = errno.EINTR
        elif call == 1 and mode == "fallback_read_error":
            error = errno.EIO
        elif mode in ("zero", "oversized", "fallback_oversized"):
            response.value = 0 if mode == "zero" else size + 1
            response.flags = 0
            event.update(completion="injected_return", returned=response.value)
        elif mode in ("partial", "fallback_partial"):
            count = 1
        elif mode in ("partial_error", "fallback_partial_error"):
            if call == 1: count = min(5, size)
            elif call == 2: error = errno.EIO
    if error is not None:
        response.error, response.flags = -error, 0
        event.update(completion="injected_error", error=error)
    if count is not None:
        assert 1 <= count <= size <= 128
        synthetic = bytes([66 if mode in ("constant", "fallback_constant") else (call * 17) & 255]) * count
        owned = ctypes.create_string_buffer(synthetic)
        local, remote = IoVec(ctypes.addressof(owned), count), IoVec(address, count)
        written = libc.process_vm_writev(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
        if written != count:
            raise OSError(ctypes.get_errno(), "owned synthetic completion write failed")
        response.value, response.flags = count, 0
        event.update(completion="synthetic_partial_bytes", returned=count)

def native_profile(raw):
    """Admit only the fixed scope table before deriving owned cleanup spans."""
    candidates = []
    cursor = 0
    while True:
        cursor = raw.find(b'HIAMOD01', cursor)
        if cursor < 0:
            break
        at = cursor
        cursor += 1
        if at % 16 or at + 64 + 8 * 128 > len(raw):
            continue
        header = struct.unpack_from('<8Q', raw, at)
        if header[1:3] != (8, 0) or header[4:] != (128, 16859136, 0, 0):
            continue
        rows = [struct.unpack_from('<8Q', raw, at + 64 + i * 128) for i in range(8)]
        if [(r[6], r[7]) for r in rows] != [(1,64),(1,28),(0,0),(0,0),(0,0),(0,0),(1,166),(4,0)]:
            continue
        if rows[7][2:4] != (24,128) or rows[7][5] != 1024:
            continue
        code, memory = at + 64 + 8 * 128, 16859136
        for index, row in enumerate(rows):
            offset, size, icap, ocap, work, worksize, flags, mask = row
            assert offset == code and 0 < size <= 1 << 20 and offset + size <= len(raw)
            assert work == memory and 0 < worksize <= 32 << 20
            assert hashlib.sha256(raw[offset:offset+size]).digest() == raw[at+64+index*128+96:at+64+index*128+128]
            code = (offset + size + 15) & -16
            assert not any(raw[offset+size:code])
            memory += ((worksize + 4095) & -4096) + 4096
        assert code == len(raw) and memory == header[3]
        candidates.append((at, rows))
    assert len(candidates) == 1, 'owned native scope table is not unique'
    return candidates[0]

def verify_native_cleanup(libc, pid, base, descriptors):
    """Inspect only bounded spans in this directly owned, notified child."""
    owned = ctypes.create_string_buffer(65536)
    total = 0
    def zero_span(address, count):
        nonlocal total
        assert base <= address < base + (1 << 30) and 0 <= count <= 32 << 20
        done = 0
        while done < count:
            size = min(65536, count-done)
            local, remote = IoVec(ctypes.addressof(owned), size), IoVec(address+done, size)
            read_count = libc.process_vm_readv(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
            if read_count != size:
                raise OSError(ctypes.get_errno(), 'owned cleanup inspection failed')
            assert not any(memoryview(owned).cast('B')[:size]), 'owned private cleanup span is not zero'
            done += size
            total += size
    for row in descriptors:
        zero_span(base+row[4], row[5])
    zero_span(base+8392704, 8388608)
    words = ctypes.create_string_buffer(40)
    local, remote = IoVec(ctypes.addressof(words), 40), IoVec(base+16793600+320, 40)
    assert libc.process_vm_readv(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0) == 40
    assert struct.unpack('<5Q', words.raw) == (0, (1 << 64)-1, (1 << 64)-1, 0, 1)
    return {'private_workspaces_zero': True, 'transport_output_zero': True,
            'private_entropy_descriptors_retired': True, 'inspected_bytes': total+40,
            'module_count': 8}

def inspect_native_idle(libc, pid, base, descriptors):
    """Observe only this owned process at a transport read between entries."""
    def read(at, size):
        assert 0 <= at <= 1 << 30 and 0 <= size <= 4 << 20
        result = ctypes.create_string_buffer(size)
        local, remote = IoVec(ctypes.addressof(result), size), IoVec(base+at, size)
        if libc.process_vm_readv(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0) != size:
            raise OSError(ctypes.get_errno(), 'owned idle inspection failed')
        return result.raw
    entropy = read(descriptors[7][4], 1024)
    phase, wanted, used, sequence, backend, cached = struct.unpack_from('<6Q', entropy)
    assert (phase, wanted, used) == (0, 0, 0)
    assert not any(entropy[48:]), 'entropy terminal retained secret or transient bytes'
    scope = read(descriptors[6][4], descriptors[6][5])
    state, references = struct.unpack_from('<2Q', scope)
    assert state in (0, 2, 3)
    assert not any(scope[160:-256]), 'scope terminal retained transient bytes'
    private_keys_zero = not any(scope[32:160])
    if state != 2:
        assert private_keys_zero
    private = struct.unpack('<5Q', read(16793600+320, 40))
    assert private[0] == sequence and private[1] == (1 << 64)-1 and private[4] == 1
    assert (private[2] != (1 << 64)-1) == bool(cached)
    return {'scope_state':state, 'scope_references':references,
            'private_keys_zero':private_keys_zero, 'scope_transient_zero':True,
            'entropy_transient_zero':True, 'entropy_sequence':sequence,
            'entropy_backend':backend, 'entropy_cached_fd':cached}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--mode", required=True, choices=MODES)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    native = len(command) == 3 and command[1:] == ["--local-read-profile", "/"]
    assert (native or len(command) == 1) and Path(command[0]).is_absolute()
    executable = Path(command[0]).resolve(strict=True)
    raw = executable.read_bytes()
    assert raw[:7] == b"\x7fELF\x02\x01\x01" and struct.unpack_from("<H", raw, 18)[0] == 62
    assert ctypes.sizeof(Notification) == 80 and ctypes.sizeof(Response) == 24
    libc = ctypes.CDLL(None, use_errno=True)
    libc.process_vm_writev.argtypes = [ctypes.c_int, ctypes.POINTER(IoVec), ctypes.c_ulong,
                                      ctypes.POINTER(IoVec), ctypes.c_ulong, ctypes.c_ulong]
    libc.process_vm_writev.restype = ctypes.c_ssize_t
    libc.process_vm_readv.argtypes = libc.process_vm_writev.argtypes
    libc.process_vm_readv.restype = ctypes.c_ssize_t
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    pid = os.fork()
    if pid == 0:
        parent.close()
        try:
            if libc.prctl(38, 1, 0, 0, 0):
                raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS")
            code = [Filter(0x20, 0, 0, 0)]
            for number in (0, 3, 7, 60, 231, 257, 318):
                code.extend((Filter(0x15, 0, 1, number), Filter(0x06, 0, 0, 0x7fc00000)))
            code.append(Filter(0x06, 0, 0, 0x7fff0000))
            filters = (Filter * len(code))(*code)
            program = Program(len(code), filters)
            listener = libc.syscall(317, 1, 8, ctypes.byref(program))
            if listener < 0:
                raise OSError(ctypes.get_errno(), "seccomp notification unavailable")
            os.set_inheritable(listener, False)
            child.sendmsg([b"L"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [listener]))])
            os.execve(str(executable), [str(executable), *command[1:]], dict(os.environ, PATH=""))
        except BaseException as error:
            os.write(2, (str(error) + "\n").encode())
            os._exit(76)
    child.close()
    if not select.select([parent], [], [], 5)[0]:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        raise RuntimeError("owned child could not install seccomp notification")
    _, ancillary, _, _ = parent.recvmsg(1, socket.CMSG_SPACE(4))
    parent.close()
    descriptors = array.array("i")
    descriptors.frombytes(ancillary[0][2][:4])
    listener = descriptors[0]
    events, counts, origin = [], {}, None
    pending = None
    native_base = None
    cleanup = None
    idle_snapshots = []
    original_auxiliary_entropy = []
    original_system_rng_callsites = []
    libc_symbols = {}
    entropy_event_order = []
    if native:
        table, descriptors = native_profile(raw)
    wait_status = None
    try:
        while True:
            ended, status = os.waitpid(pid, os.WNOHANG)
            if ended:
                wait_status = status
                break
            if not select.select([listener], [], [], .1)[0]:
                continue
            note = Notification()
            if libc.ioctl(listener, 0xc0502100, ctypes.byref(note)):
                if ctypes.get_errno() in (errno.EINTR, errno.ENOENT):
                    continue
                raise OSError(ctypes.get_errno(), "SECCOMP_IOCTL_NOTIF_RECV")
            assert note.pid == pid
            response = Response(note.id, 0, 0, 1)
            kind, address, size = None, None, None
            number = int(note.data.nr)
            values = list(map(int, note.data.args))
            if native and number == 0 and values[0] == 0:
                if native_base is None:
                    assert values[2] == 8388608 and values[1] % 4096 == 0
                    native_base = values[1]
                idle_snapshots.append(inspect_native_idle(libc, pid, native_base, descriptors))
            if number in (60, 231) and native and native_base is not None:
                cleanup = verify_native_cleanup(libc, pid, native_base, descriptors)
                cleanup['exit_code'] = values[0]
            auxiliary = False
            if not native and number == 318 and values[2] == 0 and values[1] <= 128:
                site = original_rng_callsite(pid,int(note.data.ip),libc_symbols)
                if site['symbol'] in ('getrandom','__vdso_getrandom'):
                    # Keep this real standard-library request separate before
                    # applying faults or incrementing any SystemEntropy count.
                    assert values[1] == 32 and not original_auxiliary_entropy
                    original_auxiliary_entropy.append({'kind':'standard_library_hashset_seed',
                        'requested':values[1],'flags':values[2],'completion':'kernel','callsite':site})
                    entropy_event_order.append({'domain':'original_standard_library','index':len(original_auxiliary_entropy)-1})
                    auxiliary = True
                else:
                    original_system_rng_callsites.append(site)
            if number == 318 and values[2] == 0 and values[1] <= 128 and not auxiliary:
                address, size = values[:2]
                kind = "probe" if size == 0 else "getrandom"
            elif number == 257:
                for name in ("random", "urandom"):
                    if values[1] in main_literal_addresses(pid, executable, raw, ("/dev/" + name + "\0").encode()):
                        assert ctypes.c_int(values[0]).value == -100 and values[2] == 0x80000
                        kind = "open_" + name
            elif number == 7 and values[1] == 1 and ctypes.c_int(values[2]).value == -1:
                assert any(device_for_fd(pid, int(p.name)) == "/dev/random" for p in Path(f"/proc/{pid}/fd").iterdir())
                kind = "poll"
            elif number in (0, 3):
                device = device_for_fd(pid, values[0])
                if device in ("/dev/random", "/dev/urandom"):
                    if number == 0:
                        assert device == "/dev/urandom"
                        kind, address, size = "read_urandom", values[1], values[2]
                    else:
                        kind = "close_" + device.rsplit("/", 1)[1]
            if kind is not None:
                counts[kind] = counts.get(kind, 0) + 1
                event = {"kind": kind, "call": counts[kind], "completion": "kernel"}
                if kind == "read_urandom" or kind.startswith("close_"):
                    event["device_fd"] = values[0]
                if size is not None:
                    event["requested"] = size
                    if native and native_base is None:
                        # The initial empty probe identifies this owned mapping;
                        # no PID or arbitrary address is accepted from the user.
                        assert kind == 'probe'
                        native_base = address - descriptors[7][4] - 512
                        assert native_base > 0 and native_base % 4096 == 0
                if size:
                    assert 1 <= size <= 128
                    if pending is not None:
                        start, total, used = pending
                        assert address == start + used and size == total - used
                    else:
                        start, total, used = address, size, 0
                    event["destination_delta"] = used
                apply_fault(libc, pid, args.mode, kind, counts[kind], address, size, response, event)
                if size:
                    if event['completion'] == 'synthetic_partial_bytes' and event['returned'] < size:
                        pending = (start, total, used + event['returned'])
                    elif event['completion'] == 'injected_error' and event['error'] == errno.EINTR:
                        pending = (start, total, used)
                    else:
                        # Kernel completion lengths are observed by the owner;
                        # no cross-fill stack-address equality is claimed here.
                        pending = None
                events.append(event)
                entropy_event_order.append({'domain':'system_entropy','index':len(events)-1})
            if libc.ioctl(listener, 0xc0182101, ctypes.byref(response)) and ctypes.get_errno() != errno.ENOENT:
                raise OSError(ctypes.get_errno(), "SECCOMP_IOCTL_NOTIF_SEND")
    finally:
        os.close(listener)
        if wait_status is None:
            os.kill(pid, 9)
            _, wait_status = os.waitpid(pid, 0)
        args.log.write_text(json.dumps({"events": events, "owned_child_reaped": True, 'native_cleanup': cleanup,
                                       'native_idle_snapshots': idle_snapshots,
                                       'entropy_event_order': entropy_event_order,
                                       'original_auxiliary_entropy': original_auxiliary_entropy,
                                       'original_system_rng_callsites': original_system_rng_callsites,
                                       "executable_sha256": hashlib.sha256(raw).hexdigest()}, sort_keys=True) + "\n")
    raise SystemExit(os.waitstatus_to_exitcode(wait_status))

if __name__ == "__main__":
    main()

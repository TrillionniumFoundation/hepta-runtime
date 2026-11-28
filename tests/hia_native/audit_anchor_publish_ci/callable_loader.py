"""Private sealed callable admission and actual libc capability table.

No effect dispatch or audit policy is implemented in this Python boundary.
The callable itself owns every HIA continuation and real libc call.
"""
from pathlib import Path
import ctypes as C
import struct
from common import loads, pin, read, require
from hia_native import NativeModule

from callable_contract import CONTEXT_BYTES, OFFSETS, FUNCTIONS

OBSERVER = C.CFUNCTYPE(None, C.c_void_p, C.c_void_p)
INITIALIZE = C.CFUNCTYPE(C.c_uint64, C.c_void_p, C.c_uint64, C.c_uint64,
                        C.c_void_p, C.c_void_p, C.c_void_p)
DISPOSE = C.CFUNCTYPE(C.c_uint64, C.c_void_p, C.c_uint64)


class DlInfo(C.Structure):
    _fields_ = [("filename", C.c_char_p), ("base", C.c_void_p),
                ("symbol", C.c_char_p), ("symbol_address", C.c_void_p)]


def libc_bindings():
    # Bind the actual libc object, not symbols interposed by the embedding executable.
    library = C.CDLL("libc.so.6")
    lookup = library.dladdr
    lookup.argtypes = [C.c_void_p, C.POINTER(DlInfo)]
    lookup.restype = C.c_int
    pointers = []
    rows = []
    raw_library = None
    for name in FUNCTIONS:
        pointer = C.cast(getattr(library, name), C.c_void_p).value
        require(type(pointer) is int and pointer > 0, "actual libc symbol: " + name)
        info = DlInfo()
        require(lookup(pointer, C.byref(info)) != 0 and info.filename and info.base,
                "actual loaded libc ownership: " + name)
        path = Path(info.filename.decode()).resolve(strict=True)
        raw = read(path)
        require(path.name == "libc.so.6" and raw[:4] == b"\x7fELF", "actual ELF libc")
        if raw_library is None:
            raw_library = raw
        require(raw_library == raw, "one complete native libc implementation")
        pointers.append(pointer)
        rows.append(dict(name=name, pointer=pointer, loaded_base=int(info.base),
            library_path=str(path), library=pin(raw),
            observed_symbol=None if info.symbol is None else info.symbol.decode(),
            observed_symbol_address=0 if info.symbol_address is None else int(info.symbol_address)))
    table = (C.c_uint64 * 21)(*pointers, 0)
    return library, table, rows, raw_library


class Callable:
    def __init__(self, manifest, composition):
        self.composition = composition
        self.module = NativeModule(manifest, manifest_sha256=pin(read(manifest))["sha256"])
        image = read(Path(manifest).parent / self.module.metadata["image"])
        require(pin(image) == composition["callable_image"], "complete packed callable bytes")
        offsets = composition["offsets"]
        require(offsets["entry"] == 0 and 0 < offsets["initialize"] < offsets["dispose"] <
                offsets["owner"] < offsets["json"] < offsets["end"] == len(image),
                "exact bounded callable exports")
        self.initialize = INITIALIZE(self.module._address + offsets["initialize"])
        self.dispose = DISPOSE(self.module._address + offsets["dispose"])
        self.entry = self.module._entry
        self.library, self.table, self.bindings, self.libc_bytes = libc_bindings()

    def close(self):
        self.initialize = self.dispose = self.entry = None
        self.module.close()

    def new_context(self):
        raw = bytes(CONTEXT_BYTES) + b"\x5a" * 16
        return C.create_string_buffer(raw, len(raw))

    def init(self, context, directory_fd, observer=None, user=0):
        pointer = None if observer is None else C.cast(observer, C.c_void_p).value
        returned = int(self.initialize(C.addressof(context), CONTEXT_BYTES, directory_fd,
                                      C.addressof(self.table), pointer, user))
        require(context.raw[CONTEXT_BYTES:] == b"\x5a" * 16, "complete initialization guard")
        return returned

    def run(self, wire, context):
        source = C.create_string_buffer(wire + b"\xc3" * 16, len(wire) + 16)
        output = C.create_string_buffer(b"\xa5" * (8192 + 16), 8192 + 16)
        before = (source.raw, output.raw, context.raw)
        returned = int(self.entry(C.addressof(source), len(wire), C.addressof(output), 8192,
                                  C.addressof(context), CONTEXT_BYTES))
        after = (source.raw, output.raw, context.raw)
        require(after[0] == before[0] and after[1][8192:] == b"\xa5" * 16 and
                after[2][CONTEXT_BYTES:] == b"\x5a" * 16, "complete outer borrowed buffers")
        return returned, before, after

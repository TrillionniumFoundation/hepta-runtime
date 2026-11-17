"""Actual native exports and libc identity only; no Watcher effect dispatch."""
from pathlib import Path
import ctypes as C,struct
from common import read,loads,pin,require
from hia_native import NativeModule
CONTEXT_BYTES=131072
FUNCTIONS=("inotify_init1","read","fstat","fcntl","inotify_add_watch","inotify_rm_watch","close","__errno_location")
OBSERVER=C.CFUNCTYPE(None,C.c_void_p,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)
INIT=C.CFUNCTYPE(C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_void_p,C.c_void_p)
BIND=C.CFUNCTYPE(C.c_uint64,C.c_void_p,C.c_uint64,C.c_uint64,C.c_void_p)
DISPOSE=C.CFUNCTYPE(C.c_uint64,C.c_void_p,C.c_uint64)
ADOPT=C.CFUNCTYPE(C.c_uint64,C.c_uint64,C.c_void_p,C.c_void_p)
CLONE=C.CFUNCTYPE(C.c_uint64,C.c_void_p)
RELEASE=C.CFUNCTYPE(C.c_uint64,C.c_void_p,C.c_void_p)
def word(raw,at):return struct.unpack_from("<Q",raw,at)[0]
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
    table = (C.c_uint64 * (len(FUNCTIONS)+1))(*pointers, 0)
    return library, table, rows, raw_library


class Callable:
    def __init__(self,manifest,composition):
        self.composition=composition
        self.module=NativeModule(manifest,manifest_sha256=pin(read(manifest))["sha256"])
        image=read(Path(manifest).parent/self.module.metadata["image"])
        require(pin(image)==composition["callable_image"],"actual complete packed Watcher")
        offsets=composition["offsets"]
        names=("entry","initialize","bind","dispose","pin_adopt","pin_clone","pin_release","owner","end")
        require(set(offsets)==set(names) and offsets["entry"]==0 and
            all(offsets[a]<offsets[b] for a,b in zip(names,names[1:])) and offsets["end"]==len(image),
            "all exact real native exports")
        base=self.module._address
        self.initialize=INIT(base+offsets["initialize"])
        self.bind=BIND(base+offsets["bind"])
        self.dispose=DISPOSE(base+offsets["dispose"])
        self.adopt=ADOPT(base+offsets["pin_adopt"])
        self.clone=CLONE(base+offsets["pin_clone"])
        self.release=RELEASE(base+offsets["pin_release"])
        self.entry=self.module._entry
        self.library,self.table,self.bindings,self.libc_bytes=libc_bindings()
    def close(self):
        self.initialize=self.bind=self.dispose=self.adopt=self.clone=self.release=self.entry=None
        self.module.close()
    def new_context(self):
        return C.create_string_buffer(bytes(CONTEXT_BYTES)+b"\x5a"*16,CONTEXT_BYTES+16)
    def run(self,wire,context):
        request=C.create_string_buffer(wire+b"\xc3"*16,len(wire)+16)
        output=C.create_string_buffer(b"\xa5"*144,144)
        before=(request.raw,output.raw,context.raw)
        value=int(self.entry(C.addressof(request),len(wire),C.addressof(output),128,
            C.addressof(context),CONTEXT_BYTES))
        after=(request.raw,output.raw,context.raw)
        require(before[0]==after[0] and after[1][128:]==b"\xa5"*16
            and after[2][CONTEXT_BYTES:]==b"\x5a"*16,"every complete outer physical buffer guard")
        return value,before,after

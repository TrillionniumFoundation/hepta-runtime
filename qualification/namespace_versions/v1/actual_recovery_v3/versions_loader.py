"""Actual composed HIA/native exports and exact libc pointers, without policy dispatch."""
import ctypes as C,struct
from pathlib import Path
from common import pin,read,require
from hia_native import NativeModule
FUNCTIONS=("inotify_init1","read","fstat","fcntl","inotify_add_watch","inotify_rm_watch","close","__errno_location",
    "openat","fdopendir","readdir","closedir","pthread_mutex_init","pthread_mutex_lock","pthread_mutex_unlock","pthread_mutex_destroy")
TABLE_ORDER=(0,1,2,3,4,5,6,7,8,9,6,10,11,7,None,12,13,14,15)
OBSERVER=C.CFUNCTYPE(None,C.c_void_p,C.c_void_p,C.c_uint64)
INIT=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_void_p,C.c_void_p)
ALLOCATE=C.CFUNCTYPE(C.c_uint64,C.c_void_p)
DISPOSE=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64)
ADOPT=C.CFUNCTYPE(C.c_uint64,C.c_uint64,C.c_void_p,C.c_void_p)
CLONE=C.CFUNCTYPE(C.c_uint64,C.c_void_p)
RELEASE=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_void_p)
CHILD=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)
BIND=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_uint64,C.c_void_p)
MUTEX=C.CFUNCTYPE(C.c_int,C.c_void_p)
def word(raw,at):return struct.unpack_from("<Q",raw,at)[0]
class DlInfo(C.Structure):
    _fields_=[("filename",C.c_char_p),("base",C.c_void_p),("symbol",C.c_char_p),("symbol_address",C.c_void_p)]
def libc_bindings():
    lib=C.CDLL("libc.so.6");lookup=lib.dladdr;lookup.argtypes=[C.c_void_p,C.POINTER(DlInfo)];lookup.restype=C.c_int
    pointers=[];rows=[];whole=None
    for name in FUNCTIONS:
        pointer=C.cast(getattr(lib,name),C.c_void_p).value;require(type(pointer)is int and pointer>0,"actual libc export")
        info=DlInfo();require(lookup(pointer,C.byref(info))and info.filename and info.base,"actual libc symbol owner")
        path=Path(info.filename.decode()).resolve(strict=True);raw=read(path)
        require(path.name=="libc.so.6"and raw[:4]==b"\x7fELF","actual whole ELF libc")
        if whole is None:whole=raw
        require(raw==whole,"one complete native libc")
        pointers.append(pointer);rows.append(dict(name=name,pointer=pointer,loaded_base=int(info.base),library_path=str(path),
            library=pin(raw),observed_symbol=None if info.symbol is None else info.symbol.decode(),
            observed_symbol_address=0 if info.symbol_address is None else int(info.symbol_address)))
    table=(C.c_uint64*19)(*(0 if i is None else pointers[i]for i in TABLE_ORDER))
    return lib,table,rows,whole,pointers
class Callable:
    def __init__(self,manifest,binding):
        self.composition=binding;self.module=NativeModule(manifest,manifest_sha256=pin(read(manifest))["sha256"])
        image=read(Path(manifest).parent/self.module.metadata["image"]);require(pin(image)==binding["callable_image"],"whole exact composed image")
        o=binding["offsets"];require(set(o)=={"entry","initialize","set_allocate","set_dispose","owner","watcher","fingerprint","end"}
            and o["entry"]==0 and o["end"]==len(image),"all actual native exports")
        base=self.module._address;self.entry=self.module._entry
        self.initialize=INIT(base+o["initialize"]);self.allocate=ALLOCATE(base+o["set_allocate"]);self.dispose=DISPOSE(base+o["set_dispose"])
        self.adopt=ADOPT(base+o["watcher"]+5728);self.clone=CLONE(base+o["watcher"]+5936);self.release=RELEASE(base+o["watcher"]+6048)
        self.child=CHILD(base+o["watcher"]);self.child_bind=BIND(base+o["watcher"]+5264)
        self.library,self.table,self.bindings,self.libc_bytes,pointers=libc_bindings()
        self.lock=MUTEX(pointers[13]);self.unlock=MUTEX(pointers[14]);self.pointers=pointers
        self.env=C.create_string_buffer(bytes(4096)+b"\x5a"*16,4112)
    @property
    def environment(self):return C.addressof(self.env)
    def initialize_environment(self,observer):
        before=(self.env.raw,bytes(self.table));pointer=C.cast(observer,C.c_void_p)if observer is not None else None
        returned=int(self.initialize(self.environment,4096,C.addressof(self.table),pointer,None))
        after=(self.env.raw,bytes(self.table))
        require(returned==0 and after[1]==before[1]and after[0][4096:]==b"\x5a"*16,"whole actual environment init and guards")
        return returned,before,after
    def run(self,wire,obj,capacity):
        request=C.create_string_buffer(wire+b"\xc3"*16,len(wire)+16);response=C.create_string_buffer(b"\xa5"*208,208)
        before=(request.raw,response.raw,C.string_at(obj,capacity),self.env.raw)
        returned=int(self.entry(C.addressof(request),len(wire),C.addressof(response),192,obj,capacity))
        after=(request.raw,response.raw,C.string_at(obj,capacity),self.env.raw)
        require(after[0]==before[0]and after[1][128:]==b"\xa5"*80 and after[3][4096:]==b"\x5a"*16,
            "every complete actual outer guard and untouched terminal tail")
        return returned,before,after
    def close(self):
        for name in("entry","initialize","allocate","dispose","adopt","clone","release","child","child_bind","lock","unlock"):setattr(self,name,None)
        self.module.close()

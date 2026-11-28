"""Qualification-only transport for the separately sealed composite catalog image.

The custom build record describes five images and the actual HIA linker/packer
result. It is never presented as a single compiler-produced native module.
"""
from pathlib import Path
import ctypes,fcntl,hashlib,json,mmap,os,platform,struct,sys,threading
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"scripts"))
from hia_native_loader import (NativeModule,_read,F_ADD_SEALS,F_GET_SEALS,
    F_SEAL_SEAL,F_SEAL_SHRINK,F_SEAL_GROW,F_SEAL_WRITE)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def require(value,message):
    if not value: raise ValueError(message)
class CatalogCapability(NativeModule):
    def __init__(self,build,*,build_sha256):
        root=Path(build).absolute()
        require(root.resolve(strict=True)==root,"physical capability build root required")
        report=root/"BUILD.json";raw=_read(report,4<<20)
        require(sha(raw)==build_sha256,"exact composite build record differs")
        value=json.loads(raw)
        require(value["schema"]=="hepta.runtime.full-catalog-capability-build.v1"
            and value["status"]=="PASS" and value["runtime_images"]==["owner","policy","value","sdk","retained"]
            and value["runtime_hia_images"]==5,"composite catalog source/graph differs")
        def read_member(relative,identity,limit=16<<20):
            name=Path(relative)
            require(not name.is_absolute() and ".." not in name.parts,"relative capability path required")
            path=root/name;require(path.resolve(strict=True)==path,"physical capability file required")
            data=_read(path,limit)
            require(len(data)==identity["bytes"] and sha(data)==identity["sha256"],"capability bytes differ: "+relative)
            return data
        image=read_member(value["flat_image"]["path"],value["flat_image"])
        container=read_member(value["container"]["path"],value["container"])
        require(value["flat_image"]["entry_offset"]==0 and value["flat_image"]["container_offset"]==256
            and image==container[256:],"complete PIC image extraction differs")
        offsets=value["image_offsets"]
        require(set(offsets)==set(value["runtime_images"]),"complete image offset domain differs")
        for name in value["runtime_images"]:
            row=value["members"][name]
            member=read_member(row["image"],row["image_pin"])
            at=offsets[name]
            require(type(at) is int and at>=256 and at+len(member)<=len(container)
                and container[at:at+len(member)]==member,"complete packed member differs: "+name)
        require(len(value["patches"])==5,"complete call patch domain differs")
        for index,(kind,at,member) in enumerate(value["patches"]):
            require(kind==2 and member==index and container[at-1]==0xe9
                and at+4+struct.unpack_from("<i",container,at)[0]==offsets[value["runtime_images"][index]],
                "packed relative call differs")
        require(platform.system()=="Linux" and platform.machine()=="x86_64"
            and ctypes.sizeof(ctypes.c_void_p)==8,"Linux x86-64 LP64 required")
        self.record=value
        self.metadata={"schema":value["schema"],"input_capacity":16<<20,"output_capacity":64<<20,
            "workspace_capacity":256<<20,"source_sha256":build_sha256}
        self.source_path=report
        self.manifest_sha256=build_sha256
        self._lock=threading.RLock();self._address=None;self._entry=None;self._size=len(image)
        libc=ctypes.CDLL(None,use_errno=True)
        libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
        libc.mmap.restype=ctypes.c_void_p
        libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];libc.munmap.restype=ctypes.c_int
        self._libc=libc
        descriptor=os.memfd_create("hepta-full-catalog-composite",os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        try:
            at=0
            while at<len(image):
                n=os.write(descriptor,image[at:]);require(n>0,"short composite image write");at+=n
            seals=F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL
            fcntl.fcntl(descriptor,F_ADD_SEALS,seals)
            require(fcntl.fcntl(descriptor,F_GET_SEALS)&seals==seals,"composite code kernel seals differ")
            address=libc.mmap(None,len(image),mmap.PROT_READ|mmap.PROT_EXEC,mmap.MAP_PRIVATE,descriptor,0)
            require(address is not None and address!=ctypes.c_void_p(-1).value,"composite RX mapping failed")
            self._address=address
            self._entry=ctypes.CFUNCTYPE(ctypes.c_uint64,*([ctypes.c_void_p,ctypes.c_uint64]*3))(address)
        finally:
            os.close(descriptor)

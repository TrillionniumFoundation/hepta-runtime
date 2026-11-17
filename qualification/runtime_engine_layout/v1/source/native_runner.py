"""Capture actual fixed native engines, native HIA calls and physical storage."""
from pathlib import Path
import argparse,ctypes,fcntl,json,mmap,os,platform,sys,time
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path[:0]=[str(ROOT),str(ROOT/"scripts")]
from common import source,read,pin,put,SHA
from memory import maps,cover,absent,u64,qput,MASK
from hia_native_loader import NativeModule
U=ctypes.c_uint64
LIBC=ctypes.CDLL(None,use_errno=True)
LIBC.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
LIBC.mmap.restype=ctypes.c_void_p
LIBC.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];LIBC.munmap.restype=ctypes.c_int
class EngineImage:
    def __init__(self,path,metadata):
        raw=read(path);assert pin(raw)==metadata["image"]
        self.length=len(raw);self.expected=raw;self.metadata=metadata
        fd=os.memfd_create("hepta-engine-layout",os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        try:
            at=0
            while at<len(raw):
                count=os.write(fd,raw[at:]);assert count>0;at+=count
            seals=0x0001|0x0002|0x0004|0x0008
            fcntl.fcntl(fd,1033,seals);assert fcntl.fcntl(fd,1034)&seals==seals
            self.base=LIBC.mmap(None,len(raw),mmap.PROT_READ|mmap.PROT_EXEC,mmap.MAP_PRIVATE,fd,0)
            assert self.base not in (None,ctypes.c_void_p(-1).value)
        finally:os.close(fd)
        self.functions={}
        for name,arity in {"runtime_grow_create":2,"fixture_invoke":4,"fixture_destroy":1,
                           "fixture_detach":2,"fixture_restore":2,"view_allocate":1}.items():
            offset=metadata["exports"][name];assert 0<=offset<len(raw)
            self.functions[name]=ctypes.CFUNCTYPE(U,*([U]*arity))(self.base+offset)
    def call(self,name,*args):return int(self.functions[name](*args))
    def close(self):
        assert ctypes.string_at(self.base,self.length)==self.expected
        self.functions.clear();assert LIBC.munmap(self.base,self.length)==0
class Capture:
    def __init__(self,out):
        self.out=out;self.objects=out/"objects";self.objects.mkdir()
        self.journal=(out/"journal.ndjson").open("wb");self.pins={};self.physical=0;self.snapshots=0
    def blob(self,raw):
        key=SHA(raw);self.physical+=len(raw)
        if key not in self.pins:
            path=self.objects/key;path.write_bytes(raw);self.pins[key]=len(raw)
        else:assert self.pins[key]==len(raw)
        return pin(raw)
    def write(self,value):
        self.journal.write((json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode());self.journal.flush()
    def snapshot(self,regions):
        mapraw=Path("/proc/self/maps").read_bytes();rows=maps(mapraw);result={}
        for label,region in sorted(regions.items()):
            address=region["address"];capacity=region["capacity"];guard=region["guard"]
            if cover(rows,address,capacity,"rw-p"):
                assert not guard or cover(rows,address+capacity,4096,"---p"),label
                result[label]=dict(**region,mapped=True,physical=self.blob(ctypes.string_at(address,capacity)))
            else:
                assert guard and absent(rows,address,capacity+4096),(label,"partial/unexpected mapping")
                result[label]=dict(**region,mapped=False,physical=None)
        self.snapshots+=1
        return dict(maps=self.blob(mapraw),regions=result)
    def close(self):
        self.journal.close()
        return dict(objects=len(self.pins),unique_bytes=sum(self.pins.values()),physical_bytes=self.physical,
                    snapshots=self.snapshots,journal=pin(read(self.out/"journal.ndjson")))
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--build",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--source-manifest-sha256",required=True);a=p.parse_args()
    assert platform.system()=="Linux" and platform.machine()=="x86_64"
    identity=source(a.source_manifest_sha256);build=a.build.resolve(strict=True)
    buildraw=read(build/"BUILD.json");metadata=json.loads(buildraw)
    assert metadata["source_manifest_sha256"]==identity and metadata["status"]=="PASS"
    cases=json.loads(read(ROOT/"CASES.json"));domain=json.loads(read(ROOT/"DOMAIN.json"))
    assert len(cases["cases"])==domain["cases"]
    assert not a.output.exists();a.output.mkdir(parents=True);out=a.output.resolve()
    capture=Capture(out);started=time.monotonic();completed=[];native_calls=0
    leafinfo=metadata["hia_leaf"];manifest=build/leafinfo["manifest"]
    with NativeModule(manifest,manifest_sha256=leafinfo["manifest_pin"]["sha256"]) as leaf:
        leaf_address=int(leaf._address);leaf_before=ctypes.string_at(leaf_address,leaf._size)
        assert pin(leaf_before)==leafinfo["image"];leafproof=capture.blob(leaf_before)
        capture.write(dict(kind="session",schema="hepta.runtime.engine-layout.native-journal.v1",
            source_manifest_sha256=identity,build=pin(buildraw),leaf_address=leaf_address,leaf=leafproof,
            native_os=platform.platform(),pid=os.getpid(),cases=len(cases["cases"])))
        for case in cases["cases"]:
            role=case["role"];info=metadata["images"][role];assert info["slots"]==case["slots"]
            image=EngineImage(build/role/"module.bin",info);count=case["slots"]
            frame=bytes.fromhex(cases["frame_hex"]);assert len(frame)==64
            frame_obj=ctypes.create_string_buffer(frame+b"\xc3"*16,80)
            table_obj=ctypes.create_string_buffer(8*count+16)
            for slot in range(count):U.from_address(ctypes.addressof(table_obj)+slot*8).value=leaf_address
            ctypes.memset(ctypes.addressof(table_obj)+8*count,0xef,16)
            node_obj=ctypes.create_string_buffer(528);ctypes.memset(ctypes.addressof(node_obj)+512,0xd7,16)
            frame_at=ctypes.addressof(frame_obj);table_at=ctypes.addressof(table_obj);node_at=ctypes.addressof(node_obj)
            regions={label:dict(address=address,capacity=capacity,guard=False,kind=label,slot=None,borrowed=False)
                for label,address,capacity in (("frame",frame_at,80),("table",table_at,8*count+16),("node",node_at,528))}
            before=capture.snapshot(regions)
            engine=image.call("runtime_grow_create",table_at,0);native_calls+=1
            assert 0<engine<(1<<63),"native engine allocation failed"
            regions["engine"]=dict(address=engine,capacity=info["layout"]["engine_bytes"],guard=True,
                                    kind="engine",slot=None,borrowed=False)
            U.from_address(node_at+392).value=engine
            after=capture.snapshot(regions)
            capture.write(dict(kind="create",case=case["name"],role=role,slots=count,return_u64=engine,
                engine_image_address=image.base,engine_image=capture.blob(ctypes.string_at(image.base,image.length)),
                before=before,after=after,fixture_node_engine_write=dict(offset=392,value=engine)))
            def active():
                return cover(maps(Path("/proc/self/maps").read_bytes()),engine,info["layout"]["engine_bytes"],"rw-p")
            def descriptor(slot):
                assert active() and 0<=slot<count
                return engine+info["layout"]["descriptor_base"]+64*slot
            def discover():
                if not active():return
                raw=ctypes.string_at(engine,info["layout"]["engine_bytes"])
                for slot in range(count):
                    offset=info["layout"]["descriptor_base"]+64*slot
                    for kind,p,c in (("work",8,16),("output",32,40)):
                        address=u64(raw,offset+p);capacity=u64(raw,offset+c);label=kind+":"+str(slot)
                        if not address:continue
                        if label in regions:continue
                        assert address%4096==0 and capacity and capacity%4096==0,(label,address,capacity)
                        regions[label]=dict(address=address,capacity=capacity,guard=True,
                            kind=kind,slot=slot,borrowed=False)
                for kind,offset in (("workdir-control",192),("filesystem-control",200)):
                    address=u64(raw,offset)
                    if address and kind not in regions:
                        assert address%4096==0
                        regions[kind]=dict(address=address,capacity=4096,guard=True,kind=kind,slot=None,borrowed=False)
            for index,action in enumerate(case["actions"]):
                before=capture.snapshot(regions);op=action["op"];slot=action.get("slot")
                details={};result=None;performed=0
                if op=="invoke":
                    assert active()
                    result=image.call("fixture_invoke",engine,slot,frame_at,64);performed=1
                elif op in ("detach","restore"):
                    assert active()
                    result=image.call("fixture_"+op,engine,node_at);performed=1
                elif op=="borrow":
                    ptr=descriptor(slot);addresses={}
                    for kind,po,co,fill in (("work",8,16,0x5a),("output",32,40,0xa5)):
                        address=image.call("view_allocate",4096);performed+=1
                        assert 0<address<(1<<63) and address%4096==0
                        ctypes.memset(address,fill,4096);U.from_address(ptr+po).value=address;U.from_address(ptr+co).value=4096
                        label=kind+":"+str(slot);assert label not in regions
                        regions[label]=dict(address=address,capacity=4096,guard=True,kind=kind,slot=slot,borrowed=True)
                        addresses[kind]=address
                    details["allocations"]=addresses
                elif op=="zero_entry":
                    ptr=descriptor(slot);details["previous"]=int(U.from_address(ptr).value);U.from_address(ptr).value=0
                elif op=="busy":
                    assert active();ptr=engine+512+64*slot
                    details["previous"]=int(U.from_address(ptr).value);U.from_address(ptr).value=action["value"]
                elif op in ("unalign","repair"):
                    kind=action["kind"];region=regions[kind+":"+str(slot)]
                    ptr=descriptor(slot)+(8 if kind=="work" else 32)
                    details["previous"]=int(U.from_address(ptr).value)
                    value=region["address"]+(1 if op=="unalign" else 0);U.from_address(ptr).value=value
                    details["written"]=value
                elif op=="destroy":
                    assert active();result=image.call("fixture_destroy",engine);performed=1
                elif op=="release_borrows":
                    assert not active();details["releases"]=[]
                    for label,region in sorted(regions.items()):
                        if region["borrowed"]:
                            status=LIBC.munmap(region["address"],region["capacity"]+4096)
                            details["releases"].append(dict(label=label,result=status,errno=ctypes.get_errno() if status else 0))
                else:raise AssertionError(op)
                native_calls+=performed;discover()
                after=capture.snapshot(regions)
                capture.write(dict(kind="action",case=case["name"],index=index,action=action,return_u64=result,
                                   actual_native_calls=performed,details=details,before=before,after=after))
            assert not active(),"case retained live engine after its complete cleanup inputs"
            rows=maps(Path("/proc/self/maps").read_bytes())
            for label,region in regions.items():
                if region["guard"]:assert absent(rows,region["address"],region["capacity"]+4096),(case["name"],label)
            image_after=ctypes.string_at(image.base,image.length)
            capture.write(dict(kind="case_end",case=case["name"],actions=len(case["actions"]),
                               engine_image_after=capture.blob(image_after),all_case_native_mappings_retired=True))
            image.close();completed.append(case["name"])
        leaf_after=ctypes.string_at(leaf_address,leaf._size);assert leaf_after==leaf_before
        capture.write(dict(kind="session_end",completed_cases=completed,actual_native_calls=native_calls,
                           leaf_after=capture.blob(leaf_after)))
    physical=capture.close();assert source()==identity
    report=dict(schema="hepta.runtime.engine-layout.native-capture.v1",status="CAPTURED",
        source_manifest_sha256=identity,build=pin(buildraw),cases=len(completed),
        actions=sum(len(c["actions"]) for c in cases["cases"]),actual_native_calls=native_calls,
        elapsed_seconds=time.monotonic()-started,**physical,host_semantic_fallback=False,
        old_graph_above_59_executed=False,public_handler_qualified=False,whole_runtime_replaced=False)
    put(out/"NATIVE.json",report);print(json.dumps(report,sort_keys=True))
if __name__=="__main__":main()

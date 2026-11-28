#!/usr/bin/env python3
"""Invoke only frozen private HIA transport and rejected native packets."""
from pathlib import Path
import argparse,ctypes,os,struct,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from evidence_common import decode,encoded,pin,require,source_evidence
from worker import Native,Journal
from protocol import u
def arena(size,fill,guard):
    value=(ctypes.c_ubyte*(size+16))()
    ctypes.memset(ctypes.addressof(value),fill,size);ctypes.memset(ctypes.addressof(value)+size,guard,16)
    return value
class Capture:
    def __init__(self,root,entry):
        self.root=root;root.mkdir();self.entry=entry;self.records=[]
    def put(self,index,name,raw):
        path=self.root/(str(index).zfill(4)+"-"+name+".bin");path.write_bytes(raw)
        return dict(path=path.name,**pin(path))
    def call(self,label,item,work,workspace_capacity):
        wire=bytes.fromhex(item["wire_hex"]);input=arena(len(wire),0,0xd3)
        if wire:ctypes.memmove(ctypes.addressof(input),wire,len(wire))
        output=arena(item["output_capacity"],0xa5,0xe7);index=len(self.records);before={}
        for name,value in(("input",input),("output",output),("work",work)):
            before[name]=self.put(index,name+"-before",bytes(value))
        code=self.entry(ctypes.addressof(input),len(wire),ctypes.addressof(output),item["output_capacity"],
            ctypes.addressof(work),workspace_capacity)
        after={}
        for name,value in(("input",input),("output",output),("work",work)):
            after[name]=self.put(index,name+"-after",bytes(value))
        row=dict(label=label,index=index,input=item,return_value=code,workspace_capacity=workspace_capacity,
            workspace_address=ctypes.addressof(work),before=before,after=after)
        self.records.append(row)
        (self.root/"CALLS.json").write_bytes(encoded(self.records))
        return row
def native_bytes(native):
    raw=ctypes.string_at(native.context,4096);out=raw
    for at in(64,88,104,120):
        require(u(raw,at+8)==4096,"fixed native private arena")
        out+=ctypes.string_at(u(raw,at),4096)
    out+=ctypes.string_at(native.pool,4096);return out
def main():
    p=argparse.ArgumentParser()
    for key in("source","build","output"):p.add_argument("--"+key,type=Path,required=True)
    a=p.parse_args();source=a.source.resolve(strict=True);build=a.build.resolve(strict=True);output=a.output.absolute()
    require(not output.exists(),"fresh private capture");output.mkdir()
    identity=source_evidence(source);domain=decode((source/"PRIVATE_DOMAIN.json").read_bytes())
    event_fd=os.open(output/"native-events.bin",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o644)
    journal=Journal(event_fd);binding=decode((source/"BUILD_REUSE.json").read_bytes())
    native=Native(build,binding,journal,False);meta=native.build
    (output/"BUILD.json").write_bytes((build/"BUILD.json").read_bytes())
    require(meta["image_order"]==["body"]and len(meta["image_offsets"])==1,"one qualified HIA body")
    entry=ctypes.CFUNCTYPE(ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,
        ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64)(native.base+meta["image_offsets"][0])
    capture=Capture(output/"hia",entry)
    for item in domain["framing"]:
        work=arena(item["workspace_capacity"],item["workspace_fill"],0xa9)
        capture.call("framing/"+item["name"],item,work,item["workspace_capacity"])
    for flow in domain["flows"]:
        work=arena(flow["workspace_capacity"],flow["workspace_fill"],0xa9)
        for index,item in enumerate(flow["calls"]):
            capture.call("flow/"+flow["name"]+"/"+str(index),item,work,flow["workspace_capacity"])
    rejections=[];folder=output/"native";folder.mkdir()
    for item in domain["framing"]:
        if not item["native_reject"]:continue
        wire=bytes.fromhex(item["wire_hex"]);packet=arena(len(wire),0,0xd3)
        if wire:ctypes.memmove(ctypes.addressof(packet),wire,len(wire))
        before=native_bytes(native);input_before=bytes(packet)
        code=native.invoke(native.context,ctypes.addressof(packet),len(wire))
        after=native_bytes(native);input_after=bytes(packet);index=len(rejections)
        paths={}
        for name,raw in(("before",before),("after",after),("input-before",input_before),("input-after",input_after)):
            path=folder/(str(index).zfill(3)+"-"+name+".bin");path.write_bytes(raw);paths[name]=dict(path=path.name,**pin(path))
        rejections.append(dict(input=item,name=item["name"],return_value=code,buffers=paths))
        (folder/"CALLS.json").write_bytes(encoded(rejections))
    require(journal.pin()["events"]==journal.pin()["bytes"]==0,"native rejections executed no HIA application")
    os.close(event_fd)
    result=dict(status="PRIVATE_INTERFACE_CAPTURE_COMPLETE",source=identity,domain=pin(source/"PRIVATE_DOMAIN.json"),
        executable=binding["elf"],build=pin(build/"BUILD.json"),mapping=native.base,context=native.context,pool=native.pool,
        process_pid=os.getpid(),private_hia_entry_calls=len(capture.records),private_native_admission_calls=len(rejections),
        actual_kernel_entropy_applications=0,original_applications=0,native_observer_events=journal.pin())
    (output/"CAPTURE.json").write_bytes(encoded(result))
    require(source_evidence(source)==identity,"private runner changed frozen source")
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()

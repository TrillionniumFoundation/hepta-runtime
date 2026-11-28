#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Pair real Rust 1.95 std metadata with the raw HIA callable, including seccomp and syscall traces."""
from __future__ import annotations
import argparse,ctypes,fcntl,hashlib,json,os,signal,struct,subprocess,time
from pathlib import Path
MASK=(1<<64)-1
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(path):
    raw=Path(path).read_bytes();return {"bytes":len(raw),"sha256":sha(raw)}
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
def require(value,message):
    if not value:raise AssertionError(message)
def request(command=2,fd=0,path=b""):
    return b"HNSMQ001"+struct.pack("<3Q",command,fd,len(path))+bytes(64)+path
LIBC=ctypes.CDLL(None,use_errno=True)
LIBC.ptrace.argtypes=[ctypes.c_uint64,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_void_p]
LIBC.ptrace.restype=ctypes.c_long
def ptrace(op,pid,addr=0,data=0):
    ctypes.set_errno(0);result=LIBC.ptrace(op,pid,addr,data)
    if result==-1 and ctypes.get_errno():raise OSError(ctypes.get_errno(),"ptrace")
    return result
def signed32(value):return ctypes.c_int32(value&0xffffffff).value
def read_c_string(pid,address):
    if address==0:return None
    result=bytearray()
    for offset in range(0,16384,8):
        value=ptrace(2,pid,address+offset,0)&MASK
        block=struct.pack("<Q",value)
        if b"\0" in block:return bytes(result+block.split(b"\0",1)[0]).hex()
        result.extend(block)
    raise AssertionError("metadata pathname trace exceeded the qualification bound")
def syscall_row(pid,nr,args):
    if nr==332:return ["statx",signed32(args[0]),read_c_string(pid,args[1]),args[2],args[3],args[4]==0]
    if nr==5:return ["fstat",signed32(args[0]),args[1]==0]
    if nr==262:return ["newfstatat",signed32(args[0]),read_c_string(pid,args[1]),args[3],args[2]==0]
    return None
def run_traced(binary,image,mode,input_path,folder,keep_fds):
    stdout=folder/(mode+".stdout");stderr=folder/(mode+".stderr")
    infd=os.open(input_path,os.O_RDONLY);outfd=os.open(stdout,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);errfd=os.open(stderr,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    before=time.monotonic();pid=os.fork()
    if pid==0:
        try:
            os.dup2(infd,0);os.dup2(outfd,1);os.dup2(errfd,2)
            for fd in keep_fds:os.set_inheritable(fd,True)
            for fd in (infd,outfd,errfd):
                if fd>2 and fd not in keep_fds:os.close(fd)
            ptrace(0,0);os.execv(binary,[str(binary),mode,str(image)])
        finally:os._exit(127)
    os.close(infd);os.close(outfd);os.close(errfd)
    rows=[];active=False;pending=None;terminal=None
    def timeout(signum,frame):raise TimeoutError("actual metadata process exceeded 20 seconds")
    previous=signal.signal(signal.SIGALRM,timeout);signal.alarm(20)
    try:
        _,status=os.waitpid(pid,0);require(os.WIFSTOPPED(status),"trace child did not stop at exec")
        ptrace(0x4200,pid,0,1)
        while True:
            ptrace(24,pid,0,0)
            _,status=os.waitpid(pid,0)
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):terminal=status;break
            require(os.WIFSTOPPED(status),"unknown traced wait status")
            sig=os.WSTOPSIG(status)
            require(sig==(signal.SIGTRAP|0x80),"unexpected signal in actual metadata process: "+str(sig))
            info=ctypes.create_string_buffer(128)
            size=ptrace(0x420e,pid,128,ctypes.addressof(info));require(size>=24,"missing syscall information")
            op=info.raw[0]
            if op==1:
                nr,*args=struct.unpack_from("<7Q",info.raw,24)
                if nr==1 and signed32(args[0])==-1 and args[2]==8:active=True
                elif nr==1 and signed32(args[0])==-2 and args[2]==8:active=False
                pending=syscall_row(pid,nr,args) if active else None
            elif op==2:
                if pending is not None:
                    rows.append([*pending,struct.unpack_from("<q",info.raw,24)[0]])
                pending=None
            else:raise AssertionError("unexpected syscall stop type "+str(op))
    except BaseException:
        try:os.kill(pid,signal.SIGKILL)
        except ProcessLookupError:pass
        try:os.waitpid(pid,0)
        except ChildProcessError:pass
        raise
    finally:signal.alarm(0);signal.signal(signal.SIGALRM,previous)
    row={"argv":[str(binary),mode,str(image)],"wait_status":terminal,
        "returncode":os.waitstatus_to_exitcode(terminal),"seconds":time.monotonic()-before,
        "stdout":pin(stdout),"stderr":pin(stderr),"metadata_syscalls":rows}
    (folder/(mode+".json")).write_bytes(encoded(row))
    require(row["returncode"]==0,mode+" actual process failed: "+stderr.read_text()[-2000:])
    return stdout.read_bytes(),row
def decode(raw,count):
    require(raw[:8]==b"HMTRS001" and struct.unpack_from("<Q",raw,8)[0]==count,"result framing differs")
    require(len(raw)==16+count*288,"complete result byte count differs")
    result=[]
    for i in range(count):
        record=raw[16+i*288:16+(i+1)*288]
        scalar,cache,guards,extent=struct.unpack_from("<4Q",record)
        body=record[32:];magic,kind,error,payload=struct.unpack_from("<8sQQQ",body)
        require(scalar==32 and guards==7 and magic==b"HNSMR001","native/reference scalar or guards differ")
        require(extent==32+payload and extent in (32,176),"response extent differs")
        require((kind==0 and error==0 and payload==144) or (kind==1 and payload==0 and error<=4095) or
            (kind==2 and payload==0 and error==0),"response field shape differs")
        require(body[extent:]==b"\xb6"*(256-extent),"unused output tail changed")
        result.append({"scalar":scalar,"cache":cache,"guards":guards,"extent":extent,"body_hex":body.hex()})
    return result
def map_image(image):
    LIBC.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
    LIBC.mmap.restype=ctypes.c_void_p
    raw=image.read_bytes();fd=os.memfd_create("hia-metadata-controls",os.MFD_ALLOW_SEALING)
    try:
        at=0
        while at<len(raw):at+=os.write(fd,raw[at:])
        fcntl.fcntl(fd,1033,15);require(fcntl.fcntl(fd,1034)==15,"kernel code seals differ")
        address=LIBC.mmap(None,len(raw),5,2,fd,0);require(address not in (None,ctypes.c_void_p(-1).value),"RX mapping failed")
    finally:os.close(fd)
    return address,len(raw),ctypes.CFUNCTYPE(ctypes.c_uint64,*([ctypes.c_void_p,ctypes.c_uint64]*3))(address)
def abi_controls(image):
    address,size,fn=map_image(image);rows=[]
    def call(name,wire,expected,output_capacity=256,cache_capacity=1,cache_initial=0,overlap=None):
        source=ctypes.create_string_buffer(b"\xa5"*16+wire+b"\xa5"*16)
        output=ctypes.create_string_buffer(b"\xb6"*288)
        cache=(ctypes.c_ubyte*33)(*[0xcc]*33);cache[16]=cache_initial
        sp=ctypes.addressof(source)+16;op=ctypes.addressof(output)+16;cp=ctypes.addressof(cache)+16
        if overlap=="output":op=sp
        if overlap=="source-cache":cp=sp
        if overlap=="output-cache":cp=op
        code=fn(sp,len(wire),op,output_capacity,cp,cache_capacity)
        require(code==expected,name+" status differs")
        require(source.raw[:len(wire)+32]==b"\xa5"*16+wire+b"\xa5"*16,name+" changed original input/guards")
        require(output.raw[:288]==b"\xb6"*288,name+" changed output/guards on rejection")
        require(bytes(cache[:16])+bytes(cache[17:])==b"\xcc"*32 and cache[16]==cache_initial,name+" changed cache on rejection")
        rows.append({"name":name,"scalar":code,"input":pin_bytes(wire),"whole_output_unchanged":True,"cache_and_guards_unchanged":True})
    good=request(1,0)
    call("short-header",good[:95],0xffffffff)
    call("bad-magic",b"badmagic"+good[8:],0xffffffff)
    call("unknown-command",request(3,0),0xffffffff)
    call("fd-outside-i32",request(1,1<<31),0xffffffff)
    call("fd-has-payload",request(1,0,b"x"),0xffffffff)
    call("path-has-fd",request(2,1,b"x"),0xffffffff)
    call("length-mismatch",good+b"x",0xffffffff)
    for offset in range(32,96,8):
        malformed=bytearray(good);struct.pack_into("<Q",malformed,offset,1);call("reserved-"+str(offset),bytes(malformed),0xffffffff)
    call("small-output",good,0xfffffffe,output_capacity=175)
    call("empty-cache-capacity",good,0xfffffffe,cache_capacity=0)
    call("invalid-cache-state",good,0xffffffff,cache_initial=3)
    call("request-output-alias",good,0xffffffff,overlap="output")
    call("request-cache-alias",good,0xffffffff,overlap="source-cache")
    call("output-cache-alias",good,0xffffffff,overlap="output-cache")
    LIBC.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];require(LIBC.munmap(address,size)==0,"unmapping qualification image failed")
    return rows
def pin_bytes(raw):return {"bytes":len(raw),"sha256":sha(raw)}
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ("source","build","reference","output"):p.add_argument("--"+key,type=Path,required=True)
    a=p.parse_args();root=a.source.resolve(strict=True);build=a.build.resolve(strict=True);reference=a.reference.resolve(strict=True);out=a.output.absolute()
    require(not out.exists(),"fresh qualification output required");out.mkdir(parents=True)
    report=json.loads((build/"BUILD.json").read_bytes());image=build/report["flat_image"]["path"]
    require(pin(image)=={k:report["flat_image"][k] for k in ("bytes","sha256")},"complete native image identity differs")
    for name,identity in report["source_files"].items():require(pin(root/name)==identity,"bound build source changed: "+name)
    reference_report=json.loads((reference/"COMPILE.json").read_bytes());binary=reference/"actual"
    require(reference_report.get("returncode")==0 and "rustc 1.95.0 " in reference_report["rustc_version"] and pin(binary)==reference_report["binary"],"actual original Rust 1.95 binary differs")
    require(pin(root/"authoring/namespace_metadata/reference/actual.rs")==reference_report["source"],"reference source differs")
    fixtures=out/"fixtures";fixtures.mkdir();file=fixtures/"regular";file.write_bytes(b"fixed metadata test contents\n")
    raw_name=os.fsencode(fixtures)+b"/raw-\xff";fd=os.open(raw_name,os.O_CREAT|os.O_WRONLY,0o600);os.write(fd,b"raw");os.close(fd)
    directory=fixtures/"directory";directory.mkdir();symlink=fixtures/"symlink";symlink.symlink_to(file)
    (fixtures/"loop-a").symlink_to("loop-b");(fixtures/"loop-b").symlink_to("loop-a")
    os.chmod(file,0o640);os.utime(file,ns=(1_700_000_000_000_000_001,1_700_000_100_000_000_002))
    file_fd=os.open(file,os.O_RDONLY);dir_fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
    groups=[]
    try:
        base=[request(2,0,os.fsencode(file)),request(1,file_fd),request(2,0,os.fsencode(directory)),request(1,dir_fd),
              request(2,0,os.fsencode(symlink)),request(2,0,raw_name),request(2,0,os.fsencode(fixtures/"missing")),
              request(2,0,os.fsencode(file)+b"/child"),request(2,0,b""),request(2,0,b"nul\0suffix"),
              request(2,0,os.fsencode(fixtures/"loop-a")),request(2,0,b"x"*5000),request(1,0)]
        configs=[("ordinary",0,0,base),("nul-first",0,0,[request(2,0,b"a\0b"),base[0],base[1]]),
                 ("missing-first",0,0,[base[6],base[0],base[1]]),("non-directory-first",0,0,[base[7],base[0],base[1]])]
        for filter in range(1,11):
            for warm in (0,1):
                configs.append(("seccomp-"+str(filter)+"-warm-"+str(warm),filter,warm,[base[0],base[1],base[6],base[7],base[9]]))
        for name,filter,warm,requests in configs:
            folder=out/name;folder.mkdir()
            frame=b"HMTST001"+struct.pack("<3Q",filter,warm,len(requests))+b"".join(struct.pack("<Q",len(x))+x for x in requests)
            input_path=folder/"input.bin";input_path.write_bytes(frame)
            now=time.time_ns();os.utime(input_path,ns=(now+86_400_000_000_000,now))
            pairs=[]
            for mode in ("reference","native"):
                raw,process=run_traced(binary,image,mode,input_path,folder,(file_fd,dir_fd))
                pairs.append((decode(raw,len(requests)),process))
            original,current=pairs
            require(original[1]["metadata_syscalls"]==current[1]["metadata_syscalls"],name+" actual syscall sequence differs")
            for i,(left,right) in enumerate(zip(original[0],current[0],strict=True)):
                require({k:v for k,v in left.items() if k!="cache"}=={k:v for k,v in right.items() if k!="cache"},
                    name+" complete 256-byte result differs at request "+str(i))
            row={"name":name,"filter":filter,"warm":warm,"requests":len(requests),"full_results_equal":True,
                "actual_metadata_syscalls_equal":True,"native_cache_values":[x["cache"] for x in current[0]],
                "original":original[1],"native":current[1]}
            (folder/"pair.json").write_bytes(encoded(row));groups.append(row)
            print(json.dumps({"group":name,"requests":len(requests),"status":"PASS","syscalls":len(row["native"]["metadata_syscalls"])}),flush=True)
        controls=abi_controls(image)
    finally:os.close(file_fd);os.close(dir_fd)
    for name,identity in report["source_files"].items():require(pin(root/name)==identity,"terminal build source changed: "+name)
    result={"schema":"hepta.runtime.namespace-metadata-actual.v1","status":"PASS",
        "source":{str(p.relative_to(root)):pin(p) for p in (
            root/"authoring/namespace_metadata/qualify.py",root/"authoring/namespace_metadata/reference/actual.rs")},
        "build":pin(build/"BUILD.json"),"image":pin(image),"rust_reference":reference_report,
        "paired_process_groups":len(groups),"paired_requests":sum(x["requests"] for x in groups),
        "abi_controls":controls,"groups":groups,"terminal_scalar":32,"success_extent":176,"error_extent":32,
        "stat64_fields_and_padding_compared":True,"fileattr_extra_btime_exposed":False,
        "runtime_python_required":False,"runtime_libc_required":False,"whole_namespace_qualified":False,"whole_runtime_replaced":False}
    (out/"RESULT.json").write_bytes(encoded(result))
    print(json.dumps({"status":"PASS","groups":len(groups),"requests":result["paired_requests"],"abi_controls":len(controls)}),flush=True)
if __name__=="__main__":main()

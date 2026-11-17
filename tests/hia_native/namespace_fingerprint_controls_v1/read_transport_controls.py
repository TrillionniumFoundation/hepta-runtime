"""Whole native-control buffers, exact actual code/libc ownership and unchanged original recovery."""
import gzip,io,struct
from common import ROOT,loads,read,pin,require,source,files
from callable_contract import CONTEXT_BYTES,semantic,word
from protocol import domain
from read_frames import Outer,equal
from read_context import Context
from read_owner import put
from read_filesystem import Tree
from read_libc import verify as verify_libc
from transport_cases import SPECS,wire,sequence,argv,mutate,source_case
import control_common as rc
ORDER=("input","output","context","table")
class Physical:
    def __init__(self,path,magic):
        self.stream=gzip.GzipFile(fileobj=io.BytesIO(read(path)),mode="rb");self.count=0;self.total=0
        require(self.exact(8)==magic,"whole physical control header")
    def exact(self,n):
        require(type(n)is int and n>=0,"bounded full control read");raw=self.stream.read(n)
        require(len(raw)==n,"entire physical control extent");self.total+=n;return raw
    def end(self,magic):
        require(self.exact(8)==magic and struct.unpack("<Q",self.exact(8))[0]==self.count and self.stream.read()==b"",
                "all physical control calls, footer, CRC and absence of suffix")
        return self.total
    def close(self):self.stream.close()
def original_recovery(capture):
    folder=capture/"paired-ordinary/roles/native-off/capture";report=loads(read(folder/"NATIVE.json"))
    library=verify_libc(folder);bindings={r["case"]:r for r in loads(read(folder/"CONTEXTS.json"))}
    outer=Outer(folder);selected=[]
    for case in [r for r in domain(ROOT)["cases"]if r["group"]=="ordinary"]:
        ci=case["case"];b=bindings[ci]
        outer.next(ci,0,0,dict(directory=96,table=b["table"],observer=0,user=0),library["table"])
        for si,_ in enumerate(case["steps"]):
            before,after=outer.next(ci,si,1,dict(observer=False),library["table"])
            if ci==source_case()["case"]and si==0:selected.append((after[1][:128],after[2]))
        outer.next(ci,0,2,{},library["table"])
    outer.finish();require(len(selected)==1 and report["observer_enabled"]is False,"exact one unchanged original-compared recovery")
    terminal,context=selected[0]
    require(semantic(terminal)==dict(kind=1,errno=20,digest="00"*32)and word(context,56)==2 and word(context,184)==1,
            "original-compared first-open ENOTDIR recovery")
    return terminal,context
def verify(folder,capture,build):
    report=loads(read(folder/"CONTROLS.json"));names={"CALLS.json","OBSERVATIONS.json","RETIREMENT.json","buffers.bin.gz",
        "LIBC.bin","LIBC-BINDINGS.json","PROCESS-MAPS.txt"}
    require(set(files(folder))==names|{"CONTROLS.json"}and set(report["files"])==names,"complete control file set")
    for name in names:equal(report["files"][name],pin(read(folder/name)),"entire control file "+name)
    image=pin(read(build/"callable/callable.image.bin"));binding=loads(read(build/"callable/BINDING.json"))
    require(report["schema"]=="hepta.namespace-fingerprint.transport-controls.v1"and report["status"]=="PASS"and
            report["source_manifest_sha256"]==source()and report["control_source_sha256"]==rc.source()and
            report["cases"]==report["refusals"]==report["recoveries"]==len(SPECS)and
            report["actual_calls"]==4*len(SPECS)and report["callable"]==image and report["original_rust_replay"]==0 and
            report["admission_only_refusal_atomicity"]is True and report["foreign_executable_capabilities"]is False and
            report["namespace_version_qualified"]is False and report["public_handler_qualified"]is False,
            "fixed full exported ABI/refusal/recovery domain")
    require(all(type(report[k])is int and report[k]>0 for k in("uid","gid","pid","parent_pid","pgid")),
            "actual unprivileged control process identity")
    library=verify_libc(folder);loaded=report["loaded_image"]
    require(set(loaded)=={"address","bytes"}and type(loaded["address"])is int and loaded["address"]>0 and
            loaded["bytes"]==image["bytes"]and any(m["lo"]<=loaded["address"]and loaded["address"]+loaded["bytes"]<=m["hi"]and
                m["permissions"][:3]=="r-x"for m in library["maps"]),"complete actual sealed callable mapping")
    equal(report["exports"],{n:loaded["address"]+binding["offsets"][n]for n in("entry","initialize","dispose")},"fixed actual callable exports")
    rows=loads(read(folder/"CALLS.json"));observations=loads(read(folder/"OBSERVATIONS.json"));retired=loads(read(folder/"RETIREMENT.json"))
    require(len(rows)==4*len(SPECS)and len(observations)==len(SPECS)and retired["completed"]is True and
            retired["owned_root"]==report["fixture"]and len(retired["cases"])==len(SPECS),"entire native control and retirement corpus")
    expected_terminal,reference_context=original_recovery(capture)
    stream=Physical(folder/"buffers.bin.gz",b"NFCTLOG1")
    try:
        for ci,spec in enumerate(SPECS):
            current=dict(input=wire()+b"\xc3"*16,output=b"\xa5"*144,context=bytes(CONTEXT_BYTES)+b"\x5a"*16,table=library["table"])
            addresses=None
            for phase,function,parameters,changes,expected in sequence(spec):
                require(stream.exact(8)==b"NFCTCALL","actual control marker")
                index,returned,nm,ni,no,nc,nt=struct.unpack("<7Q",stream.exact(56))
                require((index,ni,no,nc,nt)==(stream.count,80,144,32784,56)and 0<nm<=65536,"whole actual control extents")
                raw_meta=stream.exact(nm);record=loads(raw_meta)
                before=[stream.exact(n)for n in(ni,no,nc,nt)];after=[stream.exact(n)for n in(ni,no,nc,nt)]
                equal(record,rows[index],"complete physical control receipt")
                wanted=dict(index=index,case=ci,name=spec[0]+"/"+spec[1],phase=phase,function=function,parameters=parameters,
                    mutations=[list(x)for x in changes],expected=expected,returned=returned,addresses=record["addresses"],
                    arguments=record["arguments"],elapsed_ns=record["elapsed_ns"],before=[pin(x)for x in before],after=[pin(x)for x in after])
                equal(record,wanted,"every actual control scalar and buffer")
                require(type(record["elapsed_ns"])is int and record["elapsed_ns"]>=0,"exact elapsed integer")
                here=record["addresses"]
                require(set(here)==set(ORDER)|{"root"}and all(type(v)is int and 0<=v<1<<64 for v in here.values())and
                        all(here[n]>0 and here[n]%8==0 for n in ORDER)and 2<here["root"]<=0x7fffffff,
                        "actual owned control allocations and real borrowed root")
                if addresses is None:addresses=here
                equal(here,addresses,"same actual allocations throughout refusal and recovery")
                intervals=sorted((here[n],here[n]+extent)for n,extent in zip(ORDER,(ni,no,nc,nt)))
                require(all(a[1]<=b[0]for a,b in zip(intervals,intervals[1:])),"all physical allocation regions disjoint")
                changed=mutate(current,changes)
                require(before==[changed[n]for n in ORDER],"only exact source-owned caller mutations")
                equal(record["arguments"],argv(function,parameters,addresses),"complete actual export arguments")
                require(type(returned)is int and returned==expected,"exact native result")
                if phase=="refusal":require(after==before,"every input/output/context/table byte unchanged on refusal")
                elif function=="initialize":
                    expected_context=Context(dict(context=here["context"],root_fd=here["root"],observer=0),library["table"],library["maps"]).raw()
                    wanted=dict(current,context=expected_context)
                    require(after==[wanted[n]for n in ORDER],"whole actual initializer")
                    current=wanted
                elif function=="dispose":
                    wanted=dict(current,context=bytes(CONTEXT_BYTES)+b"\x5a"*16)
                    require(after==[wanted[n]for n in ORDER],"whole actual disposal")
                    current=wanted
                else:
                    wanted_context=bytearray(reference_context)
                    put(wanted_context,24,here["root"]);wanted_context[64:112]=library["table"][:48]
                    obs=list(struct.unpack_from("<16Q",wanted_context,4864))
                    obs[3]=here["context"]+256;obs[5]=here["context"]+4608;obs[7]=here["context"]+8192;obs[9]=here["context"]
                    wanted_context[4864:4992]=struct.pack("<16Q",*obs)
                    wanted=dict(current,output=expected_terminal+b"\xa5"*16,context=bytes(wanted_context))
                    require(after==[wanted[n]for n in ORDER],"every actual recovery byte equals original-compared observer-free checkpoint")
                    observation=observations[ci]
                    equal({k:v for k,v in observation.items()if k not in("before","after")},dict(case=ci,name=spec[0]+"/"+spec[1],
                        native_frame_hex=expected_terminal.hex(),semantic=semantic(expected_terminal)),"whole actual native recovery semantic")
                    tree=Tree(source_case(),report["uid"],report["gid"]);tree.verify(observation["before"]);tree.verify(observation["after"])
                    equal(observation["before"],observation["after"],"all actual file bytes, mode, identity and metadata unchanged")
                    equal(retired["cases"][ci],dict(complete_before=observation["after"],retired=True,
                        root=report["fixture"]+"/case-%04d"%ci),"exact whole fixture retired after capture")
                    current=wanted
                stream.count+=1
        require(stream.count==len(rows),"every actual native control consumed once")
        total=stream.end(b"NFCTEND1")
    finally:stream.close()
    return dict(status="COMPLETE_FINGERPRINT_TRANSPORT_CONTROLS_PASS",cases=len(SPECS),refusals=len(SPECS),recoveries=len(SPECS),
        actual_calls=len(rows),complete_buffer_bytes=total,native_or_rust_executions=0,reader_writes=0)

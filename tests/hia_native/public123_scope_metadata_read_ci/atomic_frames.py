"""Read retained complete callable row 7 and closed-FD state; never execute it."""
from pathlib import Path
import gzip,hashlib,json,struct
from read_capture_fixed import pin,doc
FIXED={b"HRGTR002":224,b"HRCNAK02":128,b"HWDIOAK2":160,b"HFSPCL02":80,b"HFSPAK02":192,b"HVRDACK1":128,b"HFLKEYFX":128}
def words(raw):
    return list(struct.unpack_from("<"+"Q"*(len(raw)//8),raw))
def inspect(folder):
    folder=Path(folder);process=doc(folder/"complete-process.json");item=process["fixed_capabilities"]["host-trace"]
    path=folder/Path(item["path"]).name
    assert pin(path.read_bytes())==item["compressed"]
    digest=hashlib.sha256();size=0;frames=[];inputs={};context=None;callable_index=None;stage=None
    with gzip.open(path,"rb") as stream:
        def read(n):
            nonlocal size
            raw=stream.read(n);assert len(raw)==n;digest.update(raw);size+=n;return raw
        while True:
            magic=stream.read(8)
            if not magic:break
            assert len(magic)==8;digest.update(magic);size+=8
            if magic==b"HXLTR001":
                head=magic+read(56);w=struct.unpack_from("<7Q",head,8);read(w[4]+w[5]);continue
            if magic!=b"HPTREV01":
                assert magic in FIXED
                read(FIXED[magic]-8);continue
            head=magic+read(120);w=struct.unpack_from("<15Q",head,8)
            extent,seq,event,hgen,gen,node,engine,clock,an,bn,cn,phase,written,capacity,zero=w
            assert extent==128+an+bn+cn and zero==0
            a=read(an);b=read(bn);c=read(cn);key=(node,hgen)
            if event==1:
                inputs[key]={"input_hex":a.hex(),"input":pin(a),"sequence":seq}
            if event in (3,4,7):stage=event
            if event==9:
                assert len(a)==len(b)==len(c)==4096
                context={"trace_sequence":seq,"stage":stage,"node":node,"host_generation":hgen,"generation":gen,
                    "node_header":words(a[:512]),"caller_header":words(b[:256]),"body_header":words(c[:256]),
                    "atomic_context":words(c[2304:2432]),"retained_temp_fd":struct.unpack_from("<q",c,2384)[0],
                    "full_contexts":{"node":pin(a),"caller":pin(b),"body":pin(c)},
                    "accepted":inputs.get(key)}
                callable_index=0
            if event==11:
                assert context is not None and callable_index is not None and len(a)==64
                row=words(a);assert len(b)==row[2] and len(c)==row[4]
                if callable_index==7:
                    value={"context":context,"trace_sequence":seq,"descriptor":row,"workspace":pin(b),"output":pin(c),
                        "workspace_first_512_hex":b[:512].hex(),"workspace_first_512_words":words(b[:512]),
                        "output_first_256_hex":c[:256].hex()}
                    if len(b)>=1024:
                        q=lambda off:struct.unpack_from("<Q",b,off)[0]
                        value["paths"]={}
                        for name,offset,length in (("target",1024,q(40)),("temporary",q(64),q(72))):
                            if offset+length<len(b):
                                value["paths"][name]={"offset":offset,"length":length,"bytes_hex":b[offset:offset+length].hex(),"terminator":b[offset+length]}
                    frames.append(value)
                callable_index+=1
                assert callable_index<=14
    assert {"bytes":size,"sha256":digest.hexdigest()}==item["uncompressed"]
    journal=process["fixed_capabilities"]["worker-journal"]
    return {"complete_trace":item,"worker_journal":journal,"atomic_frames":frames,
        "application_executions":0,"qualification_changed":False}

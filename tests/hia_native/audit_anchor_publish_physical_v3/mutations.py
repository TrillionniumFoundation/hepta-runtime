"""Fixed physical rehashed refusals. Only the new copies are changed."""
import gzip,re,struct
from pathlib import Path
import physical_common as pc

NAMES=("hia-input","hia-output-tail","hia-workspace","syscall-errno","syscall-capability",
       "missing-boundary","outer-context-tail","off-missing-operation","entropy-trace-byte",
       "source-copy","packer-output-tail","process-parent","original-result",
       "owner-control-return","transport-control-return")

def changes(base,name,*,compressed=None):
    pc.check(name in NAMES,"fixed complete physical mutation")
    changed={}
    def get(path):return changed[path] if path in changed else pc.read(base/path)
    def obj(path):return pc.loads(get(path))
    def put(path,value):changed[path]=pc.enc(value)
    def gz(path,raw):
        raw=bytes(raw)
        if compressed is None:changed[path]=gzip.compress(raw,compresslevel=1,mtime=0)
        else:
            pc.check(path in compressed and gzip.decompress(compressed[path])==raw,"all physical compressed mutation bytes equal exact logical mutation")
            changed[path]=compressed[path]
    prefix="semantic/native-observed-normal"
    if name in ("hia-input","hia-output-tail","hia-workspace"):
        p=prefix+"/buffers.bin.gz";raw=bytearray(gzip.decompress(get(p)));rows=obj(prefix+"/INVOCATIONS.json")
        pc.check(raw[:16]==b"AIOLOG01AIOCAL01","actual complete first HIA record")
        f=struct.unpack_from("<9Q",raw,16);ni,no,nw=f[5:8];positions=[88]
        for size in (ni+16,no+16,nw+16)*2:positions.append(positions[-1]+size)
        if name=="hia-input":
            raw[positions[0]+8]^=1;raw[positions[3]+8]^=1
        else:raw[positions[4]+no-1 if name=="hia-output-tail" else positions[5]]^=1
        rows[0]["before"]=[pc.pin(bytes(raw[positions[j]:positions[j+1]])) for j in range(3)]
        rows[0]["after"]=[pc.pin(bytes(raw[positions[j]:positions[j+1]])) for j in range(3,6)]
        gz(p,raw);put(prefix+"/INVOCATIONS.json",rows)
    elif name in ("syscall-errno","syscall-capability","missing-boundary"):
        p=prefix+"/boundaries.bin.gz";raw=bytearray(gzip.decompress(get(p)));rows=obj(prefix+"/BOUNDARIES.json");at=8;chosen=None
        for i,row in enumerate(rows):
            pc.check(raw[at:at+8]==b"AIOFX001","actual complete native boundary")
            f=struct.unpack_from("<12Q",raw,at+8);sizes=tuple(f[j]+f[j+3] for j in (4,5,6));record=at+104
            positions=[record+256]
            for size in sizes*2:positions.append(positions[-1]+size)
            end=positions[-1]+f[10]+f[11];actual=struct.unpack_from("<16Q",raw,record+128)
            if f[3]==3 and (name!="syscall-errno" or actual[12]==(1<<64)-1):
                chosen=(i,at,record,positions,end,f,actual);break
            at=end
        pc.check(chosen is not None,"existing actual syscall selected")
        i,at,record,positions,end,f,actual=chosen
        if name=="missing-boundary":
            del raw[at:end];rows.pop(i);struct.pack_into("<Q",raw,len(raw)-8,len(rows))
        else:
            if name=="syscall-errno":struct.pack_into("<Q",raw,record+128+104,1 if actual[13]!=1 else 2)
            else:raw[positions[5]+16]^=1
            row=rows[i];row["before_record"]=pc.pin(bytes(raw[record:record+128]));row["after_record"]=pc.pin(bytes(raw[record+128:record+256]))
            row["before"]=[pc.pin(bytes(raw[positions[j]:positions[j+1]])) for j in range(3)]
            row["after"]=[pc.pin(bytes(raw[positions[j]:positions[j+1]])) for j in range(3,6)]
            row["complete_record"]=pc.pin(bytes(raw[at+8:end]))
        gz(p,raw);put(prefix+"/BOUNDARIES.json",rows)
    elif name=="outer-context-tail":
        p=prefix+"/outer.bin.gz";raw=bytearray(gzip.decompress(get(p)));rows=obj(prefix+"/OUTER.json");at=8
        for i,row in enumerate(rows):
            pc.check(raw[at:at+8]==b"AIOENT01","actual whole outer invocation")
            f=struct.unpack_from("<12Q",raw,at+8);sizes=(f[5]+f[9],f[6]+f[10],f[7]+f[11],f[8]);positions=[at+104]
            for size in sizes*2:positions.append(positions[-1]+size)
            if f[3]==1:
                raw[positions[6]+f[7]-1]^=1
                row["after"]=[pc.pin(bytes(raw[positions[j]:positions[j+1]])) for j in range(4,8)];break
            at=positions[-1]
        else:raise ValueError("missing actual run")
        gz(p,raw);put(prefix+"/OUTER.json",rows)
    elif name=="off-missing-operation":
        p="semantic/native-off-normal/OBSERVATIONS.json";rows=obj(p);pc.check(rows,"actual observer-off rows");rows.pop();put(p,rows)
    elif name=="entropy-trace-byte":
        p="semantic/native-off-normal.strace";raw=get(p)
        pattern=rb'getrandom\("((?:\\x[0-9a-f]{2}){32})", 32, 0\)\s+=\s+32'
        match=re.search(pattern,raw);pc.check(match is not None,"actual full 32-byte getrandom observation")
        at=match.start(1)+2;replacement=("%02x"%(int(raw[at:at+2],16)^1)).encode()
        changed[p]=raw[:at]+replacement+raw[at+2:]
    elif name=="source-copy":
        p="semantic/source/protocol.py";changed[p]=get(p)+b"\n"
    elif name=="packer-output-tail":
        p="semantic/build/emission/valid.output-after.bin";raw=bytearray(get(p));raw[-1]^=1;changed[p]=bytes(raw)
        m=obj("semantic/build/emission/EMISSION.json")
        next(r for r in m["calls"] if r["name"]=="valid")["files"]["output-after"].update(pc.pin(changed[p]))
        put("semantic/build/emission/EMISSION.json",m);b=obj("semantic/build/BUILD.json");b["emission"]=m;put("semantic/build/BUILD.json",b)
    elif name=="process-parent":
        p=prefix+"/NATIVE.json";m=obj(p);m["parent_pid"]+=1;put(p,m)
    elif name=="original-result":
        folder="semantic/original-normal";processes=obj(folder+"/processes.json");row=processes[0];case="case-%04d"%row["case"]
        p=folder+"/"+case+"/stdout";raw=bytearray(get(p))
        pc.check(len(raw)>=72 and struct.unpack_from("<Q",raw,0)[0]==64,"actual complete first original result")
        raw[16]^=1;changed[p]=bytes(raw);row["streams"]["stdout"]=pc.pin(changed[p])
        put(folder+"/"+case+"/process.json",row);put(folder+"/processes.json",processes)
        m=obj(folder+"/ORIGINAL.json");m["processes"]=pc.pin(get(folder+"/processes.json"));put(folder+"/ORIGINAL.json",m)
    elif name in ("owner-control-return","transport-control-return"):
        folder="owner-controls" if name=="owner-control-return" else "transport-controls"
        p=folder+"/buffers.bin.gz";raw=bytearray(gzip.decompress(get(p)));rows=obj(folder+"/CALLS.json");at=8
        owner=name=="owner-control-return"
        pc.check(raw[:8]==(b"HAPCT001" if owner else b"AIOCTLOG"),"whole actual native control header")
        for i,row in enumerate(rows):
            pc.check(raw[at:at+8]==(b"HAPCALL1" if owner else b"AIOCTL01"),"actual native control record")
            f=struct.unpack_from("<6Q" if owner else "<7Q",raw,at+8);meta_at=at+(56 if owner else 64);nm=f[5] if owner else f[2];end=meta_at+nm
            if (owner and row["expected"] in (0xffffffff,0xfffffffe)) or (not owner and row["phase"]=="refusal"):
                row["returned"]=0;meta=pc.enc(row);raw[meta_at:end]=meta
                struct.pack_into("<Q",raw,at+16,0);struct.pack_into("<Q",raw,at+(48 if owner else 24),len(meta));break
            at=end+2*(sum(n+16 for n in f[2:5]) if owner else sum(f[3:]))
        else:raise ValueError("missing real native refusal")
        gz(p,raw);put(folder+"/CALLS.json",rows)
    # Rehash exact enclosing reports, real stdout, process pins, and both whole inventories.
    for folder in ("native-observed-normal","native-off-normal"):
        p="semantic/"+folder+"/NATIVE.json";m=obj(p)
        mapping=dict(observations="OBSERVATIONS.json",contexts="CONTEXTS.json",outer="OUTER.json",outer_buffers="outer.bin.gz",
                     retirement="RETIREMENT.json",libc="LIBC.bin",libc_bindings="LIBC-BINDINGS.json",maps="PROCESS-MAPS.txt",environment="ENVIRONMENT.json")
        if folder=="native-observed-normal":
            mapping.update(buffers="buffers.bin.gz",invocations="INVOCATIONS.json",boundary_buffers="boundaries.bin.gz",boundary_rows="BOUNDARIES.json",
                           effects="effects.jsonl",observer_errors="OBSERVER-ERRORS.json")
        for key,leaf in mapping.items():m[key]=pc.pin(get("semantic/"+folder+"/"+leaf))
        put(p,m)
    p="owner-controls/CONTROLS.json";m=obj(p);m["calls"]=pc.pin(get("owner-controls/CALLS.json"));m["buffers"]=pc.pin(get("owner-controls/buffers.bin.gz"));put(p,m)
    p="transport-controls/CONTROLS.json";m=obj(p);m["files"]={n:pc.pin(get("transport-controls/"+n)) for n in m["files"]};put(p,m)
    for phase in ("owner","transport"):
        p="processes/"+phase+"/processes.json";rows=obj(p);pc.check(len(rows)==1,"actual one control process")
        row=rows[0];name="publisher-"+phase+".stdout";changed["processes/"+phase+"/"+name]=get(phase+"-controls/CONTROLS.json")
        row["stdout"]=dict(file=name,**pc.pin(changed["processes/"+phase+"/"+name]));put(p,rows)
    p="semantic/processes/processes.json";rows=obj(p)
    reports={"native-build":"build/BUILD.json","native-observed-normal":"native-observed-normal/NATIVE.json",
             "native-off-normal":"native-off-normal/NATIVE.json","original-normal":"original-normal/ORIGINAL.json"}
    for row in rows:
        if row["name"] in reports:
            name=row["name"]+".stdout";changed["semantic/processes/"+name]=get("semantic/"+reports[row["name"]])
            row["stdout"]=dict(file=name,**pc.pin(changed["semantic/processes/"+name]))
    put(p,rows)
    m=obj("semantic/CAPTURE.json")
    for path,raw in list(changed.items()):
        if path.startswith("semantic/") and path!="semantic/CAPTURE.json":
            n=path[len("semantic/"):];pc.check(n in m["files"],"only admitted semantic files mutated")
            m["files"][n]=dict(**pc.pin(raw),mode=m["files"][n]["mode"])
    put("semantic/CAPTURE.json",m)
    changed={n:b for n,b in changed.items() if b!=pc.read(base/n)}
    m=obj("BUNDLE.json")
    for path,raw in changed.items():
        pc.check(path in m["files"],"only original bundle files mutated")
        m["files"][path]=dict(**pc.pin(raw),mode=m["files"][path]["mode"])
    put("BUNDLE.json",m)
    pc.check(changed and all(raw!=pc.read(base/n) for n,raw in changed.items()),"nonempty exact physical mutation")
    return changed

"""Fixed complete physical mutations, with all enclosing byte digests recomputed."""
import gzip,re,struct
from pathlib import Path
import physical_common as pc
NAMES=("hia-input","hia-output-tail","hia-workspace","syscall-errno","syscall-capability",
       "missing-boundary","outer-context-tail","off-missing-operation","kernel-dirent-inode",
       "source-copy","packer-output-tail","process-parent","original-result",
       "owner-control-return","transport-control-return")

def changes(base,name,*,compressed=None):
    pc.check(name in NAMES,"fixed complete physical mutation")
    changed={};original={}
    def prior(path):
        if path not in original:original[path]=pc.read(base/path)
        return original[path]
    def get(path):return changed[path]if path in changed else prior(path)
    def obj(path):return pc.loads(get(path))
    def put(path,value):changed[path]=pc.enc(value)
    def gz(path,raw):
        raw=bytes(raw)
        if compressed is None:changed[path]=gzip.compress(raw,compresslevel=1,mtime=0)
        else:
            pc.check(path in compressed and gzip.decompress(compressed[path])==raw,
                     "all physical compressed mutation bytes equal exact logical mutation")
            changed[path]=compressed[path]
    def physical(raw,outer=False):
        magic=b"NFTOP001"if outer else b"NFRCLOG1"
        tag=b"NFTOPCAL"if outer else b"NFRCAL01"
        endmagic=b"NFTOPEND"if outer else b"NFRCEND1"
        pc.check(raw[:8]==magic,"complete actual journal before mutation")
        at=8;rows=[]
        while raw[at:at+8]!=endmagic:
            pc.check(raw[at:at+8]==tag and len(raw)>=at+104,"complete actual physical record")
            f=struct.unpack_from("<12Q",raw,at+8)
            if outer:sizes=(f[5]+f[9],f[6]+f[10],f[7]+f[11],f[8]);positions=[at+104]
            else:sizes=tuple(f[j]+f[j+3]for j in(4,5,6));positions=[at+360]
            for size in sizes*2:positions.append(positions[-1]+size)
            pc.check(positions[-1]<=len(raw),"entire actual before/after buffers")
            rows.append(dict(at=at,end=positions[-1],fields=f,positions=positions))
            at=positions[-1]
        pc.check(at+16==len(raw)and struct.unpack_from("<Q",raw,at+8)[0]==len(rows),
                 "complete original footer and absence of suffix")
        return rows
    prefix="semantic/paired-ordinary/roles/native-observed/capture"
    if name in("hia-input","hia-output-tail","hia-workspace","syscall-errno","syscall-capability","missing-boundary"):
        p=prefix+"/records.bin.gz";raw=bytearray(gzip.decompress(get(p)));rows=obj(prefix+"/RECORDS.json");records=physical(raw)
        pc.check(len(records)==len(rows),"entire physical journal and receipt set")
        kind=1 if name.startswith("hia-")else 2
        chosen=next((r for r in records if r["fields"][3]==kind),None)
        pc.check(chosen is not None,"actual source role record exists")
        f=chosen["fields"];i=f[0];at=chosen["at"];pos=chosen["positions"];ni,no,nw=f[4:7]
        pc.check(0<=i<len(rows)and rows[i]["index"]==i,"actual original record identity")
        if name=="missing-boundary":
            del raw[at:chosen["end"]];rows.pop(i)
            # All later physical indices and complete receipt indices are rehashed.
            cursor=8
            for index,row in enumerate(rows):
                pc.check(raw[cursor:cursor+8]==b"NFRCAL01","remaining complete native record")
                struct.pack_into("<Q",raw,cursor+8,index);row["index"]=index
                q=struct.unpack_from("<12Q",raw,cursor+8)
                cursor+=360+2*sum(q[j]+q[j+3]for j in(4,5,6))
            pc.check(raw[cursor:cursor+8]==b"NFRCEND1","retained actual footer")
            struct.pack_into("<Q",raw,cursor+8,len(rows))
        else:
            if name=="hia-input":
                raw[pos[0]+8]^=1;raw[pos[3]+8]^=1
            elif name=="hia-output-tail":raw[pos[4]+no-1]^=1
            elif name=="hia-workspace":raw[pos[5]+nw-1]^=1
            elif name=="syscall-errno":
                errno_at=at+104+128+13*8;old=struct.unpack_from("<Q",raw,errno_at)[0]
                struct.pack_into("<Q",raw,errno_at,1 if old!=1 else 2)
            else:
                # Keep both copies of the borrowed effect immutable but change its capability.
                raw[pos[0]+40]^=1;raw[pos[3]+40]^=1
            row=rows[i];row["before_record"]=pc.pin(bytes(raw[at+104:at+232]))
            row["after_record"]=pc.pin(bytes(raw[at+232:at+360]))
            row["before"]=[pc.pin(bytes(raw[pos[j]:pos[j+1]]))for j in range(3)]
            row["after"]=[pc.pin(bytes(raw[pos[j]:pos[j+1]]))for j in range(3,6)]
        gz(p,raw);put(prefix+"/RECORDS.json",rows)
    elif name=="outer-context-tail":
        p=prefix+"/outer.bin.gz";raw=bytearray(gzip.decompress(get(p)));rows=obj(prefix+"/OUTER.json")
        record=next(r for r in physical(raw,True)if r["fields"][3]==1)
        f=record["fields"];pos=record["positions"];raw[pos[6]+30000]^=1
        rows[f[0]]["after"]=[pc.pin(bytes(raw[pos[j]:pos[j+1]]))for j in range(4,8)]
        gz(p,raw);put(prefix+"/OUTER.json",rows)
    elif name=="off-missing-operation":
        p="semantic/paired-ordinary/roles/native-off/capture/OBSERVATIONS.json";rows=obj(p)
        pc.check(len(rows)>1,"actual observer-free complete operation domain");rows.pop();put(p,rows)
    elif name=="kernel-dirent-inode":
        p="semantic/paired-ordinary.strace";raw=get(p)
        processes=obj("semantic/paired-ordinary/PROCESSES.json")
        native=next(row for row in processes if row["role"]=="native-observed")
        pid=native["pid"];pc.check(type(pid)is int and pid>1,"actual observed child, not coordinator")
        first=re.search(rb"d_ino=(\d+)",raw);pc.check(first is not None,"retained first trace dirent")
        begin=b"".join(("\\x%02x"%x).encode()for x in b"NFNATB01")
        end=b"".join(("\\x%02x"%x).encode()for x in b"NFNATE01")
        active=False;offset=0;chosen=None;first_owned=None
        for line in raw.splitlines(keepends=True):
            fields=line.split(None,1);pc.check(len(fields)==2 and fields[0].isdigit(),"actual complete trace PID")
            actual_pid=int(fields[0]);body=fields[1]
            if actual_pid==pid and body.startswith(b"write(2, ")and begin in body:
                pc.check(not active,"non-overlapping actual observed turn");active=True
            if offset<=first.start()<offset+len(line):
                first_owned=active and actual_pid==pid
            if actual_pid==pid and active and(b"getdents64(80, "in body or body.startswith(b"<... getdents64 resumed>")):
                match=re.search(rb"d_ino=(\d+)",line)
                if match is not None and chosen is None:
                    chosen=(offset+match.start(1),offset+match.end(1),int(match.group(1)))
            if actual_pid==pid and body.startswith(b"write(2, ")and end in body:
                pc.check(active,"matching actual observed end");active=False
            offset+=len(line)
        pc.check(offset==len(raw)and not active and chosen is not None and first_owned is False,
                 "old unscoped selection was outside the actual fingerprint; new selection is inside its owned turn")
        start,stop,inode=chosen
        changed[p]=raw[:start]+str(inode+1).encode()+raw[stop:]
    elif name=="source-copy":
        p="semantic/source/imports/namespace_fingerprint.hepta";changed[p]=get(p)+b"\n"
    elif name=="packer-output-tail":
        p="semantic/build/emission/valid.output-after.bin";raw=bytearray(get(p));raw[-1]^=1;changed[p]=bytes(raw)
    elif name=="process-parent":
        p="semantic/processes/processes.json";rows=obj(p)
        row=next(r for r in rows if r["name"]=="paired-ordinary")
        row["parent_pid"]+=1;put(p,rows)
    elif name=="original-result":
        from protocol import line
        p="semantic/paired-ordinary/roles/original/stdout"
        lines=get(p).splitlines(keepends=True);values=[pc.loads(x)for x in lines]
        index=next(i for i,x in enumerate(values)if x.get("command")=="run"and x["semantic"]["kind"]==0)
        digest=values[index]["semantic"]["digest"]
        values[index]["semantic"]["digest"]=("1"if digest[0]!="1"else"2")+digest[1:]
        lines[index]=line(values[index]);changed[p]=b"".join(lines)
    elif name in("owner-control-return","transport-control-return"):
        owner=name=="owner-control-return";folder="owner-controls"if owner else"transport-controls"
        p=folder+"/buffers.bin.gz";raw=bytearray(gzip.decompress(get(p)));rows=obj(folder+"/CALLS.json");at=8
        pc.check(raw[:8]==(b"HNFCT001"if owner else b"NFCTLOG1"),"whole actual native control header")
        for row in rows:
            pc.check(raw[at:at+8]==(b"HNFCALL1"if owner else b"NFCTCALL"),"actual native control record")
            f=struct.unpack_from("<6Q"if owner else"<7Q",raw,at+8)
            meta_at=at+(56 if owner else 64);nm=f[5]if owner else f[2];end=meta_at+nm
            if(owner and row["expected"]in(0xffffffff,0xfffffffe))or(not owner and row["phase"]=="refusal"):
                row["returned"]=0;meta=pc.enc(row);raw[meta_at:end]=meta
                struct.pack_into("<Q",raw,at+16,0)
                struct.pack_into("<Q",raw,at+(48 if owner else 24),len(meta));break
            at=end+2*(sum(n+16 for n in f[2:5])if owner else sum(f[3:]))
        else:raise ValueError("missing real native refusal")
        gz(p,raw);put(folder+"/CALLS.json",rows)

    # Rehash every exact enclosing pin, including actual stdout reports. These are
    # untrusted evidence metadata, not the immutable source registry or expected values.
    inventory=obj("BUNDLE.json")["files"]
    candidates=[]
    for path in inventory:
        eligible=(path.startswith("semantic/paired-")and path.endswith(".json")or
                  path in("semantic/build/BUILD.json","semantic/build/emission/EMISSION.json",
                           "semantic/processes/processes.json","owner-controls/CONTROLS.json","transport-controls/CONTROLS.json")or
                  path.startswith("processes/")and(path.endswith("processes.json")or path.endswith(".stdout"))or
                  path.startswith("semantic/processes/")and path.endswith(".stdout"))
        if eligible:candidates.append(path)
    def replace(value,mapping):
        if type(value)is dict:
            key=(value.get("bytes"),value.get("sha256"))
            if type(key[0])is int and type(key[1])is str and key in mapping:
                result=dict(value);result.update(mapping[key]);return result
            return {k:replace(v,mapping)for k,v in value.items()}
        if type(value)is list:return [replace(v,mapping)for v in value]
        return value
    primary=dict(changed)
    for iteration in range(12):
        mapping={(pc.pin(prior(path))["bytes"],pc.pin(prior(path))["sha256"]):pc.pin(raw)
                 for path,raw in changed.items()if raw!=prior(path)}
        previous=dict(changed)
        for path in candidates:
            raw=primary[path]if path in primary else prior(path)
            try:value=pc.loads(raw)
            except ValueError:
                pc.check(path.endswith(".stdout"),"only non-JSON tool stdout may be skipped");continue
            update=replace(value,mapping)
            if pc.enc(update)!=pc.enc(value):put(path,update)
            elif path in primary:changed[path]=primary[path]
            else:changed.pop(path,None)
        if changed==previous:break
    else:raise ValueError("acyclic evidence metadata pin propagation did not finish")
    # Both complete physical inventories retain the exact file set and modes.
    capture=obj("semantic/CAPTURE.json")
    for path,raw in list(changed.items()):
        if path.startswith("semantic/")and path!="semantic/CAPTURE.json":
            n=path[len("semantic/"):];pc.check(n in capture["files"],"only admitted semantic files mutated")
            capture["files"][n]=dict(**pc.pin(raw),mode=capture["files"][n]["mode"])
    put("semantic/CAPTURE.json",capture)
    changed={n:b for n,b in changed.items()if b!=prior(n)}
    bundle=obj("BUNDLE.json")
    for path,raw in changed.items():
        pc.check(path in bundle["files"],"only original bundle files mutated")
        bundle["files"][path]=dict(**pc.pin(raw),mode=bundle["files"][path]["mode"])
    put("BUNDLE.json",bundle)
    pc.check(changed and all(raw!=prior(n)for n,raw in changed.items()),"nonempty exact rehashed physical mutation")
    return changed

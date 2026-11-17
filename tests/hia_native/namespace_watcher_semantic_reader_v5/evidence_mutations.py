"""Source-defined physical evidence changes, all derived from complete baseline bytes."""
import copy,gzip,struct,re
from reader_common import loads,encoded,pin,require,git
from read_pairs import wire
from evidence_codec import encoded as compact
NAMES=("original-response","omitted-case","changed-input","output-guard","context-guard",
    "pin-strong","omitted-owner-pair","omitted-boundary-pair","syscall-read","outer-close",
    "root-metadata","observer-count","trace-pid","unused-workspace-tail","input-guard","source-rehashed")
BASE="group/roles/native-observed/"
def get(data,name):return loads(data[name])
def put(data,name,value):data[name]=encoded(value)
def rebind_group(data):
    for role in("native-observed","native-off","original"):
        base="group/roles/"+role+"/";p=get(data,base+"PROCESS.json")
        for name in p["streams"]:p["streams"][name]=pin(data[base+name])
        put(data,base+"PROCESS.json",p)
    put(data,"group/PROCESSES.json",[get(data,"group/roles/"+r+"/PROCESS.json")for r in("native-observed","native-off","original")])
    p=get(data,"group/PAIRED.json")
    for name in p["files"]:p["files"][name]=pin(data["group/"+name])
    put(data,"group/PAIRED.json",p)
def exchanges(data,role,request_index=None,response_index=None):
    base="group/roles/"+role+"/";rows=get(data,base+"EXCHANGES.json")
    if request_index is not None:
        line=data[base+"stdin"].splitlines(keepends=True)[request_index]
        rows[request_index]["request"]=pin(line);rows[request_index]["request_hex"]=line.hex()
    if response_index is not None:
        line=data[base+"stdout"].splitlines(keepends=True)[response_index+1]
        rows[response_index]["response"]=pin(line);rows[response_index]["response_hex"]=line.hex()
    put(data,base+"EXCHANGES.json",rows)
def decoded(data):
    rows=get(data,BASE+"capture/RECORDS.json");raw=gzip.decompress(data[BASE+"capture/complete-native-buffers.bin.gz"])
    require(raw[:8]==b"HNWLOG01","whole baseline native stream");at=8;result=[]
    for row in rows:
        n=struct.unpack_from("<Q",raw,at)[0];at+=8
        require(raw[at:at+n]==compact(row),"exact full baseline native header");at+=n;buffers=[]
        for item in row["buffers"]:
            b=raw[at:at+item["bytes"]];require(pin(b)==item,"full baseline physical buffer");at+=len(b);buffers.append(b)
        result.append((copy.deepcopy(row),buffers))
    require(raw[at:]==b"HNWEND01"+struct.pack("<Q",len(rows)),"whole baseline native footer")
    return result
def repack(data,records):
    rows=[];parts=[b"HNWLOG01"];offset=8
    for row,buffers in records:
        row=dict(row,index=len(rows),offset=offset,buffers=[pin(b)for b in buffers]);head=compact(row)
        parts.extend((struct.pack("<Q",len(head)),head,*buffers));offset+=8+len(head)+sum(map(len,buffers));rows.append(row)
    parts.append(b"HNWEND01"+struct.pack("<Q",len(rows)));plain=b"".join(parts)
    data[BASE+"capture/complete-native-buffers.bin.gz"]=gzip.compress(plain,compresslevel=1,mtime=0)
    put(data,BASE+"capture/RECORDS.json",rows)
    p=get(data,BASE+"capture/NATIVE.json")
    p["records"]=len(rows)
    p["actual_hia_calls"]=sum(r["kind"]=="observation"and bytes.fromhex(r["meta"]["event"])[:16]==b"HNWOWN01"+struct.pack("<Q",1)for r in rows)
    p["actual_boundaries"]=sum(r["kind"]=="observation"and bytes.fromhex(r["meta"]["event"])[:16]==b"HNWBN001"+struct.pack("<Q",1)for r in rows)
    put(data,BASE+"capture/NATIVE.json",p)
def changed_byte(raw,index):
    require(0<=index<len(raw),"actual physical mutation extent");b=bytearray(raw);b[index]^=1;return bytes(b)
def mutate(baseline,name):
    require(name in NAMES,"fixed physical refusal domain");data=dict(baseline)
    if name=="original-response":
        base="group/roles/original/";lines=data[base+"stdout"].splitlines(keepends=True)
        at=next(i for i,line in enumerate(lines)if get_line(line).get("command")=="run"and get_line(line)["semantic"]["version"]is not None)
        v=get_line(lines[at]);v["semantic"]["version"][1]+=1;lines[at]=wire(v);data[base+"stdout"]=b"".join(lines)
        exchanges(data,"original",response_index=at-1)
        obs=get(data,"group/OBSERVATIONS.json")
        target=next(r for r in obs if r["case"]==v["case"]and r["step"]==v["step"])
        target["answers"][2]=v;put(data,"group/OBSERVATIONS.json",obs)
    elif name=="omitted-case":
        rows=get(data,"group/INITIALS.json");require(len(rows)>1,"multiple complete ordinary cases");put(data,"group/INITIALS.json",rows[1:])
    elif name=="changed-input":
        lines=data[BASE+"stdin"].splitlines(keepends=True)
        at=next(i for i,line in enumerate(lines)if get_line(line).get("operation",{}).get("op")=="new")
        v=get_line(lines[at]);v["operation"]["limit"]+=1;lines[at]=wire(v);data[BASE+"stdin"]=b"".join(lines)
        exchanges(data,"native-observed",request_index=at)
    elif name in("syscall-read","outer-close","trace-pid"):
        path=BASE+"syscalls.strace";lines=data[path].decode().splitlines(keepends=True)
        if name=="syscall-read":
            at=next(i for i,line in enumerate(lines)if line.startswith(" | 00000  "))
            line=lines[at];value=int(line[10:12],16)^1;lines[at]=line[:10]+("%02x"%value)+line[12:]
        elif name=="outer-close":
            at=next(i for i,line in enumerate(lines)if re.match(r"^\d+\s+close\(512\)\s+=",line));del lines[at]
        else:
            at=next(i for i,line in enumerate(lines)if "inotify_init1("in line)
            match=re.match(r"^(\d+)(.*)$",lines[at].rstrip("\n"));lines[at]=str(int(match[1])+1)+match[2]+"\n"
        data[path]="".join(lines).encode()
    elif name=="observer-count":
        p=get(data,BASE+"capture/NATIVE.json");p["actual_hia_calls"]+=1;put(data,BASE+"capture/NATIVE.json",p)
    elif name=="source-rehashed":
        path="source/read_pairs.py";data[path]+=b"\n# retained physical source substitution control\n"
        manifest=get(data,"source/SOURCE.json");manifest["files"]["read_pairs.py"].update(**pin(data[path]),git_blob=git(data[path]))
        put(data,"source/SOURCE.json",manifest)
    else:
        records=decoded(data)
        if name in("output-guard","context-guard","input-guard"):
            at=next(i for i,(r,b)in enumerate(records)if r["kind"]=="entry")
            row,buffers=records[at]
            if name=="output-guard":buffers[4]=changed_byte(buffers[4],len(buffers[4])-1)
            elif name=="context-guard":buffers[5]=changed_byte(buffers[5],len(buffers[5])-1)
            else:
                buffers[0]=changed_byte(buffers[0],len(buffers[0])-1)
                buffers[3]=changed_byte(buffers[3],len(buffers[3])-1)
        elif name=="pin-strong":
            at=next(i for i,(r,b)in enumerate(records)if r["kind"]=="checkpoint"and r["meta"]["pins"])
            row,buffers=records[at];index=len(row["meta"]["contexts"]);raw=bytearray(buffers[index])
            struct.pack_into("<Q",raw,8,struct.unpack_from("<Q",raw,8)[0]+1);buffers[index]=bytes(raw)
        elif name=="root-metadata":
            at=next(i for i,(r,b)in enumerate(records)if r["kind"]=="checkpoint"and r["meta"]["state"]["roots"])
            records[at][0]["meta"]["state"]["roots"][0]["inode"]+=1
        elif name in("omitted-owner-pair","omitted-boundary-pair"):
            magic=b"HNWOWN01"if name=="omitted-owner-pair"else b"HNWBN001"
            at=next(i for i,(r,b)in enumerate(records)if r["kind"]=="observation"and
                bytes.fromhex(r["meta"]["event"])[:16]==magic+bytes(8))
            require(at+1<len(records)and records[at+1][0]["kind"]=="observation"and
                bytes.fromhex(records[at+1][0]["meta"]["event"])[:16]==magic+struct.pack("<Q",1),
                "actual whole adjacent before/after pair")
            del records[at:at+2]
        elif name=="unused-workspace-tail":
            entry=next(r for r,b in records if r["kind"]=="entry");context=entry["meta"]["context"];changed=0
            for row,buffers in records:
                owns=row["meta"].get("context")==context or row["kind"]=="checkpoint"and any(x["pointer"]==context for x in row["meta"]["contexts"])
                if not owns:continue
                for i,raw in enumerate(buffers):
                    if len(raw)in(131072,131088)and raw[:8]==b"HNWCTX01"and raw[32768:32776]==b"HNWST001"and struct.unpack_from("<Q",raw,32776)[0]==1:
                        buffers[i]=changed_byte(raw,32768+49152);changed+=1
            require(changed>1,"physical unused byte carried through actual whole before/after contexts")
        else:raise ValueError("unlisted physical native mutation")
        repack(data,records)
    rebind_group(data)
    require(data!=baseline,"physical control actually changed complete retained bytes")
    return data
def get_line(raw):return loads(raw)

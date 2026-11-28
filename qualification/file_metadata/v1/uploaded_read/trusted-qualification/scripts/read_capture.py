"""Pure complete capture admission and original/native metadata comparison."""
from pathlib import Path,PurePosixPath
import gzip,hashlib,json,struct
from evidence_common import decode,encoded,pin,require,source_evidence
from buffer_store import Reader
from protocol import U,I,result,stat_decode
from cases import group,wire,snapshot
from read_journal import Journal,invocation,collapse
PYTHON=dict(bytes=8020928,sha256="e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f")
def walk(value,reader):
    if isinstance(value,dict):
        if set(value)=={"bytes","sha256","blocks"}:reader.get(value)
        else:
            for child in value.values():walk(child,reader)
    elif isinstance(value,list):
        for child in value:walk(child,reader)
def rows(folder,report):
    file=folder/"cases.jsonl.gz";require(pin(file)==report["cases_file"],"complete case archive identity")
    result=[];digest=hashlib.sha256();count=0
    with gzip.open(file,"rb")as stream:
        for raw in stream:
            require(raw.endswith(b"\n")and len(raw)<=256<<20,"complete fixed case row")
            digest.update(raw);count+=len(raw);value=decode(raw)
            expected=report["case_rows"][len(result)]
            require(expected==dict(id=value["input"]["id"],bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),"complete case row hash")
            result.append(value)
    require(dict(bytes=count,sha256=digest.hexdigest())==report["cases_raw"]and len(result)==report["cases"],"complete case stream")
    return result
def terminal_equivalent(original,native):
    require(original["ok"]==native["ok"],"actual success/error differs")
    if original["ok"]:
        require(original==native,"complete actual success value or compact JSON differs")
    else:
        old,new=original["error"],native["error"]
        require(all(old[k]==new[k]for k in("type","errno","filename")),"actual structured exception type/errno/descriptor")
        require(new["message"]==(old["message"]if old["errno"]is None else""),"literal exception or errno-owned diagnostic")
def stream_custody(folder,receipt,exchanges,reader):
    require(receipt["returncode"]==0 and receipt["same_outer_process_group"]is True
        and receipt["parent_pgid"]==receipt["child_pgid"]and receipt["fixed_journal_fd"]==3
        and receipt["fixed_notify_fd"]==4 and receipt["fixed_ack_fd"]==5,"complete actual process custody")
    require(receipt["elapsed_ns"]<=180000000000,"carrier lane exceeded original process budget")
    for name in("stdin","stderr"):require(pin(folder/("carrier."+name))==receipt["streams"][name],"complete process stream")
    require((folder/"carrier.stderr").read_bytes()==b"","carrier stderr")
    require(pin(folder/"carrier.stdout.gz")==receipt["stdout"]["compressed"],"complete stdout compressed identity")
    digest=hashlib.sha256();size=0
    with (folder/"carrier.stdin").open("rb")as incoming,gzip.open(folder/"carrier.stdout.gz","rb")as outgoing:
        last_journal=0
        for index,row in enumerate(exchanges,1):
            require(row["exchange"]==index and 0<=row["elapsed_ns"]<=60000000000,"complete ordered exchange/budget")
            raw=reader.get(row["input"]);reply=reader.get(row["output"])
            require(incoming.read(len(raw))==raw and outgoing.read(len(reply))==reply,"full process streams vs buffers")
            digest.update(reply);size+=len(reply)
            require(len(raw)>=72 and U(raw,0)==len(raw)-8 and raw[8:16]==b"HMDTFQ01"
                and U(raw,16)==row["command"]in range(1,18)and U(raw,24)==row["session"]in(0,1)
                and U(raw,32)==len(raw)-72 and raw[40:72]==bytes(32),"fixture full input")
            require(len(reply)>=64 and reply[:8]==b"HMDTFR01"and U(reply,16)==len(reply)-64,"fixture full output")
            require(row["journal_begin"]==last_journal<=row["journal_end"],"contiguous full journal custody")
            last_journal=row["journal_end"]
        require(not incoming.read(1)and not outgoing.read(1),"unread process stream suffix")
    require(dict(bytes=size,sha256=digest.hexdigest())==receipt["stdout"]["raw"]
        and last_journal==receipt["journal"]["raw"]["bytes"],"complete stdout/journal length")
def read_role(source,data,role,name):
    folder=data/role;report=decode((folder/"CAPTURE.json").read_bytes());expected=group(name)
    require(report["status"]=="PASS"and report["role"]==role and report["group"]==name
        and report["cases"]==len(expected)and report["actual_inputs_only"]and not report["expected_values_generated"],"capture identity")
    require(report["source"]==source_evidence(source),"complete capture source binding")
    receipt=decode((folder/"carrier/carrier-process.json").read_bytes())
    require(receipt==report["carrier"],"complete carrier receipt binding")
    binding=decode((source/"BUILD_REUSE.json").read_bytes())
    require(receipt["binary"]==(PYTHON if role=="original"else binding["elf"]),"actual process executable pin")
    if role=="native":require(pin(data/"production/file-metadata-callable.elf")==binding["elf"],"retained native ELF bytes")
    values=rows(folder,report);require([r["input"]for r in values]==expected,"fixed declared inputs")
    exchanges=[decode(r)for r in(folder/"carrier/exchanges.jsonl").read_bytes().splitlines()]
    reader=Reader(folder/"buffers")
    for value in values:walk(value,reader)
    for value in exchanges:walk(value,reader)
    require(reader.images==report["buffers"]["images"]and reader.logical_bytes==report["buffers"]["logical_bytes"],
        "all original producer buffer references")
    original_buffer_counts=dict(images=reader.images,logical_bytes=reader.logical_bytes)
    stream_custody(folder/"carrier",receipt,exchanges,reader)
    if role=="native":journal=Journal(folder/"carrier/carrier.journal.gz")
    else:journal=gzip.open(folder/"carrier/carrier.journal.gz","rb")
    original_hash=hashlib.sha256();original_size=0;effects_out=[];next_exchange=1;calls=0;protocol_controls=0
    def exchange(number,command,slot):
        require(1<=number<=len(exchanges),"captured exchange reference");r=exchanges[number-1]
        require(r["command"]==command and r["session"]==slot,"actual fixture command ownership")
        return r,reader.get(r["input"])[72:],reader.get(r["output"])
    for case in values:
        query=case["input"];actual=case["actual"];chain=actual["chain"];slot=chain["slot"]
        require(slot==query["id"]%2 and chain["create_exchange"]==next_exchange,"complete case exchange partition")
        create,_,created=exchange(next_exchange,8 if query["observer"]else 9,slot);require(U(created,8)==0,"context creation")
        for setup in case["setup"]:
            file_role=setup["role"];spec=query[file_role];observed=setup["actual"]
            require(observed["exists"]and observed["kind"]==("regular"if spec["kind"]=="preexisting"else spec["kind"]),"actual fixture kind")
            attrs={x["name_hex"]:x["value_hex"]for x in observed["attributes"]}
            require(len(attrs)==len(observed["attributes"]),"actual fixture duplicate attributes")
            if spec["kind"]=="preexisting":
                require(setup["preexisting_readonly"]and observed["stat"]["st_uid"]==spec["require_uid"]
                    and observed["stat"]["st_nlink"]==spec["require_nlink"],"actual existing readonly input")
                cap=b"security.capability".hex()
                if spec.get("require_no_capability"):require(cap not in attrs,"preexisting no-capability input")
                if "require_capability_hex"in spec:require(attrs.get(cap)==spec["require_capability_hex"],"preexisting actual capability bytes")
            else:
                st=observed["stat"];require(not setup["preexisting_readonly"]and st["st_uid"]==report["platform"]["uid"]
                    and st["st_gid"]==spec.get("gid",report["platform"]["gid"])and st["st_mode"]&4095==spec["mode"],"actual fixture ownership/mode")
                declared={x["name_hex"]:x["value_hex"]for x in spec.get("attributes",[])}
                acl=b"system.posix_acl_access".hex()
                require({k:v for k,v in attrs.items()if k!=acl}==declared and(acl in attrs)==bool(spec.get("acl")),"actual declared attribute bytes")
                if spec.get("acl"):
                    aclraw=bytes.fromhex(attrs[acl]);require(len(aclraw)==44 and struct.unpack_from("<I",aclraw)[0]==2,"actual Linux POSIX ACL input")
                    entries=[struct.unpack_from("<HHI",aclraw,4+8*i)for i in range(5)]
                    tags=[x[0]for x in entries];require(tags==([1,2,4,16,32]if spec["acl"]=="named-user"else[1,4,8,16,32]),"actual ACL entry order")
                    named=entries[1]if spec["acl"]=="named-user"else entries[2]
                    require(named[1]==4 and named[2]==(report["platform"]["uid"]+1 if spec["acl"]=="named-user"else 4)
                        and entries[0][1]==(spec["mode"]>>6)&7 and entries[3][1]==(spec["mode"]>>3)&7
                        and entries[4][1]==spec["mode"]&7,"actual named ACL and chmod mask")
                if spec["kind"]=="regular":
                    content=bytes.fromhex(observed["content"]["hex"])
                    require(content==bytes.fromhex(spec["content_hex"])and observed["content"]==dict(bytes=len(content),sha256=hashlib.sha256(content).hexdigest(),hex=content.hex())
                        and st["st_size"]==len(content)and st["st_nlink"]==spec.get("links",1),"actual fixture content/hardlinks")
        files=chain["files"];require(set(files)==(set()if query["mode"]=="summary"else{"source","target"}),"held fixture capability set")
        for file_role,command in(("source",10),("target",11)):
            if file_role not in files:continue
            r,raw,reply=exchange(files[file_role]["exchange"],command,slot)
            path=case["fixture_paths"][file_role];require(raw==path.encode()+b"\0"and U(reply,8)==files[file_role]["fd"]<2147483648
                and U(reply,16)==0,"complete actual held file")
            spec=query[file_role]
            if file_role=="target"and query.get("target_is_source"):require(path==case["fixture_paths"]["source"],"same-inode input path")
            elif spec["kind"]=="preexisting":require(path==spec["path"],"fixed readonly input")
            else:
                root=case["fixture_roots"][spec.get("filesystem",query["filesystem"])]
                require(path==str(Path(root)/file_role)and PurePosixPath(root).name.startswith("hia-metadata-%03d-"%query["id"]),"owned fixture input path")
            if query.get("close_"+file_role+"_before"):
                r,_,reply=exchange(chain["close_"+file_role+"_exchange"],16 if file_role=="source"else 17,slot)
                require(I(U(reply,8))==0,"actual closed negative input")
        fds={r:v["fd"]for r,v in files.items()};require(len(set(fds.values()))==len(fds),"distinct fixture descriptor slots")
        for row in chain["borrows"]:
            r,_,reply=exchange(row["exchange"],14 if row["role"]=="source"else 15,slot)
            require(reader.get(row["stat"])==reply[64:],"full borrowed descriptor observation")
            if query.get("close_"+row["role"]+"_before"):require(I(U(reply,8))==-9 and not reply[64:],"real EBADF fixture")
            else:
                require(U(reply,8)==0 and len(reply)==208,"borrowed descriptor survives")
                st=stat_decode(reply[64:]);before=chain["before"]["held"][row["role"]]["stat"]
                require((st["st_dev"],st["st_ino"])==(before["st_dev"],before["st_ino"]),"same live borrowed file identity")
        hooks=actual["hooks"];require(hooks["actual_actor_count"]==len(query["actions"])
            and hooks["replacements_of_native_result"]==0 and hooks["ack_is_only_eight_zero_bytes"],"frozen actual actor custody")
        all_hooks=[]
        for h in hooks["events"]:
            item=dict(h,raw_bytes=reader.get(h["raw"]),ack_bytes=reader.get(h["ack"]))
            require(item["raw_bytes"][:8]==b"HMDTHK01"and len(item["raw_bytes"])==64 and item["ack_bytes"]==bytes(8),"complete actual hook")
            require(h["fd"]==fds[h["role"]],"hook borrowed capability")
            all_hooks.append(item)
        require([r["input"]for r in hooks["actions"]]==query["actions"],"every fixed real actor input")
        per_inv=[];last_work=None
        for i,inv in enumerate(chain["invocations"]):
            call,payload,reply=exchange(inv["exchange"],1,slot);packet=reader.get(inv["packet"]);frame=reader.get(inv["frame"])
            require(payload==packet and inv["generation"]==i+1==U(reply,32),"actual invocation packet/generation")
            if role=="native":
                require(reply[64:]==frame and U(reply,8)==64 and U(reply,24)==2 and U(reply,40)==0
                    and result(frame)==inv["result"],"actual native terminal result")
                want=wire(query["mode"],snapshot(query["snapshot"])if query["mode"]=="summary"else b"")if i==0 else wire("summary",reader.get(chain["invocations"][0]["frame"])[64:])
                require(packet==want,"actual snapshot continuation input")
                arena={}
                for cmd,label in((4,"context"),(5,"workspace"),(6,"output"),(7,"input")):
                    cap=inv["snapshots"][label];r,_,whole=exchange(cap["exchange"],cmd,slot);raw=reader.get(cap["bytes"])
                    require(U(whole,8)==0 and U(whole,24)==2 and whole[64:]==raw,"complete native arena observation");arena[label]=raw
                ctx=arena["context"];require(len(ctx)==4096 and ctx[:8]==b"HMDTCI01"and U(ctx,56)==2
                    and U(ctx,184)==0 and U(ctx,192)==inv["generation"]and all(U(ctx,p)==0 for p in(344,352,360,368))
                    and ctx[256:320]==b"\xff"*64,"complete native capability retirement")
                require(U(ctx,96)==len(arena["workspace"])and U(ctx,112)==len(arena["output"])
                    and U(ctx,72)==len(arena["input"])and U(ctx,168)==len(frame)and arena["output"][:len(frame)]==frame,
                    "full arena extents and result loan")
                injected=bytearray(packet);mode=U(packet,24)
                struct.pack_into("<QQ",injected,32,fds.get("source",0)if mode!=2 else 0,fds.get("target",0)if mode==3 else 0)
                require(arena["input"][:len(packet)]==bytes(injected),"trusted-register injection")
                selected=[h for h in all_hooks if h["generation"]==inv["generation"]]
                if query["observer"]:
                    require(journal.position==call["journal_begin"],"complete journal invocation prefix")
                    decoded=invocation(journal,packet,frame,inv["generation"],files,selected,last_work)
                    require(journal.position==call["journal_end"]and decoded["workspace"]==arena["workspace"]
                        and decoded["output"]==arena["output"],"complete journal invocation suffix/arena")
                    last_work=decoded["workspace"];per_inv.append(collapse(decoded["effects"]))
                else:
                    require(not selected and call["journal_begin"]==call["journal_end"]==0,"observer-off emits nothing");per_inv.append([])
                released,_,rr=exchange(inv["release_exchange"],2,slot)
                require(U(rr,8)==0 and U(rr,24)==0 and U(rr,40)==0,"actual result release")
            else:
                require(U(reply,8)==0 and reply[64:]==frame and decode(frame)==inv["result"],"actual original value")
                request=decode(packet);require(request==dict(mode=query["mode"]if i==0 else"summary-held",observer=query["observer"],snapshot=query.get("snapshot")),
                    "original exact declared input")
                require(original_size==call["journal_begin"],"original trace prefix")
                current=[];selected=[h for h in all_hooks if h["generation"]==inv["generation"]]
                while original_size<call["journal_end"]:
                    raw=journal.readline();require(raw.endswith(b"\n"),"complete original OS record")
                    original_hash.update(raw);original_size+=len(raw);r=decode(raw)
                    require(r["generation"]==inv["generation"]and r["call"]==len(current)+1,"original exact OS order")
                    require(len(current)<len(selected),"original hook absent");hook=selected[len(current)]
                    require(hook["raw_bytes"]==b"HMDTHK01"+struct.pack("<7Q",r["generation"],r["call"],r["call"],r["operation"],r["fd"],
                        r["args"].get("uid",r["args"].get("mode",0)),r["args"].get("gid",0)),"original actual OS barrier")
                    file_role=next(k for k,v in fds.items()if v==r["fd"])
                    if r["operation"]==1 and r["ok"]:require(hook["after"]["ok"]and r["value"]==hook["after"]["stat"],"original actual fstat")
                    row=dict(operation=r["operation"],role=file_role,args=r["args"],ok=r["ok"])
                    row["value"if r["ok"]else"errno"]=r["value"]if r["ok"]else r["error"]["errno"];current.append(row)
                require(original_size==call["journal_end"]and len(current)==len(selected),"complete original trace suffix")
                per_inv.append(current)
            calls+=1
        require(chain["invocations"]and actual["result"]==chain["invocations"][-1]["result"]
            and len(chain["invocations"])==(2 if query["mode"]=="capture-summary"and chain["invocations"][0]["result"]["ok"]else 1),
            "complete metadata function sequence")
        if role=="native":
            for control in chain["controls"]:
                r,payload,reply=exchange(control["exchange"],control["command"],slot)
                before=reader.get(control["before"]["bytes"]);after=reader.get(control["after"]["bytes"])
                first,_,fb=exchange(control["before"]["exchange"],4,slot);last,_,fa=exchange(control["after"]["exchange"],4,slot)
                require(before==after==fb[64:]==fa[64:]and U(reply,8)==control["code"]and r["journal_begin"]==r["journal_end"],
                    "actual physical protocol refusal/full context")
                protocol_controls+=1
            destroyed,_,rr=exchange(chain["destroy_exchange"],3,slot);require(U(rr,8)==0 and U(rr,24)==0,"actual context destroy")
        expected_fds={str(i)for i in range(6)}|{str(fd)for r,fd in fds.items()if not query.get("close_"+r+"_before")}
        require(set(chain["process"]["fd"])==expected_fds,"owner opened/closed an undeclared descriptor")
        maps=reader.get(chain["process"]["maps"]).decode()
        if role=="native":
            for line in maps.splitlines():
                parts=line.split(maxsplit=5);perms=parts[1]
                require(not("w"in perms and"x"in perms),"writable executable mapping")
                if"x"in perms:require(len(parts)==6 and(parts[5]in("[vdso]","[vsyscall]")or parts[5]==receipt["argv"][0]),"foreign executable image")
        last=chain.get("destroy_exchange",chain["invocations"][-1]["exchange"])
        for file_role,command in(("source",12),("target",13)):
            if file_role not in files:continue
            row,_,reply=exchange(files[file_role]["close_exchange"],command,slot);last=max(last,row["exchange"])
            require(I(U(reply,8))==(-9 if query.get("close_"+file_role+"_before")else 0),"actual parent-owned close")
        require(last>=next_exchange,"case suffix");next_exchange=last+1
        effects_out.append(per_inv)
    require(next_exchange==len(exchanges)+1 and calls==report["entry_invocations"],"all fixture exchanges/functions consumed")
    if role=="native":
        if any(q["observer"]for q in expected):journal_result=journal.finish(receipt["journal"])
        else:
            require(not journal.stream.read(1)and receipt["journal"]["raw"]==dict(bytes=0,sha256=hashlib.sha256(b"").hexdigest()),"unobserved journal empty")
            journal.stream.close();require(pin(folder/"carrier/carrier.journal.gz")==receipt["journal"]["compressed"],"unobserved journal archive")
            journal_result=dict(events=0,body_calls=0,child_calls=0,raw_os_effects=0,journal_bytes=0,full_buffer_bytes=0)
    else:
        require(not journal.read(1),"unread original OS trace");journal.close()
        require(dict(bytes=original_size,sha256=original_hash.hexdigest())==receipt["journal"]["raw"]
            and pin(folder/"carrier/carrier.journal.gz")==receipt["journal"]["compressed"],"complete original journal custody")
        journal_result=dict(raw_os_calls=sum(len(v)for case in effects_out for v in case),journal_bytes=original_size)
    buffer_result=reader.finish();require(buffer_result["blocks"]==report["buffers"]["blocks"],"complete captured block set")
    return dict(cases=values,effects=effects_out,report=dict(status="PASS",role=role,cases=len(values),entry_invocations=calls,
        complete_producer_buffers=original_buffer_counts,buffer_read=buffer_result,journal=journal_result,protocol_controls=protocol_controls))

class Normalize:
    """Compare semantic stat fields and same-object time-change relations.
    Raw numeric dev/inode/timestamps and allocator fields remain fully retained.
    Files stay held throughout each case, so numeric identities cannot be reused."""
    def __init__(self):self.objects={};self.times={}
    def apply(self,value):
        if isinstance(value,list):return[self.apply(v)for v in value]
        if not isinstance(value,dict):return value
        if "st_dev"in value and"st_ino"in value:
            identity=(value["st_dev"],value["st_ino"])
            if identity not in self.objects:self.objects[identity]=len(self.objects)
            obj=self.objects[identity];result={k:value[k]for k in("st_mode","st_uid","st_gid","st_nlink","st_size","st_rdev")}
            result["object"]=obj
            for field in("st_mtime_ns","st_ctime_ns"):
                table=self.times.setdefault((obj,field),{})
                if value[field]not in table:table[value[field]]=len(table)
                result[field+"_relation"]=table[value[field]]
            return result
        if value.get("exists")is False:
            return dict(exists=False,error={k:value["error"][k]for k in("type","errno")})
        if {"type","errno","message","exact_str","args_repr"}.issubset(value):
            return {k:value[k]for k in("type","errno","message")}
        if set(value)=={"name_hex","value_hex"}:return value
        return {k:self.apply(v)for k,v in value.items()}
def comparison_view(case,effects):
    actual=case["actual"];chain=actual["chain"]
    actions=[dict(input=r["input"],before=r["before"],after=r["after"])for r in actual["hooks"]["actions"]]
    return dict(before=chain["before"],effects=effects,actions=actions,after=chain["after"])
def verify(source,data,name):
    source,data=Path(source),Path(data)
    original=read_role(source,data,"original",name);native=read_role(source,data,"native",name)
    require(len(original["cases"])==len(native["cases"]),"actual pair extent")
    for i,(left,right)in enumerate(zip(original["cases"],native["cases"])):
        require(left["input"]==right["input"],"same actual input")
        oi,ni=left["actual"]["chain"]["invocations"],right["actual"]["chain"]["invocations"]
        require(len(oi)==len(ni),"actual function count differs")
        for a,b in zip(oi,ni):terminal_equivalent(a["result"],b["result"])
        a=Normalize().apply(comparison_view(left,original["effects"][i]))
        b=Normalize().apply(comparison_view(right,native["effects"][i]))
        require(a==b,"actual metadata OS sequence/files/identity/time-change relations differ: "+str(left["input"]["id"]))
    return dict(status="COMPLETE_ORIGINAL_NATIVE_METADATA_PASS",group=name,inputs=len(original["cases"]),
        original=original["report"],native=native["report"],complete_actual_os_and_filesystem_comparison=True,
        structured_exception_fields_only=True,public_errno_formatter_executed=False,
        observer_off=name=="observer-off",whole_runtime_replaced=False)

"""Complete actual read/orphan calls, full buffers, original effects and FD lifetimes."""
from pathlib import Path
import ast,gzip,hashlib,struct
from evidence_common import decode,encoded,pin,require,source_evidence
from buffer_store import Reader
from protocol import U,I,result,wire,stat_decode,version
from cases import group,actual_query
from read_journal import Journal,invocation
PYTHON=dict(bytes=8020928,sha256="e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f")
def walk(value,reader):
    if isinstance(value,dict):
        if set(value)=={"bytes","sha256","blocks"}:reader.get(value)
        else:
            for v in value.values():walk(v,reader)
    elif isinstance(value,list):
        for v in value:walk(v,reader)
def rows(folder,report):
    path=folder/"cases.jsonl.gz";require(pin(path)==report["cases_file"],"complete case archive identity")
    values=[];digest=hashlib.sha256();size=0
    with gzip.open(path,"rb")as stream:
        for raw in stream:
            require(raw.endswith(b"\n")and len(raw)<=256<<20,"complete case row")
            v=decode(raw);expected=report["case_rows"][len(values)]
            require(expected==dict(id=v["input"]["id"],bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),"whole case row hash")
            digest.update(raw);size+=len(raw);values.append(v)
    require(dict(bytes=size,sha256=digest.hexdigest())==report["cases_raw"]and len(values)==report["cases"],"complete cases stream")
    return values
def stream_custody(folder,receipt,exchanges,reader):
    require(receipt["returncode"]==0 and receipt["same_outer_process_group"]is True
        and receipt["parent_pgid"]==receipt["child_pgid"]and receipt["fixed_journal_fd"]==3
        and receipt["fixed_notify_fd"]==4 and receipt["fixed_ack_fd"]==5 and receipt["elapsed_ns"]<=180000000000,
        "natural bounded actual process custody")
    for n in("stdin","stderr"):require(pin(folder/("carrier."+n))==receipt["streams"][n],"full actual stream")
    require((folder/"carrier.stderr").read_bytes()==b"","actual process stderr")
    require(pin(folder/"carrier.stdout.gz")==receipt["stdout"]["compressed"],"complete stdout compressed identity")
    digest=hashlib.sha256();size=0;last=0
    with (folder/"carrier.stdin").open("rb")as inp,gzip.open(folder/"carrier.stdout.gz","rb")as out:
        for index,r in enumerate(exchanges,1):
            require(r["exchange"]==index and 0<=r["elapsed_ns"]<=60000000000,"ordered full exchange/budget")
            a=reader.get(r["input"]);b=reader.get(r["output"])
            require(inp.read(len(a))==a and out.read(len(b))==b,"whole process stream/buffer equality")
            digest.update(b);size+=len(b)
            require(len(a)>=72 and U(a,0)==len(a)-8 and a[8:16]==b"HBRDFQ01"
                and U(a,16)==r["command"]in range(1,26)and U(a,24)==r["session"]in(0,1)
                and U(a,32)==len(a)-72 and a[40:72]==bytes(32),"fixed complete fixture input")
            require(len(b)>=64 and b[:8]==b"HBRDFR01"and U(b,16)==len(b)-64,"fixed complete fixture output")
            require(r["journal_begin"]==last<=r["journal_end"],"complete contiguous journal")
            if r["command"]not in(1,11):require(r["journal_begin"]==r["journal_end"],"unexpected fixture semantic call")
            last=r["journal_end"]
        require(not inp.read(1)and not out.read(1),"unread complete process suffix")
    require(dict(bytes=size,sha256=digest.hexdigest())==receipt["stdout"]["raw"]and last==receipt["journal"]["raw"]["bytes"],"whole stdout/journal extent")
def pool(raw):
    require(len(raw)>=4128 and raw[:8]==b"HOPSN001","complete process orphan snapshot")
    address,total,pages=(U(raw,p)for p in(8,16,24));header=raw[32:4128]
    require(address>0 and address%4096==0 and header[:8]==b"HPORP001"and U(header,8)==4096
        and U(header,16)>0 and U(header,24)==0 and U(header,48)==total and U(header,56)==pages
        and U(header,64)==0 and header[72:]==bytes(4096-72)and len(raw)==4128+4096*pages,"full quiescent pool header")
    records=[];addresses=[];next_page=U(header,32)
    for i in range(pages):
        page=raw[4128+4096*i:4128+4096*(i+1)];addresses.append(next_page);used=U(page,24)
        require(next_page>0 and next_page%4096==0 and page[:8]==b"HPORL001"and U(page,8)==address
            and 1<=used<=126 and U(page,32)==len(records)+1 and page[40:64]==bytes(24),"complete orphan record page")
        for j in range(used):
            fd,context,generation,sequence=struct.unpack_from("<4Q",page,64+j*32)
            require(fd<=2147483647 and context>0 and context%4096==0 and generation>0 and sequence==len(records)+1,
                "complete immutable orphan record")
            records.append(dict(fd=fd,context=context,generation=generation,sequence=sequence))
        require(page[64+32*used:]==bytes(4096-64-32*used),"all unused orphan page bytes")
        next_page=U(page,16)
    require(len(records)==total and next_page==0 and U(header,40)==(addresses[-1]if addresses else 0)
        and(pages>0 or U(header,32)==0),"complete orphan chain")
    require(len({r["fd"]for r in records})==len(records),"live orphan FD reused")
    return dict(address=address,pid=U(header,16),records=records,pages=addresses)
def mappings(raw):
    values=[]
    for line in raw.decode().splitlines():
        fields=line.split();lo,hi=(int(x,16)for x in fields[0].split("-"));require(lo<hi,"actual mapping extent")
        values.append((lo,hi,fields[1]))
    return values
def mapped(rows,address,size,permission=None):
    return any(lo<=address and address+size<=hi and(permission is None or p==permission)for lo,hi,p in rows)
def guarded_mapping(rows,address):
    return mapped(rows,address,4096,"rw-p")and mapped(rows,address+4096,4096,"---p")
def reference_binding(source):
    raw=(source/"target/binary_file.py").read_bytes();m=ast.parse(raw)
    fn=next(n for n in m.body if isinstance(n,ast.FunctionDef)and n.name=="main")
    branches=[n for n in ast.walk(fn)if isinstance(n,ast.If)and isinstance(n.test,ast.Compare)
        and isinstance(n.test.left,ast.Name)and n.test.left.id=="op"
        and any(isinstance(v,ast.Constant)and v.value=="private_read"for v in n.test.comparators)]
    require(len(branches)==1,"original private branch")
    value=ast.dump(ast.Module(body=branches[0].body,type_ignores=[]),include_attributes=False).encode()
    return dict(original=pin(source/"target/binary_file.py"),metadata=pin(source/"target/file_metadata.py"),
        private_branch_ast_sha256=hashlib.sha256(value).hexdigest(),exact_private_branch=True,
        fingerprint_regular_parent_main_functions_unedited=True)
def references(value):
    out=[]
    if isinstance(value,dict):
        for k,v in value.items():
            if(k=="exchange"or k.endswith("_exchange"))and type(v)is int:out.append(v)
            else:out+=references(v)
    elif isinstance(value,list):
        for v in value:out+=references(v)
    return out
def verify_setup(case,platform):
    q=case["input"];root=Path(case["fixture_root"]);entries=case["setup"]["entries"]
    require(root.name.startswith("hia-read-orphan-%03d-"%q["id"])and case["initial_parent"]==str(root/"parent")
        and case["setup"]["root"]==str(root),"fixed owned fixture path")
    name=q["basename"];physical=name if name and "\0"not in name and "/"not in name and len(name.encode())<=255 else"data.bin"
    require(case["physical_name"]==physical,"exact physical fixture name")
    replacement=entries["parent/replacement.bin"];expected=b"replacement inode bytes\n"
    require(replacement["kind"]=="regular"and replacement["content"]==dict(bytes=len(expected),sha256=hashlib.sha256(expected).hexdigest(),hex=expected.hex())
        and replacement["stat"]["st_mode"]&4095==0o600,"precreated actual replacement")
    path="parent/"+physical;spec=q["file"]
    if spec["kind"]=="missing":require(path not in entries,"actual missing input");return
    actual=entries[path];st=actual["stat"]
    require(actual["exists"]and actual["kind"]==spec["kind"]and st["st_uid"]==platform["uid"]
        and st["st_gid"]==platform["gid"]and st["st_mode"]&4095==spec["mode"],"actual fixed target kind/owner/mode")
    if spec["kind"]=="symlink":require(actual["link"]=="replacement.bin","actual fixed symlink");return
    attrs={r["name_hex"]:r["value_hex"]for r in actual["attributes"]};require(len(attrs)==len(actual["attributes"]),"actual attributes unique")
    acl=b"system.posix_acl_access".hex()
    require({k:v for k,v in attrs.items()if k!=acl}=={r["name_hex"]:r["value_hex"]for r in spec["attributes"]}
        and(acl in attrs)==bool(spec.get("acl")),"all actual xattr input bytes")
    if spec.get("acl"):
        raw=bytes.fromhex(attrs[acl]);require(len(raw)==44 and struct.unpack_from("<I",raw)[0]==2,"actual ACL wire")
        rows=[struct.unpack_from("<HHI",raw,4+8*i)for i in range(5)]
        require([r[0]for r in rows]==[1,2,4,16,32]and rows[1]==(2,4,(platform["uid"]+1)&0xffffffff),"actual named ACL input")
    if spec["kind"]=="regular":
        raw=bytes.fromhex(spec["content_hex"]);require(st["st_size"]==len(raw)and st["st_nlink"]==spec.get("links",1),"actual fixed size/link count")
        if spec["mode"]&0o400:
            require(actual["content"]==dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),hex=raw.hex()),"all actual input content bytes")
        else:require(actual["content_error"]["type"]=="PermissionError"and actual["content_error"]["errno"]==13,"actual read-denied fixture")
        for i in range(1,spec.get("links",1)):
            other=entries["parent/initial-link-"+str(i)]["stat"]
            require((other["st_dev"],other["st_ino"])==(st["st_dev"],st["st_ino"]),"actual initial hardlink alias")

def read_role(source,data,role,name):
    folder=data/role;report=decode((folder/"CAPTURE.json").read_bytes());queries=group(name)
    require(report["status"]=="PASS"and report["role"]==role and report["group"]==name and report["cases"]==len(queries)
        and report["source"]==source_evidence(source)and report["actual_inputs_only"]is True
        and report["expected_values_generated"]is False,"complete source-owned capture identity")
    values=rows(folder,report);require([v["input"]for v in values]==queries,"all fixed original inputs")
    reader=Reader(folder/"buffers");counts=dict(calls=0,children=0,effects=0,journal_bytes=0,full_buffer_bytes=0,
        events=0,controls=0,orphans=0,eof_witnesses=0)
    expected_binding=reference_binding(source);build=decode((source/"BUILD_REUSE.json").read_bytes())
    require(len(report["processes"])==len(values),"one actual process per frozen input")
    if role=="native":require(pin(data/"production/binary-read-body-callable.elf")==build["elf"],"retained native ELF bytes")
    for item in values:
        walk(item,reader)
        for line in(folder/item["process_path"]/"exchanges.jsonl").read_bytes().splitlines():walk(decode(line),reader)
    require(reader.images==report["buffers"]["images"]and reader.logical_bytes==report["buffers"]["logical_bytes"],"complete producer buffer reference counts")
    producer_buffers=dict(images=reader.images,logical_bytes=reader.logical_bytes)
    for case,process_pin in zip(values,report["processes"]):
        q=case["input"];actual=case["actual"];chain=actual["chain"];where=folder/case["process_path"]
        verify_setup(case,report["platform"]);query=actual_query(q,Path(case["fixture_root"]))
        require(chain["actual_query"]==query,"dynamic fixture path binding")
        receipt=decode((where/"carrier-process.json").read_bytes())
        require(process_pin==dict(id=q["id"],path=case["process_path"],receipt=pin(where/"carrier-process.json"))
            and receipt==case["process"]and receipt["binary"]==(build["elf"]if role=="native"else PYTHON)
            and case["whole_process_exited"]is True,"complete per-input actual process")
        exchanges=[decode(r)for r in(where/"exchanges.jsonl").read_bytes().splitlines()]
        stream_custody(where,receipt,exchanges,reader)
        require(set(references(actual))==set(range(1,len(exchanges)+1)),"all fixture exchange ownership")
        def exchange(number,command,slot):
            require(1<=number<=len(exchanges),"owned exchange reference");r=exchanges[number-1]
            require(r["command"]==command and r["session"]==slot,"exact fixture command binding")
            return r,reader.get(r["input"])[72:],reader.get(r["output"])
        slots=[0,1]if q["attempts"]==2 and not q["reuse_context"]else[q["id"]%2]
        invocation_slots=slots if len(slots)==q["attempts"]else[slots[0]]*q["attempts"]
        require(chain["slots"]==slots and chain["invocation_slots"]==invocation_slots
            and len(chain["creates"])==len(slots),"actual distinct/reused context set")
        for row,slot in zip(chain["creates"],slots):
            _,body,reply=exchange(row["exchange"],8 if q["observer"]else 9,slot)
            require(not body and U(reply,8)==0,"actual context creation")
        parents={int(k):v["fd"]for k,v in chain["parents"].items()}
        require(set(parents)==set(slots)and len(set(parents.values()))==len(parents),"distinct borrowed parents")
        for slot in slots:
            r=chain["parents"][str(slot)];_,body,reply=exchange(r["exchange"],10,slot)
            require(body==case["initial_parent"].encode()+b"\0"and U(reply,8)==r["fd"]<=2147483647,"same held parent capability")
        if q["control_fd0"]is not None:
            _,body,reply=exchange(chain["control_move_exchange"],17,slots[0]);require(not body and U(reply,8)==0,"only control-pipe relocation")
            if q["control_fd0"]=="parent":require(parents[slots[0]]==0,"borrowed parent FD0 input")
        else:require("control_move_exchange"not in chain,"undeclared FD relocation")
        for row in chain["borrows"]:
            _,body,reply=exchange(row["exchange"],13,row["slot"])
            require(not body and U(reply,8)==0 and len(reply)==208 and reader.get(row["stat"])==reply[64:],"full parent stat observation")
            st=stat_decode(reply[64:]);initial=chain["before"]["held"][str(row["slot"])]["stat"]
            require((st["st_dev"],st["st_ino"])==(initial["st_dev"],initial["st_ino"]),"same live parent object")
        for c in chain["controls"]:
            _,_,reply=exchange(c["exchange"],c["command"],slots[0]);require(U(reply,8)==c["code"],"actual private control return")
            require(reader.get(c["before"]["bytes"])==reader.get(c["after"]["bytes"]),"entire context changed on rejection");counts["controls"]+=1
        require(len(chain["controls"])==(10 if role=="native"and q["native_protocol_controls"]else 0),"complete private refusal domain")
        hooks=actual["hooks"];require(hooks["actual_actor_count"]==0 and hooks["actions"]==[]
            and hooks["replacements_of_native_result"]==0 and hooks["ack_is_only_eight_zero_bytes"],"fixed actual ACK ownership")
        all_hooks=[]
        for h in hooks["events"]:
            row=dict(h,raw_bytes=reader.get(h["raw"]),ack_bytes=reader.get(h["ack"]))
            require(row["ack_bytes"]==bytes(8)and row["raw_bytes"][:8]==b"HBRDHK01","complete fixed notification")
            all_hooks.append(row)
        require(len(hooks["limits"])==(q["attempts"]if q["fd_limit"]else 0),"actual descriptor pressure input")
        for limit in hooks["limits"]:
            require(limit["after"]==limit["before"]and limit["during"][0]==limit["only_free_fd"]+1
                and sorted(map(int,limit["fds"]))==list(range(limit["only_free_fd"])),"exact single-free-FD profile")
        pools=[]
        if role=="native":
            for row in chain["pool_snapshots"]:
                _,body,reply=exchange(row["exchange"],14,slots[0]);raw=reader.get(row["bytes"])
                require(not body and U(reply,8)==0 and reply[64:]==raw,"entire real orphan inventory")
                value=pool(raw);require(value["pid"]==receipt["pid"],"pool belongs to actual producer PID")
                pools.append(dict(label=row["label"],raw=raw,value=value))
            require(pools and pools[0]["label"]=="fresh"and not pools[0]["value"]["records"],"empty fresh shared pool")
            require(len({p["value"]["address"]for p in pools})==1,"one pool for every context")
            journal=Journal(where/"carrier.journal.gz")
        else:
            require(not chain["pool_snapshots"],"original must not invent orphan inventory")
            original_events=[];digest=hashlib.sha256();size=0
            with gzip.open(where/"carrier.journal.gz","rb")as stream:
                for raw in stream:
                    require(raw.endswith(b"\n"),"complete original effect line");digest.update(raw);size+=len(raw);original_events.append(decode(raw))
            require(dict(bytes=size,sha256=digest.hexdigest())==receipt["journal"]["raw"]
                and pin(where/"carrier.journal.gz")==receipt["journal"]["compressed"],"full original effect journal")
            case["_original_events"]=original_events;counts["journal_bytes"]+=size
        case["_native_invocations"]=[];previous_fds=set(chain["fds_before"]);orphan_fds=[];workspaces={};context_addresses={}
        require(len(chain["invocations"])==q["attempts"],"all actual read invocations")
        for attempt,row in enumerate(chain["invocations"],1):
            slot=invocation_slots[attempt-1];generation=attempt if q["reuse_context"]else 1
            require(row["attempt"]==attempt and row["slot"]==slot and row["generation"]==generation,"actual context generation")
            x,packet,reply=exchange(row["exchange"],11 if q["entry"]=="at"else 1,slot);frame=reader.get(row["frame"])
            require(packet==reader.get(row["packet"])==(wire(query)if role=="native"else encoded(query))and frame==reply[64:]
                and U(reply,8)==(64 if role=="native"else 0)and U(reply,24)==2 and U(reply,40)==0,"actual exact input/result loan")
            arm={"first":15,"second":16,"last":23}.get(q["arm"])
            if arm:
                _,body,armed=exchange(row["arm_exchange"],arm,slot);require(not body and U(armed,8)==0,"real fixed kernel error arm")
            else:require(row["arm_exchange"]is None,"undeclared error injection")
            if role=="native":
                value=result(frame);raw_context={}
                for command,key in((4,"context"),(5,"workspace"),(6,"output"),(7,"input")):
                    snap=row["snapshots"][key];_,body,observed=exchange(snap["exchange"],command,slot)
                    raw_context[key]=reader.get(snap["bytes"]);require(not body and U(observed,8)==0 and observed[64:]==raw_context[key],"complete actual native arena")
                ctx=raw_context["context"]
                require(len(ctx)==4096 and ctx[:8]==b"HBRDCI01"and U(ctx,8)==4096 and U(ctx,56)==2
                    and U(ctx,168)==len(frame)and U(ctx,176)==64 and U(ctx,184)==0 and U(ctx,192)==generation
                    and U(ctx,344)==U(ctx,352)==0 and ctx[256:320]==b"\xff"*64,"complete drained read context")
                require((U(ctx,40)==0)==(not q["observer"]),"actual null observer")
                copied=bytearray(packet)
                if q["entry"]=="at":struct.pack_into("<Q",copied,32,parents[slot])
                require(raw_context["input"][:len(copied)]==copied and raw_context["input"][len(copied):]==bytes(len(raw_context["input"])-len(copied)),
                    "complete fixed input and trusted parent injection")
                require(raw_context["output"][:len(frame)]==frame and raw_context["output"][len(frame):]==b"\xa5"*(len(raw_context["output"])-len(frame))
                    and U(raw_context["workspace"],8)==99 and all(U(raw_context["workspace"],p)==(1<<64)-1 for p in(88,96,112)),
                    "complete terminal read arenas")
                if q["observer"]:
                    require(journal.position==x["journal_begin"],"complete invocation journal beginning")
                    parsed=invocation(journal,bytes(copied),frame,generation,previous_work=workspaces.get(slot),
                        borrowed=(parents[slot],case["initial_parent"])if q["entry"]=="at"else None,
                        hooks=[h for h in all_hooks if h["attempt"]==attempt])
                    require(journal.position==x["journal_end"]and parsed["workspace"]==raw_context["workspace"]
                        and parsed["output"]==raw_context["output"],"whole actual terminal buffer equals full journal")
                    workspaces[slot]=parsed["workspace"];case["_native_invocations"].append(parsed)
                else:require(x["journal_begin"]==x["journal_end"]==0,"observer-off emitted journal")
                require(value==row["result"],"actual native terminal result")
                observed_pool=next(p for p in pools if p["label"]=="after-result-"+str(attempt));records=observed_pool["value"]["records"]
                require(len(records)==(attempt if q["arm"]=="first"else 0)and U(ctx,400)==(generation if q["arm"]=="first"else 0)
                    and U(ctx,376)==observed_pool["value"]["address"],"actual shared orphan ledger transition")
                if q["arm"]=="first":
                    newest=records[-1];require(newest["generation"]==generation,"orphan actual generation")
                    if slot in context_addresses:require(newest["context"]==context_addresses[slot],"same context reuse")
                    else:require(newest["context"]not in context_addresses.values(),"distinct contexts");context_addresses[slot]=newest["context"]
                    orphan_fds.append(str(newest["fd"]))
                    require(q["observer"]and len(parsed["orphans"])==1 and parsed["orphans"][0]["fd"]==newest["fd"],
                        "one exact opened token became process orphan")
                elif q["observer"]:require(not parsed["orphans"],"non-first-fstat path orphaned")
                maps=mappings(reader.get(row["process_with_result"]["maps"]))
                require(guarded_mapping(maps,observed_pool["value"]["address"])and all(guarded_mapping(maps,p)for p in observed_pool["value"]["pages"]),
                    "actual pool/page guard mappings")
                for record in records:require(guarded_mapping(maps,record["context"]),"live originating context mapping")
                if q["cleanup"]!="eof-borrow":
                    after=next(p for p in pools if p["label"]=="after-release-"+str(attempt));require(after["raw"]==observed_pool["raw"],"release changed immutable inventory")
            else:
                value=decode(frame);require(value==row["result"]and value["binding"]==expected_binding,"actual original value and exact target binding")
                require(value["actual_seccomp_filters"]==(attempt if q["arm"]is not None else 0),"actual original seccomp count")
                if value["ok"]:require(decode(value["original_json"])==value["value"],"complete original actual JSON")
                current=set(row["fds_with_result"]);new=current-previous_fds
                require(len(new)==int(q["arm"]=="first"),"original actual leaked FD extent")
                orphan_fds+=sorted(new);previous_fds=current
            now=set(chain["fds_before"])|set(orphan_fds)
            require(set(row["fds_with_result"])==now,"no borrowed close, dup, or hidden live descriptor")
            if q["arm"]is not None:
                require(not value["ok"]and value["error"]["type"]=="OSError"and value["error"]["errno"]==5
                    and value["error"]["filename"]is None,"actual kernel EIO error envelope")
            if q["control_fd0"]=="file"and q["arm"]=="first":require(orphan_fds[-1]=="0","actual orphan FD0")
            target=case["setup"]["entries"]["parent/"+case["physical_name"]]["stat"]
            for fd in orphan_fds:
                st=row["fds_with_result"][fd]["stat"]
                require((st["st_dev"],st["st_ino"],st["st_mode"])==(target["st_dev"],target["st_ino"],target["st_mode"]),"orphan remains same actual target object")
            if q["cleanup"]!="eof-borrow":
                _,body,released=exchange(row["release_exchange"],2,slot)
                require(not body and U(released,8)==U(released,24)==U(released,40)==0 and set(row["fds_after_release"])==now,"actual loan release custody")
            else:require("release_exchange"not in row,"EOF borrowed-result input was prematurely released")
        if q["cleanup"]=="explicit":
            require(len(chain["destroys"])==len(slots),"complete context destruction")
            for destroy in chain["destroys"]:
                _,body,reply=exchange(destroy["exchange"],3,destroy["slot"])
                require(not body and U(reply,8)==U(reply,24)==0 and set(destroy["fd"])==set(chain["fds_before"])|set(orphan_fds),"destroy closed process orphan")
                if role=="native":
                    observed=next(p for p in pools if p["label"]=="after-destroy-"+str(destroy["slot"]))
                    require(observed["raw"]==pools[-1]["raw"],"destroy changed immutable pool")
                    if destroy["slot"]in context_addresses:
                        require(not mapped(mappings(reader.get(destroy["process"]["maps"])),context_addresses[destroy["slot"]],4096),"origin context not retired")
            for slot in slots:
                _,body,reply=exchange(chain["parents"][str(slot)]["close_exchange"],12,slot)
                require(not body and U(reply,8)==0,"caller-owned final parent close")
            live=set(chain["fds_before"])|set(orphan_fds)
            require(set(chain["before_parent_close"])==live and set(chain["before_eof"])==live-{str(x)for x in parents.values()},"exact final parent ownership")
            require(not hooks["eof"],"undeclared EOF witness")
        else:
            require(not chain["destroys"]and len(hooks["eof"])==1,"actual EOF cleanup witness")
            _,body,reply=exchange(chain["eof_arm_exchange"],22,slots[0]);require(not body and U(reply,8)==0,"fixed EOF arm")
            witness=hooks["eof"][0];raw=reader.get(witness["raw"])
            require(reader.get(witness["ack"])==bytes(8)and len(raw)==64 and raw[:8]==b"HBRDEOF1","whole pre-exit barrier")
            live=set(chain["fds_before"])|set(orphan_fds)
            require(set(chain["before_eof"])==live and set(witness["fds"])==live-{str(x)for x in parents.values()},"real EOF cleanup preserves only original process orphans")
            if role=="native":
                require(U(raw,8)==len(orphan_fds)and U(raw,16)==len(pools[-1]["value"]["pages"])and raw[24:]==bytes(40),"EOF actual pool counts")
                maps=mappings(reader.get(witness["maps"]));last=pools[-1]["value"]
                require(guarded_mapping(maps,last["address"])and all(guarded_mapping(maps,p)for p in last["pages"])
                    and all(not mapped(maps,a,4096)for a in context_addresses.values()),"EOF retired contexts while keeping guarded process pool")
            else:require(raw[8:]==bytes(56),"original EOF observation has no invented pool")
            counts["eof_witnesses"]+=1
        if role=="native":
            if q["native_protocol_controls"]:
                _,body,reply=exchange(chain["fork_refusal_exchange"],20,slots[0]);require(not body and U(reply,8)==0,"actual fork/PID refusal")
                before=next(p for p in pools if p["label"]=="before-foreign-pid");after=next(p for p in pools if p["label"]=="after-foreign-pid")
                require(before["raw"]==after["raw"],"foreign PID modified pool");counts["controls"]+=1
            measured=journal.finish(receipt["journal"])
            for k in("journal_bytes","full_buffer_bytes","events"):counts[k]+=measured[k]
            for key,field in(("calls","body_calls"),("children","child_calls"),("effects","raw_os_effects")):counts[key]+=measured[field]
        counts["orphans"]+=len(orphan_fds)
        if not q["observer"]:require(not all_hooks,"observer-off hooks emitted")
        case["_hooks"]=all_hooks;case["_orphan_fds"]=orphan_fds
    final_buffers=reader.finish();require(final_buffers["blocks"]==report["buffers"]["blocks"],"all complete stored blocks")
    counts["producer_buffers"]=producer_buffers;counts["buffer_read"]=final_buffers
    require(sum(len(c["actual"]["chain"]["invocations"])for c in values)==report["entry_invocations"],"all entry invocations")
    return values,counts,report
class Normalize:
    """Owned-object and timestamp-change relation comparison. Every raw field stays retained.
    Only the declared fixture actor mutates files. Replacement is precreated and old
    objects stay held through their last read; no freed numeric inode is reused."""
    def __init__(self,root):self.root=root;self.objects={};self.times={}
    def text(self,s):return s.replace(self.root,"$FIXTURE")if isinstance(s,str)else s
    def stat(self,value):
        identity=(value["st_dev"],value["st_ino"])
        if identity not in self.objects:self.objects[identity]=len(self.objects)
        obj=self.objects[identity]
        result={k:value[k]for k in("st_mode","st_uid","st_gid","st_nlink","st_size","st_rdev")}
        result["object"]=obj
        for field in("st_mtime_ns","st_ctime_ns"):
            table=self.times.setdefault((obj,field),{})
            if value[field]not in table:table[value[field]]=len(table)
            result[field+"_relation"]=table[value[field]]
        return result
    def apply(self,value):
        if isinstance(value,list):return[self.apply(v)for v in value]
        if not isinstance(value,dict):return self.text(value)
        if "st_dev"in value and"st_ino"in value:return self.stat(value)
        if value.get("exists")is False:
            return dict(exists=False,error={k:value["error"][k]for k in("type","errno")})
        if {"type","errno","message","exact_str","args_repr"}.issubset(value):
            return {k:self.apply(value[k])for k in("type","errno","filename","message","exact_str","args_repr")}
        return {k:self.apply(v)for k,v in value.items()}

def original_effects(case,attempt):
    selected=[h for h in case["_hooks"]if h["attempt"]==attempt]
    prefix=sum(1 for h in case["_hooks"]if h["attempt"]<attempt)
    rows=case["_original_events"][prefix:prefix+len(selected)]
    require(len(rows)==len(selected),"complete original effect partition")
    out=[]
    for row,hook in zip(rows,selected):
        require((row["owner"],row["generation"],row["call"],row["operation"],row["fd"])==
            (hook["owner"],hook["generation"],hook["call"],hook["operation"],hook["fd"]),"original syscall hook binding")
        op=row["operation"];arg=row["args"].get("count",row["args"].get("offset",0))
        require(hook["raw_bytes"]==b"HBRDHK01"+struct.pack("<7Q",row["generation"],row["call"],row["call"],op,row["fd"],arg,0),
            "whole original effect hook")
        if op==6 and row["ok"]:
            require(hook["after"]["ok"]and row["value"]==hook["after"]["stat"],"actual original full fstat")
        v=dict(owner="read",operation=op,fd=row["fd"],ok=row["ok"],args=row["args"])
        if row["ok"]:v["value"]=row["value"]
        else:v["errno"]=row["error"]["errno"]
        out.append(v)
    return out
def buffered_read_effects(effects,q):
    """Admit complete native fills, then project the unedited BufferedReader calls.
    The retained native events stay complete. No return is supplied to execution."""
    out=[];at=0
    while at<len(effects):
        e=effects[at]
        if e["operation"]!=11:out.append(e);at+=1;continue
        first=e;data=bytearray();fd=e["fd"];eof=False
        wanted=1048576 if q["mode"]=="fingerprint"else 4097 if q["mode"]=="private"else e["a"]
        while at<len(effects)and effects[at]["operation"]==11:
            e=effects[at];at+=1
            require(e["fd"]==fd and e["a"]==wanted-len(data)and e["b"]==0,"exact buffered fill request")
            ret=e["raw_return"];chunk=bytes.fromhex(e["payload"])
            if ret<0:
                require(not data and not chunk,"read error partial domain");out.append(e);break
            require(len(chunk)==ret<=e["a"],"full raw read fill");data.extend(chunk)
            if ret==0:eof=True
            if len(data)==wanted or eof:
                row=dict(first,a=wanted,raw_return=len(data),payload=data.hex(),returned_bytes=len(data),
                    returned_sha256=hashlib.sha256(data).hexdigest());out.append(row)
                if q["mode"]=="fingerprint"and eof and data:
                    out.append(dict(first,a=wanted,raw_return=0,payload="",returned_bytes=0,
                        returned_sha256=hashlib.sha256(b"").hexdigest()))
                break
        else:raise ValueError("unfinished actual BufferedReader fill")
    return out
def native_effects(case,attempt):
    effects=case["_native_invocations"][attempt-1]["effects"];out=[]
    for e in buffered_read_effects(effects,case["input"]):
        op=e["operation"];ret=e["raw_return"]
        if op==4:continue # A proven process-pool transfer has no original file syscall.
        args={}
        if op in(1,2,3):
            args=dict(path="/"if op==1 else bytes.fromhex(e["request"])[:-1].decode(),
                flags=720896 if op in(1,2)else 657408,mode=0)
        elif op==11:args=dict(count=e["a"])
        elif op==19:args=dict(offset=e["a"],whence=0)
        row=dict(owner="read",operation=op,fd=e["fd"],ok=ret>=0,args=args)
        if ret<0:row["errno"]=-ret
        elif op in(1,2,3,9,19):row["value"]=ret
        elif op==6:row["value"]=stat_decode(bytes.fromhex(e["payload"]))
        elif op==11:row["value"]=dict(bytes=e["returned_bytes"],sha256=e["returned_sha256"])
        else:row["value"]=None
        out.append(row)
    return out
def comparison_effects(rows,case):
    """Resolve each observed openat component through its actual live parent FD.
    Raw component bytes, return FDs and complete journals remain retained. Only
    the exact declared fixture-root prefix has a cross-process symbolic name."""
    chain=case["actual"]["chain"]
    paths={value["fd"]:case["initial_parent"]for value in chain["parents"].values()}
    require(len(paths)==len(chain["parents"]),"distinct actual borrowed parent descriptors")
    fixture=case["fixture_root"]
    require(fixture.startswith("/")and not fixture.endswith("/"),"absolute declared fixture root")
    out=[]
    for old in rows:
        row=dict(old,args=dict(old["args"]));op=row["operation"];fd=row["fd"]
        if op in(1,2,3):
            # open/openat ignores mode when neither O_CREAT nor O_TMPFILE is set.
            # Retain the original mode and native fixed zero in the raw rows.
            require(row["args"]["flags"]in(720896,657408),"fixed noncreating read open flags")
            row["args"].pop("mode")
            component=row["args"]["path"]
            if op==1:
                require(component=="/","actual root-open spelling");absolute="/"
            else:
                require(fd in paths,"openat requires the actual live parent FD")
                require(isinstance(component,str)and component not in("","/",".","..")
                    and "/"not in component and "\0"not in component,"one actual path component")
                absolute=paths[fd].rstrip("/")+"/"+component
            row["args"]["path"]=("$FIXTURE"+absolute[len(fixture):]
                if absolute==fixture or absolute.startswith(fixture+"/")else absolute)
            if row["ok"]:
                opened=row["value"]
                require(type(opened)is int and 0<=opened<=2147483647 and opened not in paths,
                    "actual open returns a fresh live descriptor")
                paths[opened]=absolute
        else:
            require(fd in paths,"actual operation requires its live opened or borrowed descriptor")
            if op==9 and row["ok"]:del paths[fd]
        if row.get("ok")and isinstance(row.get("value"),dict)and set(row["value"])=={"bytes_hex"}:
            raw=bytes.fromhex(row["value"]["bytes_hex"]);row["value"]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        out.append(row)
    return out
def result_equivalent(old,new,old_effects,new_effects,q,left,right,na,nb):
    require(old["ok"]==new["ok"],"actual read success/error differs")
    if old["ok"]:
        a=dict(old["value"]);b=dict(new["value"])
        if q["mode"]=="private":
            require(set(a)==set(b)=={"data_base64","private_file_verified"}and a==b,"complete private actual result")
        else:
            av,bv=a.pop("version"),b.pop("version")
            require(na.apply(a)==nb.apply(b),"complete actual read/fingerprint result")
            target_a=left["setup"]["entries"]["parent/"+left["physical_name"]]["stat"]
            target_b=right["setup"]["entries"]["parent/"+right["physical_name"]]["stat"]
            require(av==version(target_a)and bv==version(target_b),"actual result version bound to unchanged target")
            if q["observer"]:
                astats=[e["value"]for e in old_effects if e["operation"]==6 and e["ok"]]
                bstats=[e["value"]for e in new_effects if e["operation"]==6 and e["ok"]]
                require(len(astats)==len(bstats)==3 and av==version(astats[1])and bv==version(bstats[1]),"actual second-fstat version")
    else:
        a,b=old["error"],new["error"]
        require(all(a[k]==b[k]for k in("type","errno","filename","message")),"complete actual structured exception")
def verify(source,data,name):
    source,data=Path(source),Path(data)
    left,lc,lr=read_role(source,data,"original",name);right,rc,rr=read_role(source,data,"native",name)
    require(len(left)==len(right),"all actual paired inputs");calls=0;off=0
    for a,b in zip(left,right):
        q=a["input"];require(q==b["input"],"same frozen original/native input")
        require(a["physical_name"]==b["physical_name"]and len(a["actual"]["chain"]["invocations"])==len(b["actual"]["chain"]["invocations"]),
            "same exact name/attempt set")
        na,nb=Normalize(a["fixture_root"]),Normalize(b["fixture_root"])
        require(na.apply(a["setup"])==nb.apply(b["setup"]),"complete actual initial filesystem input")
        require(na.apply(a["actual"]["chain"]["before"])==nb.apply(b["actual"]["chain"]["before"]),"actual pre-invocation filesystem")
        for attempt,(old,new)in enumerate(zip(a["actual"]["chain"]["invocations"],b["actual"]["chain"]["invocations"]),1):
            oe=original_effects(a,attempt)if q["observer"]else[]
            ne=native_effects(b,attempt)if q["observer"]else[]
            result_equivalent(old["result"],new["result"],oe,ne,q,a,b,na,nb)
            if q["observer"]:
                require(na.apply(comparison_effects(oe,a))==nb.apply(comparison_effects(ne,b)),
                    "actual complete original/native effect sequence differs: "+str(q["id"]))
            else:off+=1
            calls+=1
        require(na.apply(a["actual"]["chain"]["after"])==nb.apply(b["actual"]["chain"]["after"])
            and na.apply(a["after_exit"])==nb.apply(b["after_exit"]),"complete actual final filesystem/identity")
        if q["observer"]:require(len(a["_original_events"])==len(a["_hooks"]),"all original effects consumed")
        else:require(not a["_original_events"],"original observer-off emitted effects")
        require(len(a["_orphan_fds"])==len(b["_orphan_fds"]),"same original/native process-lifetime orphan extent")
    return dict(status="COMPLETE_ORIGINAL_NATIVE_READ_ORPHANS_PASS",group=name,inputs=len(left),entry_invocations=calls,
        observer_off_invocations=off,original=lc,native=rc,original_native_structured_errors=True,
        borrowed_parent_survives=True,first_regular_fstat_orphans=True,later_fstat_cleanup_retained=True,
        actual_seccomp_kernel_EIO=True,shared_pool_across_contexts_and_generations=True,actual_orphan_process_exit=True,
        first_fstat_entry_calls=sum(c["input"]["attempts"]for c in left if c["input"]["arm"]=="first"),
        later_fstat_inputs=sum(c["input"]["arm"]in("second","last")for c in left),
        sharing_inputs=sum(c["input"]["attempts"]==2 for c in left),eof_inputs=sum(c["input"]["cleanup"]!="explicit"for c in left),
        shared_pool_growth_concurrency_or_OOM_qualified=False,formatter_or_stdio_qualified=False,
        file_info_child_rebound=False,public_route=False,remote_ssh=False,full_sdk=False,whole_runtime_replaced=False)

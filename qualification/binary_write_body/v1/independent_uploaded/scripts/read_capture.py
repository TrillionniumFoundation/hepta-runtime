"""Complete owned streams, buffers, contexts, effects and actual write comparisons."""
from pathlib import Path
import ast,gzip,hashlib,os,re,struct
from evidence_common import decode,encoded,pin,require,source_evidence
from buffer_store import Reader
from protocol import U,I,result,wire,stat_decode,version,prior_value
from read_write_journal import Journal,invocation,formatter
from read_kernel import read_trace
from kernel_binding import bind,fd_history
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
        and receipt["fixed_notify_fd"]==4 and receipt["fixed_ack_fd"]==5 and receipt["elapsed_ns"]<=60000000000,
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
            require(len(a)>=72 and U(a,0)==len(a)-8 and a[8:16]==b"HBWTFQ01"
                and U(a,16)==r["command"]in range(1,27)and U(a,24)==r["session"]in(0,1)
                and U(a,32)==len(a)-72 and a[40:72]==bytes(32),"fixed complete fixture input")
            require(len(b)>=64 and b[:8]==b"HBWTFR01"and U(b,16)==len(b)-64,"fixed complete fixture output")
            require(r["journal_begin"]==last<=r["journal_end"],"complete contiguous journal")
            if r["command"]not in(1,13):require(r["journal_begin"]==r["journal_end"],"unexpected fixture semantic call")
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


def references(value):
    out=[]
    if isinstance(value,dict):
        for k,v in value.items():
            if(k=="exchange"or k.endswith("_exchange"))and type(v)is int:out.append(v)
            else:out+=references(v)
    elif isinstance(value,list):
        for v in value:out+=references(v)
    return out
def reference_binding(source,runtime):
    raw=(source/"target/binary_file.py").read_bytes();module=ast.parse(raw)
    names=("regular","current","expected","all_write","fingerprint","publish","version","json_read","json_save")
    helpers={n.name:ast.dump(n,include_attributes=False)for n in module.body if isinstance(n,ast.FunctionDef)and n.name in names}
    require(set(helpers)==set(names),"all exact original helper ASTs")
    main=next(n for n in module.body if isinstance(n,ast.FunctionDef)and n.name=="main")
    suite=next(n for n in main.body if isinstance(n,ast.Try)).body
    op=next(n for n in suite if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=="op"for t in n.targets))
    lockname=next(n for n in suite if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=="lockname"for t in n.targets))
    locked=next(n for n in suite if isinstance(n,ast.With)and isinstance(n.items[0].optional_vars,ast.Name)and n.items[0].optional_vars.id=="lock")
    return dict(original=pin(source/"target/binary_file.py"),metadata=pin(source/"target/file_metadata.py"),
        helper_ast_sha256={k:hashlib.sha256(v.encode()).hexdigest()for k,v in sorted(helpers.items())},
        original_suite_ast_sha256={k:hashlib.sha256(ast.dump(v,include_attributes=True).encode()).hexdigest()
            for k,v in(("op",op),("lockname",lockname),("locked_suite",locked))},
        exact_original_helpers_and_locked_suite=True,borrowed_parent_boundary=True,
        original_fdopen=dict(module="os",qualname="fdopen"),
        original_uuid_module={k:runtime["modules"]["uuid"][k]for k in("bytes","sha256")},signal_profile={"13":1,"25":1})
def verify_setup(case,platform):
    q=case["input"];root=Path(case["fixture_root"]);entries=case["setup"]["entries"]
    require(root.name.startswith("hia-write-%03d-"%q["id"])and case["initial_parent"]==str(root/"parent")
        and case["setup"]["root"]==str(root),"fixed original/native fixture root")
    name=q["basename"];physical=name if name and"\0"not in name and"/"not in name and len(name.encode())<=255 else"destination.bin"
    lock=".hepta-lock-"+hashlib.sha256(name.encode()).hexdigest()[:24]
    require(case["physical_name"]==physical and case["lockname"]==lock,"exact caller basename and lock hash")
    allowed={".","parent","parent/replacement.bin"};replacement=entries["parent/replacement.bin"];data=b"replacement inode bytes\n"
    require(replacement["kind"]=="regular"and replacement["content"]==dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),hex=data.hex())
        and replacement["stat"]["st_mode"]&4095==384,"exact precreated actor replacement")
    for role,name in(("destination",physical),("lock",lock)):
        key="parent/"+name;spec=q[role]
        if spec["kind"]=="missing":require(key not in entries,"fixed absent input");continue
        allowed.add(key);item=entries[key];st=item["stat"]
        require(item["exists"]and item["kind"]==spec["kind"]and st["st_uid"]==platform["uid"]and st["st_gid"]==platform["gid"],
            "actual fixture type and target account")
        if spec["kind"]=="symlink":require(item["link"]=="replacement.bin","fixed symlink bytes");continue
        require(st["st_mode"]&4095==spec["mode"],"fixed actual mode")
        if "attributes"in item:
            attrs={x["name_hex"]:x["value_hex"]for x in item["attributes"]};acl=b"system.posix_acl_access".hex()
            require(len(attrs)==len(item["attributes"])and {k:v for k,v in attrs.items()if k!=acl}==
                {x["name_hex"]:x["value_hex"]for x in spec["attributes"]}and(acl in attrs)==bool(spec.get("acl")),
                "all frozen xattr/ACL inputs")
        else:require(spec["mode"]==0 and item["attribute_error"]["errno"]==13,"actual inaccessible attribute profile")
        if spec["kind"]=="regular":
            data=bytes.fromhex(spec["content_hex"])
            require(st["st_size"]==len(data)and st["st_nlink"]==spec["links"],"fixed size/link count")
            if "content"in item:require(item["content"]==dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),hex=data.hex()),"full original file content")
            else:require(spec["mode"]==0 and item["content_error"]["errno"]==13,"actual unreadable input")
            for i in range(1,spec["links"]):
                alias="parent/"+role+"-link-"+str(i);allowed.add(alias);other=entries[alias]["stat"]
                require((st["st_dev"],st["st_ino"])==(other["st_dev"],other["st_ino"]),"exact original hardlink relation")
    require(set(entries)==allowed,"complete initial fixture set")
def actual_uuids(trace,scopes):
    devices=set();pending=bytearray();values=[]
    for r in trace["calls"]:
        if "exit"not in r:continue
        n=r["number"];a=r["args"];ret=r["exit"]["result"]
        if n==257 and ret>=0 and r["input_spans"]["path"]["raw"]==b"/dev/urandom\0":devices.add(ret)
        if n==3 and ret==0:devices.discard(a[0])
        if r["scope"]not in scopes:continue
        if n==318 and a[2]==0:
            if ret in(-38,-1,0):pending.clear()
            elif ret>0:pending+=r["output_spans"]["random"]["raw"]
        elif n==0 and a[0]in devices and ret>0:pending+=r["output_spans"]["read"]["raw"]
        if len(pending)==16:
            data=bytearray(pending);data[6]=(data[6]&15)|64;data[8]=(data[8]&63)|128
            values.append(".hepta-write-"+data.hex());pending.clear()
        require(len(pending)<16,"random source crossed fixed UUID extent")
    names=[]
    for r in trace["calls"]:
        if "exit"in r and r["scope"]in scopes and r["number"]==257:
            name=r["input_spans"]["path"]["raw"][:-1].decode("utf-8","surrogateescape")
            if name.startswith(".hepta-write-")and name not in names:names.append(name)
    require(names==values,"every actual UUID stage name comes from its own kernel random source")
    return values
def read_role(source,data,role,case_id,runtime):
    folder=data/role;report=decode((folder/"CAPTURE.json").read_bytes());query=decode((source/"DOMAIN.json").read_bytes())["cases"][case_id]
    require(report["status"]=="PASS"and report["role"]==role and report["group"]==str(case_id)and report["cases"]==1
        and report["source"]==source_evidence(source)and report["actual_inputs_only"]and not report["expected_values_generated"],
        "one complete frozen actual capture")
    values=rows(folder,report);require(len(values)==1 and values[0]["input"]==query,"exact frozen input")
    case=values[0];q=query;chain=case["actual"]["chain"];hooks=case["actual"]["hooks"]
    verify_setup(case,report["platform"]);where=folder/case["process_path"];reader=Reader(folder/"buffers")
    exchanges=[decode(x)for x in(where/"exchanges.jsonl").read_bytes().splitlines()]
    walk(case,reader)
    for x in exchanges:walk(x,reader)
    require(reader.images==report["buffers"]["images"]and reader.logical_bytes==report["buffers"]["logical_bytes"],"every producer buffer reference")
    receipt=decode((where/"carrier-process.json").read_bytes())
    build=decode((source/"BUILD_REUSE.json").read_bytes())
    require(receipt==case["process"]and receipt["binary"]==(build["elf"]if role=="native"else PYTHON)
        and case["whole_process_exited"]and report["processes"]==[dict(id=q["id"],path=case["process_path"],receipt=pin(where/"carrier-process.json"))],
        "actual fixed binary, natural exit and final reap")
    stream_custody(where,receipt,exchanges,reader)
    require(set(references(case["actual"]))==set(range(1,len(exchanges)+1)),"all private fixture exchanges have an owner")
    def exchange(index,command,slot):
        require(1<=index<=len(exchanges),"owned private exchange reference");x=exchanges[index-1]
        require(x["command"]==command and x["session"]==slot,"exact private command binding")
        return x,reader.get(x["input"])[72:],reader.get(x["output"])
    slots=[0,1]if q["requests"]==2 else[q["id"]%2];require(chain["slots"]==slots,"fixed context slots")
    require(len(chain["creates"])==len(slots),"all original/native contexts")
    for row,slot in zip(chain["creates"],slots):
        _,body,reply=exchange(row["exchange"],8 if q["observer"]else 9,slot);require(not body and U(reply,8)==0,"actual context creation")
    parents={int(k):v["fd"]for k,v in chain["parents"].items()}
    require(set(parents)==set(slots)and len(set(parents.values()))==len(parents),"distinct caller-owned parents")
    for slot in slots:
        row=chain["parents"][str(slot)];_,body,reply=exchange(row["exchange"],10,slot)
        require(body==case["initial_parent"].encode()+b"\0"and U(reply,8)==row["fd"]<=2147483647,"actual held parent")
        if q["close_parent_before"]:
            _,body,reply=exchange(row["closed_exchange"],16,slot);require(not body and U(reply,8)==0,"actual negative parent")
    if q["control_fd0"]!="none":
        _,body,reply=exchange(chain["control_move_exchange"],17,slots[0]);require(not body and U(reply,8)==0,"actual control relocation")
        if q["control_fd0"]=="parent":require(parents[slots[0]]==0,"actual borrowed parent FD0")
    else:require("control_move_exchange"not in chain,"undeclared control relocation")
    _,body,reply=exchange(chain["eof_arm_exchange"],23,slots[0]);require(not body and U(reply,8)==0,"actual EOF arm")
    if q["file_limit"]is not None:
        _,body,reply=exchange(chain["file_limit_exchange"],24,slots[0])
        require(body==struct.pack("<Q",q["file_limit"])and U(reply,8)==0,"actual regular-file limit")
    else:require("file_limit_exchange"not in chain,"undeclared file-size limit")
    for row in chain["borrows"]:
        _,body,reply=exchange(row["exchange"],14,row["slot"]);require(not body and reader.get(row["stat"])==reply[64:],"complete live parent stat")
        if q["close_parent_before"]:require(I(U(reply,8))==-9 and len(reply)==64,"closed parent stays EBADF")
        else:
            require(U(reply,8)==0 and len(reply)==208,"borrowed parent survives invocation/release/destroy")
            current=stat_decode(reply[64:]);initial=chain["before"]["held"][str(row["slot"])]["stat"]
            require((current["st_dev"],current["st_ino"])==(initial["st_dev"],initial["st_ino"]),"same held directory object")
    for c in chain["controls"]:
        _,_,reply=exchange(c["exchange"],c["command"],slots[0])
        actual=I(U(reply,8))if c["code"]<0 else U(reply,8)
        require(actual==c["code"]and reader.get(c["before"]["bytes"])==reader.get(c["after"]["bytes"]),"complete private refusal preservation")
    require(hooks["actual_actor_count"]==len(q["actions"])*q["requests"]and hooks["replacements_of_native_result"]==0
        and hooks["ack_is_only_eight_zero_bytes"],"actual actor and fixed ACK provenance")
    full_hooks=[]
    for row in hooks["events"]:
        full_hooks.append(dict(row,raw_bytes=reader.get(row["raw"]),ack_bytes=reader.get(row["ack"])))
        require(full_hooks[-1]["ack_bytes"]==bytes(8),"fixed zero-only actual barrier")
    for action in hooks["actions"]:
        require(action["input"]==q["actions"][action["index"]]and action["actor_pid"]!=action["target_pid"]==receipt["pid"],
            "separate actual actor")
    require(len(hooks["limits"])==(q["requests"]if q["fd_limit"]else 0),"actual descriptor limit inputs")
    for limit in hooks["limits"]:
        require(limit["after"]==limit["before"]and limit["during"][0]==limit["only_free_fd"]+1
            and sorted(map(int,limit["fds"]))==list(range(limit["only_free_fd"])),"actual single-free-FD custody")
    trace=read_trace(where,receipt["kernel"]);require(trace["application_calls"]==q["requests"],"one trace application per admitted request")
    scopes={r["scope"]for r in trace["marks"]if r["application"]}
    temporaries=actual_uuids(trace,scopes)
    eof_calls=[r for r in trace["calls"]if r["number"]==1 and r["args"][0]==4 and"exit"in r
        and r["input_spans"].get("notification",{}).get("raw",b"").startswith(b"HBWTEOF1")]
    require(len(eof_calls)==len(hooks["eof"])==1,"one actual pre-exit EOF witness")
    eof=hooks["eof"][0];eof_raw=reader.get(eof["raw"]);require(eof_raw==eof_calls[0]["input_spans"]["notification"]["raw"]
        and reader.get(eof["ack"])==bytes(8),"EOF frame derives from actual kernel pipe write")
    history=fd_history(trace,through=eof_calls[0]["ordinal"])
    control_fd=0
    if q["control_fd0"]!="none":
        move_scope=exchanges[chain["control_move_exchange"]-1]["trace_begin"]["scope"]
        moves=[r for r in trace["calls"]if r["scope"]==move_scope
            and(r["number"]in(32,33,292)or(r["number"]==72 and r["args"][1]in(0,1030)))
            and"exit"in r and r["exit"]["result"]>=0 and r["args"][0]==0]
        require(len(moves)==1,"one actual stdin descriptor relocation");control_fd=moves[0]["exit"]["result"]
    base=set(chain["fds_before"])-{str(v)for v in parents.values()}
    if control_fd:base.discard(str(control_fd))
    require(set(eof["fds"])==base|{str(fd)for fd in history["live"]},"full EOF descriptors equal actual kernel open/close history")
    journal=Journal(where/"carrier.journal.gz")if role=="native"else None;pools=[];expected_binding=reference_binding(source,runtime)
    if role=="native":
        for row in chain["pool_snapshots"]:
            _,body,reply=exchange(row["exchange"],11,slots[0]);raw=reader.get(row["bytes"])
            require(not body and U(reply,8)==0 and reply[64:]==raw,"complete process pool snapshot")
            parsed=pool(raw);require(parsed["pid"]==receipt["pid"],"pool bound to actual process")
            pools.append(dict(label=row["label"],raw=raw,value=parsed))
        require(pools and pools[0]["label"]=="fresh"and not pools[0]["value"]["records"],"one initially empty process pool")
        for command,key in((21,"fresh_entropy"),(22,"fresh_entropy_workspace")):
            item=chain[key];_,body,reply=exchange(item["exchange"],command,slots[0])
            require(not body and U(reply,8)==0 and reply[64:]==reader.get(item["bytes"]),"complete initial shared entropy state")
    else:require(not chain["pool_snapshots"],"original pool not fabricated")
    root_contexts={};all_contexts={};observed_orphans=[];completed_values=[];native_calls=0
    for attempt,row in enumerate(chain["invocations"],1):
        slot=slots[attempt-1];query=dict(q,prior_kind=q["prior_kind"]if attempt==1 else"current")
        prior=prior_value(query,row["observed_before"],case["physical_name"])
        require(row["attempt"]==attempt and row["slot"]==slot and row["generation"]==1 and row["query"]==query and row["prior"]==prior,
            "actual request generation and own captured prior version")
        x,packet,reply=exchange(row["exchange"],1,slot);frame=reader.get(row["frame"])
        wanted=wire(query,prior)if role=="native"else encoded(dict(query,op="write",expected_version=prior))
        require(packet==reader.get(row["packet"])==wanted and frame==reply[64:]and x["application"]
            and U(reply,8)==(64 if role=="native"else 0)and U(reply,24)==2 and U(reply,40)==0,"complete actual write request and loan")
        if q["faults"]and attempt==1:
            _,body,armed=exchange(row["arm_exchange"],18,slot)
            expected=b"".join(struct.pack("<7Q",*r["native"])for r in q["faults"])if role=="native"else encoded(q["faults"])
            require(body==expected and U(armed,8)==0,"complete frozen real-kernel fault plan")
        else:require(row["arm_exchange"]is None,"undeclared fault arming")
        if role=="native":
            value=result(frame);spans={}
            for command,key in((4,"context"),(5,"workspace"),(6,"output"),(7,"input"),(15,"children"),(21,"entropy"),(22,"entropy_workspace")):
                snap=row["snapshots"][key];_,body,out=exchange(snap["exchange"],command,slot);spans[key]=reader.get(snap["bytes"])
                require(not body and U(out,8)==0 and out[64:]==spans[key],"every complete actual native arena")
            ctx=spans["context"];child=spans["children"];require(len(ctx)==4096 and ctx[:8]==b"HBWTCI01"
                and U(ctx,8)==4096 and U(ctx,56)==2 and U(ctx,168)==len(frame)and U(ctx,176)==64 and U(ctx,184)==0
                and U(ctx,192)==1 and U(ctx,480)==receipt["pid"]and all(U(ctx,p)==0 for p in(344,352,360,368)),
                "complete write context, process and released borrow")
            require(len(child)==16416 and child[:8]==b"HBWTCX01"and U(child,8)==4 and child[16:32]==bytes(16),"all four actual child contexts")
            chunks=[child[32+4096*i:32+4096*(i+1)]for i in range(4)]
            observed_pool=next(p for p in pools if p["label"]=="after-result-"+str(attempt))
            root_maps=mappings(reader.get(row["process_with_result"]["maps"]))
            observation=row["snapshots"]["context"]["observed_context"]
            before=reader.get(observation["maps_before"]);after=reader.get(observation["maps_after"])
            require(before==after and observation["observation"]=="process_vm_readv"and observation["writes"]==0,
                "actual read-only quiescent context observation")
            observed_maps=mappings(before)
            candidates=[hi-4096 for lo,hi,p in observed_maps if p=="rw-p"and hi-lo>=4096
                and mapped(observed_maps,hi,4096,"---p")]
            require([r["address"]for r in observation["candidates"]]==candidates,"every actual guarded candidate inspected")
            matches=[]
            for candidate in observation["candidates"]:
                first=reader.get(candidate["bytes"]);second=reader.get(candidate["second"])
                require(first==second and len(first)==4096,"complete stable actual candidate bytes")
                if first==ctx:matches.append(candidate["address"])
            require(matches==[observation["address"]]and guarded_mapping(root_maps,matches[0]),"unique actual write context address")
            addresses={"write":matches[0],"read":U(ctx,384),"publish":U(ctx,392),"metadata":U(chunks[1],392),"entropy":U(ctx,408)}
            require(mapped(root_maps,U(ctx,16),1,"r-xp"),"fixed write HIA callable pointer")
            root_contexts[slot]=addresses["write"];all_contexts[slot]=dict(addresses)
            for tag,c,owner in zip((b"HBRDCI01",b"HPUBCI01",b"HMDTCI01",b"HENTCI01"),chunks,("read","publish","metadata","entropy")):
                require(c[:8]==tag and len(c)==4096 and U(c,8)==4096 and U(c,56)==U(c,168)==0
                    and(U(c,184)==0 if owner!="entropy"else U(c,184)<=1),"every child loan explicitly released")
                require(guarded_mapping(root_maps,addresses[owner]),"actual child context guard pages")
                if owner!="metadata":require(U(c,376)==observed_pool["value"]["address"],"one shared process orphan pool")
                if owner!="entropy":require((U(c,40)==0)==(not q["observer"]),"null child observer profile")
            require(chunks[3]==spans["entropy"],"one actual shared entropy context snapshot")
            require((U(ctx,40)==0)==(not q["observer"])and U(ctx,376)==observed_pool["value"]["address"],"write observer and shared pool")
            copied=bytearray(packet);struct.pack_into("<Q",copied,32,parents[slot])
            require(spans["input"][:len(copied)]==copied and spans["input"][len(copied):]==bytes(len(spans["input"])-len(copied)),
                "complete copied input and injected trusted parent")
            require(spans["output"][:len(frame)]==frame and spans["output"][len(frame):]==b"\xa5"*(len(spans["output"])-len(frame))
                and U(spans["workspace"],8)==99 and all(U(spans["workspace"],p)==(1<<64)-1 for p in(96,104,112,120)),
                "complete terminal workspace/output")
            for offset in(64,88,104,120,448,464):
                address,capacity=U(ctx,offset),U(ctx,offset+8)
                if address:require(capacity%4096==0 and mapped(root_maps,address,capacity,"rw-p")
                    and mapped(root_maps,address+capacity,4096,"---p"),"write guarded complete arena")
            if q["observer"]:
                require(journal.position==x["journal_begin"],"actual complete invocation journal start")
                journal.application_scope=x["trace_begin"]["scope"]
                parsed=invocation(journal,packet,frame,1,parents[slot],[h for h in full_hooks if h["attempt"]==attempt],addresses)
                require(journal.position==x["journal_end"]and parsed["workspace"]==spans["workspace"]and parsed["output"]==spans["output"],
                    "every actual terminal span equals its full call journal")
                native_calls+=parsed["body_calls"]
                for e in journal.effect_records:
                    if(e["owner"],e["operation"])in(("write",4),("publish",4),("read",4),("entropy",6)):
                        identity=dict(fd=e["fd"],context=e["context"],generation=e["generation"])
                        if identity not in observed_orphans:observed_orphans.append(identity)
                records=observed_pool["value"]["records"]
                require([{k:r[k]for k in("fd","context","generation")}for r in records]==observed_orphans,"entire process orphan chain matches actual HIA transfers")
            else:require(x["journal_begin"]==x["journal_end"]==0,"observer-off emitted HIA bytes")
            for r in observed_pool["value"]["records"]:
                require(str(r["fd"])in row["fds_with_result"]and guarded_mapping(root_maps,r["context"]),"actual live orphan and originating context")
            require(guarded_mapping(root_maps,observed_pool["value"]["address"])
                and all(guarded_mapping(root_maps,p)for p in observed_pool["value"]["pages"]),"actual persistent pool guard pages")
            if not value["ok"]:
                f=row["formatted"];fx,body,out=exchange(f["exchange"],13,slot);text=reader.get(f["bytes"])
                require(not body and text==out[64:]and U(out,8)==U(out,16)==len(text),"actual 34-function error renderer")
                value["error"]["exact_str"]=text.decode()
                if q["observer"]:
                    require(journal.position==fx["journal_begin"],"complete formatter start");formatter(journal,frame[64:],text)
                    require(journal.position==fx["journal_end"],"complete formatter end")
            require(value==row["result"],"native result from actual full output frame")
            after=next(p for p in pools if p["label"]=="after-release-"+str(attempt))
            require(after["raw"]==observed_pool["raw"],"output release changed persistent pool")
        else:
            value=decode(frame);require(value==row["result"]and value["binding"]==expected_binding,"complete exact original helper/suite binding")
            require(value["unused_fault_plans"]==0 and len(value["actual_seccomp_filters"])==len(q["faults"]),"all actual original fault installations")
            if value["ok"]:require(decode(value["original_json"])==value["value"],"original successful JSON bytes")
        require(set(row["fds_with_result"])==set(row["fds_after_release"]),"release changed actual descriptors")
        _,body,released=exchange(row["release_exchange"],2,slot);require(not body and U(released,8)==U(released,24)==U(released,40)==0,"actual output release")
        completed_values.append(value)
    require(len(completed_values)==q["requests"]==report["entry_invocations"],"all admitted requests captured")
    for d in chain["destroys"]:
        _,body,reply=exchange(d["exchange"],3,d["slot"]);require(not body and U(reply,8)==U(reply,24)==0,"actual context destroy")
        require(set(d["fd"])==set(chain["invocations"][-1]["fds_after_release"]),"context destroy changed process FDs")
        if role=="native":
            finalpool=next(p for p in pools if p["label"]=="after-destroy-"+str(d["slot"]))
            require(finalpool["raw"]==pools[-1]["raw"],"context destruction modified persistent pool")
            maps=mappings(reader.get(d["process"]["maps"]));addresses=all_contexts[d["slot"]]
            require(all(not mapped(maps,addresses[k],4096)for k in("write","read","publish","metadata"))
                and guarded_mapping(maps,addresses["entropy"]),"private children retired; process entropy remains")
    for slot in slots:
        _,body,reply=exchange(chain["parents"][str(slot)]["close_exchange"],12,slot)
        require(not body and I(U(reply,8))==(-9 if q["close_parent_before"]else 0),"caller-owned final parent close")
    if role=="native":
        if q["native_protocol_controls"]:
            _,body,reply=exchange(chain["fork_refusal_exchange"],20,slots[0]);require(not body and U(reply,8)==0,"actual foreign-PID pool refusal")
            require(next(p for p in pools if p["label"]=="before-foreign-pid")["raw"]==
                next(p for p in pools if p["label"]=="after-foreign-pid")["raw"],"foreign PID modified parent pool")
        measured=journal.finish(receipt["journal"])
        effect_binding=bind(journal.effect_records,trace,scopes,control_fd)if q["observer"]else None
        require(U(eof_raw,8)==len(pools[-1]["value"]["records"])and U(eof_raw,16)==len(pools[-1]["value"]["pages"]),
            "actual EOF pool survives all private teardown")
    else:
        raw=gzip.open(where/"carrier.journal.gz","rb").read()
        require(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==receipt["journal"]["raw"],"complete original observation bytes")
        events=[decode(x)for x in raw.splitlines()]
        require(len(events)==len(full_hooks)and(q["observer"]or not events),"every original observation matched")
        for event,hook in zip(events,full_hooks):
            require(all(event[k]==hook[k]for k in("owner","generation","call","operation","fd")),"original actual observation/barrier binding")
        case["_original_events"]=events
        measured=dict(journal_bytes=len(raw),events=len(events),full_buffer_bytes=0);effect_binding=None
        require(eof_raw==b"HBWTEOF1"+bytes(56),"original did not invent HIA pool state")
    final=reader.finish();require(final["blocks"]==report["buffers"]["blocks"],"every stored complete block read")
    case["_values"]=completed_values;case["_temporaries"]=temporaries;case["_trace"]=trace;case["_fd_history"]=history;case["_eof"]=eof
    return case,dict(status="COMPLETE_ACTUAL_ROLE_READ_PASS",role=role,case=case_id,inputs=1,calls=q["requests"],
        controls=len(chain["controls"])+int(q["native_protocol_controls"]and role=="native"),kernel_calls=len(trace["calls"]),
        kernel_bytes=trace["complete_bytes"],journal=measured,buffers=final,write_body_hia_calls=native_calls,
        effect_binding=effect_binding)

class Normalize:
    """Compare actual identity/change relations while retaining every unmodified raw field."""
    def __init__(self,case):
        self.root=case["fixture_root"];self.process="/proc/"+str(case["process"]["pid"]);self.temps={x:"$STAGE_"+str(i)for i,x in enumerate(case["_temporaries"])}
        self.objects={};self.times={}
    def text(self,value):
        if not isinstance(value,str):return value
        value=value.replace(self.root,"$FIXTURE").replace(self.process+"/","$PROCESS/")
        for name,label in self.temps.items():value=value.replace(name,label)
        return value
    def stat(self,value):
        key=(value["st_dev"],value["st_ino"])
        if key not in self.objects:self.objects[key]=len(self.objects)
        obj=self.objects[key]
        result={k:value[k]for k in("st_mode","st_uid","st_gid","st_nlink","st_size","st_rdev","st_blksize","st_blocks")}
        result["object"]=obj
        for name in("st_mtime_ns","st_ctime_ns"):
            table=self.times.setdefault((obj,name),{})
            if value[name]not in table:table[value[name]]=len(table)
            result[name+"_relation"]=table[value[name]]
        return result
    def apply(self,value):
        if isinstance(value,list):return [self.apply(v)for v in value]
        if not isinstance(value,dict):return self.text(value)
        if "st_dev"in value and"st_ino"in value:return self.stat(value)
        return {self.text(k):self.apply(v)for k,v in value.items()}
def successful_result(case,row,value):
    q=case["input"];result=value["value"]
    parent="moved"if any(x["effect"]=="rename-parent"for x in q["actions"])else"parent"
    observed=row["observed_after"]["entries"][parent+"/"+case["physical_name"]]
    require(observed["exists"]and observed["kind"]=="regular","successful real target is regular")
    content=observed["content"];st=observed["stat"];raw=bytes.fromhex(content["hex"])
    import base64
    admitted=base64.b64decode(q["data_base64"],validate=True)
    require(len(admitted)<=1048576 and result["written"]==len(admitted)and raw==admitted
        and content==dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),hex=raw.hex())
        and set(result)=={"written","size","version","sha256","mode"}
        and result["size"]==st["st_size"]==len(raw)and result["sha256"]==content["sha256"]
        and result["version"]==version(st)and result["mode"]==st["st_mode"]&4095,
        "complete actual published bytes, own kernel version, hash, size and mode")
    return {k:v for k,v in result.items()if k!="version"}
def actual_faults(case,role):
    q=case["input"];trace=case["_trace"];plans=q["faults"]
    scopes={r["scope"]for r in trace["marks"]if r["application"]}
    filters=[r for r in trace["calls"]if r["scope"]in scopes and r["number"]==317]
    require(len(filters)==len(plans),"all and only declared actual seccomp installations")
    report=[]
    for plan,r in zip(plans,filters):
        require("exit"in r and r["exit"]["result"]==0 and r["args"][:2]==[1,0],"actual filter installation success")
        raw=r["input_spans"]["seccomp-bpf"]["raw"]
        require(len(raw)==56,"complete actual seven-row kernel BPF")
        decoded=[list(struct.unpack_from("<HBBI",raw,i*8))for i in range(7)]
        number,error,match=plan["native"][4:7];fd=decoded[4][3]
        expected=[[0x20,0,0,0],[0x15,1 if match else 3,0,number],
            [0x15,0 if match else 2,3,262 if number==5 else number],
            [0x20,0,0,16],[0x15,0,1,fd],[0x06,0,0,0x50000|error],[0x06,0,0,0x7fff0000]]
        require(decoded==expected,"exact frozen real-kernel fault bytes")
        failed=[v for v in trace["calls"]if v["ordinal"]>r["ordinal"]and v["scope"]in scopes
            and v["number"]in((5,262)if number==5 else(number,))
            and(not match or v["args"][0]&0xffffffff==fd)
            and"exit"in v and v["exit"]["result"]==-error]
        require(failed,"frozen fault reached an actual unchanged kernel return")
        if role=="original":
            installed=case["_values"][-1]["actual_seccomp_filters"][len(report)]["installed"]
            require(installed==dict(number=number,errno=error,fd=fd,match_fd=match,bpf=expected),
                "original observer filter bytes bound to actual syscall")
        report.append(dict(number=number,errno=error,match_fd=match,failed_calls=len(failed),
            first_return=failed[0]["exit"]["result"]))
    return report
def fileio_observations(case):
    """Require the actual unmodified C-level lock operations when that constructor is reached."""
    trace=case["_trace"];events=case.get("_original_events",[]);scopes={r["scope"]for r in trace["marks"]if r["application"]}
    constructors=[v for v in events if v["owner"]=="write"and v["operation"]==20]
    groups=[]
    for event in constructors:
        fd=event["fd"];seq=event["call"]
        phase=dict(magic_hex=b"HBWTHK01".hex(),words=[event["generation"],seq,seq,20,fd,0,0])
        calls=[r for r in trace["calls"]if r["scope"]in scopes and r["phase"]==phase and"exit"in r]
        stats=[r for r in calls if r["number"]in(5,262)and r["args"][0]==fd]
        seeks=[r for r in calls if r["number"]==8 and r["args"][0]==fd]
        ttys=[r for r in calls if r["number"]==16 and r["args"][0]==fd and r["args"][1]==0x5401]
        require(stats,"actual C FileIO constructor fstat")
        if event["ok"]:
            require(any(r["args"][1:3]==[0,2]for r in seeks)and ttys,"actual C append seek and isatty")
            require(any(r["args"][1:3]==[0,1]for r in seeks),"actual C buffered/text tell")
        groups.append(dict(fd=fd,fstat=[r["exit"]["result"]for r in stats],
            seeks=[dict(offset=r["args"][1],whence=r["args"][2],result=r["exit"]["result"])for r in seeks],
            isatty=[r["exit"]["result"]for r in ttys],constructor_ok=event["ok"]))
    return groups
def verify(source,data,case_id,runtime):
    source,data=Path(source),Path(data)
    a,lc=read_role(source,data,"original",case_id,runtime);b,rc=read_role(source,data,"native",case_id,runtime)
    q=a["input"];require(q==b["input"],"one exact frozen paired input")
    require(a["physical_name"]==b["physical_name"]and len(a["_temporaries"])==len(b["_temporaries"]),
        "same target and actual entropy stage count")
    na,nb=Normalize(a),Normalize(b);ac=a["actual"]["chain"];bc=b["actual"]["chain"]
    for label,old,new in(("setup",a["setup"],b["setup"]),("before",ac["before"],bc["before"])):
        require(na.apply(old)==nb.apply(new),"complete actual filesystem "+label+" differs")
    ar,br=ac["invocations"],bc["invocations"];require(len(ar)==len(br)==q["requests"],"all actual calls paired")
    for i,(old,new,ov,nv)in enumerate(zip(ar,br,a["_values"],b["_values"]),1):
        require(na.apply(old["observed_before"])==nb.apply(new["observed_before"]),"actual pre-call filesystem differs")
        require(ov["ok"]==nv["ok"],"actual write success/error differs")
        if ov["ok"]:
            require(successful_result(a,old,ov)==successful_result(b,new,nv),"actual complete write result differs")
        else:
            oe,ne=ov["error"],nv["error"]
            require(all(na.apply(oe[k])==nb.apply(ne[k])for k in("type","errno","filename","filename2","message"))
                and nb.text(ne["exact_str"])==na.text(oe["type"]+": "+oe["exact_str"]),
                "actual exception fields and exact native diagnostic differ")
        left=[v for v in a["actual"]["hooks"]["actions"]if v["attempt"]==i]
        right=[v for v in b["actual"]["hooks"]["actions"]if v["attempt"]==i]
        require(len(left)==len(right)==len(q["actions"]),"all separately owned actors paired")
        for x,y in zip(left,right):
            require(x["input"]==y["input"]and na.apply(x["before"])==nb.apply(y["before"])
                and na.apply(x["after"])==nb.apply(y["after"]),"complete actual actor filesystem differs")
        require(na.apply(old["observed_after"])==nb.apply(new["observed_after"]),"actual post-call filesystem differs")
    require(na.apply(ac["after"])==nb.apply(bc["after"])and na.apply(a["after_exit"])==nb.apply(b["after_exit"]),
        "complete final filesystem and identity/change relations differ")
    def survivors(case,normal):
        rows=[]
        for fd,item in case["_fd_history"]["live"].items():
            actual=case["_eof"]["fds"][str(fd)]
            rows.append(dict(fd=fd,path=normal.text(item["path"]),target=normal.text(actual["target"]),
                stat=normal.stat(actual["stat"])))
        return sorted(rows,key=lambda r:r["fd"])
    sa,sb=survivors(a,na),survivors(b,nb)
    require(sa==sb,"actual process-lifetime descriptor survivors differ")
    af,bf=actual_faults(a,"original"),actual_faults(b,"native")
    require([(x["number"],x["errno"],x["match_fd"])for x in af]==
        [(x["number"],x["errno"],x["match_fd"])for x in bf],"same real fault input/errno coverage")
    c=fileio_observations(a)if q["observer"]else[]
    if q["file_limit"]is not None:
        for case in(a,b):
            scopes={r["scope"]for r in case["_trace"]["marks"]if r["application"]}
            writes=[r for r in case["_trace"]["calls"]if r["scope"]in scopes and r["number"]==1
                and r["args"][0]not in(1,2,3,4)and"exit"in r]
            if q["file_limit"]==23 and q["data_base64"]:
                require(any(r["exit"]["result"]==23 for r in writes)and any(r["exit"]["result"]==-27 for r in writes)
                    and any(r["signal"]==25 for r in case["_trace"]["signals"]),"actual partial write then EFBIG/SIGXFSZ")
            elif q["data_base64"]:
                require(any(r["exit"]["result"]==-27 for r in writes),"actual zero-limit EFBIG")
    return dict(status="COMPLETE_ORIGINAL_NATIVE_WRITE_PASS",case=case_id,name=q["name"],inputs=1,
        entry_invocations=q["requests"],original=lc,native=rc,original_c_fileio=c,
        real_faults=dict(original=af,native=bf),actual_actor_count=len(q["actions"])*q["requests"],
        survivors=sa,all_raw_kernel_calls_and_memory_retained=True,
        complete_native_buffers_and_real_contexts=True,complete_original_results_errors_and_filesystems=True,
        native_kernel_resume_binding=q["observer"],observer_off=not q["observer"],
        parent_path_policy=False,public_route=False,upload=False,remote_ssh=False,whole_runtime_replaced=False)

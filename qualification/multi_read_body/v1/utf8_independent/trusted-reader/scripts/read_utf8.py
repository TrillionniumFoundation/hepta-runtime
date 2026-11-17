#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Pure reader of actual CPython and native captures; no decoder or image execution."""
from pathlib import Path
import ast,gzip,hashlib,stat,struct
from evidence_common import encoded,decode,pin,require,source_evidence,owned,sha
from buffer_store import Reader
from inputs import inputs,public_input
PYTHON_PIN=dict(bytes=8020928,sha256="e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f")
WORD=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]
def stream(folder,report):
    file=owned(folder,"cases.jsonl.gz")
    require(pin(file)==report["case_stream"]["compressed"],"complete case archive identity")
    raw_hash=hashlib.sha256();raw_size=0;rows=[];line_hashes=[]
    with gzip.open(file,"rb") as source:
        for line in source:
            require(line.endswith(b"\n"),"complete case line")
            raw_hash.update(line);raw_size+=len(line);line_hashes.append(sha(line));rows.append(decode(line))
    require(dict(bytes=raw_size,sha256=raw_hash.hexdigest())==report["case_stream"]["raw"]
        and line_hashes==report["case_stream"]["line_sha256"] and len(rows)==report["cases"],
        "complete case raw bytes and order")
    return rows
def original_identity(source):
    target=source/"trusted-build/target/multi_read_host.py"
    module=ast.parse(target.read_bytes())
    function=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=="multi_read")
    calls=[n for n in ast.walk(function) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=="decode"]
    expected=ast.dump(ast.parse("data.decode('utf-8', errors='strict')",mode="eval").body,include_attributes=False)
    require(len(calls)==1 and ast.dump(calls[0],include_attributes=False)==expected,"actual target decode AST")
    return dict(target=pin(target),expression=expected,descriptor_type="method_descriptor",
        descriptor_name="decode",descriptor_class="bytes")
def report_identity(source,folder,role,group,identity):
    report=decode(owned(folder,"CAPTURE.json").read_bytes())
    require(report["status"]=="PASS" and report["role"]==role and report["group"]==group
        and report["source"]==identity and report["expected_outputs_supplied_to_native"] is False
        and report["body_or_parent_application_calls"]==0,"actual capture identity and scope")
    py=report["actual_python"]
    require(py["implementation"]=="cpython" and py["binary"]==PYTHON_PIN
        and py["version"].startswith("3.12.3 ") and py["pid"]==py["pgid"] and py["pid"]>0,
        "exact original CPython and owned capture process")
    require(report["original_decoder"]==(original_identity(source) if role=="original" else None),
        "actual original decoder provenance")
    require(report["original_decode_calls"]==(report["cases"] if role=="original" else 0)
        and report["native_utf8_calls"]==(report["cases"] if role=="native" else 0),"actual call counts")
    return report
def full_buffers(reader,report):
    result=reader.finish()
    require(report["buffers"]==dict(images=result["complete_images"],logical_bytes=result["logical_buffer_bytes"],
        blocks=result["blocks"]),"all complete stored buffers consumed")
    return result
def original_rows(source,folder,group,identity):
    report=report_identity(source,folder,"original",group,identity)
    require(report["native_receipt"] is None and report["eof"]==[],"original never starts native")
    rows=stream(folder,report);expected=[r for r in inputs(group) if r["kind"]=="semantic"]
    require(len(rows)==len(expected) and report["kinds"]=={"semantic":len(rows)},"original input-only corpus count")
    store=Reader(folder/"buffers");results={};success=0
    for row,item in zip(rows,expected):
        require(set(row)=={"id","input","actual_input","result"} and row["id"]==item["id"]
            and row["input"]==public_input(item),"actual original exact input order")
        raw=store.get(row["actual_input"]);require(raw==item["data"],"actual original input bytes")
        result=row["result"]
        if result["kind"]=="valid":
            require(set(result)=={"kind","text_utf8","codepoints"} and store.get(result["text_utf8"])==raw
                and result["codepoints"]==sum(b&0xc0!=0x80 for b in raw),"actual original decoded value")
            success+=1
        else:
            require(set(result)=={"kind","type","encoding","start","end","reason","object","message","diagnostic"}
                and result["kind"]=="error" and result["type"]=="UnicodeDecodeError" and result["encoding"]=="utf-8"
                and type(result["start"]) is int and type(result["end"]) is int
                and 0<=result["start"]<result["end"]<=len(raw)
                and result["reason"] in ("invalid start byte","invalid continuation byte","unexpected end of data")
                and store.get(result["object"])==raw and result["diagnostic"]=="UnicodeDecodeError: "+result["message"]
                and result["diagnostic"].isascii(),"actual original complete UnicodeDecodeError")
        require(row["id"] not in results,"original duplicate case")
        results[row["id"]]=result
    return report,results,full_buffers(store,report),success
def native_value(complete,item,original):
    require(len(complete)==64+16416 and complete[:8]==b"HMRDFR01"
        and WORD(complete,16)==16416 and complete[24:64]==bytes(40),
        "actual native full private reply")
    raw=complete[64:];oc,wc,ret,size=struct.unpack_from("<4Q",raw)
    require((oc,wc,size)==(item["out_capacity"],item["work_capacity"],len(item["wire"]))
        and ret==WORD(complete,8) and ret<=0xffffffff,"actual native return and capacities")
    ob,wb,oa,wa=(raw[32:4128],raw[4128:8224],raw[8224:12320],raw[12320:16416])
    require(ob==bytes([item["out_seed"]])*4096 and wb==bytes([item["work_seed"]])*4096,
        "complete physical pre-call seeds")
    require(oa[oc:]==ob[oc:] and wa[wc:]==wb[wc:],"outside passed physical capacity unchanged")
    if item["kind"]=="framing":
        require(ret==0xffffffff and oa==ob and wa==wb,"actual framing rejection and no mutation")
        return "framing"
    if oc<256 or wc<512:
        require(ret==0xfffffffe and oa==ob and wa==wb,"actual capacity rejection and no mutation")
        return "capacity"
    require(original is not None and oa[:8]==b"HUTFD001" and 64<=ret<=256
        and WORD(oa,48)==len(item["data"]) and oa[ret:]==ob[ret:],"actual native diagnostic header and tail")
    kind=WORD(oa,8)
    if original["kind"]=="valid":
        expected=b"HUTFD001"+struct.pack("<7Q",0,0,0,0,0,len(item["data"]),0)
        require(kind==0 and ret==64 and oa[:64]==expected and wa==wb,"actual native full valid result")
        return "valid"
    start,end=original["start"],original["end"]
    reason={"invalid start byte":1,"invalid continuation byte":2,"unexpected end of data":3}[original["reason"]]
    message=original["diagnostic"].encode("ascii")
    expected=b"HUTFD001"+struct.pack("<7Q",3,start,end,reason,len(message),len(item["data"]),len(message))+message
    require(kind==3 and ret==len(expected) and oa[:ret]==expected,"actual native complete diagnostic equals original")
    # This source-bound physical layout is independent of UTF-8 decoding: all
    # values come from the retained actual CPython span and complete message.
    work=bytearray(wb);work[:len(message)]=message
    work[384:408]=struct.pack("<3Q",start,end,reason)
    last_decimal=start if end==start+1 else end-1
    if last_decimal:
        digits=str(last_decimal).encode("ascii")[::-1];work[256:256+len(digits)]=digits
    require(wa==bytes(work),"complete native error workspace including untouched bytes")
    return "error"
def carrier_evidence(folder,report,store,expected_exchanges,binary_pin):
    receipt=decode(owned(folder,"carrier-process.json").read_bytes())
    require(receipt==report["native_receipt"] and receipt["binary"]==binary_pin
        and type(receipt["pid"]) is int and receipt["pid"]>0
        and receipt["returncode"]==0 and receipt["same_outer_process_group"] is True
        and receipt["child_pgid"]==receipt["parent_pgid"]==report["actual_python"]["pgid"]
        and receipt["fixed_journal_fd"]==3 and receipt["fixed_notify_fd"]==4 and receipt["fixed_ack_fd"]==5
        and 0<=receipt["elapsed_ns"]<180_000_000_000 and len(receipt["argv"])==1
        and Path(receipt["argv"][0]).name=="multi-read-body-callable.elf","actual owned native process lifecycle")
    require(pin(owned(folder,"carrier.stdout.gz"))==receipt["stdout"]["compressed"],
        "complete stdout compressed identity")
    require(pin(owned(folder,"carrier.journal.gz"))==receipt["journal"]["compressed"],
        "complete native journal compressed identity")
    with gzip.open(folder/"carrier.journal.gz","rb") as journal:raw=journal.read()
    require(raw==b"" and receipt["journal"]["raw"]==dict(bytes=0,sha256=sha(b""))
        and receipt["journal"]["complete_raw_bytes_in_gzip"] is True,"zero hidden body calls")
    for suffix in ("stdin","stderr"):
        require(pin(owned(folder,"carrier."+suffix))==receipt["streams"][suffix],"complete native "+suffix+" identity")
    require((folder/"carrier.stderr").read_bytes()==b"","native stderr empty")
    rows=[decode(line) for line in owned(folder,"exchanges.jsonl").read_bytes().splitlines()]
    require(len(rows)==len(expected_exchanges),"complete actual exchange count")
    stdout_digest=hashlib.sha256();stdout_count=0
    with (folder/"carrier.stdin").open("rb") as sent,gzip.open(folder/"carrier.stdout.gz","rb") as received:
        for row,(payload,complete,exchange) in zip(rows,expected_exchanges):
            require(row["exchange"]==exchange and row["command"]==21 and row["session"]==0
                and row["journal_begin"]==row["journal_end"]==0 and 0<=row["elapsed_ns"]<60_000_000_000,
                "exact actual direct-leaf exchange and bound")
            packet=b"HMRDFQ01"+struct.pack("<7Q",21,0,len(payload),0,0,0,0)+payload
            packet=struct.pack("<Q",len(packet))+packet
            require(store.get(row["input"])==packet and store.get(row["output"])==complete,
                "case bound to actual carrier complete exchange")
            require(sent.read(len(packet))==packet and received.read(len(complete))==complete,
                "complete ordered native stdin/stdout bytes")
            stdout_digest.update(complete);stdout_count+=len(complete)
        require(sent.read(1)==b"" and received.read(1)==b"","no unbound native stream suffix")
    require(receipt["stdout"]["raw"]==dict(bytes=stdout_count,sha256=stdout_digest.hexdigest()),"complete raw native stdout")
    eof=report["eof"];require(len(eof)==1,"one actual pre-exit witness")
    require(store.get(eof[0]["raw"])==b"HMRDEOF1"+bytes(56) and store.get(eof[0]["ack"])==bytes(8),
        "actual empty pool at EOF")
    observed=eof[0]["observed"];fd=observed["fd"]
    require(set(fd)==set(map(str,range(6))) and all(fd[str(n)].startswith("pipe:[") for n in (0,1,3,4,5))
        and fd["2"].endswith("/carrier.stderr"),"all live native descriptors at EOF")
    maps=store.get(observed["maps"]).decode("ascii");mapped=[]
    for line in maps.splitlines():
        parts=line.split(None,5);require(len(parts)>=5,"complete actual maps line")
        if len(parts)==6 and parts[5].startswith("/"):
            require(parts[5]==receipt["argv"][0],"native process mapped a foreign runtime")
            mapped.append(parts)
    require(mapped and any("x" in parts[1] for parts in mapped),"actual native ELF executable mapping")
    return len(rows)
def verify(source,data,group):
    source,data=Path(source),Path(data)
    identity=source_evidence(source);binding=decode(owned(source,"BUILD_REUSE.json").read_bytes())
    binary=owned(data,"production/multi-read-body-callable.elf")
    require(pin(binary)==binding["elf"] and stat.S_IMODE(binary.stat().st_mode)==0o500,"retained native ELF bytes")
    original_report,original,original_buffers,valid=original_rows(source,data/"original",group,identity)
    folder=data/"native";report=report_identity(source,folder,"native",group,identity)
    rows=stream(folder,report);items=list(inputs(group));require(len(rows)==len(items),"native corpus count")
    store=Reader(folder/"buffers");counts={};kinds={};exchanges=[]
    for n,(row,item) in enumerate(zip(rows,items),1):
        require(set(row)=={"id","input","packet","complete_reply","exchange"}
            and row["id"]==item["id"] and row["input"]==public_input(item) and row["exchange"]==n,
            "actual native exact input order")
        payload=store.get(row["packet"]);complete=store.get(row["complete_reply"])
        require(payload==struct.pack("<4Q",item["out_capacity"],item["work_capacity"],item["out_seed"],item["work_seed"])+item["wire"],
            "actual native input-only packet")
        reference=original.get(item.get("reference",item["id"]))
        kind=native_value(complete,item,reference);counts[kind]=counts.get(kind,0)+1
        kinds[item["kind"]]=kinds.get(item["kind"],0)+1
        exchanges.append((payload,complete,n))
    require(kinds==report["kinds"],"all native semantic and private-control counts")
    actual=carrier_evidence(folder,report,store,exchanges,binding["elf"])
    native_buffers=full_buffers(store,report)
    allowed={"production/multi-read-body-callable.elf"}
    for role in ("original","native"):
        base=data/role
        names={"CAPTURE.json","cases.jsonl.gz"}|{"buffers/"+p.name for p in (base/"buffers").iterdir()}
        if role=="native":names|={"exchanges.jsonl","carrier.stdin","carrier.stdout.gz","carrier.stderr",
            "carrier.journal.gz","carrier-process.json"}
        allowed|={role+"/"+name for name in names}
    require({p.relative_to(data).as_posix() for p in data.rglob("*") if p.is_file()}==allowed,
        "complete application evidence file set")
    return dict(status="COMPLETE_ORIGINAL_NATIVE_MULTI_UTF8_PASS",group=group,
        original_decodes=len(original),original_valid=valid,original_errors=len(original)-valid,
        actual_native_calls=actual,native_outcomes=counts,private_controls=actual-len(original),
        original_complete_buffers=original_buffers,native_complete_buffers=native_buffers,
        complete_physical_arena_bytes=actual*16384,actual_original_AST=original_report["original_decoder"],
        production_elf=binding["elf"],source=identity,body_or_parent_application_calls=0,
        application_replays=0,public_handler_qualified=False)

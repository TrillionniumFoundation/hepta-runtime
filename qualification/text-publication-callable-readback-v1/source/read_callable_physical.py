#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Full retained callable wire, two-context borrow, arena, journal and original readback."""
from pathlib import Path
import gzip
import hashlib
import struct
from callable_common import decode,encoded,owned,pin,require,sha,sources,SCOPE
from read_callable_build import verify as read_build
from build_callable import object_layout
from read_callable_journal import Journal,invoke,word
SOURCE_MANIFEST_SHA="982cb3ad3fe24da3019ebc9b3cdd847b34b78877a65e3a1cbb94f69b9b657226"

def references(value):
    if type(value) is dict:
        if set(value)=={"bytes","sha256","blocks"}:return [value]
        return [r for child in value.values() for r in references(child)]
    if type(value) is list:return [r for child in value for r in references(child)]
    return []

def expected_controls():
    bad=b"HTPBQ001"+struct.pack("<7Q",1,0,1,1,0,6,7)+b"rabsent";rows=[]
    for sid in (0,1):
        def add(name,command,data,code,state=None):rows.append((name+"-"+str(sid),command,sid,data,code,state))
        add("existing-create",8,b"",0xfffffffd);add("idle-release",2,b"",0xffffffff)
        for name,value in (("short",b"x"),("magic",b"INVALID!"+bad[8:]),("resume",bad[:8]+struct.pack("<Q",2)+bad[16:]),("sequence",bad[:16]+struct.pack("<Q",1)+bad[24:])):
            add(name,1,value,0xffffffff)
        add("borrow",1,bad,64,2);add("borrow-invoke",1,bad,0xfffffffd);add("borrow-destroy",3,b"",0xfffffffd)
        add("borrow-create",8,b"",0xfffffffd);add("release",2,b"",0,0);add("destroy",3,b"",0,0)
        add("destroy-absent",3,b"",0xffffffff,0);add("recreate",8,b"",0,0)
    for sid in (0,1):rows.append(("eof-borrow-"+str(sid),1,sid,bad,64,2))
    return rows

def fixed_callback(text,symbols):
    # GAS discards .L symbols; derive the two real RIP-relative create-site loans
    # from the complete admitted object bytes, without executing or disassembling it.
    targets=[]
    for at in range(len(text)-17):
        if text[at:at+3]!=b"\x48\x8d\x3d" or text[at+7:at+13]!=b"\xbe\x03\x00\x00\x00\xe8":continue
        callback=at+7+struct.unpack_from("<i",text,at+3)[0]
        callee=at+17+struct.unpack_from("<i",text,at+13)[0]
        if callee==symbols["text_publication_create"]:targets.append(callback)
    require(len(targets)==2 and len(set(targets))==1 and 0<targets[0]<len(text),
        "fixed two-context callback binding is not present in admitted object")
    return targets[0]

def arena_maps(row,context,buffers):
    observed=row["chain"]["process"]
    require(set(observed["fd"])=={"0","1","2","3"},"native body leaked an OS descriptor")
    text=buffers.get(observed["maps"]).decode();areas=[]
    for line in text.splitlines():
        words=line.split();lo,hi=[int(x,16) for x in words[0].split("-")]
        require(lo<hi,"process mapping invalid");areas.append((lo,hi,words[1]))
    spans=[]
    for offset,cap in ((64,word(context,72)),(88,word(context,96)),(104,word(context,112)),
        (120,word(context,128)),(136,4096),(144,4096)):
        ptr=word(context,offset);require(ptr>0 and ptr%4096==0 and cap>0 and cap%4096==0,"owned arena alignment differs")
        require(any(a<=ptr and ptr+cap<=b and flags[:3]=="rw-" for a,b,flags in areas)
            and any(a<=ptr+cap and ptr+cap+4096<=b and flags[:3]=="---" for a,b,flags in areas),"actual owned arena/guard mapping missing")
        spans.append((ptr,ptr+cap+4096))
    require(all(a1<=b0 or b1<=a0 for i,(a0,a1) in enumerate(spans) for b0,b1 in spans[i+1:]),"actual borrowed arenas overlap")
    require(all(not ("w" in flags[:3] and "x" in flags[:3]) for _,_,flags in areas),"native process exposed writable executable mapping")
    return len(areas)

def physical(root,summary,cases,buffers,build):
    process=decode(owned(root,"carrier-process.json").read_bytes())
    require(process==summary["native_process"] and process["returncode"]==0 and process["same_outer_process_group"] is True
        and process["parent_pgid"]==process["child_pgid"] and process["fixed_journal_fd"]==3
        and 0<=process["elapsed_ns"]<180_000_000_000 and process["binary"]==pin(build/"text-publication-callable.elf"),
        "actual native carrier process differs")
    for name in ("stdin","stderr"):require(pin(owned(root,"carrier."+name))==process["streams"][name],"complete carrier stream changed")
    require(owned(root,"carrier.stderr").read_bytes()==b"","native stderr differs")
    stdout=owned(root,"carrier.stdout.gz");require(pin(stdout)==process["stdout"]["compressed"],"complete native stdout gzip changed")
    exchanges=[decode(line) for line in owned(root,"exchanges.jsonl").read_bytes().splitlines()]
    controls=decode(owned(root,"controls.json").read_bytes());expected=expected_controls()
    require(len(exchanges)==summary["exchanges"] and len(controls)==summary["private_controls"]==len(expected)==30,"exchange/control count differs")
    journal=Journal(owned(root,"carrier.journal.gz"),process["journal"])
    require(process["journal"]["ordinary_raw_removed_only_after_complete_equal_read"] is True
        and not (root/"carrier.journal.raw").exists(),"journal retirement custody differs")
    object_text,symbols=object_layout(owned(build,"bridge.o").read_bytes());callback_at=fixed_callback(object_text,symbols)
    state=[dict(alive=False,generation=0,state=0,wcap=4096,ocap=4096,input=b"",last=None),dict(alive=False,generation=0,state=0,wcap=4096,ocap=4096,input=b"",last=None)]
    record_by={};snapshots={};results={};raw_in=hashlib.sha256();raw_out=hashlib.sha256();inbytes=outbytes=0
    def initialized(s):
        s.update(alive=True,generation=0,state=0,wcap=4096,ocap=4096,input=b"",last=None)
    with owned(root,"carrier.stdin").open("rb") as incoming,gzip.open(stdout,"rb") as outgoing:
        for count,row in enumerate(exchanges,1):
            require(row["exchange"]==count and type(row["elapsed_ns"]) is int and 0<=row["elapsed_ns"]<60_000_000_000,"private exchange ordering/limit differs")
            wire=buffers.get(row["input"]);out=buffers.get(row["output"]);raw_in.update(wire);raw_out.update(out);inbytes+=len(wire);outbytes+=len(out)
            require(incoming.read(len(wire))==wire and outgoing.read(len(out))==out,"complete actual native stdin/stdout differs")
            require(len(wire)>=72 and word(wire,0)==len(wire)-8 and wire[8:16]==b"HTPCFQ01"
                and wire[40:72]==bytes(32) and len(out)>=64 and out[:8]==b"HTPCFR01" and len(out)==64+word(out,16),"private carrier framing differs")
            cmd,sid,n=struct.unpack_from("<3Q",wire,16);payload=wire[72:];require(len(payload)==n and sid in (0,1)
                and (cmd,sid)==(row["command"],row["session"]) and cmd in range(1,9),"private command differs")
            s=state[sid];code=word(out,8);require(row["journal_begin"]==journal.count,"journal window begins at different exchange")
            if cmd==1:
                if not s["alive"]:initialized(s)
                if code==64:
                    require(s["state"]==0 and word(out,32)==s["generation"]+1,"new generation or input while borrowed")
                    s["generation"]+=1;s["state"]=2
                    result=invoke(journal,payload,out,(s["wcap"],s["ocap"]))
                    s["wcap"]=result["workspace_capacity"];s["ocap"]=result["output_capacity"];s["last"]=result
                    cap=(len(payload)+4095)&~4095
                    s["input"]=payload+(s["input"]+bytes(max(0,cap-len(s["input"]))))[len(payload):]
                    results[count]=result
                else:require(code==(0xfffffffd if s["state"]!=0 else 0xffffffff),"private invoke refusal differs")
            elif cmd==2:
                require(payload==b"" and code==(0 if s["alive"] and s["state"]==2 else 0xffffffff),"borrow release refusal differs")
                if code==0:s["state"]=0
            elif cmd==3:
                require(payload==b"","destroy payload differs")
                expected_code=0xffffffff if not s["alive"] else 0xfffffffd if s["state"] in (1,2) else 0
                require(code==expected_code,"destroy did not respect live final borrow")
                if code==0:s.update(alive=False,state=0,generation=0)
            elif cmd==8:
                require(payload==b"" and code==(0xfffffffd if s["alive"] else 0),"fixed context creation differs")
                if code==0:initialized(s)
            else:
                require(payload==b"" and code==(0 if s["alive"] else 0xffffffff),"arena observation differs")
                if code==0:
                    data=out[64:];snapshots[count]=(cmd,sid,row["output"])
                    if cmd==4:
                        require(len(data)==4096 and data[:8]==b"HTPCCI01" and word(data,8)==4096
                            and word(data,56)==s["state"] and word(data,192)==s["generation"] and word(data,184)==0
                            and data[256:320]==b"\xff"*64 and word(data,96)==s["wcap"] and word(data,112)==s["ocap"],
                            "complete private context/FD ledger differs")
                        for offset,name in ((16,"text_publication_body_call_displacement"),(24,"text_publication_codec_call_displacement"),(32,"text_publication_errno_call_displacement")):
                            require(word(data,offset)==4194304+256+symbols[name]-1,"mutable image binding differs")
                        require(word(data,40)==4194304+256+callback_at and word(data,48)==3,"fixed observer binding differs")
                        if s["state"]==2:require(word(data,168)==64+word(s["last"]["final_output"],56) and word(data,176)==64,"complete final borrow extent differs")
                        else:require(word(data,168)==word(data,176)==0,"released borrow remains published")
                    elif cmd==5:require(len(data)==s["wcap"],"full workspace observation differs")
                    elif cmd==6:
                        require(len(data)==s["ocap"] and data==(s["last"]["final_output"] if s["last"] else bytes(s["ocap"])),"full output observation differs")
                    elif cmd==7:require(data==s["input"],"complete owned request buffer differs")
            require(row["journal_end"]==journal.count,"journal contains omitted/unowned callbacks")
            if s["alive"]:
                require(word(out,24)==s["state"] and word(out,32)==s["generation"] and word(out,40)==0
                    and word(out,48)==s["ocap"] and word(out,56)==s["wcap"],"complete carrier state summary differs")
            else:require(out[24:64]==bytes(40),"destroyed context still exposed")
            record_by[count]=(cmd,sid,payload,out)
        require(incoming.read(1)==outgoing.read(1)==b"","extra complete carrier stream bytes")
    require(dict(bytes=inbytes,sha256=raw_in.hexdigest())==process["streams"]["stdin"]
        and dict(bytes=outbytes,sha256=raw_out.hexdigest())==process["stdout"]["raw"],"whole native transport digest differs")
    maps=0
    for row in cases:
        chain=row["chain"];start=chain["first_exchange"];end=chain["last_exchange"];sid=chain["session"]
        require(end==start+5 and sid==row["id"]%2 and record_by[start][:2]==(1,sid)
            and record_by[end][:2]==(2,sid),"body case does not own complete invoke/snapshot/release sequence")
        request=row["request"];path=request["path"].encode();content=request["content"].encode();expected_digest=request["expected_sha256"].encode()
        expected_wire=b"HTPBQ001"+struct.pack("<7Q",1,0,{"create":1,"replace":2,"append":3}[request["mode"]],len(path),len(content),len(expected_digest),len(path)+len(content)+len(expected_digest))+path+content+expected_digest
        require(record_by[start][2]==expected_wire and chain["generation"]==word(record_by[start][3],32),"case input/generation differs")
        final=record_by[start][3][64:]
        require(dict(id=row["id"],ok=word(final,8)==0,text=final[64:].decode())==row["result"],"actual body publication differs from compared wire")
        for offset,(command,name) in enumerate(((4,"context"),(5,"workspace"),(6,"output"),(7,"input")),1):
            saved=chain["snapshots"][name];idx=start+offset
            require(saved["exchange"]==idx and snapshots[idx][:2]==(command,sid)
                and buffers.get(saved["bytes"])==buffers.get(snapshots[idx][2])[64:],"whole case arena snapshot differs")
        maps+=arena_maps(row,buffers.get(snapshots[start+1][2])[64:],buffers)
    for spec,row in zip(expected,controls):
        name,cmd,sid,payload,code,status=spec
        require((row["name"],row["command"],row["session"],buffers.get(row["input"]),row["expected_code"],row["expected_state"])==spec,"private control domain differs")
        actual=record_by[row["exchange"]];require(actual[:3]==(cmd,sid,payload) and actual[3]==buffers.get(row["response"])
            and word(actual[3],8)==code and (status is None or word(actual[3],24)==status),"private control actual response differs")
        if "before_context" in row:
            before=row["before_context"];after=row["after_context"]
            b=buffers.get(before["bytes"]);a=buffers.get(after["bytes"])
            require(snapshots[before["exchange"]][:2]==(4,sid) and buffers.get(snapshots[before["exchange"]][2])[64:]==b\
                and snapshots[after["exchange"]][:2]==(4,sid) and buffers.get(snapshots[after["exchange"]][2])[64:]==a
                and before["exchange"]<row["exchange"]<after["exchange"],"control snapshots outside actual call")
            if name.startswith("release-"):
                correct=bytearray(b)
                for at in (56,168,176):struct.pack_into("<Q",correct,at,0)
                require(a==correct,"release changed unrelated full-context bytes")
            else:require(a==b,"rejected call changed full context")
    descriptors=references(exchanges)+references(cases)+references(controls)
    require(len(descriptors)==summary["complete_buffer_images"] and sum(r["bytes"] for r in descriptors)==summary["logical_buffer_bytes"],
        "retained complete buffer accounting differs")
    for descriptor in descriptors:buffers.get(descriptor)
    blocks=buffers.finish()
    return dict(status="COMPLETE_CALLABLE_PHYSICAL_READBACK_PASS",journal=journal.finish(),exchanges=len(exchanges),
        cases=len(cases),controls=len(controls),two_contexts=True,borrow_release_observed=True,
        mapped_regions_verified=maps,complete_buffer_images=len(descriptors),logical_buffer_bytes=sum(r["bytes"] for r in descriptors),blocks=blocks["blocks"])

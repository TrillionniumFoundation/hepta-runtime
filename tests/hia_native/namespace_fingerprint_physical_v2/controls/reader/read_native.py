"""Complete observed and observer-free native custody; no executable is loaded."""
import struct
from common import encoded,files,loads,pin,read,require
from callable_contract import initial,response,semantic,word
from read_frames import Records,Outer,equal
from read_context import Context
from read_owner import put
from read_libc import verify as libc_verify
def fixed(report,folder):
    names=("LIBC.bin","LIBC-BINDINGS.json","PROCESS-MAPS.txt","CONTEXTS.json","OBSERVATIONS.json",
           "ENVIRONMENT.json","LAYOUT.json","outer.bin.gz","OUTER.json")
    if report["observer_enabled"]:names+=("records.bin.gz","RECORDS.json","OBSERVER-ERRORS.json","FAILED-PENDING.bin")
    require(set(files(folder))==set(names)|{"NATIVE.json"} and set(report["files"])==set(names),
            "whole native capture file set")
    for name in names:equal(pin(read(folder/name)),report["files"][name],"entire native retained file "+name)
    if report["observer_enabled"]:
        require(read(folder/"OBSERVER-ERRORS.json")==encoded([])and read(folder/"FAILED-PENDING.bin")==b"",
                "no swallowed callback failure or unfinished before record")
def verify(folder,group,cases,paired,initials,ready,expected_binary,source_sha,process,*,observed,observed_turns=None):
    report=loads(read(folder/"NATIVE.json"));fixed(report,folder)
    require(report["schema"]=="hepta.namespace-fingerprint.native-child.v1"and report["status"]=="PASS"and
            report["group"]==group and report["observer_enabled"]is observed and
            report["source_manifest_sha256"]==source_sha,"same frozen native role")
    for key in("pid","parent_pid","pgid","uid","gid"):
        require(type(report[key])is int and report[key]==ready[key],"actual native identity "+key)
    require(report["uid"]>0 and report["pid"]==process["pid"]and report["source_root"]==process["cwd"],
            "unprivileged actual child and complete source custody")
    equal(report["callable"],expected_binary,"full actual native image")
    equal(ready["callable"],expected_binary,"actual ready loaded image")
    equal(report["loaded_image"],ready["loaded_image"],"same actual loaded image span")
    lib=libc_verify(folder);table=lib["table"];loaded=report["loaded_image"]
    require(set(loaded)=={"address","bytes"} and type(loaded["address"])is int and loaded["address"]>0 and
            loaded["bytes"]==expected_binary["bytes"]and
            any(m["lo"]<=loaded["address"]and loaded["address"]+loaded["bytes"]<=m["hi"]and
                m["permissions"][:3]=="r-x"for m in lib["maps"]),"whole image in retained executable, non-writable mapping")
    layout=loads(read(folder/"LAYOUT.json"));equal(layout,ready["layout"],"actual held descriptor layout")
    require(set(layout)=={"base","held","stream_fd","root_fd"}and layout["stream_fd"]==80 and layout["root_fd"]==96 and
            type(layout["base"])is int and 3<=layout["base"]<128 and layout["base"]not in(80,96)and
            type(layout["held"])is list and layout["held"]==sorted(set(layout["held"]))and
            all(type(n)is int and 3<=n<128 and n not in(80,96,layout["base"])for n in layout["held"]),
            "bounded privately filled descriptor holes, never overwrite the two reserved slots")
    environment=loads(read(folder/"ENVIRONMENT.json"))
    contexts=loads(read(folder/"CONTEXTS.json"));observations=loads(read(folder/"OBSERVATIONS.json"))
    require(type(contexts)is list and len(contexts)==len(cases)==report["cases"] and
            type(observations)is list and len(observations)==len(paired)==report["operations"],"complete native domain")
    outer=Outer(folder);records=Records(folder)if observed else None
    at=0;turns=[];owner_calls=boundary_calls=0;full_bytes=0
    for case,bind,init in zip(cases,contexts,initials):
        ci=case["case"]
        require(set(bind)=={"case","context","table","observer","root_fd","root_identity"}and
                bind["case"]==ci and type(bind["context"])is int and bind["context"]>4096 and bind["context"]%8==0 and
                type(bind["table"])is int and bind["table"]>4096 and bind["table"]%8==0 and
                bind["root_fd"]==96 and type(bind["observer"])is int and
                (bind["observer"]>4096 if observed else bind["observer"]==0),"actual private native storage binding")
        equal(bind["root_identity"],init["replies"][0]["root_identity"],"same actual tree root")
        equal(environment,init["replies"][0]["environment"],"same actual fault environment")
        args=dict(directory=96,table=bind["table"],observer=bind["observer"],user=0)
        before,after=outer.next(ci,0,0,args,table)
        require(before[:2]==after[:2]==[b"",b""]and before[2]==bytes(32768)+b"\x5a"*16,
                "complete zero initialized exclusive native context")
        context=Context(bind,table,lib["maps"]);require(after[2]==context.raw(),"every initializer byte")
        last=after[2];case_owner=case_boundary=0
        for si,_ in enumerate(case["steps"]):
            row=observations[at];pair=paired[at];require(pair["case"]==ci and pair["step"]==si,"ordered complete native turn")
            wire=initial(si+1);before,after=outer.next(ci,si,1,dict(observer=observed),table)
            require(before[0]==wire+b"\xc3"*16 and before[2]==last,"whole input and preceding context, including old tails")
            first=None if records is None else records.position
            if observed:
                context.begin(wire)
                while True:
                    terminal=context.owner(records,ci,si)
                    if terminal is not None:break
                    context.boundary(records,ci,si)
                require(context.complete()==terminal and after[2]==context.raw()and after[1][:128]==terminal,
                        "entire native transport final context and delivered 128-byte terminal")
                turn=dict(case=ci,step=si,generation=si+1,effects=list(context.effects),entries=list(context.model.entries),
                    final_context=after[2],padding=sorted(context.padding),binding=bind)
                case_owner=word(context.data,56);case_boundary=word(context.data,184)
            else:
                require(observed_turns is not None and at<len(observed_turns),"complete paired actual effects for observer-free proof")
                prior=observed_turns[at];require((prior["case"],prior["step"])==(ci,si),"same observer-free source turn")
                terminal=after[1][:128];equal(terminal.hex(),pair["answers"][0]["native_frame_hex"],"all observed/off terminal bytes")
                wanted=bytearray(prior["final_context"][:-16])
                # Only actual per-process pointers, ambient cleanup errno, and kernel dirent padding differ.
                put(wanted,32,0);wanted[64:112]=table[:48]
                obs=list(struct.unpack_from("<16Q",wanted,4864));base=bind["context"]
                obs[3]=base+256;obs[5]=base+4608;obs[7]=base+8192;obs[9]=base
                wanted[4864:4992]=struct.pack("<16Q",*obs)
                lastack=after[2][256:352]
                require(lastack[:8]==b"HNFACK01"and word(lastack,64)==96 and word(lastack,56)==0 and
                        lastack[:40]==wanted[256:296]and lastack[48:]==wanted[304:352],
                        "complete final actual observer-free ACK identity and extent")
                ambient=word(lastack,40);require(0<=ambient<=4095,"actual cleanup errno")
                put(wanted,296,ambient);put(wanted,176,ambient);put(wanted,8192+2136,ambient)
                if word(lastack,24)!=5:
                    require(ambient==word(prior["final_context"],296),"non-ignored original error unchanged")
                for index in prior["padding"]:
                    require(0<=index<32768,"exact prior kernel padding byte");wanted[index]=after[2][index]
                require(after[2]==bytes(wanted)+b"\x5a"*16,"every observer-free native byte with only identified kernel padding and private addresses")
                case_owner=word(wanted,56);case_boundary=word(wanted,184)
                turn=dict(case=ci,step=si,generation=si+1,effects=prior["effects"],entries=prior["entries"],
                          final_context=after[2],padding=prior["padding"],binding=bind)
            expected=dict(case=ci,step=si,generation=si+1,initial_hex=wire.hex(),first_record=first,
                last_record=None if records is None else records.position-1,native_frame_hex=terminal.hex(),semantic=semantic(terminal))
            equal(row,expected,"whole native observation row")
            answer=pair["answers"][0 if observed else 1]
            equal(answer,dict(command="run",case=ci,step=si,generation=si+1,semantic=semantic(terminal),
                native_frame_hex=terminal.hex(),returned=128),"complete actual native answer")
            turns.append(turn);at+=1;last=after[2]
        before,after=outer.next(ci,0,2,{},table)
        require(before[:2]==after[:2]==[b"",b""]and before[2]==last and after[2]==bytes(32768)+b"\x5a"*16,
                "whole native quiescent disposal, all bytes and guards")
        owner_calls+=case_owner;boundary_calls+=case_boundary
    require(at==len(paired)and len(observations)==at,"all native observations consumed exactly once")
    equal(report["counts"],dict(owner_calls=owner_calls,boundary_calls=boundary_calls),"actual complete HIA and libc call totals")
    require(report["outer_calls"]==at+2*len(cases)==outer.position,"whole native outer call domain")
    full_bytes+=outer.finish()
    if records is not None:
        require(report["records"]==records.position==owner_calls+boundary_calls,"all complete observed HIA/libc borrows")
        full_bytes+=records.finish()
    else:require(report["records"]==0,"actual observer-free entry")
    return dict(turns=turns,calls=owner_calls,boundaries=boundary_calls,logical_bytes=full_bytes,report=report,libc=lib,layout=layout)

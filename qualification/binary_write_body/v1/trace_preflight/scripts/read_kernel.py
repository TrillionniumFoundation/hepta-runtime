"""Complete read-only admission of actual Linux ptrace records, including C-layer effects."""
from pathlib import Path
import gzip,hashlib,struct
from evidence_common import decode,pin,require
def memory_rows(rows):
    out={}
    for row in rows:
        require("error"not in row and set(row)=={"label","address","bytes","hex"},"incomplete actual kernel memory observation")
        require(row["label"]not in out and type(row["address"])is int and row["address"]>=0,
            "duplicate or invalid actual kernel memory span")
        raw=bytes.fromhex(row["hex"]);require(len(raw)==row["bytes"],"complete observed syscall buffer")
        out[row["label"]]=dict(address=row["address"],raw=raw)
    return out
def read_trace(folder,binding):
    path=Path(folder)/"kernel.jsonl.gz";require(pin(path)==binding["compressed"],"full kernel trace archive identity")
    digest=hashlib.sha256();count=0;row_count=0;calls=[];current=None;marks=[];signals=[];execs=[];end=None;done=None;start=None
    with gzip.open(path,"rb")as stream:
        for raw in stream:
            digest.update(raw);count+=len(raw);require(raw.endswith(b"\n"),"complete kernel JSON row")
            row=decode(raw);require(row["trace_row"]==row_count,"contiguous kernel record index");row_count+=1
            kind=row["record"]
            if kind=="START":
                require(start is None and row_count==1,"kernel trace unique start");start=row
                require(row["options"]==1048593 and row["ptrace_requests"]==[24,0x4200,0x420e]
                    and row["memory_reader"]=="process_vm_readv"and not row["follow_forks"]
                    and row["register_or_memory_writes"]==row["syscall_result_replacements"]==0,
                    "read-only actual kernel observer profile")
            elif kind=="MARK":
                require(row["calls"]==len(calls)+(current is not None),"kernel marker call count");marks.append(row)
            elif kind=="ENTER":
                require(current is None and row["ordinal"]==len(calls)+1,"kernel complete syscall entry sequence")
                info=bytes.fromhex(row["syscall_info_hex"])
                require(len(info)==80 and info[0]==1 and struct.unpack_from("<I",info,4)[0]==0xc000003e
                    and list(struct.unpack_from("<7Q",info,24))==[row["number"],*row["args"]]
                    and struct.unpack_from("<Q",info,8)[0]==row["instruction_pointer"],"actual kernel entry struct bytes")
                row["input_spans"]=memory_rows(row["input"]);current=row
            elif kind=="LEAVE":
                require(current is not None and row["ordinal"]==current["ordinal"]and row["number"]==current["number"]
                    and row["scope"]==current["scope"],"kernel complete syscall exit binding")
                info=bytes.fromhex(row["syscall_info_hex"])
                require(len(info)==33 and info[0]==2 and struct.unpack_from("<I",info,4)[0]==0xc000003e
                    and struct.unpack_from("<q",info,24)[0]==row["result"]and info[32]==row["is_error"]
                    and row["is_error"]==int(-4095<=row["result"]<0),"actual kernel exit struct bytes")
                current["exit"]=row;current["output_spans"]=memory_rows(row["output"]);calls.append(current);current=None
            elif kind=="EXEC":
                require(current is not None and current["number"]in(59,322)
                    and row["pending_call"]==current["ordinal"],"actual exec custody")
                execs.append(row)
            elif kind=="SIGNAL":
                require(row["forwarded_without_change"]is True and 1<=row["signal"]<=64
                    and (row["wait_status"]&255)==127 and ((row["wait_status"]>>8)&255)==row["signal"],
                    "actual signal delivered unchanged");signals.append(row)
            elif kind=="EXIT":
                require(end is None and(current is None or current["number"]in(60,231)),"actual natural process exit")
                require(row["open_exit"]is not None if current else row["open_exit"]is None,"open exit syscall witness")
                end=row
                if current:
                    require(row["open_exit"]["ordinal"]==current["ordinal"],"actual final exit call")
                    current["terminal_exit"]=row;calls.append(current);current=None
            elif kind=="DONE":
                require(done is None and end is not None,"actual kernel terminal receipt");done=row
            else:raise ValueError("unknown actual kernel record")
    require(start and end and done and current is None and row_count==binding["rows"]
        and dict(bytes=count,sha256=digest.hexdigest())==binding["raw"],"complete actual kernel trace bytes/set")
    require(done["calls"]==len(calls)==binding["calls"]and done["signals"]==len(signals)==binding["signals"]
        and done["execs"]==len(execs)==binding["execs"]==1 and done["capture_errors"]==binding["capture_errors"]==[]
        and done["application_calls"]==binding["application_calls"]==sum(x["application"]for x in marks)
        and done["register_or_memory_writes"]==done["syscall_result_replacements"]==0
        and binding["returncode"]==end["returncode"]==0,"complete actual observer terminal counters")
    for call in calls:
        if "exit"not in call:continue
        n=call["number"];a=call["args"];ret=call["exit"]["result"];before=call["input_spans"];after=call["output_spans"]
        def span(rows,name,address,size):
            require(name in rows and rows[name]["address"]==address and len(rows[name]["raw"])==size,"exact actual syscall memory ABI "+name)
        if n==1 and a[0]not in(1,2,3,4):span(before,"write",a[1],a[2])
        if n==1 and a[0]==4:span(before,"notification",a[1],a[2])
        if ret>=0:
            if n==5:span(after,"stat",a[1],144)
            if n==262:span(after,"stat",a[2],144)
            if n in(0,17)and a[0]not in(3,5):span(after,"read",a[1],ret)
            if n==318:span(after,"random",a[0],ret)
            if n==193:span(after,"attribute-value",a[2],ret if a[3]else 0)
            if n==196:span(after,"attribute-list",a[1],ret if a[2]else 0)
        else:require(not after,"negative kernel result invented payload bytes")
        for name,row in before.items():
            if name in("path","source","destination","attribute"):
                require(row["raw"].endswith(b"\0")and b"\0"not in row["raw"][:-1],"whole actual NUL-terminated syscall name")
    return dict(calls=calls,marks=marks,signals=signals,execs=execs,start=start,end=end,
        complete_bytes=count,rows=row_count,application_calls=done["application_calls"])

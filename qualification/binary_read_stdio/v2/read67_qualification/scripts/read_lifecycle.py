#!/usr/bin/env python3
"""Read complete release/destruction/pool snapshots without executing native code."""
import hashlib,struct
from common import require
from read_journal import U
from read_kernel import mapping_rows,covered
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

def lifecycle(journal,process,invoked,kernel,case):
    frames=[]
    def take():
        header=journal.stream.read(64);require(len(header)==64 and header[:8]==b"HBRLJR01","full lifecycle header")
        h=struct.unpack("<8Q",header);require(h[6:]==(0,0)and h[2]in(0,4096),"lifecycle complete fixed span")
        raw=journal.stream.read(h[2]);require(len(raw)==h[2],"complete lifecycle mapping")
        for block in(header,raw):journal.digest.update(block);journal.position+=len(block)
        frames.append((h,raw));return h,raw
    h1,before=take();h2,after=take()
    require(h1[1]==1 and h2[1]==2 and h1[2]==h2[2]==4096 and h1[3]==h2[3]>0
        and h1[4]==h2[4]>0 and h1[5]==h2[5]==0,"same full pre/post release context")
    require(before[:8]==after[:8]==b"HBRDCI01"and U(before,8)==4096 and U(before,56)==2
        and U(before,168)==len(invoked["frame"])and U(before,176)==64 and U(before,184)==0
        and U(before,192)==1 and U(before,48)==3 and U(before,376)==h1[4]
        and U(before,400)==int(case["fault"])and before[256:320]==b"\xff"*64
        and before[408:]==bytes(4096-408)
        and all(U(before,x)==0 for x in(152,160,344,352,360,368,384,392)),
        "actual complete finished read67 context")
    expected=bytearray(before)
    for offset in(56,168,176):struct.pack_into("<Q",expected,offset,0)
    require(after==expected,"release changes only state/output loan/return fields")
    hp,header=take();require(hp[1]==3 and hp[2]==4096 and hp[3]==hp[4]==h1[4],"exact shared process pool")
    pages=[];page_headers=[]
    for i in range(U(header,56)):
        h,data=take();require(h[1]==4 and h[2]==4096 and h[4]==hp[4]and h[5]==i,"full linked record page")
        pages.append(data);page_headers.append(h)
    end,empty=take();require(end[1]==5 and end[2]==end[3]==0 and not empty and end[4]==hp[4]
        and end[5]==hp[5]==U(header,48),"full process-lifetime EOF boundary")
    raw=b"HOPSN001"+struct.pack("<3Q",hp[4],U(header,48),len(pages))+header+b"".join(pages)
    value=pool(raw);require(value["pid"]==process["pid"]and value["address"]==kernel["native_pool_address"],
        "same actual process/pool as passive kernel mapping")
    require([h[3]for h in page_headers]==value["pages"],"page snapshot addresses follow real links")
    require(set(kernel["native_live_mappings"])=={value["address"],*value["pages"]},
        "no owned helper/child mapping survives ordinary EOF")
    maps=mapping_rows(kernel["pre_exit_maps"])
    require(not covered(maps,h1[3],4096),"actual origin context retired before process exit")
    for offset in(64,88,104,120,136,144):
        address=U(before,offset)
        require(address>0 and not covered(maps,address,1),"actual input/work/output/child arena retired")
    records=value["records"];require(len(records)==len(invoked["orphans"])==len(kernel["orphans"])==int(case["fault"]),
        "one kernel failed open token becomes one immutable process orphan")
    for r,h,k in zip(records,invoked["orphans"],kernel["orphans"]):
        require(r["fd"]==h["fd"]==k["fd"]and r["context"]==h1[3]
            and r["generation"]==h["generation"]==1 and r["sequence"]==1,
            "orphan keeps exact descriptor, context and generation after destruction")
    ack=process["lifecycle_ack"];require(ack==dict(bytes=8,hex=bytes(8).hex(),body_offset=journal.position,
        sent_after_full_final_frame=True),"final zero ACK follows all lifecycle bytes")
    require(kernel["observer_acks"]==[bytes(8).hex()],"actual kernel consumes exact final zero ACK")
    return dict(records=len(records),pages=len(pages),full_context_bytes=8192,
        full_pool_bytes=4096*(1+len(pages)),complete_context_release_bytes_preserved=True,
        only_process_pool_mappings_survive=True,ordinary_eof_does_not_close_orphans=True,
        actual_process_exit=True,application_executed=False)

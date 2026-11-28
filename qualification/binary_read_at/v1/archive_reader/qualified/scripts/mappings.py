# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
from common import require
from read_journal import U
def mapped(context,maps):
    require(len(context)==4096 and context[:8]==b"HBRDCI01"and U(context,8)==4096
        and U(context,56)==2 and U(context,176)==64 and U(context,184)==0
        and context[256:320]==b"\xff"*64,"context state or complete descriptor ledger differs")
    entries=[]
    for line in maps.decode().splitlines():
        columns=line.split();begin,end=(int(x,16)for x in columns[0].split("-"))
        require(begin<end and len(columns)>=5,"process mapping record")
        entries.append((begin,end,columns[1]," ".join(columns[5:])))
    require(not any(".so"in row[3]or"python"in row[3].lower()for row in entries),"native process mapped a host runtime")
    for at,cap in((64,72),(88,96),(104,112),(120,128)):
        address,size=U(context,at),U(context,cap)
        require(address%4096==size%4096==0 and size>=4096
            and any(lo<=address and address+size<=hi and flags[:3]=="rw-"for lo,hi,flags,_ in entries)
            and any(lo<=address+size and address+size+4096<=hi and flags[:3]=="---"for lo,hi,flags,_ in entries),
            "owned arena/guard mapping differs")
    for at,size in((136,1400832),(144,4096)):
        address=U(context,at)
        require(any(lo<=address and address+size<=hi and flags[:3]=="rw-"for lo,hi,flags,_ in entries)
            and any(lo<=address+size and address+size+4096<=hi and flags[:3]=="---"for lo,hi,flags,_ in entries),
            "child arena/guard mapping differs")

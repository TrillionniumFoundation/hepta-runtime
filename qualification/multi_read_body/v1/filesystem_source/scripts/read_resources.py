"""Exact shared orphan-pool and mapping readers from the closed read67 profile."""
import struct
from evidence_common import require
from protocol import U
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

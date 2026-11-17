"""Read-only physical map parsing, shared by capture and admission."""
import struct
MASK=(1<<64)-1
def u64(raw,offset):return struct.unpack_from("<Q",raw,offset)[0]
def qput(raw,offset,value):struct.pack_into("<Q",raw,offset,value&MASK)
def maps(raw):
    result=[]
    for line in raw.decode().splitlines():
        fields=line.split(maxsplit=5);low,high=(int(x,16) for x in fields[0].split("-"))
        assert low<high
        result.append(dict(low=low,high=high,permissions=fields[1],name=fields[5] if len(fields)>5 else ""))
    assert all(a["high"]<=b["low"] for a,b in zip(result,result[1:]))
    return result
def cover(rows,address,length,permissions):
    end=address+length;position=address
    for row in rows:
        if row["high"]<=position:continue
        if row["low"]>position:return False
        if row["permissions"]!=permissions:return False
        position=min(end,row["high"])
        if position==end:return True
    return False
def absent(rows,address,length):
    return not any(row["low"]<address+length and address<row["high"] for row in rows)
def stack_pointer(rows,value):
    return any(row["name"]=="[stack]" and row["low"]<=value<row["high"] and row["permissions"]=="rw-p" for row in rows)

"""Read the captured HIA node arena against complete observed original trees."""
import struct
from common import require
def word(raw,at):
    require(0<=at<=len(raw)-8,"complete native word extent");return struct.unpack_from("<Q",raw,at)[0]
def span(raw,at,n):
    require(0<=at<=len(raw)and 0<=n<=len(raw)-at,"complete native span extent");return raw[at:at+n]
def node(w,at):
    end=word(w,12288);heap=word(w,12296)
    require(16384<=at<end and(at-16384)%64==0 and end<=heap<=len(w)and end%64==0,
        "native reachable node belongs to complete allocated arena")
    tag=word(w,at);require(tag<=7,"native ordinary JSON tag");return tag
def string(w,at):
    require(node(w,at)==5,"native dictionary key is a string")
    size=word(w,at+48);place=word(w,at+40)
    require(place>=word(w,12296),"native string belongs to retained decoded heap")
    raw=span(w,place,size*4)
    require(all(cp[0]<=0x10ffff for cp in struct.iter_unpack("<I",raw)),"native decoded code points")
    return raw,size
def integer(s,w,at):
    begin=word(w,at+40);size=word(w,at+48);start=word(w,at+56)&0xffffffff
    raw=span(s,64+begin*4,size*4);digits=[x[0]for x in struct.iter_unpack("<I",raw)]
    require(size>0 and all(48<=x<=57 for x in digits),"native source integer decimal digits")
    value=bytes(digits)
    if start!=begin:
        require(begin==start+1 and word(s,64+start*4)&0xffffffff==45,"native signed integer span")
        if value!=b"0":value=b"-"+value
    return value
def children(w,at):
    tag=node(w,at);require(tag in(6,7),"native container")
    size=word(w,at+48);item=word(w,at+24);rows=[];seen=set()
    while item:
        require(item not in seen and len(rows)<size,"native finite exact child list");seen.add(item);node(w,item)
        rows.append(item);item=word(w,item+16)
    require(len(rows)==size,"native complete container cardinality")
    if tag==7:
        positions=[]
        for child in rows:
            key=word(w,child+32);string(w,key);positions.append(word(w,key+24))
        require(len(set(positions))==len(positions),"native distinct first key positions")
        rows.sort(key=lambda child:word(w,word(w,child+32)+24))
    return rows
def observe(s,w,root):
    out=bytearray();pending=[root];seen=set()
    while pending:
        at=pending.pop();require(at not in seen,"native tree has no repeated reachable node");seen.add(at)
        tag=node(w,at);payload=b"";count=0
        if tag==3:payload=integer(s,w,at);count=len(payload)
        elif tag==4:payload=span(w,at+40,8);count=8
        elif tag==5:payload,count=string(w,at)
        elif tag in(6,7):
            rows=children(w,at);count=len(rows)
            if tag==6:pending.extend(reversed(rows))
            else:
                for child in reversed(rows):pending.extend((child,word(w,child+32)))
        out.extend(struct.pack("<2Q",tag,count));out.extend(payload)
    return bytes(out)
def auxiliary_root(s,w,primary,auxiliary):
    begin=len(primary)+len(auxiliary)-len(auxiliary.lstrip(" \t\r\n"));found=[]
    for at in range(16384,word(w,12288),64):
        if(word(w,at+56)&0xffffffff)==begin and word(w,at+8)==0:found.append(at)
    require(len(found)==1,"one complete native auxiliary root");return found[0]
def selected_root(w,root,key):
    if node(w,root)!=7:return None
    encoded=key.encode("utf-32-le","surrogatepass")
    for child in children(w,root):
        raw,_=string(w,word(w,child+32))
        if raw==encoded:return child
    return None

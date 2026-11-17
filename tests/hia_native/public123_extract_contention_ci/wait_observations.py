"""Complete retained observation decoding, including actual live mutex leases."""
import hashlib,json,struct
import observations as original
import native_observations as ordinary
def need(ok,text):
    if not ok:raise ValueError(text)
def q(raw,at=0,n=1):
    need(0<=at<=len(raw) and 8*n<=len(raw)-at,"complete observation words")
    return struct.unpack_from("<"+"Q"*n,raw,at)
def serial(value):
    if isinstance(value,bytes):return value.hex()
    if isinstance(value,dict):return {k.hex() if isinstance(k,bytes) else k:serial(v) for k,v in value.items()}
    if isinstance(value,(list,tuple)):return [serial(v) for v in value]
    return value
def logical(value):return serial({k:v for k,v in value.items() if k not in ("phase","generation")})
def locks(arena):
    need(len(arena)>=256 and arena[:8]==b"HFLSTATE","actual shared lock magic")
    version,used,free_head,node_head,count,next_node,next_lease,lease_head,nleases=q(arena,8,9)
    need(version==1 and 256<=used<=len(arena) and used%16==0 and next_node>0 and next_lease>0 and not any(arena[80:256]) and not any(arena[used:]),"complete lock arena header/tail")
    free={};nodes={};leases={};at=256
    while at<used:
        size,marker=q(arena,at,2)
        need(size>=32 and size%16==0 and size<=used-at,"complete allocator block")
        p=at+16
        if marker==int.from_bytes(b"HFLALLOC","little"):
            magic=arena[p:p+8]
            if magic==b"HFLNODE1":
                need(size>=96,"full node allocation")
                identity,following,refs,kn,digest,owner,head,tail,reserved=q(arena,p+8,9)
                need(0<identity<next_node and kn<=at+size-p-80 and reserved==0,"complete node fields")
                key=bytes(arena[p+80:p+80+kn]);key.decode("utf-8")
                need(digest==ordinary.key_hash(key) and not any(arena[p+80+kn:at+size]),"complete exact node key/padding")
                nodes[p]={"identity":identity,"following":following,"refs":refs,"key":key,"owner":owner,"head":head,"tail":tail}
            else:
                need(magic==b"HFLLEAS1" and size>=96,"full live lease allocation")
                identity,node,state,prev,nxt,allprev,allnext,z0,z1=q(arena,p+8,9)
                need(0<identity<next_lease and state in (0,1,2,3) and z0==z1==0 and not any(arena[p+80:at+size]),"complete live lease fields")
                leases[p]={"identity":identity,"node":node,"state":state,"prev":prev,"next":nxt,"allprev":allprev,"allnext":allnext}
        else:
            need(not any(arena[p:at+size]),"released allocation fully zero")
            free[at]=marker
        at+=size
    need(at==used,"complete used arena")
    seen=set();cursor=free_head;last=0
    while cursor:
        need(cursor in free and cursor not in seen and cursor>last,"ordered complete free list")
        seen.add(cursor);last=cursor;cursor=free[cursor]
    need(seen==set(free),"all free blocks retained")
    seen=set();cursor=lease_head;last=0;ids=set()
    while cursor:
        need(cursor in leases and cursor not in seen,"complete all-lease list")
        row=leases[cursor];need(row["allprev"]==last and row["identity"] not in ids and row["node"] in nodes,"lease owner/list identity")
        seen.add(cursor);ids.add(row["identity"]);last=cursor;cursor=row["allnext"]
    need(seen==set(leases) and len(leases)==nleases,"all retained leases accounted")
    seen=set();ids=set();entries={};queues={};owners={};cursor=node_head
    while cursor:
        need(cursor in nodes and cursor not in seen,"complete retained map")
        row=nodes[cursor];need(row["identity"] not in ids and row["key"] not in entries,"unique node/key")
        associated={p:l for p,l in leases.items() if l["node"]==cursor}
        need(len(associated)==row["refs"],"strong references equal all actual retained leases")
        queued=[];p=row["head"];prev=0
        while p:
            need(p in associated and p not in queued,"actual FIFO queue has complete owned leases")
            l=associated[p];need(l["state"]==1 and l["prev"]==prev,"actual FIFO links")
            queued.append(p);prev=p;p=l["next"]
        need(prev==row["tail"] and set(queued)=={p for p,l in associated.items() if l["state"]==1},"complete FIFO head/tail and membership")
        owner=row["owner"]
        need((owner==0 and not any(l["state"] in (2,3) for l in associated.values())) or (owner in associated and associated[owner]["state"] in (2,3) and sum(l["state"] in (2,3) for l in associated.values())==1),"held/reserved ownership")
        for p,l in associated.items():
            if l["state"]!=1:need(l["prev"]==l["next"]==0,"nonqueued lease links")
        entries[row["key"]]=1+row["refs"];queues[row["key"]]=[associated[p]["identity"] for p in queued]
        owners[row["key"]]=None if owner==0 else {"lease":associated[owner]["identity"],"state":associated[owner]["state"]}
        seen.add(cursor);ids.add(row["identity"]);cursor=row["following"]
    need(seen==set(nodes) and len(nodes)==count,"complete lock map extent")
    return {"poisoned":False,"entries":serial(entries)},{"queues":serial(queues),"owners":serial(owners),"lease_count":nleases,"leases":{str(l["identity"]):dict(l,node_key_hex=nodes[l["node"]]["key"].hex()) for l in leases.values()}}

def original_state(value):
    need(value["schema"]=="hepta.runtime.original-extract-wait-observation.v1","actual original observer schema")
    phase,seq=value["phase"],value["sequence"]
    need(phase in (0,90,91) and seq>0 and value["observer_task_scope_unbound"] is True,"original observer task phase")
    parsed={}
    for name,field,magic,read in (("locks","lock_snapshot_hex",b"HLTBLK01",original.locks),("history","history_snapshot_hex",b"HLTBHS01",original.history),("cache","cache_snapshot_hex",b"HLCSCS01",original.cache)):
        raw=bytes.fromhex(value[field]);need(raw[:8]==magic,"actual original complete state magic")
        state=read(raw);need(state["phase"]==phase and (name=="cache" or state["generation"]==seq),"original state phase/generation")
        parsed[name]=logical(state)
    s=value["session"];need(set(s)=={"root","current","effective","session_applied","poisoned"},"complete original session")
    parsed["session"]={"root_hex":s["root"].encode().hex(),"current_hex":None if s["current"] is None else s["current"].encode().hex(),"effective_hex":s["effective"].encode().hex(),"session_applied":s["session_applied"],"poisoned":s["poisoned"]}
    need(len(value["fixture_holders"])==4 and all(type(x) is bool for x in value["fixture_holders"]),"four actual held guard slots")
    return parsed,{"fixture_holders":value["fixture_holders"],"observer_scope_unbound_only":True}

def native_state(rows,phase,seq):
    expected=[(1,0),(2,0),(3,6),(4,6),(5,6),(3,58),(4,58),(5,58),(6,3),(7,3),(8,3),(6,6),(7,6),(8,6),(9,0),(10,0)]+[(k,s) for s in (5,6,7,8,10) for k in (11,12)]+[(13,0)]
    need(list(rows)==expected,"entire fixed27 mapping inventory")
    state=lambda k,s:rows[(k,s)]["data"]
    lock,live=locks(state(7,3))
    history=state(7,6)
    h={"poisoned":False,"entries":{},"order":[],"snapshots":0,"total_bytes":0} if not any(history) else logical(ordinary.history(history,phase,seq))
    cache=state(11,8)
    c={"poisoned":False,"entries":{}} if not cache or not any(cache) else logical(ordinary.cache(cache,phase,seq))
    session=state(4,6);need(session[:8]==b"HRSWST02","actual session workspace")
    rn,cn,present,poisoned,applied,initialized,reserved=q(session,8,7)
    need(present in (0,1) and poisoned in (0,1) and applied in (0,1) and initialized==1 and reserved==0 and (present or cn==0) and 64+rn+cn<=len(session) and not any(session[64+rn+cn:]),"complete session workspace bytes")
    root=bytes(session[64:64+rn]);current=bytes(session[64+rn:64+rn+cn]);root.decode();current.decode()
    s={"root_hex":root.hex(),"current_hex":current.hex() if present else None,"effective_hex":(root if poisoned or not present else current).hex(),"session_applied":bool(applied),"poisoned":bool(poisoned)}
    fixture=state(13,0);need(len(fixture)==8192 and fixture[:8]==b"HXLTC001","complete fixture retained context")
    held=q(fixture,256,4)
    for identity in held:
        if identity:need(str(identity) in live["leases"] and live["leases"][str(identity)]["state"]==3,"fixture holder is actual held HIA lease")
    hub=state(1,0);need(len(hub)==4096,"complete shared hub")
    head,wake,count=q(hub,192,3)
    scopes={}
    for slot,magic in ((7,b"HRCLST01"),(6,b"HRSCST01"),(10,b"HRCXST01")):
        raw=state(11,slot)
        if raw and any(raw):need(raw[:8]==magic and q(raw,8)[0]==1,"actual View owner state identity")
        scopes[str(slot)]={"present":bool(raw),"initialized":bool(raw and any(raw)),"header_hex":bytes(raw[:256]).hex(),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
    if phase in (90,91):
        need(head==count==0,"runtime Drop retains no WAIT hub node")
        context=state(11,10);scope=state(11,6)
        if context and any(context):need(q(context,24,3)==(64,0,0),"runtime Drop closes actual request contexts")
        if scope and any(scope):need(q(scope,24)[0]==0 and q(scope,64)[0]==0,"runtime Drop closes actual operation scopes")
    return {"locks":lock,"history":h,"cache":c,"session":s},{**live,"fixture_holders":[bool(x) for x in held],"held_lease_ids":list(held),"hub":{"head":head,"wake_sequence":wake,"pending":count},"scopes":scopes}

def frame(raw,side):
    need(len(raw)>=96 and raw[:8]==b"HXLTR001","full fixed observation reply")
    seq,operation,slot,status,on,sn,phase=q(raw,8,7)
    need(seq>0 and status==0 and slot<4 and operation in (1,2,3,4,90,91) and phase in (0,90,91) and len(raw)==64+on+sn,"complete fixed observation extent")
    body=memoryview(raw)[64+on:];need(len(body)>=32 and body[:8]==b"HXLTS001","complete snapshot header")
    mode,count,flags=q(body,8,3)
    rows={};pins=[]
    if side=="original":
        need(mode==1 and flags==0 and count==len(body)-32,"complete original snapshot JSON")
        value=json.loads(bytes(body[32:]));need(value["phase"]==phase and value["sequence"]==seq,"original snapshot identity")
        parsed,private=original_state(value)
    else:
        need(mode==0 and count==27 and flags in (0,1),"complete native snapshot inventory")
        at=32
        for _ in range(count):
            kind,owner,address,extent=q(body,at,4);at+=32
            need((kind,owner) not in rows and ((address==0 and extent==0) or (address>0 and 0<extent<=256<<20)) and extent<=len(body)-at,"complete fixed mapping span")
            data=bytes(body[at:at+extent]);at+=extent
            rows[(kind,owner)]={"address":address,"data":data}
            pins.append({"kind":kind,"owner":owner,"address":address,"bytes":extent,"sha256":hashlib.sha256(data).hexdigest()})
        need(at==len(body) and bool(flags)==bool(rows[(9,0)]["address"]),"all mapping bytes accounted")
        parsed,private=native_state(rows,phase,seq)
    return {"sequence":seq,"operation":operation,"slot":slot,"phase":phase,"output_hex":bytes(raw[64:64+on]).hex(),"state":parsed,"private":private,"full_native_mappings":pins}

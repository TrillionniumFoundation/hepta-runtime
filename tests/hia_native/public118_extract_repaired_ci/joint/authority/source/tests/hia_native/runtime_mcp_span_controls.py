"""Actual HIA continuation/endpoint controls; no Rust or scheduler claim."""
import ctypes,json,mmap,struct
from pathlib import Path
word=lambda raw,at:struct.unpack_from('<Q',raw,at)[0]
pack=lambda *v:struct.pack('<'+'Q'*len(v),*v)

def invoke(module,wire,workspace,capacity):
    maps=[mmap.mmap(-1,len(wire)+16),mmap.mmap(-1,len(workspace)+16),mmap.mmap(-1,capacity+16)]
    p=[ctypes.addressof(ctypes.c_char.from_buffer(v)) for v in maps];sizes=[len(wire),len(workspace),capacity]
    ctypes.memmove(p[0],wire,len(wire));ctypes.memmove(p[1],workspace,len(workspace));ctypes.memset(p[2],0xa5,capacity)
    for address,n in zip(p,sizes):ctypes.memset(address+n,0x7d,16)
    try:
        code=module._entry(p[0],len(wire),p[2],capacity,p[1],len(workspace))
        assert ctypes.string_at(p[0],len(wire))==wire
        assert all(ctypes.string_at(address+n,16)==b'}'*16 for address,n in zip(p,sizes))
        return code,ctypes.string_at(p[2],capacity),ctypes.string_at(p[1],len(workspace))
    finally:
        for value in maps:value.close()

def run(manifest,output,save):
    from hia_native_loader import NativeModule
    bundle=json.loads(Path(manifest).read_bytes());members={r['name']:r for r in bundle['members']}
    modules={name:NativeModule(Path(members[name]['manifest']),manifest_sha256=members[name]['manifest_sha256']) for name in ('mcp','protocol','endpoint')}
    rows=[]
    def record(owner,kind,wire,before,capacity,actual):
        n=len(rows);code,out,after=actual
        rows.append(dict(number=n,owner=owner,kind=kind,return_code=code,
            input=save(output/(str(n)+'.input.bin.gz'),wire),
            workspace_before=save(output/(str(n)+'.before.bin.gz'),before),
            workspace_after=save(output/(str(n)+'.after.bin.gz'),after),
            output=save(output/(str(n)+'.output.bin.gz'),out),
            workspace_capacity=len(before),output_capacity=capacity,member_manifest_sha256=members[owner]['manifest_sha256']))
        return actual
    try:
        request=b'{"jsonrpc":"2.0","id":1,"method":"ping"}';before=bytes(8192)
        code,out,waiting=record('mcp','initial-actual-call',request,before,512,invoke(modules['mcp'],request,before,512))
        assert code==0xfffffff0 and waiting[256:264]==b'HRMCFA02'
        sequence=word(waiting,264);assert word(waiting,272)==0
        for offset in (0,8,16,24,32,40,48,56,64,80,88,104):
            bad=bytearray(waiting);struct.pack_into('<Q',bad,320,sequence)
            struct.pack_into('<Q',bad,256+offset,word(bad,256+offset)^(1<<63))
            value=record('mcp','refuse-action-'+str(offset),request,bytes(bad),512,invoke(modules['mcp'],request,bytes(bad),512))
            assert value==(0xffffffff,b'\xa5'*512,bytes(bad))
        for size in (0,1,31,63):
            value=record('mcp','refuse-short-output',request,before,size,invoke(modules['mcp'],request,before,size))
            assert value==(0xfffffffe,b'\xa5'*size,before)
        start,length=word(waiting,288),word(waiting,296);wire=waiting[start:start+length]
        child=record('protocol','actual-protocol-output-growth',wire,bytes(16384),512,invoke(modules['protocol'],wire,bytes(16384),512))
        assert child[0]==0xffffffd0 and child[1][:8]==b'HGRWS002' and word(child[1],8)==2
        needed=word(child[1],16);assert needed>512 and word(child[1],24)==0
        child=record('protocol','actual-protocol-child',wire,child[2],needed,invoke(modules['protocol'],wire,child[2],needed))
        assert child[0]==192 and child[1][:8]==b'HRJPRR02'
        extent=192+word(child[1],48)+word(child[1],56)+word(child[1],64);assert extent>word(waiting,312)
        delivery=bytearray(waiting);struct.pack_into('<Q',delivery,320,sequence)
        struct.pack_into('<Q',delivery,328,0xffffffcd);struct.pack_into('<Q',delivery,352,extent)
        again=record('mcp','actual-delivery-only',request,bytes(delivery),512,invoke(modules['mcp'],request,bytes(delivery),512))
        assert again[0]==0xfffffff0
        ready=bytearray(again[2]);assert word(ready,280)==1 and word(ready,264)==sequence and word(ready,312)>=extent
        at=word(ready,304);ready[at:at+extent]=child[1][:extent]
        struct.pack_into('<Q',ready,320,sequence);struct.pack_into('<Q',ready,328,child[0]);struct.pack_into('<Q',ready,352,extent)
        done=record('mcp','complete-retained-child',request,bytes(ready),512,invoke(modules['mcp'],request,bytes(ready),512))
        assert done[0]==64 and done[1][:8]==b'HRCMFR02' and word(done[1],8)==1
        n=word(done[1],24)+word(done[1],32);assert json.loads(done[1][64:64+n])=={'jsonrpc':'2.0','id':1,'result':{}}
        wire=b'HIAEP002'+pack(2,1,0)+b'x'
        full=record('endpoint','complete-wide-endpoint',wire,bytes(4096),256,invoke(modules['endpoint'],wire,bytes(4096),256))
        assert full[0]==32
        extent=32+word(full[1],24)
        short=record('endpoint','exact-needed-output',wire,bytes(4096),32,invoke(modules['endpoint'],wire,bytes(4096),32))
        assert short[0]==0xffffffd0 and short[1]==b'HGRWS002'+pack(2,extent,0) and full[2]==short[2]
        for bad in (wire[:31],b'BADMAGIC'+wire[8:],b'HIAEP002'+pack(2,1,0)+b'\xff',b'HIAEP002'+pack(2,(1<<64)-1,0)):
            value=record('endpoint','refuse-invalid-endpoint',bad,bytes(4096),256,invoke(modules['endpoint'],bad,bytes(4096),256))
            assert value==(0xffffffff,b'\xa5'*256,bytes(4096))
    finally:
        for module in modules.values():module.close()
    (output/'calls.json').write_text(json.dumps(rows,sort_keys=True,indent=2)+'\n')
    return dict(actual_native_calls=len(rows),invalid_controls=20,actual_protocol_child_calls=2,
        actual_protocol_output_growth_retries=1,
        real_child_positive_continuations=1,
        delivery_only_calls=1,exact_needed_output_controls=1,new_original_processes=0,concurrent_scheduler_qualification=False)

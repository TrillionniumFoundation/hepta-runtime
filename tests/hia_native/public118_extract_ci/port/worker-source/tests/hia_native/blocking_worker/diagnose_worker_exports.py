"""Actual mapped-export borrow and FIFO controls; no Rust or worker simulation."""
from __future__ import annotations
import argparse,ctypes,json,mmap,struct,sys
from pathlib import Path
from diagnose_timed_core import Capture,sha
from worker_transport import frame
from worker_evidence import words

PUBLIC={'bellman_worker_init':1,'bellman_worker_control':3,'bellman_worker_poll':1,
        'bellman_worker_receive':3,'bellman_worker_release':2,'bellman_worker_wake_fd':1,
        'bellman_worker_shutdown':1,'bellman_worker_destroy':1}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bridge',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    component=json.loads((a.bridge/'component.json').read_bytes());raw=(a.bridge/'bellman-worker.elf').read_bytes()
    assert sha(raw)==component['executable_sha256'] and set(component['exports'])==set(PUBLIC)
    assert len({v['offset'] for v in component['exports'].values()})==len(PUBLIC)
    mapping=mmap.mmap(-1,len(raw),prot=mmap.PROT_READ|mmap.PROT_WRITE)
    mapping.write(raw);address=ctypes.addressof(ctypes.c_char.from_buffer(mapping))
    libc=ctypes.CDLL(None,use_errno=True);libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];libc.mprotect.restype=ctypes.c_int
    assert libc.mprotect(address,len(raw),mmap.PROT_READ|mmap.PROT_EXEC)==0
    calls={}
    for name,count in PUBLIC.items():
        offset=component['exports'][name]['offset'];assert 176<=offset<component['prefix_bytes']
        calls[name.removeprefix('bellman_worker_')]=ctypes.CFUNCTYPE(ctypes.c_uint64,*([ctypes.c_uint64]*count))(address+offset)
    capture=Capture(a.output);handle=0;borrow=None;rows=[];tags=[];refusals=0;sequence=0

    def state():
        if not handle:return b'',b''
        global_bytes=ctypes.string_at(handle,4096);pool,size=struct.unpack_from('<2Q',global_bytes,8)
        assert size==4096
        return global_bytes,ctypes.string_at(pool,size)

    def invoke(name,args,*,wire=None,out=None,expect=None):
        nonlocal handle,borrow,refusals
        before_global,before_pool=state();before_output=bytes(out.raw) if out is not None else b''
        before_wire=bytes(wire.raw) if wire is not None else b''
        before_borrow=ctypes.string_at(*borrow[:2]) if borrow is not None else b''
        result=calls[name](*args)
        if name=='init' and result not in (0xffffffff,0xfffffffe):handle=result
        if name=='destroy' and result==0:handle=0
        after_global,after_pool=state();after_output=bytes(out.raw) if out is not None else b''
        after_wire=bytes(wire.raw) if wire is not None else b''
        after_borrow=ctypes.string_at(*borrow[:2]) if borrow is not None else b''
        row={'index':len(rows),'function':name,'result':result,'arguments':list(args)}
        for key,value in [('before_global',before_global),('after_global',after_global),('before_pool',before_pool),('after_pool',after_pool),
                          ('before_output',before_output),('after_output',after_output),('input',before_wire),('after_input',after_wire),
                          ('before_borrow',before_borrow),('after_borrow',after_borrow)]:row[key]=capture.blob(value,key)
        rows.append(row);capture.rows.append(row)
        if expect is not None:assert result==expect,(name,hex(result),hex(expect))
        if result in (0xffffffff,0xfffffffe,0xfffffff8,0xfffffff9):
            assert before_global==after_global and before_pool==after_pool and before_output==after_output
            assert before_borrow==after_borrow;refusals+=1
        assert before_wire==after_wire
        return result

    def control(command,tag,*,wire_bytes=None,expect=0):
        wire=ctypes.create_string_buffer(frame(command,tag)[8:] if wire_bytes is None else wire_bytes)
        return invoke('control',[handle,ctypes.addressof(wire),len(wire.raw)-1],wire=wire,expect=expect)

    def receive(capacity=32,expect=32):
        nonlocal borrow,sequence
        out=ctypes.create_string_buffer(bytes([0xa5])*40,40)
        invoke('receive',[handle,ctypes.addressof(out),capacity],out=out,expect=expect)
        if expect!=32:
            assert out.raw==bytes([0xa5])*40
            return None
        assert out.raw[:8]==b'HBWBRW01' and out.raw[32:]==bytes([0xa5])*8
        pointer,size,token=struct.unpack_from('<3Q',out.raw,8);assert token==sequence+1 and size>=192
        sequence=token;borrow=(pointer,size,token);raw=ctypes.string_at(pointer,size)
        assert raw[:8]==b'HBPMSR01';h=words(raw[:64]);assert h[1]==len(raw)==192 and h[2]==1 and h[4:]==[0,128,0,0]
        assert raw[64:72]==b'HBPWRS01' and words(raw[64:])[2:]==[0,10]+[0]*12
        tags.append(h[3]);rows[-1]['event']=capture.blob(raw,'event')
        return raw

    def release(token=None,expect=0):
        nonlocal borrow
        actual=borrow[2] if token is None else token
        invoke('release',[handle,actual],expect=expect)
        if expect==0:borrow=None

    try:
        invoke('init',[1],expect=0xffffffff)
        invoke('init',[2]);assert handle>0xffffffff
        fd=invoke('wake_fd',[handle]);assert 3<=fd<1<<31
        invoke('poll',[handle],expect=0)
        receive(expect=0);invoke('destroy',[handle],expect=0xfffffff8)
        valid=frame(5,1)[8:]
        mutations=[b'',valid[:7],valid[:63],valid+b'X',b'X'+valid[1:]]
        for offset,value in [(8,0),(8,8),(24,1),(32,1),(40,(1<<64)-1),(48,1),(56,1)]:
            changed=bytearray(valid);struct.pack_into('<Q',changed,offset,value);mutations.append(bytes(changed))
        for wire in mutations:control(5,1,wire_bytes=wire,expect=0xffffffff)
        control(5,1)
        for capacity in [0,1,7,31]:receive(capacity,expect=0xfffffffe)
        first=receive();assert first is not None
        control(5,2,expect=0xffffffff);invoke('poll',[handle],expect=0xffffffff)
        receive(expect=0xffffffff);invoke('shutdown',[handle],expect=0xffffffff);invoke('destroy',[handle],expect=0xffffffff)
        invoke('wake_fd',[handle],expect=fd)
        release(0,expect=0xffffffff);release(borrow[2]+1,expect=0xffffffff)
        token=borrow[2];release();invoke('release',[handle,token],expect=0xffffffff)
        receive(expect=0)
        for tag in range(2,42):control(5,tag)
        assert invoke('poll',[handle],expect=1)==1
        for _ in range(40):receive();release()
        assert tags==list(range(1,42))
        receive(expect=0);invoke('poll',[handle],expect=0)
        invoke('shutdown',[handle],expect=0);invoke('poll',[handle],expect=0)
        invoke('destroy',[handle],expect=0)
        result={'status':'ACTUAL_CALLABLE_EXPORT_CONTROLS_PASS','calls':len(rows),'atomic_refusals':refusals,
                'complete_fifo_events':len(tags),'borrow_tokens':sequence,'complete_buffer_bytes':capture.bytes,
                'executable_sha256':component['executable_sha256'],'exports':component['exports'],
                'same_qualified_worker_images':True,'concurrent_host_entry_qualified':False,'public_handler_qualified':False}
        (a.output/'report.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps(result,sort_keys=True))
    finally:
        capture.close()
        # This control domain starts no OS worker; failing assertions retain the
        # mappings for process-exit cleanup instead of inventing successful calls.
        calls.clear();mapping.close()

if __name__=='__main__':main()

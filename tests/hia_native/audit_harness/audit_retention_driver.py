"""Invoke the actual HIA owner and transport predeclared child results only."""
import ctypes,struct
from audit_retention_cases import request

def invoke(module,case):
    from hia_native_loader import NativeRejected
    wire=request(case);outcap=64+len(case['records'])*520 if case['operation']==4 else 576
    rules={(e['kind'],e['argument_hex'],e['flags']):e for e in case['effects']};assert len(rules)==len(case['effects'])
    trace=[];calls=0
    with module.session(output_capacity=outcap,workspace_capacity=4<<20) as session:
        while True:
            calls+=1;assert calls<4096
            try:
                result=session.invoke(wire);return dict(result_hex=result.hex(),trace=trace,native_calls=calls)
            except NativeRejected as error:
                if error.code!=0xfffffff0:raise
            action=struct.unpack('<12Q',ctypes.string_at(ctypes.addressof(session._workspace)+256,96))
            magic,sequence,kind,flags,span,count,reply_at,capacity,ack,returned,errno,reserved=action
            assert magic==int.from_bytes(b'HRAKA001','little') and ack==returned==errno==reserved==0
            assert kind in (100,101,102,103) and flags in (0,1) and span==8192 and count<=512 and reply_at==4096 and capacity==560
            argument=ctypes.string_at(ctypes.addressof(session._workspace)+span,count)
            key=(kind,argument.hex(),flags);assert key in rules,('unexpected effect',case['name'],key)
            e=rules[key];trace.append(e.copy());response=bytes.fromhex(e['reply_hex']);assert len(response)<=capacity
            ctypes.memmove(ctypes.addressof(session._workspace)+reply_at,response,len(response))
            struct.pack_into('<2Q',session._workspace,320,sequence,len(response))

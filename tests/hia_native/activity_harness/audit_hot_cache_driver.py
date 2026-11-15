"""Transport ordered child replies only; all cache and retry choices execute in HIA."""
import ctypes
import struct
from audit_hot_cache_cases import request

def invoke(session,command):
    from hia_native_loader import NativeRejected
    wire=request(command);trace=[];calls=0;effects=command['effects']
    while True:
        calls+=1;assert calls<=2056
        try:
            result=session.invoke(wire)
            assert len(trace)==len(effects),('unconsumed declared child',command['name'],len(trace),len(effects))
            assert result[:8]==b'HRACR001' and len(result)>=64
            return dict(name=command['name'],result_hex=result.hex(),trace=trace,native_calls=calls)
        except NativeRejected as error:
            if error.code!=0xfffffff0:raise
        action=struct.unpack('<12Q',ctypes.string_at(ctypes.addressof(session._workspace)+256,96))
        magic,sequence,kind,flags,span,count,reply_at,capacity,ack,returned,errno,reserved=action
        assert magic==int.from_bytes(b'HRACA001','little') and ack==returned==errno==reserved==0
        assert kind in (100,101,102,103) and flags==(2 if kind==103 else 0)
        assert span==8192 and count<=525 and reply_at==524288 and capacity==266288
        argument=ctypes.string_at(ctypes.addressof(session._workspace)+span,count)
        assert len(trace)<len(effects),('unexpected extra effect',command['name'],kind,argument.hex(),flags)
        value=effects[len(trace)]
        assert (kind,argument.hex(),flags)==(value['kind'],value['argument_hex'],value['flags']),('effect order',command['name'],len(trace),kind,argument.hex(),flags,value)
        trace.append(value.copy());response=bytes.fromhex(value['reply_hex']);assert len(response)<=capacity
        ctypes.memmove(ctypes.addressof(session._workspace)+reply_at,response,len(response))
        struct.pack_into('<2Q',session._workspace,320,sequence,len(response))

"""Private parent packet construction and complete terminal DATA decoding."""
import struct
from evidence_common import require,decode
from protocol import error_frame,U


def wire(query):
    prior=query["expected_version"]
    parts=[query["root"].encode(),query["path"].encode(),b""if prior is None else prior.encode(),query["data_base64"].encode()]
    return b"HBPWQ001"+struct.pack("<11Q",1,0,1,*(len(p)for p in parts),int(prior is not None),0,0,
                                     sum(len(p)for p in parts))+b"".join(parts)


def result(raw):
    require(len(raw)>=64 and raw[:8]==b"HBPWR001" and U(raw,56)==len(raw)-64
            and all(U(raw,at)==0 for at in (24,32,40,48)),"complete parent terminal frame")
    if U(raw,8)==0:
        value=decode(raw[64:])
        require(type(value)is dict and set(value)=={"written","size","version","sha256","mode"},"complete retained write result")
        require(type(value["written"])is int and 0<=value["written"]<=1048576
                and type(value["size"])is int and value["size"]>=0
                and type(value["mode"])is int and 0<=value["mode"]<=4095
                and type(value["version"])is str and type(value["sha256"])is str
                and len(value["sha256"])==64 and all(c in"0123456789abcdef"for c in value["sha256"]),"write scalar fields")
        return dict(ok=True,value=value)
    require(U(raw,8)==3,"parent did not terminate with a result/error")
    return dict(ok=False,error=error_frame(raw[64:]))
